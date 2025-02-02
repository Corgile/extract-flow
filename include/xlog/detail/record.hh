//
// xlog / record.hh
// Created by brian on 2024-06-02.
//

#ifndef XLOG_RECORD_HH
#define XLOG_RECORD_HH

#include "xlog/detail/level.hh"
#include "xlog/detail/time_util.hh"
#include "xlog/vendor/dragonbox_to_chars.h"
#include "xlog/vendor/meta_string.hpp"

#include <charconv>
#include <chrono>
#include <iomanip>
#include <ostream>

namespace xlog {
namespace detail {
template<class T>
constexpr inline bool c_array_v =
    std::is_array_v<std::remove_cvref_t<T>> && (std::extent_v<std::remove_cvref_t<T>> > 0);

template<typename Type, typename = void>
struct has_data : std::false_type {};

template<typename T>
struct has_data<T, std::void_t<decltype(std::declval<std::string>().append(std::declval<T>().data()))>>
    : std::true_type {};

template<typename T>
constexpr inline bool has_data_v = has_data<std::remove_cvref_t<T>>::value;

template<typename Type, typename = void>
struct has_str : std::false_type {};

template<typename T>
struct has_str<T, std::void_t<decltype(std::declval<std::string>().append(std::declval<T>().str()))>> : std::true_type {
};

template<typename T>
constexpr inline bool has_str_v = has_str<std::remove_cvref_t<T>>::value;
} // namespace detail
/// @brief 一条日志记录实体类
class record_t {
  using time_point_t = std::chrono::system_clock::time_point;

public:
  record_t() = default;

  record_t(time_point_t tm_point, Level level, std::string_view str)
      : timePoint_(tm_point),
        level_(level),
        tid_(getTid()),
        fileStr_(str) {
    content_.reserve(64);
  }

  record_t(record_t&&) = default;

  record_t& operator=(record_t&&) = default;

  Level getLevel() const { return level_; }

  const char* getMessage() {
    content_.push_back('\n');
    return content_.data();
  }

  /// @brief 获取日志输出所在的源代码文件
  /// @return 短文件路径
  std::string_view getFileStr() const { return fileStr_; }

  /// @brief 获取logger名
  /// @return sv
  std::string_view getLoggerName() const { return loggerName_; }

  /// @brief 获取当前线程 ID
  unsigned int getThreadId() const { return tid_; }

  /// @brief 获取时间戳
  auto getTimePoint() const { return timePoint_; }

  /// @brief 返回一个自身的引用
  record_t& ref() { return *this; }

  ///@brief 按类型追加内容
  template<typename T>
  record_t& operator<<(const T& data) {
    using U = std::remove_cvref_t<T>;
    if constexpr (std::is_floating_point_v<U>) {
      char       temp[40];
      const auto end = jkj::dragonbox::to_chars(data, temp);
      content_.append(temp, std::distance(temp, end));
    } else if constexpr (std::is_same_v<bool, U>) {
      data ? content_.append("true") : content_.append("false");
    } else if constexpr (std::is_same_v<char, U>) {
      content_.push_back(data);
    } else if constexpr (std::is_enum_v<U>) {
      int val = (int)data;
      *this << val;
    } else if constexpr (std::is_integral_v<U>) {
      char buf[32];
      auto [ptr, err] = std::to_chars(buf, buf + 32, data);
      content_.append(buf, std::distance(buf, ptr));
    } else if constexpr (std::is_pointer_v<U>) {
      char buf[32]    = {"0x"};
      auto [ptr, err] = std::to_chars(buf + 2, buf + 32, (uintptr_t)data, 16);
      content_.append(buf, std::distance(buf, ptr));
    } else if constexpr (std::is_same_v<std::string, U> || std::is_same_v<std::string_view, U>) {
      content_.append(data.data(), data.size());
    } else if constexpr (detail::c_array_v<U>) {
      content_.append(data);
    } else if constexpr (detail::has_data_v<U>) {
      content_.append(data.data());
    } else if constexpr (detail::has_str_v<U>) {
      content_.append(data.str());
    } else if constexpr (std::is_same_v<std::chrono::system_clock::time_point, U>) {
      content_.append(xlog::time_util::get_local_time_str(data));
    } else {
      std::stringstream ss;
      ss << data;
      content_.append(std::move(ss).str());
    }

    return *this;
  }

  template<typename... Args>
  record_t& sprintf(const char* fmt, Args&&... args) {
    printf_string_format(fmt, std::forward<Args>(args)...);
    return *this;
  }

  template<typename String>
  record_t& format(String&& str) {
    content_.append(str.data());
    return *this;
  }

  void setLoggerName(const std::string& name) { loggerName_ = name; }
  void setLoggerId(size_t id) { loggerId_ = id; }

private:
  template<typename... Args>
  void printf_string_format(const char* fmt, Args&&... args) {
    size_t size = snprintf(nullptr, 0, fmt, std::forward<Args>(args)...);
#if defined(XLOG_ENABLE_PMR) and __has_include(<memory_resource> )
    char                                arr[1024];
    std::pmr::monotonic_buffer_resource resource(arr, 1024);
    std::pmr::string                    buf{&resource};
#else
    std::string buf;
#endif
    buf.reserve(size + 1);
    buf.resize(size);
    snprintf(buf.data(), size + 1, fmt, args...);
    content_.append(buf);
  }

  ///@brief 返回线程ID
  unsigned int getTid() {
    static thread_local unsigned int tid = getTidImpl();
    return tid;
  }

  ///@brief 获取线程ID不同平台的实现
  unsigned int getTidImpl() {
#ifdef _WIN32
    return std::hash<std::thread::id>{}(std::this_thread::get_id());
#elif defined(__linux__)
    return static_cast<unsigned int>(::syscall(__NR_gettid));
#elif defined(__FreeBSD__)
    long tid;
    syscall(SYS_thr_self, &tid);
    return static_cast<unsigned int>(tid);
#elif defined(__rtems__)
    return rtems_task_self();
#elif defined(__APPLE__)
    uint64_t tid64;
    pthread_threadid_np(NULL, &tid64);
    return static_cast<unsigned int>(tid64);
#else
    return 0;
#endif
  }

  time_point_t timePoint_;
  Level        level_;
  uint32_t     tid_;
  uint32_t     fiberId_ = 0; // 协程id
  size_t       loggerId_{0};
  std::string  loggerName_{"UnNamed"};
  std::string  fileStr_;
#if defined(XLOG_ENABLE_PMR) and __has_include(<memory_resource> )
  char                                arr_[1024];
  std::pmr::monotonic_buffer_resource resource_;
  std::pmr::string                    ss_{&resource_};
#else
  std::string content_;
#endif
};

#define TO_STR(s) #s

/// 一个lambda函数的执行结果
#define GET_STRING(filename, line)                                                                                     \
  [] {                                                                                                                 \
    constexpr auto   path   = refvalue::meta_string{filename};                                                         \
    constexpr size_t pos    = path.rfind(std::filesystem::path::preferred_separator);                                  \
    constexpr auto   name   = path.substr<pos + 1>();                                                                  \
    constexpr auto prefix = name + ":" + TO_STR(line);          \
    return "[" + prefix + "] ";                                 \
  }()
}
#endif // XLOG_RECORD_HH
