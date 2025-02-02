//
// xlog / logger.hh
// Created by brian on 2024-06-02.
//

#ifndef XLOG_SINK_HH
#define XLOG_SINK_HH

#include "xlog/detail/record.hh"
#include "xlog/vendor/concurrent_queue.hh"

#include <charconv>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <system_error>

namespace xlog {
namespace helper {
constexpr char digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

template<size_t N, char c>
inline void toInt(int num, char* p, int& size) {
  for (int i = 0; i < N; i++) {
    p[--size] = digits[num % 10];
    num = num / 10;
  }
  if constexpr (N != 4)
    p[--size] = c;
}

inline char* getTimeStr(const auto& now) {
  static thread_local char buf[24];
  static thread_local std::chrono::seconds last_sec_{};

  std::chrono::system_clock::duration d = now.time_since_epoch();
  std::chrono::seconds s = std::chrono::duration_cast<std::chrono::seconds>(d);
  auto mill_sec =
    std::chrono::duration_cast<std::chrono::milliseconds>(d - s).count();
  int size = 23;
  if (last_sec_ == s) {
    toInt<3, '.'>(mill_sec, buf, size);
    return buf;
  }

  last_sec_ = s;
  auto tm = std::chrono::system_clock::to_time_t(now);
  auto gmt = localtime(&tm);

  toInt<3, '.'>(mill_sec, buf, size);
  toInt<2, ':'>(gmt->tm_sec, buf, size);
  toInt<2, ':'>(gmt->tm_min, buf, size);
  toInt<2, ' '>(gmt->tm_hour, buf, size);

  toInt<2, '-'>(gmt->tm_mday, buf, size);
  toInt<2, '-'>(gmt->tm_mon + 1, buf, size);
  toInt<4, ' '>(gmt->tm_year + 1900, buf, size);
  return buf;
}

/// @brief 日志等级对应的字符串
/// @param level 等级 enum
/// @return 长度为 6 的字符串
inline std::string_view LevelStr(Level level) {
  switch (level) {
    //@format:off
    case Level::TRACE:return "TRACE ";
    case Level::DEBUG:return "DEBUG ";
    case Level::INFO: return "INFO  ";
    case Level::WARN: return "WARN  ";
    case Level::ERROR:return "ERROR ";
    case Level::FATAL:return "FATAL ";
    default:          return "NONE  ";
    // @format:on
  }
}

#ifdef _WIN32
enum class color_type : int {
    none = -1,
    black = 0,
    blue,
    green,
    cyan,
    red,
    magenta,
    yellow,
    white,
    black_bright,
    blue_bright,
    green_bright,
    cyan_bright,
    red_bright,
    magenta_bright,
    yellow_bright,
    white_bright
  };

  void windows_set_color(color_type fg, color_type bg) {
    auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle != nullptr) {
      CONSOLE_SCREEN_BUFFER_INFO info{};
      auto status = GetConsoleScreenBufferInfo(handle, &info);
      if (status) {
        WORD color = info.wAttributes;
        if (fg != color_type::none) {
          color = (color & 0xFFF0) | int(fg);
        }
        if (bg != color_type::none) {
          color = (color & 0xFF0F) | int(bg) << 4;
        }
        SetConsoleTextAttribute(handle, color);
      }
    }
  }
#endif

inline std::string_view addColor(Level level) {
  #if defined(_WIN32)
  if (level == Level::WARN)
      windows_set_color(color_type::black, color_type::yellow);
    if (level == Level::ERROR)
      windows_set_color(color_type::black, color_type::red);
    if (level == Level::FATAL)
      windows_set_color(color_type::white_bright, color_type::red);
  #elif __APPLE__
  #else
  if (level == Level::WARN) return "\x1B[93;1m";
  if (level == Level::ERROR) return "\x1B[91;1m";
  if (level == Level::FATAL) return "\x1B[97;1m\x1B[41m";
  #endif
  return {};
}

inline std::string_view cleanColor(Level level) {
  #if defined(_WIN32)
  if (level >= Level::WARN)
      windows_set_color(color_type::white, color_type::black);
  #elif __APPLE__
  #else
  if (level >= Level::WARN) return "\x1B[0m\x1B[0K";
  #endif
  return {};
}

inline std::string_view getTidBuf(unsigned int tid) {
  static thread_local char buf[24];
  static thread_local unsigned int last_tid;
  static thread_local size_t last_len;
  if (tid == last_tid) {
    return {buf, last_len};
  }

  buf[0] = '[';
  auto [ptr, ec] = std::to_chars(buf + 1, buf + 21, tid);
  buf[22] = ']';
  buf[23] = ' ';
  last_tid = tid;
  last_len = ptr - buf;
  buf[last_len++] = ']';
  buf[last_len++] = ' ';
  return {buf, last_len};
}
}
struct empty_mutex {
  void lock() {}

  void unlock() {}

};

constexpr inline std::string_view BOM_STR = "\xEF\xBB\xBF";

/// @brief 日志消息消费者，默认支持file和console
class Sink {
public:
  using ptr = Sink*;
  Sink()    = default;

  Sink(const std::string& filename, bool async, bool enableConsole,
       size_t fileMaxSize, size_t maxFileCount, bool realTimeFlush)
    : hasInit_(true), realTimeFlush_(realTimeFlush),
      enableConsole_(enableConsole), fileMaxSize_(fileMaxSize) {
    filename_ = filename;
    maxFileCount_ = (std::min)(maxFileCount, static_cast<size_t>(1000));
    openLogFile();
    if (async) startThread();
  }

  void enableConsole(bool b) { enableConsole_ = b; }

  void startThread() {
    writeFileThd_ = std::thread([this] {
      while (not stopped_) {
        if (maxFileCount_ > 0
            && currFileSize_ > fileMaxSize_
            && static_cast<size_t>(-1) != currFileSize_) {
          rollLogFiles();
        }

        record_t record;
        if (queue_.try_dequeue(record)) {
          enableConsole_ ? writeRecord<false, true>(record)
                         : writeRecord<false, false>(record);
        }

        /// 当队列没有日志消息要写的时候 死等.
        if (queue_.size_approx() > 0) continue;
        std::unique_lock lock(queMtx_);
        /// wait xxx until {...}
        cnd_.wait(lock, [&]() { return queue_.size_approx() > 0 or stopped_; });
      }
    });
  }

  template<bool sync>
  auto& IoStreamMtx() {
    if constexpr (sync) {
      return mtx_;
    } else {
      return empty_;
    }
  }

  template<bool synced = false, bool console = false>
  void writeRecord(record_t& record) {
    std::lock_guard guard(IoStreamMtx<synced>());
    if constexpr (synced) {
      if (maxFileCount_ > 0
          && currFileSize_ > fileMaxSize_
          && static_cast<size_t>(-1) != currFileSize_) {
        rollLogFiles();
      }
    }

    auto timeStr = helper::getTimeStr(record.getTimePoint());
    auto levelStr = helper::LevelStr(record.getLevel());
    auto tidStr = helper::getTidBuf(record.getThreadId());
    auto fileStr = record.getFileStr();
    auto msg = record.getMessage();
    auto name = record.getLoggerName();

    writeFile(timeStr);
    writeFile(" ");
    writeFile(levelStr);
    writeFile("[");
    writeFile(name);
    writeFile("] ");
    writeFile(tidStr);
    writeFile(fileStr);
    writeFile(msg);

    if constexpr (console) {
      std::cout << helper::addColor(record.getLevel());
      std::cout << timeStr;
      std::cout << ' ';
      std::cout << levelStr;
      std::cout << helper::cleanColor(record.getLevel());
      std::cout << "[";
      std::cout << name;
      std::cout << "] ";
      std::cout << tidStr;
      std::cout << fileStr;
      std::cout << helper::addColor(record.getLevel());
      std::cout << msg;
      std::cout << helper::cleanColor(record.getLevel());
      std::cout << std::flush;
    }
  }

  void write(record_t&& r) {
    queue_.enqueue(std::move(r));
    cnd_.notify_one();
  }

  void flush() {
    std::lock_guard guard(mtx_);
    if (file_.is_open()) {
      file_.flush();
      file_.sync_with_stdio();
    }
  }

  void stop() {
    std::lock_guard guard(mtx_);
    if (not writeFileThd_.joinable()) return;
    if (stopped_) return;
    stopped_ = true;
    cnd_.notify_one();
    record_t record;
    while (queue_.try_dequeue(record)) {
      if (maxFileCount_ > 0
          && currFileSize_ > fileMaxSize_
          && static_cast<size_t>(-1) != currFileSize_) {
        rollLogFiles();
      }
      enableConsole_ ? writeRecord<false, true>(record)
                     : writeRecord<false, false>(record);
    }
  }

  ~Sink() {
    stop();
    if (writeFileThd_.joinable()) writeFileThd_.join();
  }

private:
  void openLogFile() {
    currFileSize_ = 0;
    std::string filename = buildFilename();

    if (std::filesystem::path(filename).has_parent_path()) {
      std::error_code ec;
      auto parent = std::filesystem::path(filename).parent_path();
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        std::cout << "create directories error: " << ec.message() << std::flush;
        abort();
      }
    }

    file_.open(filename, std::ios::binary | std::ios::out | std::ios::app);
    if (file_) {
      std::error_code ec;
      size_t _fileSize = std::filesystem::file_size(filename, ec);
      if (ec) {
        std::cout << "get file size error" << std::flush;
        abort();
      }

      if (_fileSize == 0) {
        if (file_.write(BOM_STR.data(), BOM_STR.size())) {
          currFileSize_ += BOM_STR.size();
        }
      }
    }
  }

  std::string buildFilename(int fileIndex = 0) {
    if (fileIndex == 0) {
      return filename_;
    }

    auto filePath = std::filesystem::path(filename_);
    std::string filename = filePath.stem().string();

    if (fileIndex > 0) {
      char buf[32];
      auto [ptr, ec] = std::to_chars(buf, buf + 32, fileIndex);
      filename.append(".").append(std::string_view(buf, ptr - buf));
    }

    if (filePath.has_extension()) {
      filename.append(filePath.extension().string());
    }

    if (std::filesystem::path(filePath).has_parent_path()) {
      return filePath.parent_path().append(filename).string();
    }

    return filename;
  }

  void rollLogFiles() {
    file_.close();
    std::string lastFilename = buildFilename(maxFileCount_ - 1);

    std::error_code ec;
    std::filesystem::remove(lastFilename, ec);

    for (int fileIndex = maxFileCount_ - 2; fileIndex >= 0; --fileIndex) {
      std::string currentFileName = buildFilename(fileIndex);
      std::string nextFileName = buildFilename(fileIndex + 1);
      std::filesystem::rename(currentFileName, nextFileName, ec);
    }

    openLogFile();
  }

  void writeFile(std::string_view str) {
    if (not hasInit_) return;
    file_ << str;
    if (realTimeFlush_) file_ << std::flush;
    currFileSize_ += str.size();
  }

  bool hasInit_ = false; // 全局logger是否已经被实例化
  std::string filename_;

  bool enableConsole_ = false;
  bool realTimeFlush_;
  size_t currFileSize_ = 0; // B
  size_t fileMaxSize_ = 0;
  size_t maxFileCount_ = 0;

  /// 输出流
  std::shared_mutex mtx_;
  empty_mutex empty_;
  std::ofstream file_;

  std::mutex queMtx_;

  moodycamel::ConcurrentQueue <record_t> queue_;
  std::thread writeFileThd_;
  std::condition_variable cnd_;
  std::atomic<bool> stopped_ = false;
};
}
#endif // XLOG_SINK_HH
