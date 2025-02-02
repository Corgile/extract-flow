//
// xlog / logger.hh
// Created by brian on 2024-06-03.
//

#ifndef XLOG_LOGGER_HH
#define XLOG_LOGGER_HH

#if __has_include(<format>)
  #include <format>
#endif

#if __has_include(<fmt/format.h> )
  #ifndef FMT_HEADER_ONLY
    #define FMT_HEADER_ONLY

    #include <fmt/format.h>

  #endif
#endif

#include "xlog/detail/record.hh"
#include "xlog/detail/sink.hh"
#include "xlog/detail/util.hh"

#include <functional>
#include <string_view>
#include <utility>
#include <vector>
// #define ENABLE_DEV_DEBUG
#ifdef ENABLE_DEV_DEBUG
  #define DEV_DEBUG(x) x
#else
  #define DEV_DEBUG(x)
#endif

namespace xlog {
using namespace xlog::util;

class ILogger {
public:
  using sptr = std::shared_ptr<ILogger>;

  virtual ~ILogger()                         = default;
           ILogger()                         = default;
           ILogger(const ILogger& other)     = delete;
           ILogger(ILogger&& other) noexcept = delete;

  ILogger& operator=(const ILogger& other)     = delete;
  ILogger& operator=(ILogger&& other) noexcept = delete;

public:
  ///@brief 进行日志记录
  virtual void log(record_t& record) const        = 0;
  virtual void operator+=(record_t& record) const = 0;
  virtual void flush() const                      = 0;

  virtual void init(Level minLevel, bool async, bool console, std::string const& filename, size_t fileMaxSize,
                    size_t maxFileCount, bool alwaysFlush) = 0;

  /// 只有当 level ≥ 最低level才进行日志记录
  virtual bool checkLevel(Level level) const                     = 0;
  /// 添加日志下游流向
  virtual void addSink(std::function<void(std::string_view)> fn) = 0;

  /// 停止异步日志线程
  virtual void  stopAsyncLog() const           = 0;
  virtual void  setMinLevel(Level level)       = 0;
  virtual Level getMinLevel() const            = 0;
  virtual void  setConsole(bool enabled)       = 0;
  virtual bool  consoleEnabled() const         = 0;
  virtual void  setAsync(bool asynced)         = 0;
  virtual bool  isAsynced() const              = 0;
  virtual void  setName(std::string_view name) = 0;
  virtual void  setHash(size_t const& id)      = 0;

protected:
  void appendRecord(record_t record) const { pSink_->write(std::move(record)); }
  void appendFormat(record_t& record) const {
    if (not pSink_)
      return;
    if (enableConsole_) {
      pSink_->writeRecord<true, true>(record);
    } else {
      pSink_->writeRecord<true, false>(record);
    }
  }
  Level minLevel_ =
#if NDEBUG
      Level::WARN;
#else
      Level::TRACE;
#endif
  bool        async_         = false;
  bool        enableConsole_ = true;
  Sink::ptr   pSink_         = nullptr;
  std::string loggerName_    = {};
  size_t      id_            = 0;
  /// 其他下游日志消息消费者
  std::vector<std::function<void(std::string_view)>> sinks_;
};

template<size_t ID = "UnNamed"_hash>
class Logger final : public ILogger {
  using ptr = std::shared_ptr<Logger>;

public:
  static ILogger::sptr getInstance(std::string_view name = "UnNamed") {
    DEV_DEBUG(std::cout << __FUNCTION__ << "  " << ID << "  " << hashed(name) << "\n");
    if (allLoggers.contains(ID)) [[likely]] {
      DEV_DEBUG(std::cout << __FUNCTION__ << "  " << name << "  contain\n");
      return allLoggers.at(ID);
    }
    DEV_DEBUG(std::cout << __FUNCTION__ << "  " << name << "  NO contain\n");
    static Logger<ID>::sptr instance = Logger::createInstance();
    instance->setName(name);
    instance->setHash(hashed(name));
    ILogger::sptr baseInstance = std::dynamic_pointer_cast<ILogger>(instance);
    allLoggers.insert_or_assign(hashed(name), baseInstance);
    return baseInstance;
  }

  ///@brief 进行日志记录
  void log(record_t& record) const override {
    record.setLoggerName(loggerName_);
    record.setLoggerId(ID);
    if (async_ and pSink_) {
      appendRecord(std::move(record));
    } else {
      appendFormat(record);
    }

    if (record.getLevel() == Level::FATAL) {
      flush();
      std::exit(EXIT_FAILURE);
    }
  }
  void operator+=(record_t& record) const override { log(record); }
  void flush() const override {
    if (pSink_)
      pSink_->flush();
  }
  void init(Level minLevel, bool async, bool console, std::string const& filename, size_t fileMaxSize,
            size_t maxFileCount, bool alwaysFlush) override {
    static Sink sink(filename, async, console, fileMaxSize, maxFileCount, alwaysFlush);
    async_         = async;
    pSink_         = &sink;
    minLevel_      = minLevel;
    enableConsole_ = console;
  }
  /// 只有当 level ≥ 最低level才进行日志记录
  bool checkLevel(const Level level) const override { return level >= minLevel_; }
  /// 停止异步日志线程
  void stopAsyncLog() const override { pSink_->stop(); }
  void setMinLevel(const Level level) override { minLevel_ = level; }
  void setAsync(const bool asynced) override { async_ = asynced; }
  void setConsole(const bool enabled) override {
    enableConsole_ = enabled;
    if (pSink_)
      pSink_->enableConsole(enabled);
  }
  void setName(std::string_view name) override { loggerName_ = std::string(name); }
  void setHash(size_t const& id) override { id_ = id; }
  /// 添加日志下游流向
  void  addSink(std::function<void(std::string_view)> fn) override { sinks_.emplace_back(std::move(fn)); }
  bool  consoleEnabled() const override { return enableConsole_; }
  bool  isAsynced() const override { return async_; }
  Level getMinLevel() const override { return minLevel_; }

  ~Logger() override {}

private:
  static Logger<ID>::sptr createInstance() { return Logger<ID>::sptr(new Logger<ID>()); }

  Logger() : ILogger() {
    static Sink sink{};
    sink.startThread();
    sink.enableConsole(true);
    async_ = true;
    pSink_ = &sink;
  }

  Logger(const Logger&) = default;

};
} // xhl

#endif // XLOG_LOGGER_HH
