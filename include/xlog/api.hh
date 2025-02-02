//
// xlog / api.hh
// Created by brian on 2024-06-02.
// ReSharper disable CppDFAUnreachableFunctionCall

#ifndef XLOG_LOG_API_HH
#define XLOG_LOG_API_HH

#include "xlog/detail/logger.hh"
#include "xlog/detail/util.hh"

using namespace xlog::util;
namespace xlog {
class ILogger;
template<size_t ID>
class Logger;

namespace util {
inline std::unordered_map<size_t, std::shared_ptr<xlog::ILogger>> allLoggers;
inline std::unordered_map<size_t, std::string>                    names;
} // namespace util

/// @brief  实例化日志记录器
/// @tparam ID  可以根据ID实例化不同logger
/// @param level    日志输出的最小等级
/// @param filename 日志文件名(无则不创建)
/// @param async    是否开启异步日志
/// @param console  是否同时开启console日志
/// @param fileMaxSize  单个日志文件最大字节数 默认 10KB
/// @param maxFileCount 最大日志文件个数, 不能超过1000, >1 时开启滚动日志
/// @param alwaysFlush  写入一条刷新一次
template<size_t ID = "UnNamed"_hash>
inline void InstantiateFileLogger(Level level, std::string const& filename = {}, bool async = true, bool console = true,
                                  size_t fileMaxSize = 10_KB, size_t maxFileCount = 1, bool alwaysFlush = false) {
  Logger<ID>::getInstance()->init(level, async, console, filename, fileMaxSize, maxFileCount, alwaysFlush);
}

/// @brief 修改日志记录级别
/// @tparam ID  logger的ID
/// @param level 日志记录级别
template<size_t ID = "UnNamed"_hash>
inline void setLogLevelTo(Level level) {
  Logger<ID>::getInstance()->setMinLevel(level);
}

/// @brief 获取当前日志记录级别
/// @tparam ID 实例ID
/// @return Level
template<size_t ID = "UnNamed"_hash>
inline Level currentLogLevel() {
  return Logger<ID>::getInstance()->getMinLevel();
}

/// @brief 开启或关闭console日志输出
/// @tparam ID  logger id
/// @param enable   bool
template<size_t ID = "UnNamed"_hash>
inline void toggleConsoleLogging(bool enable) {
  Logger<ID>::getInstance()->setConsole(enable);
}

/// @brief 当前logger是否允许控制台打印日志
/// @tparam ID  logger id
/// @return \p true if enabled else \p false
template<size_t ID = "UnNamed"_hash>
inline bool consoleLogEnabled() {
  return Logger<ID>::getInstance()->consoleEnabled();
}

/// @brief 开启或关闭将当前logger的异步模式
/// @tparam ID  logger id
/// @param asynced \p true for async
template<size_t ID = "UnNamed"_hash>
inline void toggleAsyncLogging(bool asynced) {
  Logger<ID>::getInstance()->setAsync(asynced);
}

/// @brief 当前logger是否是异步模式
/// @tparam ID logger id
/// @return \p true for asynced
template<size_t ID = "UnNamed"_hash>
inline bool loggerIsAsynced() {
  return Logger<ID>::getInstance()->isAsynced();
}

/// @brief 刷新当前logger的输出
/// @tparam ID logger id
template<size_t ID = "UnNamed"_hash>
inline void flushLogs() {
  Logger<ID>::getInstance()->flush();
}

/// @brief 停止当前logger的异步记录线程
/// @tparam ID logger id
template<size_t ID = "UnNamed"_hash>
inline void stopAsyncLog() {
  Logger<ID>::getInstance()->stopAsyncLog();
}

/// @brief 添加用户自定义日志输出sink
/// @tparam ID  logger id
/// @param fn   函数对象
template<size_t ID = "UnNamed"_hash>
inline void addCustomLoggerSink(std::function<void(std::string_view)> fn) {
  Logger<ID>::getInstance()->addSink(std::move(fn));
}
}

#endif // XLOG_LOG_API_HH

// ReSharper disable once CppUnusedIncludeDirective
#include "xlog/detail/api_macro.hh"