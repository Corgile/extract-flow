//
// xlog / api_macro.hh
// Created by brian on 2024-06-04.
//

#ifndef XLOG_API_MACRO_HH
#define XLOG_API_MACRO_HH

#define now_               std::chrono::system_clock::now()
#define instance_ptr(name) xlog::Logger<xlog::util::hashed(std::string_view(name))>::getInstance(name)
#define instance_(name)    (*instance_ptr(name))

#define XLOG_IMPL(level, name, ...)                                                                                    \
  if (!(instance_ptr(name)->checkLevel(level))) {                                                                      \
  } else                                                                                                               \
    instance_(name) += xlog::record_t(now_, level, GET_STRING(__FILE__, __LINE__)).ref()

#ifndef XLOG
  #define XLOG(level, ...) XLOG_IMPL(xlog::Level::level, __VA_ARGS__)
#endif

#define XLOGV_IMPL(level, name, fmt, ...)                                                                              \
  if (!(instance_ptr(name)->checkLevel(level))) {                                                                      \
  } else                                                                                                               \
    do {                                                                                                               \
      instance_(name) += xlog::record_t(now_, level, GET_STRING(__FILE__, __LINE__)).sprintf(fmt, __VA_ARGS__);        \
      if constexpr (level == xlog::Level::FATAL) {                                                                     \
        xlog::flushLogs<xlog::util::hashed(name)>();                                                                   \
        std::exit(EXIT_FAILURE);                                                                                       \
      }                                                                                                                \
    } while (false)

#ifndef XLOGV
  #define XLOGV(level, ...) XLOGV_IMPL(xlog::Level::level, "UnNamed", __VA_ARGS__, "\n")
#endif

#ifndef MXLOGV
  #define MXLOGV(level, LoggerId, ...) XLOGV_IMPL(xlog::Level::level, LoggerId, __VA_ARGS__, "\n")
#endif

#if __has_include(<fmt/format.h> ) or __has_include(<format>)
  #define XLOGFMT_IMPL0(level, name, prefix, ...)                                                                      \
    if (!(instance_ptr(name)->checkLevel(level))) {                                                                    \
    } else                                                                                                             \
      do {                                                                                                             \
        instance_(name) +=                                                                                             \
            xlog::record_t(now_, level, GET_STRING(__FILE__, __LINE__)).format(prefix::format(__VA_ARGS__));           \
        if constexpr (level == xlog::Level::FATAL) {                                                                   \
          xlog::flushLogs<xlog::util::hashed(name)>();                                                                 \
          std::exit(EXIT_FAILURE);                                                                                     \
        }                                                                                                              \
      } while (false)

  #if __has_include(<fmt/format.h> )
    #define XLOGFMT_IMPL(level, name, ...) XLOGFMT_IMPL0(level, name, fmt, __VA_ARGS__)
  #else
    #define XLOGFMT_IMPL(level, name, ...) XLOGFMT_IMPL0(level, name, std, __VA_ARGS__)
  #endif

  #ifndef XLOGFMT
    #define XLOGFMT(level, ...) XLOGFMT_IMPL(xlog::Level::level, "UnNamed", __VA_ARGS__)
  #endif

  /// named logger
  #ifndef MXLOGFMT
    #define MXLOGFMT(level, name, ...) XLOGFMT_IMPL(xlog::Level::level, name, __VA_ARGS__)
  #endif
#endif

#define XLOG_TRACE XLOG(TRACE, "UnNamed")
#define XLOG_DEBUG XLOG(DEBUG, "UnNamed")
#define XLOG_INFO  XLOG(INFO, "UnNamed")
#define XLOG_WARN  XLOG(WARN, "UnNamed")
#define XLOG_ERROR XLOG(ERROR, "UnNamed")
#define XLOG_FATAL XLOG(FATAL, "UnNamed")

/// named logger
#ifndef MXLOG_TRACE
  #define MXLOG_TRACE(name) XLOG(TRACE, name)
#endif
#ifndef MXLOG_DEBUG
  #define MXLOG_DEBUG(name) XLOG(DEBUG, name)
#endif
#ifndef MXLOG_INFO
  #define MXLOG_INFO(name) XLOG(INFO, name)
#endif
#ifndef MXLOG_WARN
  #define MXLOG_WARN(name) XLOG(WARN, name)
#endif
#ifndef MXLOG_ERROR
  #define MXLOG_ERROR(name) XLOG(ERROR, name)
#endif
#ifndef MXLOG_FATAL
  #define MXLOG_FATAL(name) XLOG(FATAL, name)
#endif
#define TOGGLE_ON  true
#define TOGGLE_OFF false
#endif // XLOG_API_MACRO_HH
