//
// xlog / log_option.hh
// Created by brian on 2024-06-04.
//

#ifndef XLOG_LOG_OPTION_HH
#define XLOG_LOG_OPTION_HH

#include <atomic>

namespace xlog {

struct log_option {
  /// 允许console打印
  volatile std::atomic_bool console_;
  /// 允许异步
  volatile std::atomic_bool async_;
};
extern log_option logOption;
} // namespace xlog

#endif // XLOG_LOG_OPTION_HH
