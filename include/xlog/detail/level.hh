//
// xlog / level.hh
// Created by brian on 2024-06-03.
//

#ifndef XLOG_LEVEL_HH
#define XLOG_LEVEL_HH

namespace xlog {

enum class Level {
  NONE = 0,
  TRACE,
  DEBUG,
  INFO,
  WARN,
  ERROR,
  FATAL,
};

} // xhl

#endif //XLOG_LEVEL_HH
