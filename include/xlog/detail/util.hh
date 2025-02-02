//
// xlog / util.hh
// Created by brian on 2024-06-03.
//

#ifndef XLOG_MY_LITERALS_HH
#define XLOG_MY_LITERALS_HH

#include <unordered_map>

namespace xlog {
class ILogger;
template <size_t ID> class Logger;
} // namespace xlog

namespace xlog::util {

extern inline std::unordered_map<size_t, std::shared_ptr<xlog::ILogger>>
    allLoggers;
extern std::unordered_map<size_t, std::string> names;

constexpr size_t custom_hash(const char *data, const size_t length) {
  size_t hash = 0;
  constexpr size_t prime = 109ULL;
  for (size_t i = 0; i < length; ++i) {
    hash = hash * prime + static_cast<size_t>(data[i]);
  }
  return hash;
}

constexpr size_t hashed(std::string_view const name) {
  return util::custom_hash(name.data(), name.length());
}

constexpr size_t operator""_hash(const char *char_, const size_t length) {
  return util::custom_hash(char_, length);
}

inline std::string getName(const size_t id) {
  if (not names.contains(id))
    names[id] = "UnNamed";
  return names[id];
}
#ifndef SIZE_HUMAN_READABLE
#define SIZE_HUMAN_READABLE
constexpr unsigned long long operator""_B(unsigned long long bytes) {
  return bytes;
}

constexpr unsigned long long operator""_KB(unsigned long long kilobytes) {
  return kilobytes << 10;
}

constexpr unsigned long long operator""_MB(unsigned long long megabytes) {
  return megabytes << 20;
}

constexpr unsigned long long operator""_GB(unsigned long long gigabytes) {
  return gigabytes << 30;
}
#endif

} // namespace xlog::util

#endif // XLOG_MY_LITERALS_HH
