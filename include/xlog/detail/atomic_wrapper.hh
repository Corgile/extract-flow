//
// xlog / atomic_wrapper.hh
// Created by brian on 2024-06-03.
//

#ifndef XLOG_ATOMIC_WRAPPER_HH
#define XLOG_ATOMIC_WRAPPER_HH

#include <atomic>

namespace xlog {
/// @brief 因为std::atomic不支持所有权转移，这里写一个wrapper类来实现.
/// @tparam T
template<typename T>
struct Atomic {
  Atomic() : _a() {}

  Atomic(const std::atomic<T>& a) : _a(a.load()) {}

  Atomic(Atomic&& other) : _a(other.load()) {}

  Atomic& operator=(const Atomic& other) { store(other.load()); }

  T load(std::memory_order memoryOrder = std::memory_order::seq_cst) {
    return _a.load(memoryOrder);
  }

  void store(T value, std::memory_order memoryOrder = std::memory_order::seq_cst) {
    _a.store(value, memoryOrder);
  }

private:
  std::atomic<T> _a;
};

} // xlog

#endif //XLOG_ATOMIC_WRAPPER_HH
