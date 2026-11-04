#pragma once

#include <stdint.h>

// Keeps the last N items added, overwriting the oldest, plus a count of everything ever added.
template <typename T, int N>
class RecentHistory {
  T _items[N];
  uint8_t _next = 0;   // slot the next item goes into
  uint8_t _count = 0;  // items held, up to N
  uint32_t _total = 0;

public:
  void add(const T& item) {
    _items[_next] = item;
    _next = (_next + 1) % N;
    if (_count < N) _count++;
    _total++;
  }

  int count() const { return _count; }
  uint32_t total() const { return _total; }

  // i = 0 is the newest item, count() - 1 the oldest
  const T& get(int i) const { return _items[(_next + N - 1 - i) % N]; }
};
