#pragma once
// Just enough Arduino for running the CLI code on a PC (env:native_cli)

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include "Stream.h"

using std::isnan;

inline uint32_t g_mock_millis = 0;
inline uint32_t millis() { return g_mock_millis; }
inline void delay(uint32_t ms) { g_mock_millis += ms; }
template<typename T, typename U> inline auto min(T a, U b) { return a < b ? a : b; }
template<typename T, typename U> inline auto max(T a, U b) { return a > b ? a : b; }
template<typename T, typename L, typename H> inline T constrain(T x, L lo, H hi) { return x < lo ? lo : (x > hi ? hi : x); }
inline char* ltoa(long v, char* buf, int base) {
  if (base == 16) sprintf(buf, "%lx", v); else sprintf(buf, "%ld", v);
  return buf;
}
inline long random(long lo, long hi) { return lo + (std::rand() % (hi - lo)); }

class MockSerial : public Stream {
public:
  size_t write(uint8_t) override { return 1; }
  void println(const char* = "") { }
  void begin(unsigned long) { }
};
inline MockSerial Serial;
