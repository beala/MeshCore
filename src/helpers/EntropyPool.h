#pragma once

#include <stdint.h>
#include <stddef.h>

/**
 * A SHA-256 entropy pool for generating keys.
 *
 * Everything added is hashed into a 32-byte state, so output is as strong as the best source
 * that went in, even if other sources are biased, stuck or predictable. Each call to generate()
 * also mixes in the MCU's hardware random generator where there is one (nRF52 CC310, ESP32 RNG)
 * and a timestamp, and moves the state on afterwards, so earlier outputs can't be recovered from it.
 */
class EntropyPool {
public:
  /** Mix in data (radio noise, timings, ...). Doesn't need to be secret or uniform. */
  static void add(const void* data, size_t len);

  /** Fill dest with random bytes. */
  static void generate(uint8_t* dest, size_t len);

  /** true if this platform has a hardware random generator that generate() mixes in */
  static bool hasHardwareSource();
};
