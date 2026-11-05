#pragma once

#include <stdint.h>
#include <stddef.h>

// Fuzzing only: a cheap, deterministic stand-in for SHA-256. Every HMAC is all zeros, so the fuzzer
// passes MAC checks by writing 00 00. Plain hashes still differ by input, for the seen-packets table.
#include <string.h>

class SHA256 {
  uint8_t _state[32];
  size_t _len;
public:
  SHA256() : _len(0) { memset(_state, 0, sizeof(_state)); }

  void update(const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++) {
      uint8_t b = bytes[i];
      _state[_len % 32] ^= b;
      _state[(_len + 1) % 32] += (uint8_t)((b >> 1) | (b << 7));
      _len++;
    }
  }

  void finalize(uint8_t* hash, size_t hashLen) {
    for (size_t i = 0; i < hashLen; i++) {
      hash[i] = _state[i % 32];
    }
  }

  void resetHMAC(const uint8_t* key, size_t keyLen) {}
  void finalizeHMAC(const uint8_t*, size_t, uint8_t* hash, size_t hashLen) { memset(hash, 0, hashLen); }
};
