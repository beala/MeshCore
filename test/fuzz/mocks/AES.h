#pragma once
// Fuzzing only: "encryption" that leaves the bytes as they are, so the fuzzer writes the plaintext
// of every encrypted payload directly and reaches the code that parses it.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

class AES128 {
public:
  bool setKey(const uint8_t*, size_t) { return true; }
  void encryptBlock(uint8_t* output, const uint8_t* input) { memmove(output, input, 16); }
  void decryptBlock(uint8_t* output, const uint8_t* input) { memmove(output, input, 16); }
  void clear() { }
};
