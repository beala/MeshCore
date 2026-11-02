#include "EntropyPool.h"
#include <Arduino.h>
#include <SHA256.h>
#include <string.h>

#if defined(NRF52_PLATFORM) && defined(USE_CC310_HW_CRYPTO)
  #include <Adafruit_nRFCrypto.h>
  #define ENTROPY_HW_NRF52
#elif defined(ESP32)
  #include <esp_random.h>
  #define ENTROPY_HW_ESP32
#endif

static uint8_t pool_state[32];
static uint32_t pool_counter = 0;

static void mixIn(uint8_t tag, const void* data, size_t len) {
  SHA256 sha;
  uint32_t t = micros();          // timing jitter between calls is a little extra entropy
  uint32_t n = (uint32_t)len;
  sha.update(&tag, 1);
  sha.update(pool_state, sizeof(pool_state));
  sha.update(&t, sizeof(t));
  sha.update(&n, sizeof(n));
  if (len > 0) sha.update(data, len);
  sha.finalize(pool_state, sizeof(pool_state));
}

static void mixHardware() {
  uint8_t hw[32];
  memset(hw, 0, sizeof(hw));
#if defined(ENTROPY_HW_NRF52)
  nRFCrypto.Random.generate(hw, sizeof(hw));    // CC310 TRNG (nRFCrypto.begin() is called by NRF52Board)
#elif defined(ENTROPY_HW_ESP32)
  esp_fill_random(hw, sizeof(hw));              // true random while Wi-Fi/BT is on; mixed with other sources otherwise
#endif
  mixIn('H', hw, sizeof(hw));
  memset(hw, 0, sizeof(hw));
}

bool EntropyPool::hasHardwareSource() {
#if defined(ENTROPY_HW_NRF52) || defined(ENTROPY_HW_ESP32)
  return true;
#else
  return false;
#endif
}

void EntropyPool::add(const void* data, size_t len) {
  mixIn('A', data, len);
}

void EntropyPool::generate(uint8_t* dest, size_t len) {
  mixHardware();

  while (len > 0) {
    uint8_t block[32];
    SHA256 sha;
    uint8_t tag = 'O';
    sha.update(&tag, 1);
    sha.update(pool_state, sizeof(pool_state));
    sha.update(&pool_counter, sizeof(pool_counter));
    sha.finalize(block, sizeof(block));
    pool_counter++;

    size_t n = len < sizeof(block) ? len : sizeof(block);
    memcpy(dest, block, n);
    dest += n;
    len -= n;
    memset(block, 0, sizeof(block));
  }
  mixIn('N', NULL, 0);   // move the state on, so this output can't be recomputed from it later
}
