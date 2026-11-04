#include "EntropyPool.h"
#include <SHA256.h>
#include <string.h>

#ifdef ARDUINO
  #include <Arduino.h>
  static uint32_t timestamp() { return micros(); }
#else
  static uint32_t timestamp() { return 0; }
#endif

#if defined(NRF52_PLATFORM) && defined(USE_CC310_HW_CRYPTO)
  #include <Adafruit_nRFCrypto.h>
  #define ENTROPY_HW_NRF52
#elif defined(ESP32)
  #include <esp_random.h>
  #if __has_include(<bootloader_random.h>)
    #include <bootloader_random.h>
    #define ENTROPY_HW_ESP32_ADC
  #endif
  #define ENTROPY_HW_ESP32
#endif

// ---- state ----
static uint8_t pool[32];            // SHA-256 conditioned pool
static bool pool_dirty = false;     // new input since the DRBG was last (re)seeded
static int credited = 0;            // bits of credited entropy
static int hw_status = 0, radio_status = 0;
static size_t radio_total = 0;

static HmacDrbg drbg;
static bool drbg_ready = false;

static EntropyPool::HardwareSource test_hw = NULL;

const int EntropyPool::KEY_BITS;
const int EntropyPool::RADIO_BATCH;

void EntropyPool::secureZero(void* p, size_t len) {
  volatile uint8_t* vp = (volatile uint8_t*)p;
  while (len--) *vp++ = 0;
}

static void credit(int bits) {
  credited += bits;
  if (credited > 4096) credited = 4096;
}

// pool = SHA256(tag || pool || timestamp || len || data)
static void mixIn(uint8_t tag, const void* data, size_t len) {
  SHA256 sha;
  uint32_t t = timestamp();
  uint32_t n = (uint32_t)len;
  sha.update(&tag, 1);
  sha.update(pool, sizeof(pool));
  sha.update(&t, sizeof(t));
  sha.update(&n, sizeof(n));
  if (len > 0) sha.update(data, len);
  sha.finalize(pool, sizeof(pool));
  pool_dirty = true;
}

// ---- HMAC-DRBG, SHA-256 (NIST SP 800-90A section 10.1.2) ----

static void hmac(const uint8_t key[32], const uint8_t* a, size_t a_len, uint8_t b_byte, bool has_b,
                 const uint8_t* c, size_t c_len, uint8_t out[32]) {
  SHA256 sha;
  uint8_t tmp[32];   // out may be the key or a: write it only at the end
  sha.resetHMAC(key, 32);
  sha.update(a, a_len);
  if (has_b) sha.update(&b_byte, 1);
  if (c_len > 0) sha.update(c, c_len);
  sha.finalizeHMAC(key, 32, tmp, 32);
  memcpy(out, tmp, 32);
  EntropyPool::secureZero(tmp, sizeof(tmp));
}

void HmacDrbg::update(const uint8_t* provided, size_t len) {
  hmac(K, V, 32, 0x00, true, provided, len, K);   // K = HMAC(K, V || 0x00 || provided)
  hmac(K, V, 32, 0, false, NULL, 0, V);            // V = HMAC(K, V)
  if (len == 0) return;
  hmac(K, V, 32, 0x01, true, provided, len, K);   // K = HMAC(K, V || 0x01 || provided)
  hmac(K, V, 32, 0, false, NULL, 0, V);            // V = HMAC(K, V)
}

void HmacDrbg::instantiate(const uint8_t* seed_material, size_t len) {
  memset(K, 0x00, 32);
  memset(V, 0x01, 32);
  update(seed_material, len);
}

void HmacDrbg::reseed(const uint8_t* seed_material, size_t len) {
  update(seed_material, len);
}

void HmacDrbg::generate(uint8_t* out, size_t len) {
  while (len > 0) {   // V = HMAC(K, V), output V
    hmac(K, V, 32, 0, false, NULL, 0, V);
    size_t n = len < 32 ? len : 32;
    memcpy(out, V, n);
    out += n;
    len -= n;
  }
  update(NULL, 0);    // update(additional input = none) after every request
}

void HmacDrbg::wipe() {
  EntropyPool::secureZero(K, sizeof(K));
  EntropyPool::secureZero(V, sizeof(V));
}

static void drbgSeedFromPool() {
  static const char pers[] = "MeshCore EntropyPool";   // personalization string / additional input
  uint8_t material[32 + sizeof(pers) - 1];
  memcpy(material, pool, 32);
  memcpy(&material[32], pers, sizeof(pers) - 1);
  if (!drbg_ready) {
    drbg.instantiate(material, sizeof(material));
    drbg_ready = true;
  } else {
    drbg.reseed(material, sizeof(material));
  }
  EntropyPool::secureZero(material, sizeof(material));
  mixIn('R', NULL, 0);    // move the pool on, so the seed can't be recomputed from it later
  pool_dirty = false;
}

// ---- hardware sources ----

static bool platformHardware(uint8_t* dest, size_t len, bool& trusted) {
#if defined(ENTROPY_HW_NRF52)
  trusted = true;   // CC310 TRNG
  return nRFCrypto.Random.generate(dest, (uint16_t)len);
#elif defined(ENTROPY_HW_ESP32)
  // Only truly random while Wi-Fi/BT or the SAR ADC entropy source is on, so these bytes are
  // mixed in but not credited here; collectEarly() credits the ones taken with the ADC source on.
  trusted = false;
  esp_fill_random(dest, len);
  return true;
#else
  trusted = false;
  return false;
#endif
}

void EntropyPool::collectEarly() {
#if defined(ENTROPY_HW_ESP32_ADC)
  if (test_hw) return;
  bootloader_random_enable();
  uint8_t buf[64];
  for (int round = 0; round < 2; round++) {
    esp_fill_random(buf, sizeof(buf));   // 512 bits from the RNG with a true entropy source mixed in
    mixIn('E', buf, sizeof(buf));
  }
  secureZero(buf, sizeof(buf));
  bootloader_random_disable();
  credit(KEY_BITS);
  hw_status = 1;
#endif
  uint32_t t = timestamp();
  addUntrusted(&t, sizeof(t));
}

void EntropyPool::addUntrusted(const void* data, size_t len) {
  mixIn('U', data, len);
}

bool EntropyPool::addHardware() {
  uint8_t buf[32];
  memset(buf, 0, sizeof(buf));
  bool trusted = false;
  bool ok = test_hw ? test_hw(buf, sizeof(buf), trusted) : platformHardware(buf, sizeof(buf), trusted);
  mixIn('H', buf, sizeof(buf));   // harmless even if it failed
  secureZero(buf, sizeof(buf));
  if (ok && trusted) {
    credit(KEY_BITS);
    hw_status = 1;
    return true;
  }
  if (hw_status != 1) hw_status = -1;
  return false;
}

// SP 800-90B section 4.4 health tests, assuming min-entropy H = 1 bit per sample, alpha = 2^-20:
//   repetition count test: fail if one value repeats 1 + ceil(20 / H) = 21 times in a row
//   adaptive proportion test, window 512: fail if the window's first value occurs 410+ times
#define RCT_CUTOFF   21
#define APT_WINDOW   512
#define APT_CUTOFF   410

static bool healthTests(const uint8_t* s, size_t n) {
  size_t run = 1;
  for (size_t i = 1; i < n; i++) {
    run = (s[i] == s[i - 1]) ? run + 1 : 1;
    if (run >= RCT_CUTOFF) return false;
  }
  for (size_t start = 0; start + APT_WINDOW <= n; start += APT_WINDOW) {
    size_t count = 0;
    for (size_t i = start; i < start + APT_WINDOW; i++) {
      if (s[i] == s[start]) count++;
    }
    if (count >= APT_CUTOFF) return false;
  }
  return true;
}

bool EntropyPool::addRadioSamples(const uint8_t* samples, size_t n) {
  mixIn('N', samples, n);
  radio_total += n;
  bool ok = healthTests(samples, n);
  radio_status = ok ? 1 : -1;
  if (ok && n >= (size_t)RADIO_BATCH) credit((int)n);   // 1 bit per sample
  return ok;
}

void EntropyPool::generate(uint8_t* dest, size_t len) {
  addHardware();
  uint32_t t = timestamp();
  mixIn('T', &t, sizeof(t));
  if (pool_dirty || !drbg_ready) drbgSeedFromPool();
  drbg.generate(dest, len);
}

int EntropyPool::creditedBits() { return credited; }
int EntropyPool::hardwareStatus() { return hw_status; }
int EntropyPool::radioStatus() { return radio_status; }
size_t EntropyPool::radioSamples() { return radio_total; }

void EntropyPool::setHardwareSourceForTest(HardwareSource src) { test_hw = src; }

void EntropyPool::resetForTest() {
  memset(pool, 0, sizeof(pool));
  drbg.wipe();
  pool_dirty = false;
  drbg_ready = false;
  credited = 0;
  hw_status = radio_status = 0;
  radio_total = 0;
  test_hw = NULL;
}
