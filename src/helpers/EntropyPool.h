#pragma once

#include <stdint.h>
#include <stddef.h>

/** HMAC-DRBG with SHA-256, NIST SP 800-90A section 10.1.2 (no prediction resistance). */
class HmacDrbg {
  uint8_t K[32], V[32];
  void update(const uint8_t* provided, size_t len);
public:
  void instantiate(const uint8_t* seed_material, size_t len);   // entropy || nonce || personalization
  void reseed(const uint8_t* seed_material, size_t len);        // entropy || additional input
  void generate(uint8_t* out, size_t len);                      // no additional input
  void wipe();
};

/**
 * Randomness for keys: an entropy pool that conditions every input with SHA-256, and an
 * HMAC-DRBG (NIST SP 800-90A, SHA-256) that is reseeded from the pool and produces the output.
 *
 * Inputs are credited conservatively, and keys should only be kept when creditedBits() >= 256:
 *  - hardware RNG bytes count only when the hardware reports success and is known to be a true
 *    entropy source at that moment (nRF52 CC310; ESP32 only while its SAR ADC entropy source is
 *    on, see collectEarly())
 *  - radio noise counts 1 bit per sample, and only for a batch that passes the SP 800-90B
 *    repetition count and adaptive proportion health tests. These catch a stuck or heavily biased
 *    radio, not a predictable one: nothing can prove a source is unpredictable.
 *  - timestamps and everything passed to addUntrusted() are mixed in but count for nothing
 *
 * Not thread-safe: call only from setup() and the main loop, never from BLE or other callbacks.
 */
class EntropyPool {
public:
  static const int KEY_BITS = 256;
  static const int RADIO_BATCH = 512;   // samples needed for one credited radio batch (APT window)

  /**
   * Call first thing in setup(), before the radio, ADC, I2S or Wi-Fi/BT are started.
   * ESP32: briefly turns on the SAR ADC entropy source so its RNG is truly random, collects from
   * it, and turns it off again (it can't be used once the ADC or RF are in use). Elsewhere: no-op.
   */
  static void collectEarly();

  /** Mix in data that may be predictable (seeds, IDs, timings). Credited 0 bits. */
  static void addUntrusted(const void* data, size_t len);

  /** Mix in 32 bytes from the MCU's hardware RNG. \returns true if they were credited. */
  static bool addHardware();

  /**
   * Mix in raw radio noise samples, one byte each. Runs the health tests over the batch.
   * A batch of at least RADIO_BATCH samples that passes is credited 1 bit per sample.
   * \returns true if the batch passed the health tests
   */
  static bool addRadioSamples(const uint8_t* samples, size_t n);

  /** Fill dest with random bytes from the DRBG (reseeded first if new input arrived). */
  static void generate(uint8_t* dest, size_t len);

  /** Entropy credited so far (capped). Keys should only be kept when this is >= KEY_BITS. */
  static int creditedBits();
  static bool readyForKeys() { return creditedBits() >= KEY_BITS; }

  /** Status, for diagnostics: hardware 0 = not tried, 1 = credited, -1 = failed / not trusted */
  static int hardwareStatus();
  static int radioStatus();          // 0 = no batch yet, 1 = last batch passed, -1 = failed
  static size_t radioSamples();      // total radio samples mixed in

  /** Overwrite memory in a way the compiler can't remove */
  static void secureZero(void* p, size_t len);

  // for tests: replace the platform hardware RNG (return false = failure)
  typedef bool (*HardwareSource)(uint8_t* dest, size_t len, bool& trusted);
  static void setHardwareSourceForTest(HardwareSource src);
  static void resetForTest();
};
