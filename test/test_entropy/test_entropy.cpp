// EntropyPool / HmacDrbg tests: NIST HMAC_DRBG vectors and fault injection for entropy crediting.
// Run: pio test -e native_entropy
#include <gtest/gtest.h>
#include <string.h>
#include <vector>
#include "helpers/EntropyPool.h"
#include "nist_hmac_drbg_vectors.h"

static std::vector<uint8_t> H(const char* hex) {
  std::vector<uint8_t> v;
  for (const char* p = hex; p[0] && p[1]; p += 2) { unsigned b; sscanf(p, "%2x", &b); v.push_back((uint8_t)b); }
  return v;
}

TEST(HmacDrbg, NistCavpVectors) {
  for (const auto& t : NIST_HMAC_DRBG_SHA256) {
    auto seed = H(t.seed), reseed = H(t.reseed), expect = H(t.returned);
    HmacDrbg d;
    d.instantiate(seed.data(), seed.size());
    if (!reseed.empty()) d.reseed(reseed.data(), reseed.size());
    std::vector<uint8_t> out(expect.size());
    d.generate(out.data(), out.size());
    d.generate(out.data(), out.size());
    EXPECT_EQ(expect, out) << t.seed;
  }
}

// ---- crediting / fault injection ----

struct Pool : ::testing::Test {
  void SetUp() override { EntropyPool::resetForTest(); }
  void TearDown() override { EntropyPool::resetForTest(); }
};

static bool hwFails(uint8_t*, size_t, bool& trusted) { trusted = true; return false; }
static bool hwUntrusted(uint8_t* d, size_t n, bool& trusted) { memset(d, 0x5A, n); trusted = false; return true; }
static bool hwGood(uint8_t* d, size_t n, bool& trusted) { for (size_t i = 0; i < n; i++) d[i] = (uint8_t)(i * 37 + 11); trusted = true; return true; }

static std::vector<uint8_t> noise(size_t n, uint32_t seed) {
  std::vector<uint8_t> v(n);
  for (auto& b : v) { seed = seed * 1664525u + 1013904223u; b = (uint8_t)(seed >> 24); }
  return v;
}

TEST_F(Pool, HardwareFailureIsNotCredited) {
  EntropyPool::setHardwareSourceForTest(hwFails);
  EXPECT_FALSE(EntropyPool::addHardware());
  EXPECT_EQ(-1, EntropyPool::hardwareStatus());
  EXPECT_EQ(0, EntropyPool::creditedBits());
  EXPECT_FALSE(EntropyPool::readyForKeys());
}

TEST_F(Pool, UntrustedHardwareIsNotCredited) {   // e.g. ESP32 RNG with no RF / ADC entropy source on
  EntropyPool::setHardwareSourceForTest(hwUntrusted);
  EXPECT_FALSE(EntropyPool::addHardware());
  EXPECT_FALSE(EntropyPool::readyForKeys());
}

TEST_F(Pool, TrustedHardwareIsEnoughForKeys) {
  EntropyPool::setHardwareSourceForTest(hwGood);
  EXPECT_TRUE(EntropyPool::addHardware());
  EXPECT_EQ(1, EntropyPool::hardwareStatus());
  EXPECT_TRUE(EntropyPool::readyForKeys());
}

TEST_F(Pool, StuckRadioFailsRepetitionTest) {
  std::vector<uint8_t> zeros(EntropyPool::RADIO_BATCH, 0);
  EXPECT_FALSE(EntropyPool::addRadioSamples(zeros.data(), zeros.size()));
  EXPECT_EQ(-1, EntropyPool::radioStatus());
  EXPECT_FALSE(EntropyPool::readyForKeys());
}

TEST_F(Pool, BiasedRadioFailsAdaptiveProportionTest) {
  auto v = noise(EntropyPool::RADIO_BATCH, 7);
  for (size_t i = 0; i < v.size(); i++) if (i % 5 != 0) v[i] = 0;   // 80% zeros, runs of 4
  v[0] = 0;
  EXPECT_FALSE(EntropyPool::addRadioSamples(v.data(), v.size()));
  EXPECT_FALSE(EntropyPool::readyForKeys());
}

TEST_F(Pool, HealthyRadioBatchIsCredited) {
  auto v = noise(EntropyPool::RADIO_BATCH, 99);
  EXPECT_TRUE(EntropyPool::addRadioSamples(v.data(), v.size()));
  EXPECT_EQ(EntropyPool::RADIO_BATCH, EntropyPool::creditedBits());   // 1 bit per sample
  EXPECT_TRUE(EntropyPool::readyForKeys());
}

TEST_F(Pool, SmallRadioBatchIsNotCredited) {
  auto v = noise(64, 3);
  EXPECT_TRUE(EntropyPool::addRadioSamples(v.data(), v.size()));
  EXPECT_EQ(0, EntropyPool::creditedBits());
}

TEST_F(Pool, PredictableCounterPassesHealthTests) {
  // Documents a limit: health tests catch stuck or biased sources, not predictable ones.
  std::vector<uint8_t> v(EntropyPool::RADIO_BATCH);
  for (size_t i = 0; i < v.size(); i++) v[i] = (uint8_t)i;
  EXPECT_TRUE(EntropyPool::addRadioSamples(v.data(), v.size()));
}

TEST_F(Pool, UntrustedInputIsNeverCredited) {
  auto v = noise(4096, 1);
  EntropyPool::addUntrusted(v.data(), v.size());
  EXPECT_EQ(0, EntropyPool::creditedBits());
}

TEST_F(Pool, AllSourcesFailingMeansNoKeys) {
  EntropyPool::setHardwareSourceForTest(hwFails);
  std::vector<uint8_t> zeros(EntropyPool::RADIO_BATCH, 0);
  EntropyPool::addRadioSamples(zeros.data(), zeros.size());
  uint8_t key[32];
  EntropyPool::generate(key, sizeof(key));   // still produces bytes...
  EXPECT_FALSE(EntropyPool::readyForKeys()); // ...but callers must not keep them
}

TEST_F(Pool, OutputsDifferAndDependOnInput) {
  EntropyPool::setHardwareSourceForTest(hwGood);
  uint8_t a[48], b[48];
  EntropyPool::generate(a, sizeof(a));
  EntropyPool::generate(b, sizeof(b));
  EXPECT_NE(0, memcmp(a, b, sizeof(a)));

  EntropyPool::resetForTest();
  EntropyPool::setHardwareSourceForTest(hwGood);
  uint8_t c[48];
  auto v = noise(EntropyPool::RADIO_BATCH, 5);
  EntropyPool::addRadioSamples(v.data(), v.size());
  EntropyPool::generate(c, sizeof(c));
  EXPECT_NE(0, memcmp(a, c, sizeof(a)));   // different input, different output
}

TEST(EntropyPoolUtil, SecureZero) {
  uint8_t buf[16];
  memset(buf, 0xAB, sizeof(buf));
  EntropyPool::secureZero(buf, sizeof(buf));
  for (uint8_t b : buf) EXPECT_EQ(0, b);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
