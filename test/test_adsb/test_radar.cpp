// Radar rotation periods from 1030 MHz pulse detections (src/helpers/aircraft/RadarSweep.*), on
// synthetic listens: random noise detections, sweeps that are sometimes missed, two radars at once.
#include <gtest/gtest.h>
#include <string.h>
#include <math.h>
#include <random>
#include <vector>
#include <helpers/aircraft/RadarSweep.h>

struct Sim {
  std::vector<uint8_t> bins;
  std::mt19937 rng;
  explicit Sim(float secs, uint32_t seed) : bins((size_t)(secs * 100), 0), rng(seed) {}
  void noise(float per_bin) {
    std::poisson_distribution<int> p(per_bin);
    for (auto& b : bins) b = (uint8_t)std::min(255, b + p(rng));
  }
  // a radar of period P (s) first pointing here at t0; each sweep gives n detections over ~40 ms,
  // and is missed with probability miss
  void radar(float P, float t0, int n, float miss) {
    std::uniform_real_distribution<float> u(0, 1);
    for (float t = t0; t < bins.size() / 100.0f; t += P) {
      if (u(rng) < miss) continue;
      for (int k = 0; k < n; k++) {
        size_t i = (size_t)((t + (u(rng) - 0.5f) * 0.04f) * 100);
        if (i < bins.size()) bins[i] = (uint8_t)std::min(255, bins[i] + 1);
      }
    }
  }
  int periods(radar::Period* out, int max) {
    radar::Burst b[radar::MAX_BURSTS];
    int nb = radar::findBursts(bins.data(), (int)bins.size(), b);
    return radar::findPeriods(b, nb, bins.size() / 100.0f, out, max);
  }
};

TEST(Radar, AirportRadar) {
  Sim s(60, 1);
  s.noise(0.3f);
  s.radar(4.8f, 1.3f, 12, 0.15f);
  radar::Period p[4];
  int n = s.periods(p, 4);
  ASSERT_GE(n, 1);
  EXPECT_NEAR(p[0].seconds, 4.8f, 0.02f);
  EXPECT_GT(p[0].score, 0.6f);
}

TEST(Radar, NotHalfOrDouble) {
  for (uint32_t seed = 2; seed < 12; seed++) {
    Sim s(60, seed);
    s.noise(0.2f);
    s.radar(6.0f, 0.7f, 10, 0.1f);
    radar::Period p[4];
    ASSERT_GE(s.periods(p, 4), 1) << seed;
    EXPECT_NEAR(p[0].seconds, 6.0f, 0.03f) << seed;
  }
}

TEST(Radar, TwoRadars) {
  Sim s(90, 7);
  s.noise(0.3f);
  s.radar(4.8f, 2.0f, 14, 0.1f);
  s.radar(12.0f, 5.1f, 10, 0.1f);
  radar::Period p[4];
  int n = s.periods(p, 4);
  ASSERT_GE(n, 2);
  bool f48 = false, f12 = false;
  for (int i = 0; i < n; i++) {
    if (fabsf(p[i].seconds - 4.8f) < 0.03f) f48 = true;
    if (fabsf(p[i].seconds - 12.0f) < 0.05f) f12 = true;
  }
  EXPECT_TRUE(f48);
  EXPECT_TRUE(f12);
  EXPECT_NEAR(p[0].seconds, 4.8f, 0.03f);   // the one with more bursts first
}

TEST(Radar, NoiseOnly) {
  Sim s(60, 3);
  s.noise(0.5f);
  radar::Period p[4];
  int n = s.periods(p, 4);
  for (int i = 0; i < n; i++) EXPECT_LT(p[i].score, 0.4f);
}

TEST(Radar, EmptyAndShort) {
  uint8_t z[100] = {};
  radar::Burst b[radar::MAX_BURSTS];
  EXPECT_EQ(radar::findBursts(z, 100, b), 0);
  EXPECT_EQ(radar::findBursts(NULL, 100, b), 0);
  radar::Period p[2];
  EXPECT_EQ(radar::findPeriods(b, 0, 60, p, 2), 0);
}
