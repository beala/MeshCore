// Weather sensor decoding and listen scheduling (src/helpers/weather). The packets are the
// examples published with the protocol descriptions (rtl_433's notes); each passes the family's
// CRC-8/sum check, and the expected values are the ones published with them.
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <helpers/weather/FineOffset.h>
#include <helpers/weather/SensorTracker.h>

using namespace wxsensor;

static std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> v;
  while (*s) {
    while (*s == ' ') s++;
    if (!s[0] || !s[1]) break;
    unsigned b;
    sscanf(s, "%2x", &b);
    v.push_back((uint8_t)b);
    s += 2;
  }
  return v;
}

static Reading dec(const char* h) {
  auto b = hex(h);
  b.resize(32, 0x55);   // the radio receives a fixed 32 bytes; the rest is noise
  Reading r;
  EXPECT_TRUE(decode(b.data(), (int)b.size(), &r)) << h;
  return r;
}

static std::string fmt(const Reading& r, bool metric) {
  char buf[200];
  format(r, metric, buf, sizeof(buf));
  return buf;
}

TEST(FineOffset, WH65) {
  // "id: 191, temp: 11.8 C, humidity: 78 %, wind_dir 266 deg" (published with the WH24 example)
  Reading r = dec("24 bf 0a e2 06 4e 08 02 00 4a 00 01 00 00 00 8f 07");
  EXPECT_EQ(r.model, WH65);
  EXPECT_EQ(r.id, 191u);
  EXPECT_EQ(r.temp_c10, 118);
  EXPECT_EQ(r.humidity, 78);
  EXPECT_EQ(r.wind_dir, 266);
  EXPECT_EQ(r.rain_um, 0x4Au * 254);   // 74 tips of 0.254 mm
  EXPECT_TRUE(r.have & HAVE_UV);
  EXPECT_EQ(r.uv_x10, 0);              // raw 1: index 0
  EXPECT_EQ(r.light_lux, 0u);
  EXPECT_FALSE(r.battery_low);

  Reading r2 = dec("24 50 67 e2 87 41 00 00 00 01 00 02 00 00 00 8c 14");
  EXPECT_EQ(r2.id, 0x50u);
  EXPECT_EQ(r2.temp_c10, 0x287 - 400);
  EXPECT_EQ(r2.humidity, 0x41);
}

TEST(FineOffset, WH31) {
  Reading r = dec("30 c3 81 d5 5c 2a cf");
  EXPECT_EQ(r.model, WH31);
  EXPECT_EQ(r.id, 0xC3u);
  EXPECT_EQ(r.channel, 1);
  EXPECT_EQ(r.temp_c10, 0x1D5 - 400);   // 6.9 C
  EXPECT_EQ(r.humidity, 0x5C);
  Reading r2 = dec("30 35 c2 2f 3c 0f a1");
  EXPECT_EQ(r2.channel, 5);
  EXPECT_EQ(r2.temp_c10, 0x22F - 400);
  EXPECT_EQ(fmt(r2, true), "WH31 ch5: 15.9C 60%");
  EXPECT_EQ(fmt(r2, false), "WH31 ch5: 60.6F 60%");
}

TEST(FineOffset, WH40) {
  Reading r = dec("40 00 cd 6f 10 00 00 64 f0");
  EXPECT_EQ(r.model, WH40);
  EXPECT_EQ(r.id, 0xCD6Fu);
  EXPECT_EQ(r.rain_um, 0u);
  Reading r2 = dec("40 00 cd 6f 10 00 05 91 22");
  EXPECT_EQ(r2.rain_um, 500u);   // 5 × 0.1 mm
}

TEST(FineOffset, WH57) {
  Reading r = dec("57 81 05 c8 05 81 01 df 0b");
  EXPECT_EQ(r.model, WH57);
  EXPECT_EQ(r.strike_state, 8);   // strike
  EXPECT_EQ(r.id, 0x105C8u);
  EXPECT_EQ(r.strike_km, 1);
  EXPECT_EQ(r.strike_count, 1);
}

TEST(FineOffset, WS80) {
  Reading r = dec("80 0a 00 3b 00 00 88 8a 59 38 18 6d 1c 00 ff ff d8 df");
  EXPECT_EQ(r.model, WS80);
  EXPECT_EQ(r.id, 0x0A003Bu);
  EXPECT_EQ(r.temp_c10, 0x259 - 400);   // 20.1 C
  EXPECT_EQ(r.humidity, 0x38);
  EXPECT_EQ(r.wind_dms, 0x18);          // 2.4 m/s
  EXPECT_EQ(r.wind_dir, 0x6D);
  EXPECT_EQ(r.gust_dms, 0x1C);
  EXPECT_EQ(fmt(r, true), "WS80 a003b: 20.1C 56% wind 2.4 ESE gust 2.8 m/s UV 0.0 0 lux");
}

TEST(FineOffset, WS90) {
  Reading r = dec("90 00 34 2b 00 77 a4 82 62 39 00 3e 00 00 3f ff 20 00 ba 00 00 26 02 00 ff 9f f8 00 00 82 92 4f");
  EXPECT_EQ(r.model, WS90);
  EXPECT_EQ(r.id, 0x00342Bu);
  EXPECT_EQ(r.light_lux, 0x77u * 10);
  EXPECT_EQ(r.temp_c10, 0x262 - 400);
  EXPECT_EQ(r.humidity, 0x39);
  EXPECT_FALSE(r.have & HAVE_PRESSURE);   // 0x3FFF: no pressure sensor
  EXPECT_FALSE(r.raining);                // byte 16 = 0x20: the rain-start bit (0x10) is clear
}

TEST(FineOffset, WN34andWN38) {
  Reading r = dec("34 00 29 65 02 85 44 66 f3");
  EXPECT_EQ(r.model, WN34);
  EXPECT_EQ(r.temp_c10, 0x285 - 400);
  Reading r2 = dec("38 00 28 85 40 f5 41 4c a7");   // sub type 4: no offset
  EXPECT_EQ(r2.temp_c10, 0x0F5);
}

TEST(FineOffset, WH45andWH51) {
  Reading r = dec("45 00 36 60 02 7e 36 40 23 00 29 02 29 07 4f");
  EXPECT_EQ(r.model, WH45);
  EXPECT_EQ(r.temp_c10, 0x27E - 400);
  EXPECT_EQ(r.humidity, 0x36);
  EXPECT_EQ(r.pm25_x10, 0x23);
  EXPECT_EQ(r.pm10_x10, 0x29);
  EXPECT_EQ(r.co2_ppm, 0x229);
  Reading s = dec("51 00 6b 58 6e 7f 24 f8 d2 ff ff ff 3c 28");
  EXPECT_EQ(s.model, WH51);
  EXPECT_EQ(s.moisture, 0x24);
}

TEST(FineOffset, Rejects) {
  auto b = hex("30 c3 81 d5 5c 2a cf");
  Reading r;
  for (size_t i = 0; i < b.size(); i++) {   // any single flipped bit fails the checks
    for (int bit = 0; bit < 8; bit++) {
      auto c = b;
      c[i] ^= 1 << bit;
      EXPECT_FALSE(decode(c.data(), (int)c.size(), &r)) << i << " " << bit;
    }
  }
  EXPECT_FALSE(decode(b.data(), 6, &r));         // short
  uint8_t unknown[8] = { 0x99, 1, 2, 3, 4, 5, 6, 7 };
  EXPECT_FALSE(decode(unknown, 8, &r));
  EXPECT_FALSE(decode(b.data(), 0, &r));
}

TEST(FineOffset, FormatFitsAnyBuffer) {
  Reading r = dec("90 00 34 2b 00 77 a4 82 62 39 00 3e 00 00 3f ff 20 00 ba 00 00 26 02 00 ff 9f f8 00 00 82 92 4f");
  char big[200];
  int full = format(r, false, big, sizeof(big));
  for (size_t n = 1; n < sizeof(big); n++) {
    std::vector<char> buf(n + 8, 'Z');
    int w = format(r, false, buf.data(), n);
    EXPECT_LT(w, (int)n);
    EXPECT_EQ(buf[n], 'Z');   // nothing past the end
    EXPECT_EQ(strncmp(buf.data(), big, w), 0);
  }
  EXPECT_GT(full, 20);
}

TEST(FineOffset, Compass) {
  EXPECT_STREQ(compass(0), "N");
  EXPECT_STREQ(compass(11), "N");
  EXPECT_STREQ(compass(12), "NNE");
  EXPECT_STREQ(compass(90), "E");
  EXPECT_STREQ(compass(266), "W");
  EXPECT_STREQ(compass(350), "N");
  EXPECT_STREQ(compass(359), "N");
}

// ---- Tracker: simulated sensors, a radio that only hears inside the tracker's windows ----

struct SimSensor { Reading r; uint32_t period, phase; bool alive; };

struct Sim {
  Tracker t;
  std::vector<SimSensor> sensors;
  uint32_t listened = 0, heard = 0, sent = 0;

  // runs from 0 to end ms; returns packets heard per sensor
  std::vector<int> run(uint32_t end, uint32_t start = 0) {
    std::vector<int> got(sensors.size(), 0);
    uint32_t now = start;
    while (now < end) {
      Window w;
      if (!t.nextWindow(now, &w)) { now += 10; continue; }
      if (w.start > now) { now = w.start; continue; }
      uint32_t wend = w.start + w.len;
      bool target = false;
      for (size_t i = 0; i < sensors.size(); i++) {
        auto& s = sensors[i];
        if (!s.alive) continue;
        // packets that start inside the window and end before it closes (15 ms on air)
        for (uint32_t p = s.phase + ((w.start > s.phase) ? ((w.start - s.phase + s.period - 1) / s.period) * s.period : 0);
             p + 15 <= wend; p += s.period) {
          if (p < w.start) continue;
          t.onPacket(p + 15, s.r, -80);
          got[i]++;
          heard++;
          if (sensorKey(s.r) == w.key) target = true;
        }
      }
      listened += w.len;
      t.windowDone(wend, w, target, true);
      now = wend;
    }
    for (auto& s : sensors) if (s.alive) sent += (end - start) / s.period;
    return got;
  }
};

static Reading make(uint8_t model, uint32_t id) {
  Reading r;
  memset(&r, 0, sizeof(r));
  r.model = model;
  r.id = id;
  return r;
}

TEST(Tracker, LocksOntoSensorsAndStaysMostlyOnTheMesh) {
  Sim sim;
  sim.t.setSeed(42);
  sim.sensors.push_back({ make(WH65, 1), 16000, 3333, true });
  sim.sensors.push_back({ make(WH31, 2), 61000, 20000, true });
  sim.sensors.push_back({ make(WH57, 3), 79000, 50000, true });
  // switched on: one scan, then tracking (the WH57's interval is learnt by hunting)
  sim.t.scanFor(0);
  sim.run(20 * 60000);
  for (int i = 0; i < sim.t.count(); i++) EXPECT_GT(sim.t.get(i)->period, 0u) << i;
  EXPECT_EQ(sim.t.count(), 3);
  EXPECT_EQ(sim.t.find(sensorKey(make(WH65, 1)))->period, 16000u);
  // the next hour: every packet heard, and listening only a small share of the time
  sim.listened = 0;
  auto got = sim.run(80 * 60000, 20 * 60000);
  EXPECT_GE(got[0], 3600 / 16 - 1);
  EXPECT_GE(got[1], 3600 / 61 - 1);
  EXPECT_GE(got[2], 3600 / 79 - 1);
  double duty = sim.listened / 3600000.0;
  printf("listening %.2f%% of the hour\n", duty * 100);
  EXPECT_LT(duty, 0.04) << duty;
}

TEST(Tracker, HuntsAgainWhenASensorReturnsWithANewTiming) {
  Sim sim;
  sim.t.setSeed(7);
  sim.sensors.push_back({ make(WH65, 1), 16000, 1000, true });
  sim.t.scanFor(0);
  sim.run(15 * 60000);
  ASSERT_EQ(sim.t.find(sensorKey(make(WH65, 1)))->period, 16000u);
  // the sensor restarts (battery change, same ID here) at another phase
  sim.sensors[0].phase = 9000 + 15 * 60000;
  auto got = sim.run(30 * 60000, 15 * 60000);
  EXPECT_GT(got[0], 20);
  const Tracker::Sensor* s = sim.t.find(sensorKey(make(WH65, 1)));
  EXPECT_EQ(s->period, 16000u);
  EXPECT_LT(s->misses, Tracker::MAX_MISSES);
}

TEST(Tracker, ScansOnceThenRestsWhenNothingIsThere) {
  Tracker t;
  t.reset(0);
  t.scanFor(0);
  Window w;
  ASSERT_TRUE(t.nextWindow(0, &w));
  EXPECT_EQ(w.key, 0u);
  EXPECT_EQ(w.len, Tracker::SCAN_LEN);
  t.windowDone(Tracker::SCAN_LEN, w, false, true);
  EXPECT_FALSE(t.hunting(Tracker::SCAN_LEN + 1));
  EXPECT_FALSE(t.nextWindow(Tracker::SCAN_LEN + 1, &w));
  t.huntFor(Tracker::SCAN_LEN + 1, 60000);
  ASSERT_TRUE(t.nextWindow(Tracker::SCAN_LEN + 1, &w));
  EXPECT_EQ(w.len, Tracker::HUNT_LEN);
}

TEST(Tracker, ASensorWithAnUnknownIntervalIsHuntedUntilItsSecondPacket) {
  Sim sim;
  sim.t.setSeed(11);
  sim.sensors.push_back({ make(WN34, 5), 70000, 30000, true });   // no nominal interval
  sim.t.scanFor(0);
  sim.run(40 * 60000);
  const Tracker::Sensor* s = sim.t.find(sensorKey(make(WN34, 5)));
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(s->period % 70000, 0u);   // the interval or a multiple of it
  EXPECT_FALSE(sim.t.hunting(40 * 60000));
}

TEST(Tracker, SurvivesMillisWrap) {
  Sim sim;
  sim.t.setSeed(3);
  uint32_t base = 0xFFFFFFFFu - 10 * 60000;
  sim.t.reset(base);
  sim.t.scanFor(base);
  sim.sensors.push_back({ make(WH65, 1), 16000, base + 500, true });
  // run across the wrap with explicit wrap-safe stepping
  uint32_t now = base;
  int heard = 0;
  for (int steps = 0; steps < 200000 && heard < 60; steps++) {
    Window w;
    if (!sim.t.nextWindow(now, &w)) { now += 10; continue; }
    if ((int32_t)(w.start - now) > 0) { now = w.start; continue; }
    uint32_t wend = w.start + w.len;
    uint32_t since = w.start - sim.sensors[0].phase;
    uint32_t p = w.start + (16000 - since % 16000) % 16000;
    bool got = false;
    if ((int32_t)(wend - (p + 15)) >= 0) { sim.t.onPacket(p + 15, sim.sensors[0].r, -80); heard++; got = true; }
    sim.t.windowDone(wend, w, got && w.key != 0, true);
    now = wend;
  }
  EXPECT_GE(heard, 60);
  EXPECT_EQ(sim.t.find(sensorKey(make(WH65, 1)))->period, 16000u);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
