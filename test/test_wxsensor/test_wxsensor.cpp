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
#include "vectors.inc"

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

TEST(FineOffset, WH31BIsAWH31) {
  // an Ecowitt WN31 (FCC ID WA5WH31B) on channel 1, heard with an RTL-SDR (rtl_433: WH31B, 18.9 C, 36%)
  Reading r = dec("37 d2 82 4d 24 23 1f");
  EXPECT_EQ(r.model, WH31);
  EXPECT_EQ(r.id, 0xD2u);
  EXPECT_EQ(r.channel, 1);
  EXPECT_EQ(r.temp_c10, 189);
  EXPECT_EQ(r.humidity, 36);
  EXPECT_FALSE(r.battery_low);
  EXPECT_EQ(fmt(r, true), "WH31 ch1: 18.9C 36%");
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
        if (!s.alive || s.r.proto != w.proto) continue;   // heard only in its own format
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
  if (model == LTV_TH || model == LTV_WSDTH || model == LTV_W1 || model == LTV_R1 || model == LTV_WR1) r.proto = PROTO_LACROSSE;
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

// ---- La Crosse View ----

static uint8_t crcLa(const std::vector<uint8_t>& b, size_t n, uint8_t init) {
  uint8_t c = init;
  for (size_t i = 0; i < n; i++) {
    c ^= b[i];
    for (int k = 0; k < 8; k++) c = (c & 0x80) ? (uint8_t)((c << 1) ^ 0x31) : (uint8_t)(c << 1);
  }
  return c;
}

// TH packet: ID, flags, temperature/humidity, CRC (init 0, or 0xAC / 0xB2 as TH2 sensors use)
static std::vector<uint8_t> laTH(uint32_t id, int temp_c10, int hum, uint8_t init = 0) {
  int t = temp_c10 + 400;
  std::vector<uint8_t> b = { (uint8_t)(id >> 16), (uint8_t)(id >> 8), (uint8_t)id, 0x06,
                             (uint8_t)(t >> 4), (uint8_t)((t & 0x0F) << 4 | (hum >> 8)), (uint8_t)hum };
  // the CRC byte that makes crc over 8 bytes come out 0 from this init
  b.push_back(crcLa(b, 7, init));
  b.resize(11, 0xD2);   // trailer
  return b;
}

static std::vector<uint8_t> laBreeze(uint32_t id, int temp_c10, int hum, int kmh10, int dir) {
  int t = temp_c10 + 400;
  std::vector<uint8_t> b = { (uint8_t)(id >> 16), (uint8_t)(id >> 8), (uint8_t)id, 0x04,
                             (uint8_t)(t >> 4), (uint8_t)((t & 0x0F) << 4 | (hum >> 8)), (uint8_t)hum,
                             (uint8_t)(kmh10 >> 4), (uint8_t)((kmh10 & 0x0F) << 4 | (dir >> 8)), (uint8_t)dir };
  b.push_back(crcLa(b, 10, 0));
  return b;
}

static Reading decLa(std::vector<uint8_t> b) {
  b.resize(11, 0);
  Reading r;
  EXPECT_TRUE(decodeLaCrosse(b.data(), (int)b.size(), &r));
  return r;
}

TEST(LaCrosse, R1Published) {
  Reading r = decLa(hex("380322 0e 00aa14 6a 93"));   // 20 ticks of 0.25 mm
  EXPECT_EQ(r.model, LTV_R1);
  EXPECT_EQ(r.id, 0x380322u);
  EXPECT_EQ(r.rain_um, 20u * 250);
  Reading r2 = decLa(hex("380322 00 00aa1a 60 81"));
  EXPECT_EQ(r2.rain_um, 26u * 250);
}

TEST(LaCrosse, W1Published) {
  Reading r = decLa(hex("0fb220 0e aaaaaa 07 fa aa fe"));   // "07f aaa": 12.7 km/h ("13 km"), 3.5 m/s
  EXPECT_EQ(r.model, LTV_W1);
  EXPECT_EQ(r.id, 0x0FB220u);
  EXPECT_EQ(r.wind_dms, 35);
  Reading r2 = decLa(hex("0fb220 42 aaaaaa 00 0a aa 73"));
  EXPECT_EQ(r2.wind_dms, 0);
}

TEST(LaCrosse, TH) {
  for (uint8_t init : { 0x00, 0xAC, 0xB2 }) {
    Reading r = decLa(laTH(0xA1B2C3, 215, 47, init));
    EXPECT_EQ(r.model, LTV_TH);
    EXPECT_EQ(r.id, 0xA1B2C3u);
    EXPECT_EQ(r.temp_c10, 215);
    EXPECT_EQ(r.humidity, 47);
    EXPECT_EQ(fmt(r, true), "LTV-TH a1b2c3: 21.5C 47%");
  }
  // temperatures whose last nibble looks like a rain count's 0xA marker are still TH
  for (int t = -400; t <= 600; t++) {
    Reading r = decLa(laTH(0x123456, t, 55));
    ASSERT_EQ(r.model, LTV_TH) << t;
    ASSERT_EQ(r.temp_c10, t);
  }
}

TEST(LaCrosse, BreezePro) {
  Reading r = decLa(laBreeze(0x0C0FFE, -52, 81, 254, 225));
  EXPECT_EQ(r.model, LTV_WSDTH);
  EXPECT_EQ(r.temp_c10, -52);
  EXPECT_EQ(r.humidity, 81);
  EXPECT_EQ(r.wind_dms, 71);   // 25.4 km/h
  EXPECT_EQ(r.wind_dir, 225);
  EXPECT_EQ(fmt(r, false), "LTV-WSDTH c0ffe: 22.6F 81% wind 16 SW mph");
}

TEST(LaCrosse, Rejects) {
  auto b = laBreeze(0x0C0FFE, 100, 50, 30, 90);
  Reading r;
  for (size_t i = 0; i < 11; i++) {
    for (int bit = 0; bit < 8; bit++) {
      auto c = b;
      c[i] ^= 1 << bit;
      // a flipped bit may still form some other valid-looking packet only by CRC luck: none here
      EXPECT_FALSE(decodeLaCrosse(c.data(), 11, &r) && r.model == LTV_WSDTH && r.id == 0x0C0FFE &&
                   r.temp_c10 == 100 && r.humidity == 50) << i << " " << bit;
    }
  }
  EXPECT_FALSE(decodeLaCrosse(b.data(), 7, &r));
  uint8_t zeros[11] = {};
  zeros[7] = 1;
  EXPECT_FALSE(decodeLaCrosse(zeros, 11, &r));
}

TEST(Tracker, BothFormatsScanInTurnAndWindowsUseTheSensorsFormat) {
  Tracker t;
  t.reset(0);
  t.setProtocols(1 << PROTO_FINEOFFSET | 1 << PROTO_LACROSSE);
  t.scanFor(0);
  Window w;
  ASSERT_TRUE(t.nextWindow(0, &w));
  EXPECT_EQ(w.proto, PROTO_FINEOFFSET);
  EXPECT_EQ(w.len, Tracker::SCAN_LEN);
  ASSERT_TRUE(t.nextWindow(Tracker::SCAN_LEN + 5, &w));
  EXPECT_EQ(w.proto, PROTO_LACROSSE);
  EXPECT_EQ(w.len, Tracker::scanLen(PROTO_LACROSSE) - 5);
  EXPECT_EQ(t.scanTotal(), Tracker::SCAN_LEN + Tracker::scanLen(PROTO_LACROSSE));
  Reading la = make(LTV_TH, 0x123456);
  t.onPacket(Tracker::SCAN_LEN + 1000, la, -90);
  Reading fo = make(WH65, 7);
  t.onPacket(Tracker::SCAN_LEN + 2000, fo, -90);
  uint32_t after = t.scanTotal() + 1;
  ASSERT_FALSE(t.scanning(after));
  // each sensor's windows come up in its own format
  bool saw_la = false, saw_fo = false;
  uint32_t now = after;
  for (int i = 0; i < 20; i++) {
    ASSERT_TRUE(t.nextWindow(now, &w));
    if (w.key == sensorKey(la)) { saw_la = true; EXPECT_EQ(w.proto, PROTO_LACROSSE); }
    if (w.key == sensorKey(fo)) { saw_fo = true; EXPECT_EQ(w.proto, PROTO_FINEOFFSET); }
    now = w.start + w.len;
    t.windowDone(now, w, true, true);
  }
  EXPECT_TRUE(saw_la);
  EXPECT_TRUE(saw_fo);
}

TEST(Tracker, SkippingSensorsGetMorePatience) {
  Sim sim;
  sim.t.setSeed(5);
  sim.t.setProtocols(1 << PROTO_LACROSSE);
  sim.sensors.push_back({ make(LTV_WSDTH, 0xC0FFE), 31000, 4000, true });
  sim.t.scanFor(0);
  sim.run(10 * 60000);
  const Tracker::Sensor* s = sim.t.find(sensorKey(make(LTV_WSDTH, 0xC0FFE)));
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(s->period, 31000u);
  // it stops sending for 5 minutes (nothing changed), then carries on on the same grid
  sim.sensors[0].alive = false;
  sim.run(15 * 60000, 10 * 60000);
  EXPECT_EQ(s->period, 31000u);   // 9-10 misses: still tracked
  sim.sensors[0].alive = true;
  auto got = sim.run(25 * 60000, 15 * 60000);
  EXPECT_GE(got[0], 600 / 31 - 1);
}

TEST(Tracker, ScanForeverTakesTurnsAndFindsEverything) {
  Sim sim;
  sim.t.setSeed(9);
  sim.t.setProtocols(1 << PROTO_FINEOFFSET | 1 << PROTO_LACROSSE);
  sim.t.scanForever(0, true);
  Window w;
  ASSERT_TRUE(sim.t.nextWindow(0, &w));
  EXPECT_EQ(w.proto, PROTO_FINEOFFSET);
  EXPECT_EQ(w.len, Tracker::SCAN_SLICE);
  ASSERT_TRUE(sim.t.nextWindow(Tracker::SCAN_SLICE, &w));
  EXPECT_EQ(w.proto, PROTO_LACROSSE);
  ASSERT_TRUE(sim.t.nextWindow(10 * Tracker::SCAN_SLICE + 1, &w));
  EXPECT_EQ(w.proto, PROTO_FINEOFFSET);
  EXPECT_TRUE(sim.t.scanning(3600000));
  sim.t.scanForever(3600000, false);
  EXPECT_FALSE(sim.t.scanning(3600001));
}

TEST(Tracker, ARestartedSensorIsPickedUpOnItsNominalInterval) {
  Sim sim;
  sim.t.setSeed(21);
  sim.sensors.push_back({ make(WH31, 2), 61000, 5000, true });
  sim.t.scanFor(0);
  sim.run(10 * 60000);
  ASSERT_EQ(sim.t.find(sensorKey(make(WH31, 2)))->period, 61000u);
  // it stops, is lost, and comes back 7.3 s out of step (eg. new batteries keeping its ID here)
  sim.sensors[0].alive = false;
  sim.run(20 * 60000, 10 * 60000);
  sim.sensors[0].alive = true;
  sim.sensors[0].phase = 20 * 60000 + 7300;
  auto got = sim.run(60 * 60000, 20 * 60000);
  const Tracker::Sensor* s = sim.t.find(sensorKey(make(WH31, 2)));
  EXPECT_EQ(s->period, 61000u);
  EXPECT_GE(got[0], 20);   // found again by hunting (~13% of the time: some minutes), then every packet
}


// rtl_433's recordings of real sensors: the firmware reads the same model and values
TEST(Recordings, ReadAsRtl433ReadsThem) {
  for (const WxVector& v : WX_VECTORS) {
    auto b = hex(v.hex);
    Reading r;
    ASSERT_TRUE(decodeAs(v.proto, b.data(), (int) b.size(), &r)) << v.name;
    EXPECT_STREQ(v.model, modelName(r.model)) << v.name;
    if (v.temp_c10 != -9999) { EXPECT_TRUE(r.have & HAVE_TEMP) << v.name; EXPECT_EQ(v.temp_c10, r.temp_c10) << v.name; }
    if (v.humidity != -9999) { EXPECT_TRUE(r.have & HAVE_HUM) << v.name; EXPECT_EQ(v.humidity, r.humidity) << v.name; }
    if (v.wind_dms != -9999) { EXPECT_TRUE(r.have & HAVE_WIND) << v.name; EXPECT_NEAR(v.wind_dms, r.wind_dms, 1) << v.name; }
    if (v.wind_dir != -9999) { EXPECT_TRUE(r.have & HAVE_DIR) << v.name; EXPECT_NEAR(v.wind_dir, r.wind_dir, 1) << v.name; }
    if (v.rain_um != -9999) { EXPECT_TRUE(r.have & HAVE_RAIN) << v.name; EXPECT_NEAR(v.rain_um, (long) r.rain_um, 60) << v.name; }
    if (v.pressure_dhpa != -9999) { EXPECT_TRUE(r.have & HAVE_PRESSURE) << v.name; EXPECT_EQ(v.pressure_dhpa, r.pressure_dhpa) << v.name; }
    if (v.pm25_x10 != -9999) { EXPECT_TRUE(r.have & HAVE_PM) << v.name; EXPECT_EQ(v.pm25_x10, r.pm25_x10) << v.name; }
    if (v.moisture != -9999) { EXPECT_TRUE(r.have & HAVE_MOISTURE) << v.name; EXPECT_EQ(v.moisture, r.moisture) << v.name; }
  }
}

TEST(Recordings, EachFormatReadsOnlyItsOwn) {
  // a packet fed to another listen's decoder (on the air it can't be: another bit rate) reads
  // only by an 8-bit check, taken once heard twice. Except an LTV-R1 whose ID starts with a Fine
  // Offset family byte: it ends with the same CRC-8 and sum
  for (const WxVector& v : WX_VECTORS) {
    auto b = hex(v.hex);
    for (int p = 0; p < PROTO_COUNT; p++) {
      Reading r;
      if (p == v.proto || !decodeAs(p, b.data(), (int) b.size(), &r) || r.weak) continue;
      auto family = [](int q) { return q == PROTO_FO_WIDE ? PROTO_FINEOFFSET : q == PROTO_LTV_SLOW || q == PROTO_LTV_W1 ? PROTO_LACROSSE : q; };
      if (family(p) == family(v.proto)) continue;   // the same packets at another rate or deviation
      EXPECT_TRUE(strcmp(v.model, "LTV-R1") == 0 && packetLength(b[0]) == 9) << v.name << " as " << modelName(r.model);
    }
  }
}

TEST(FineOffset, MoreFamiliesFromTheirNotes) {
  // rtl_433's published examples
  Reading r = dec("46 00 27 f1 02 b5 33 40 32 40 39 03 0b 00 2a 00 36 01 90 e4 16");
  EXPECT_EQ(WH46, r.model);
  EXPECT_EQ(0x0027f1u, r.id);
  EXPECT_EQ(293, r.temp_c10);
  EXPECT_EQ(51, r.humidity);
  EXPECT_EQ(50, r.pm25_x10);
  EXPECT_EQ(57, r.pm10_x10);
  EXPECT_EQ(42, r.pm1_x10);
  EXPECT_EQ(779, r.co2_ppm);
  EXPECT_FALSE(r.battery_low);   // 5 bars

  r = dec("55 30 cf 55 04 02 89 be ae a4 20 10");
  EXPECT_EQ(WH55, r.model);
  EXPECT_EQ(4, r.channel);
  EXPECT_EQ(0xcf55u, r.id);
  EXPECT_FALSE(r.leak);
  EXPECT_TRUE(r.weak);
  EXPECT_EQ("WH55 cf55 ch4: dry", fmt(r, true));

  r = dec("68 00 00 c5 01 07 4b 0f ff ff 00 2e 00 02 a6 63");
  EXPECT_EQ(WS68, r.model);
  EXPECT_EQ(2630u, r.light_lux);
  EXPECT_EQ(46, r.wind_dir);
  EXPECT_EQ(2, r.uv_x10);

  r = dec("41 c7 41 ae 01 c2 f9 b3");
  EXPECT_EQ(WH41, r.model);
  EXPECT_EQ(430, r.pm25_x10);
  EXPECT_FALSE(r.have & HAVE_PM10);   // an estimate from the PM2.5: not shown

  r = dec("e5 02 72 28 27 21 c9 bb");
  EXPECT_EQ(WH25, r.model);
  EXPECT_FALSE(r.weak);   // the sum and the XOR
  EXPECT_EQ("WH25 50: 22.6C 40% 1001.7 hPa", fmt(r, true));
}

TEST(FineOffset, WH43) {
  // the WH41's fields after a 24-bit ID (rtl_433's notes); the example there has a placeholder ID,
  // so this one is built: PM2.5 12.3, 4 battery bars, then the CRC-8 and sum
  uint8_t b[32] = { 0x43, 0x12, 0x34, 0x56, 0x40 | 0x00, 123, 0x00, 140 };
  b[8] = crc8(b, 8);
  uint8_t sum = 0;
  for (int i = 0; i < 9; i++) sum += b[i];
  b[9] = sum;
  Reading r;
  ASSERT_TRUE(decode(b, sizeof(b), &r));
  EXPECT_EQ(WH43, r.model);
  EXPECT_EQ(0x123456u, r.id);
  EXPECT_EQ(123, r.pm25_x10);
  EXPECT_FALSE(r.battery_low);
}

TEST(FineOffset, WS69Pressure) {
  // a WH65 packet with the WS69's 8 more bytes: pressure 0x018b8a = 1012.58 hPa, their own CRC and sum
  auto b = hex("24 50 67 e2 87 41 00 00 00 01 00 02 00 00 00 8c 14");
  ASSERT_TRUE(checkPacket(b.data(), 17));
  b.resize(25);
  b[17] = 0x01; b[18] = 0x8b; b[19] = 0x8a; b[20] = 0x00; b[21] = 0x2f; b[22] = 0x00;
  b[23] = crc8(b.data(), 23);
  uint8_t sum = 0;
  for (int i = 0; i < 24; i++) sum += b[i];
  b[24] = sum;
  Reading r;
  ASSERT_TRUE(decode(b.data(), (int) b.size(), &r));
  EXPECT_EQ(WH65, r.model);
  EXPECT_TRUE(r.have & HAVE_PRESSURE);
  EXPECT_EQ(10126, r.pressure_dhpa);
  b[24]++;   // the extension's check fails: the WH65 part still reads, without pressure
  ASSERT_TRUE(decode(b.data(), (int) b.size(), &r));
  EXPECT_FALSE(r.have & HAVE_PRESSURE);
}

TEST(FineOffset, ItPlusAndTheWS90ShareAFamilyByte) {
  // an IT+ sensor with ID 0..3 starts 0x90 like a WS90; each check tells them apart
  uint8_t it[32] = { 0x90, 0x46, 0x13, 0x45 };   // ID 1, 24.6 + 40 BCD, humidity 69
  memset(&it[5], 0xAA, sizeof(it) - 5);
  it[4] = crc8(it, 4);
  Reading r;
  ASSERT_TRUE(decode(it, sizeof(it), &r));
  EXPECT_EQ(TX29IT, r.model);
  EXPECT_EQ(1u, r.id);
  EXPECT_EQ(213, r.temp_c10);
  EXPECT_EQ(69, r.humidity);
  EXPECT_TRUE(r.weak);
  it[3] = 0x6A;   // no humidity sensor
  it[4] = crc8(it, 4);
  ASSERT_TRUE(decode(it, sizeof(it), &r));
  EXPECT_FALSE(r.have & HAVE_HUM);
}

TEST(LaCrosse, AnEightBytePacketFollowedByZerosIsNotAnElevenByteOne) {
  // a TH3 packet then 3 zero bytes: CRC-8 over all 11 is 0 too (rtl_433's recording g498)
  auto b = hex("110851081c405513000000");
  Reading r;
  ASSERT_TRUE(decodeLaCrosse(b.data(), (int) b.size(), &r));
  EXPECT_EQ(LTV_TH, r.model);
  EXPECT_EQ(52, r.temp_c10);
  EXPECT_EQ(85, r.humidity);
}

TEST(LaCrosse, ThermoProTX7B) {
  // rtl_433's examples
  auto b = hex("e8 00 29 30 17 aa 55 aa 83 d2 d2 d2 d2");
  Reading r;
  ASSERT_TRUE(decodeAs(PROTO_TX7B, b.data(), (int) b.size(), &r));
  EXPECT_EQ(TP_TX7B, r.model);
  EXPECT_EQ(1, r.channel);
  EXPECT_EQ(259, r.temp_c10);
  EXPECT_EQ(23, r.humidity);
  EXPECT_FALSE(r.weak);
  b = hex("25 20 2c a0 0d aa 55 aa bb d2 d2 d2 d2");
  ASSERT_TRUE(decodeAs(PROTO_TX7B, b.data(), (int) b.size(), &r));
  EXPECT_EQ(3, r.channel);
  EXPECT_EQ(314, r.temp_c10);
  b[2] ^= 1;
  EXPECT_FALSE(decodeAs(PROTO_TX7B, b.data(), (int) b.size(), &r));
}

TEST(LaCrosse, TX22UQuartets) {
  // rtl_433's example: ID a2, 5 quartets: 17.2 °C, 58 %, rain 0, wind 0 from 180°, gust 0
  auto b = hex("a2 a5 05 72 10 58 20 00 38 00 40 00 fc 00");
  Reading r;
  ASSERT_TRUE(decodeAs(PROTO_TX22U, b.data(), (int) b.size(), &r));
  EXPECT_EQ(TX22U, r.model);
  EXPECT_EQ(172, r.temp_c10);
  EXPECT_EQ(58, r.humidity);
  EXPECT_EQ(180, r.wind_dir);
  EXPECT_TRUE(r.have & HAVE_GUST);
  EXPECT_TRUE(r.weak);
  // 3 quartets: humidity, rain 28 tips, wind
  b = hex("a2 83 10 72 20 1c 38 00 33 00");
  ASSERT_TRUE(decodeAs(PROTO_TX22U, b.data(), (int) b.size(), &r));
  EXPECT_EQ(72, r.humidity);
  EXPECT_EQ(28u * 518, r.rain_um);
  EXPECT_FALSE(r.have & HAVE_TEMP);
}

TEST(Unknown, ACheckedPacketOfANewFamilyShowsItsLength) {
  // a made-up family 0x63, 12 bytes, with the CRC-8 and sum every Fine Offset packet ends with
  uint8_t b[32] = { 0x63, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  b[10] = crc8(b, 10);
  uint8_t sum = 0;
  for (int i = 0; i < 11; i++) sum += b[i];
  b[11] = sum;
  for (int i = 12; i < 32; i++) b[i] = (uint8_t)(i * 37);
  Reading r;
  EXPECT_FALSE(decode(b, sizeof(b), &r));
  EXPECT_EQ(12, checkedLength(b, sizeof(b)));
  // the WH31E's radio clock packet is known, and not counted as unknown
  auto c = hex("52 27 4a 20 10 20 02 06 55 05 75");
  EXPECT_FALSE(decode(c.data(), (int) c.size(), &r));
  EXPECT_TRUE(ignoredFamily(c[0]));
  // a 9.6k packet: the shortest length its CRC-8 covers
  uint8_t d[13] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  d[6] = crc8(d, 6);
  EXPECT_EQ(7, crcLength(d, sizeof(d)));
}

TEST(Noise, StronglyCheckedReadsAreRare) {
  // random packets after each sync word: weakly checked reads are expected now and then (they count
  // only when heard twice); strongly checked ones about never
  uint32_t s = 4242;
  int strong = 0, weak = 0, unknown = 0;
  for (int k = 0; k < 200000; k++) {
    uint8_t x[32];
    for (auto& v : x) { s = s * 1103515245u + 12345u; v = (uint8_t)(s >> 16); }
    for (int p = 0; p < PROTO_COUNT; p++) {
      Reading r;
      if (decodeAs(p, x, p ? 13 : 32, &r)) { if (r.weak) weak++; else strong++; }
      else if (p == 0 && checkedLength(x, 32)) unknown++;
    }
  }
  EXPECT_LE(strong, 40);    // eg. the WH25's sum and XOR, the La Crosse View's CRC and value checks
  EXPECT_LE(unknown, 400);  // 30 lengths × 2^-16 each: about 1 in 2,200
  printf("of 1200000 random packets: %d strong, %d weak, %d 'unknown'\n", strong, weak, unknown);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
