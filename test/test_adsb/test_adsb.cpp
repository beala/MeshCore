// 1090 MHz ADS-B: parity, identification, CPR positions and velocity, checked against the worked
// examples in "The 1090 MHz Riddle" (Junzi Sun), which come from recorded traffic.
#include <gtest/gtest.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <vector>
#include <helpers/aircraft/AdsB.h>

static std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> v;
  for (; s[0] && s[1]; s += 2) { unsigned b; sscanf(s, "%2x", &b); v.push_back((uint8_t)b); }
  return v;
}

TEST(AdsB, Parity) {
  auto f = hex("8D4840D6202CC371C32CE0576098");
  EXPECT_EQ(adsb::crc24(f.data(), 11), 0x576098u);
  EXPECT_EQ(adsb::crc24(f.data(), 14), 0u);   // the whole frame divides evenly
  adsb::Message m;
  EXPECT_TRUE(adsb::decode(f.data(), 14, &m));
  f[6] ^= 0x10;
  EXPECT_FALSE(adsb::decode(f.data(), 14, &m));
  EXPECT_TRUE(adsb::decode(f.data(), 11, &m));   // 11 bytes: the radio checked the parity
}

TEST(AdsB, Identification) {
  auto f = hex("8D4840D6202CC371C32CE0576098");
  adsb::Message m;
  ASSERT_TRUE(adsb::decode(f.data(), 14, &m));
  EXPECT_EQ(m.r.address, 0x4840D6u);
  EXPECT_EQ(m.r.qualifier, 0);
  EXPECT_EQ(m.type_code, 4);
  EXPECT_STREQ(m.r.callsign, "KLM1023");
  EXPECT_FALSE(m.has_cpr);
}

TEST(AdsB, AirbornePositionGlobal) {
  auto ev = hex("8D40621D58C382D690C8AC2863A7"), od = hex("8D40621D58C386435CC412692AD6");
  adsb::Message e, o;
  ASSERT_TRUE(adsb::decode(ev.data(), 14, &e));
  ASSERT_TRUE(adsb::decode(od.data(), 14, &o));
  EXPECT_EQ(e.r.address, 0x40621Du);
  EXPECT_TRUE(e.has_cpr);
  EXPECT_FALSE(e.cpr_odd);
  EXPECT_TRUE(o.cpr_odd);
  EXPECT_EQ(e.cpr_lat, 93000u);
  EXPECT_EQ(e.cpr_lon, 51372u);
  EXPECT_EQ(o.cpr_lat, 74158u);
  EXPECT_EQ(o.cpr_lon, 50194u);
  EXPECT_TRUE(e.r.has_alt);
  EXPECT_EQ(e.r.alt_ft, 38000);
  int32_t lat, lon;
  ASSERT_TRUE(adsb::cprGlobal(e.cpr_lat, e.cpr_lon, o.cpr_lat, o.cpr_lon, false, &lat, &lon));
  EXPECT_NEAR(lat, 5225720, 2);   // 52.25720
  EXPECT_NEAR(lon, 391937, 2);    // 3.91937
}

TEST(AdsB, AirbornePositionLocal) {
  auto ev = hex("8D40621D58C382D690C8AC2863A7");
  adsb::Message e;
  ASSERT_TRUE(adsb::decode(ev.data(), 14, &e));
  int32_t lat, lon;
  ASSERT_TRUE(adsb::cprLocal(e.cpr_lat, e.cpr_lon, e.cpr_odd, false, 5225800, 391800, &lat, &lon));
  EXPECT_NEAR(lat, 5225720, 2);
  EXPECT_NEAR(lon, 391937, 2);
  // the same message decoded from a reference 100 NM away still lands on the aircraft
  ASSERT_TRUE(adsb::cprLocal(e.cpr_lat, e.cpr_lon, e.cpr_odd, false, 5390000, 391800, &lat, &lon));
  EXPECT_NEAR(lat, 5225720, 2);
}

TEST(AdsB, CprGlobalAndLocalAgreeAroundTheWorld) {
  // encode positions (the format's own maths, run forwards) and decode them both ways
  auto enc = [](double lat, double lon, int i, uint32_t* yz, uint32_t* xz) {
    double dlat = 360.0 / (60 - i);
    double y = floor(131072.0 * fmod(fmod(lat, dlat) + dlat, dlat) / dlat + 0.5);
    double rlat = dlat * (y / 131072.0 + floor(lat / dlat));
    double c = cos(M_PI / 180.0 * rlat), x1 = 1.0 - (1.0 - cos(M_PI / 30.0)) / (c * c);
    int nl = fabs(rlat) >= 87.0 ? (fabs(rlat) > 87.0 ? 1 : 2) : (int)floor(2.0 * M_PI / acos(x1));
    if (fabs(rlat) < 1e-9) nl = 59;
    int n = nl - i < 1 ? 1 : nl - i;
    double dlon = 360.0 / n;
    double x = floor(131072.0 * fmod(fmod(lon, dlon) + dlon, dlon) / dlon + 0.5);
    *yz = (uint32_t)y & 0x1FFFF;
    *xz = (uint32_t)x & 0x1FFFF;
  };
  const double pts[][2] = { { 40.1637, -105.1633 }, { -33.9, 151.2 }, { 0.3, 0.2 }, { 64.1, -21.9 }, { 51.47, -0.45 }, { 35.5, 139.8 } };
  for (auto& p : pts) {
    uint32_t ye, xe, yo, xo;
    enc(p[0], p[1], 0, &ye, &xe);
    enc(p[0], p[1], 1, &yo, &xo);
    int32_t lat, lon;
    ASSERT_TRUE(adsb::cprGlobal(ye, xe, yo, xo, true, &lat, &lon)) << p[0] << "," << p[1];
    EXPECT_NEAR(lat * 1e-5, p[0], 0.001);
    EXPECT_NEAR(lon * 1e-5, p[1], 0.001);
    ASSERT_TRUE(adsb::cprLocal(ye, xe, false, false, (int32_t)(p[0] * 1e5) + 50000, (int32_t)(p[1] * 1e5) - 50000, &lat, &lon));
    EXPECT_NEAR(lat * 1e-5, p[0], 0.001);
    EXPECT_NEAR(lon * 1e-5, p[1], 0.001);
  }
}

TEST(AdsB, VelocityOverGround) {
  auto f = hex("8D485020994409940838175B284F");
  adsb::Message m;
  ASSERT_TRUE(adsb::decode(f.data(), 14, &m));
  EXPECT_EQ(m.type_code, 19);
  EXPECT_TRUE(m.r.has_speed);
  EXPECT_EQ(m.r.speed_kt, 159);
  EXPECT_EQ(m.r.track_deg, 183);   // 182.88°
  EXPECT_TRUE(m.r.has_vs);
  EXPECT_EQ(m.r.vs_fpm, -832);
}

TEST(AdsB, VelocityAirspeed) {
  auto f = hex("8DA05F219B06B6AF189400CBC33F");
  adsb::Message m;
  ASSERT_TRUE(adsb::decode(f.data(), 14, &m));
  EXPECT_TRUE(m.r.has_speed);
  EXPECT_EQ(m.r.speed_kt, 375);
  EXPECT_EQ(m.r.track_deg, 243);   // heading 243.98°
  EXPECT_EQ(m.r.vs_fpm, -2304);
}

TEST(AdsB, NotAnExtendedSquitter) {
  uint8_t b[14] = { 0x5D, 0x48, 0x40, 0xD6 };   // DF 11
  adsb::Message m;
  EXPECT_FALSE(adsb::decode(b, 11, &m));
  EXPECT_FALSE(adsb::decode(b, 7, &m));
  EXPECT_FALSE(adsb::decode(NULL, 11, &m));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
