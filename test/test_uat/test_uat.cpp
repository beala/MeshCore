// UAT (978 MHz) aircraft messages: Reed-Solomon correction against vectors made with an independent
// encoder (Python reedsolo), and decoding of a real frame recorded near LMO with an RTL-SDR.
#include <gtest/gtest.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <helpers/aircraft/Uat.h>
#include "vectors.inc"

static std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> v;
  for (; s[0] && s[1]; s += 2) { unsigned b; sscanf(s, "%2x", &b); v.push_back((uint8_t)b); }
  return v;
}

TEST(Uat, ReedSolomonMatchesAnIndependentEncoder) {
  for (const RsVector& v : RS_VECTORS) {
    bool is_long = v.data_len == uat::LONG_DATA;
    int n = is_long ? uat::LONG_BYTES : uat::SHORT_BYTES;
    int t = (n - v.data_len) / 2;
    uint8_t cw[48];
    memcpy(cw, v.cw, 48);
    EXPECT_EQ(uat::rsDecode(cw, n, n - v.data_len), 0);   // clean
    memcpy(cw, v.bad, 48);
    int f = uat::rsDecode(cw, n, n - v.data_len);
    if (v.nerr <= t) {
      EXPECT_EQ(f, v.nerr);
      EXPECT_EQ(memcmp(cw, v.cw, n), 0);
    } else {
      // beyond the code's power: must not claim a different valid codeword silently matching data
      if (f >= 0) EXPECT_NE(memcmp(cw, v.cw, n), 0);
    }
  }
}

TEST(Uat, CorrectPicksTheLength) {
  int fixed = 0;
  for (const RsVector& v : RS_VECTORS) {
    if (v.nerr > 4) continue;
    uint8_t buf[48];
    memcpy(buf, v.bad, 48);
    if (v.data_len == uat::SHORT_DATA) for (int i = 30; i < 48; i++) buf[i] = (uint8_t)(i * 37);   // noise after
    EXPECT_EQ(uat::correct(buf, 48, &fixed), v.data_len);
    EXPECT_EQ(memcmp(buf, v.data, v.data_len), 0);
  }
  uint8_t noise[48];
  for (int i = 0; i < 48; i++) noise[i] = (uint8_t)(i * 91 + 7);
  EXPECT_EQ(uat::correct(noise, 48, &fixed), 0);
}

TEST(Uat, RealFrameFromLongmont) {
  // as received (2 byte errors), 2026-11-05 near LMO; dump978's field layout gives the values below
  auto raw = hex("10a63e163925ef6a6d481119009e23205800000000000000000000000011700000082047a3a9429c271a7f3917515d99");
  ASSERT_EQ(raw.size(), 48u);
  int fixed = 0;
  int n = uat::correct(raw.data(), 48, &fixed);
  ASSERT_EQ(n, uat::LONG_DATA);
  EXPECT_EQ(fixed, 2);
  uat::Report r;
  ASSERT_TRUE(uat::decode(raw.data(), n, &r));
  EXPECT_EQ(r.address, 0xA63E16u);
  EXPECT_EQ(r.qualifier, 0);
  EXPECT_EQ(r.payload_type, 2);
  ASSERT_TRUE(r.has_pos);
  EXPECT_NEAR(r.lat_e5 / 1e5, 40.1823, 0.0001);
  EXPECT_NEAR(r.lon_e5 / 1e5, -105.1686, 0.0001);
  ASSERT_TRUE(r.has_alt);
  EXPECT_EQ(r.alt_ft, 5800);
  EXPECT_EQ(r.ag_state, 0);
  ASSERT_TRUE(r.has_speed);
  EXPECT_EQ(r.speed_kt, 79);
  EXPECT_EQ(r.track_deg, 299);
}

TEST(Uat, DistanceBearing) {
  uint32_t d; uint16_t b;
  // LMO (40.1637, -105.1633) to the plane above: about 1.3 mi, north-west-ish
  uat::distanceBearing(4016370, -10516330, 4018230, -10516860, &d, &b);
  EXPECT_NEAR(d / 10.0, 1.3, 0.1);
  EXPECT_NEAR(b, 348, 3);
}

TEST(Uat, RejectsBadInput) {
  uat::Report r;
  uint8_t z[48] = {};
  EXPECT_FALSE(uat::decode(z, 20, &r));
  EXPECT_FALSE(uat::decode(NULL, 34, &r));
  EXPECT_EQ(uat::rsDecode(z, 300, 14), -1);
  EXPECT_EQ(uat::rsDecode(z, 10, 14), -1);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
