// FIS-B ground station frames: error correction and text reports, against real frames from
// dump978's sample data and frames made by tools/bench/fisb.py (whose frames dump978 decodes too).
#include <gtest/gtest.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <helpers/weather/Fisb.h>
#include "vectors.inc"

static std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> v;
  for (; s[0] && s[1]; s += 2) { unsigned b; sscanf(s, "%2x", &b); v.push_back((uint8_t)b); }
  return v;
}

static std::vector<std::string> reports(const uint8_t* data, int len) {
  std::vector<std::string> out;
  fisb::Reports r(data, len);
  fisb::Text t;
  while (r.next(&t)) {
    EXPECT_EQ(fisb::PRODUCT_TEXT, t.product);
    out.push_back(std::string(t.text, t.len));
  }
  return out;
}

TEST(Fisb, RealFramesGiveTheirReports) {
  int metars = 0;
  for (const RealFrame& f : REAL) {
    std::vector<uint8_t> d = hex(f.data_hex);
    ASSERT_EQ(fisb::DATA_BYTES, (int) d.size());
    std::vector<std::string> got = reports(d.data(), d.size());
    ASSERT_EQ(f.n, (int) got.size());
    for (int i = 0; i < f.n && i < 8; i++) {
      EXPECT_EQ(std::string(f.reports[i]), got[i]);
      if (got[i].compare(0, 6, "METAR ") == 0) metars++;
    }
  }
  EXPECT_GE(metars, 5);
}

TEST(Fisb, RealHeaderIsTheStation) {
  std::vector<uint8_t> d = hex(REAL[0].data_hex);
  fisb::Header h;
  fisb::header(d.data(), &h);
  EXPECT_TRUE(h.app_valid);
  EXPECT_TRUE(h.utc_coupled);
  // a station in the western US
  EXPECT_GT(h.lat_e5, 3000000);
  EXPECT_LT(h.lat_e5, 5000000);
  EXPECT_LT(h.lon_e5, -10000000);
  EXPECT_GT(h.lon_e5, -13000000);
}

TEST(Fisb, MadeFrameCorrects) {
  std::vector<uint8_t> f = hex(MADE_CLEAN);
  ASSERT_EQ(fisb::FRAME_BYTES, (int) f.size());
  uint8_t data[fisb::DATA_BYTES];
  int fixed = -1;
  ASSERT_TRUE(fisb::correct(f.data(), data, &fixed));
  EXPECT_EQ(0, fixed);
  std::vector<std::string> got = reports(data, sizeof(data));
  ASSERT_EQ(2u, got.size());
  EXPECT_EQ(std::string(MADE_REPORTS[0]), got[0]);
  EXPECT_EQ(std::string(MADE_REPORTS[1]), got[1]);
  fisb::Header h;
  fisb::header(data, &h);
  EXPECT_NEAR(4016400, h.lat_e5, 3);
  EXPECT_NEAR(-10516300, h.lon_e5, 3);
  EXPECT_EQ(7, h.slot);
}

TEST(Fisb, TenBadBytesInEveryBlockAreFixed) {
  std::vector<uint8_t> f = hex(MADE_TEN_PER_BLOCK);
  uint8_t data[fisb::DATA_BYTES];
  int fixed = 0;
  ASSERT_TRUE(fisb::correct(f.data(), data, &fixed));
  EXPECT_EQ(60, fixed);
  std::vector<std::string> got = reports(data, sizeof(data));
  ASSERT_EQ(2u, got.size());
  EXPECT_EQ(std::string(MADE_REPORTS[1]), got[1]);
}

TEST(Fisb, ElevenInOneBlockFail) {
  std::vector<uint8_t> f = hex(MADE_ELEVEN_IN_ONE);
  uint8_t data[fisb::DATA_BYTES];
  EXPECT_FALSE(fisb::correct(f.data(), data, NULL));
}

TEST(Fisb, DlacTabsAndSeparators) {
  // "AB", tab 3, "C", RS, ETX: codes 1 2 28 3 3 29 0 0
  const uint8_t in[] = { (1 << 2) | (2 >> 4), ((2 & 15) << 4) | (28 >> 2), ((28 & 3) << 6) | 3,
                         (3 << 2) | (29 >> 4), ((29 & 15) << 4) | 0, 0 };
  char out[32];
  int n = fisb::dlac(in, sizeof(in), out, sizeof(out));
  EXPECT_EQ(std::string("AB   C\x1e\x03\x03"), std::string(out, n));
  // too small an out: cut, still terminated
  char small[4];
  fisb::dlac(in, sizeof(in), small, sizeof(small));
  EXPECT_EQ(std::string("AB "), std::string(small));
}

TEST(Fisb, WordsAndOneLine) {
  const char* t = "METAR KLMO 052153Z 31012KT 10SM\n  T01171006=\n";
  char kind[8], where[8], when[10];
  ASSERT_TRUE(fisb::words(t, strlen(t), kind, sizeof(kind), where, sizeof(where), when, sizeof(when)));
  EXPECT_STREQ("METAR", kind);
  EXPECT_STREQ("KLMO", where);
  EXPECT_STREQ("052153Z", when);
  char line[64];
  fisb::oneLine(t, strlen(t), line, sizeof(line));
  EXPECT_STREQ("METAR KLMO 052153Z 31012KT 10SM T01171006", line);
  EXPECT_FALSE(fisb::words("METAR KLMO", 10, kind, sizeof(kind), where, sizeof(where), when, sizeof(when)));
  char tiny[6];
  fisb::oneLine(t, strlen(t), tiny, sizeof(tiny));
  EXPECT_STREQ("METAR", tiny);
}

TEST(Fisb, NoApplicationDataNoReports) {
  std::vector<uint8_t> d = hex(REAL[0].data_hex);
  d[6] &= ~0x20;
  EXPECT_TRUE(reports(d.data(), d.size()).empty());
}

TEST(Fisb, GarbageStaysInBounds) {
  srand(11);
  uint8_t d[fisb::DATA_BYTES];
  for (int k = 0; k < 3000; k++) {
    for (auto& b : d) b = (uint8_t) rand();
    d[6] |= 0x20;
    if (k & 1) { d[8] = 0x0D; d[9] = 0x80; d[10] = 0x06; d[11] = 0x74; }   // a text APDU's header
    reports(d, sizeof(d));
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
