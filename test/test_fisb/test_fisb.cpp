// FIS-B ground station frames: error correction and text reports, against real frames from
// dump978's sample data and frames made by tools/bench/fisb.py (whose frames dump978 decodes too).
#include <gtest/gtest.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <helpers/weather/Fisb.h>
#include <helpers/weather/Metar.h>
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

static std::string words(const char* m, bool us = true) {
  metar::Report r;
  if (!metar::parse(m, strlen(m), &r)) return "(not read)";
  char out[300];
  metar::describe(r, us, out, sizeof(out));
  return out;
}

TEST(Metar, RealReportsInWords) {
  EXPECT_EQ("37°F, humidity 38%. Clear sky. Wind NW 3 mph. Visibility 10+ mi. Pressure 30.51 inHg.",
            words("METAR KCXP 240355Z AUTO 32003KT 10SM CLR 03/M10 A3051 RMK AO2=\n"));
  EXPECT_EQ("46°F, humidity 100%. Overcast at 200 ft. Wind E 6 mph. Visibility 1 3/4 mi. Pressure 30.31 inHg.",
            words("METAR KMER 240355Z AUTO 10005KT 1 3/4SM OVC002 08/08 A3031 RMK AO1=\n"));
  // the remarks' T group gives tenths: 11.7 and 11.1 C
  EXPECT_EQ("53°F, humidity 96%. Mist. Few clouds at 900 ft. Wind NNW 10 mph. Visibility 4 mi. Pressure 30.40 inHg.",
            words("METAR KCEC 240356Z AUTO 34009KT 4SM BR FEW009 12/11 A3040 RMK AO2      SLP294 T01170111="));
  EXPECT_EQ("29°F, humidity 39%. Clear sky. Calm wind. Pressure 30.49 inHg.",
            words("METAR KBAN 240352Z AUTO 00000KT CLR M02/M14 A3049 RMK AO2 SLP363  T10171139="));
}

TEST(Metar, EveryRealMetarIsRead) {
  int n = 0;
  for (const RealFrame& f : REAL) {
    for (int i = 0; i < f.n && i < 8; i++) {
      const char* t = f.reports[i];
      if (strncmp(t, "METAR ", 6) && strncmp(t, "SPECI ", 6)) continue;
      metar::Report r;
      ASSERT_TRUE(metar::parse(t, strlen(t), &r)) << t;
      EXPECT_TRUE(r.has_time && r.has_wind && r.has_temp && r.has_pressure) << t;
      n++;
    }
  }
  EXPECT_GE(n, 5);
}

TEST(Metar, StormsGustsAndLayers) {
  EXPECT_EQ("50°F, humidity 66%. Thunderstorm with heavy rain. Mostly cloudy at 4,000 ft (thunderstorm clouds). "
            "Wind WNW 29 mph, gusts 40. Visibility 3 mi. Pressure 29.98 inHg.",
            words("SPECI KBJC 052201Z 30025G35KT 3SM +TSRA BKN040CB 10/04 A2998="));
  EXPECT_EQ("28°F. Light snow, freezing fog. Sky hidden, can see up to 300 ft. Wind variable 5 mph. "
            "Visibility 1/4 mi. Pressure 29.70 inHg.",
            words("METAR KDEN 060100Z VRB04KT 1/4SM -SN FZFG VV003 M02/ A2970"));
  EXPECT_EQ("Showers nearby. Scattered clouds at 3,500 ft, overcast at 12,000 ft. Visibility under 1/4 mi.",
            words("METAR KXYZ 060100Z M1/4SM VCSH SCT035 OVC120"));
}

TEST(Metar, MetricUnitsAndReports) {
  EXPECT_EQ("17°C, humidity 72%. Light rain. Few clouds at 610 m. Wind SW 19 km/h. Visibility 10+ km. Pressure 1013 hPa.",
            words("METAR EGLL 061020Z 22010KT 9999 -RA FEW020 17/12 Q1013", false));
  EXPECT_EQ("17°C. No low clouds, good visibility. Wind SW 19 km/h. Pressure 1013 hPa.",
            words("METAR LFPG 061020Z 22005MPS CAVOK 17/ Q1013", false));   // 5 m/s, no dew point
  EXPECT_EQ("63°F, humidity 72%. Light rain. Few clouds at 2,000 ft. Wind SW 12 mph. Visibility 6+ mi. Pressure 29.91 inHg.",
            words("METAR EGLL 061020Z 22010KT 9999 -RA FEW020 17/12 Q1013"));
}

TEST(Metar, WeatherWords) {
  char w[48];
  ASSERT_TRUE(metar::weatherWords("-SHRASN", w, sizeof(w)));
  EXPECT_STREQ("light rain and snow showers", w);
  ASSERT_TRUE(metar::weatherWords("TS", w, sizeof(w)));
  EXPECT_STREQ("thunderstorm", w);
  ASSERT_TRUE(metar::weatherWords("+FC", w, sizeof(w)));
  EXPECT_STREQ("tornado or waterspout", w);
  ASSERT_TRUE(metar::weatherWords("BCFG", w, sizeof(w)));
  EXPECT_STREQ("patches of fog", w);
  EXPECT_FALSE(metar::weatherWords("AUTO", w, sizeof(w)));
  EXPECT_FALSE(metar::weatherWords("A3002", w, sizeof(w)));
  EXPECT_FALSE(metar::weatherWords("", w, sizeof(w)));
}

TEST(Metar, NotAMetar) {
  metar::Report r;
  const char* taf = "TAF KBJC 052320Z 0600/0624 30012G20KT P6SM SCT080";
  EXPECT_FALSE(metar::parse(taf, strlen(taf), &r));
  EXPECT_FALSE(metar::parse("METAR KLMO 052153Z", 18, &r));   // nothing in it
  // too small an out: cut, still terminated
  char tiny[8];
  ASSERT_TRUE(metar::parse("METAR KLMO 052153Z 31012KT 10SM CLR 12/M01 A3002", 49, &r));
  EXPECT_LT(metar::describe(r, true, tiny, sizeof(tiny)), (int) sizeof(tiny));
  EXPECT_STREQ("54°F, ", tiny);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
