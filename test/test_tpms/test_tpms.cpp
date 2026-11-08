// Tire pressure sensors (src/helpers/tpms) on real frames: rtl_433's test captures, cut as the LR2021
// hands them over (the chips after its sync word), each checked against what rtl_433 reads.
#include <gtest/gtest.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/tpms/Tpms.h>
#include "vectors.inc"

using namespace tpms;

struct Case { const char* name; uint8_t proto; const uint8_t* chips; int n; int air; uint32_t id; int kpa10; };
#define CASE(P, NAME) { #NAME, P, NAME, (int) sizeof(NAME), NAME##_EXP.air, NAME##_EXP.id, NAME##_EXP.kpa10 }
static const Case CASES[] = {
  CASE(P_FORD, FORD_0), CASE(P_FORD, FORD_1),
  CASE(P_JEEP, JEEP_0), CASE(P_JEEP, JEEP_1),
  CASE(P_TOYOTA, TOYOTA_0), CASE(P_TOYOTA, TOYOTA_1),
  CASE(P_PMV107J, PMV107J_0), CASE(P_PMV107J, PMV107J_1),
  CASE(P_HONDA, HONDA_0), CASE(P_HONDA, HONDA_1),
  CASE(P_NISSAN, NISSAN_0), CASE(P_NISSAN, NISSAN_1),
  CASE(P_GM, GM_0), CASE(P_GM, GM_1),
};

TEST(Tpms, RealFramesReadAsRtl433ReadsThem) {
  for (const Case& c : CASES) {
    Reading r;
    ASSERT_TRUE(read(c.air, c.chips, c.n, &r)) << c.name;
    EXPECT_EQ(c.proto, r.proto) << c.name;
    EXPECT_EQ(c.id, r.id) << c.name;
    // the Jeep vectors are Citroen captures: the same frames, Jeep's pressure is twice Citroen's
    int want = c.proto == P_JEEP ? c.kpa10 * 2 : c.kpa10;
    EXPECT_LE(abs(r.kpa10 - want), 2) << c.name << " " << r.kpa10 << " vs " << want;
  }
}

TEST(Tpms, EachSettingReadsOnlyItsOwn) {
  for (const Case& c : CASES) {
    for (int a = 0; a < AIRS; a++) {
      if (a == c.air) continue;
      Reading r;
      bool ok = read(a, c.chips, c.n, &r);
      // Nissan's check is 2 bits: any Manchester-coded frame passes it one time in 4 when fed to it
      // directly. On the air its listen is another chip rate; and weak readings count only when heard
      // twice the same.
      if (ok && r.proto == P_NISSAN && r.weak_check) continue;
      EXPECT_FALSE(ok) << c.name << " read by " << air(a).name;
    }
  }
}

TEST(Tpms, AFlippedChipIsRejectedOrHarmless) {
  // a changed chip either stops the frame reading, or (where Manchester's second half is ignored, or a
  // weak sum lets it through) still gives the same ID: never a different sensor
  int rejected = 0, total = 0;
  for (const Case& c : CASES) {
    for (int i = 0; i < c.n * 8; i++) {
      uint8_t x[32];
      memcpy(x, c.chips, c.n);
      x[i >> 3] ^= 0x80 >> (i & 7);
      Reading r;
      total++;
      if (!read(c.air, x, c.n, &r)) { rejected++; continue; }
      if (!r.weak_check) EXPECT_EQ(c.id, r.id) << c.name << " chip " << i;
    }
  }
  EXPECT_GT(rejected, total / 3);
}

TEST(Tpms, NoiseDoesntRead) {
  // random chips after each sync word: the checks reject them (weak ones are taken only when heard twice)
  uint32_t s = 12345;
  int strong = 0;
  for (int k = 0; k < 20000; k++) {
    uint8_t x[32];
    for (auto& v : x) { s = s * 1103515245u + 12345u; v = (uint8_t)(s >> 16); }
    for (int a = 0; a < AIRS; a++) {
      Reading r;
      if (read(a, x, air(a).pkt_bytes, &r) && !r.weak_check) strong++;
    }
  }
  EXPECT_LE(strong, 2);   // CRC-8 with a pressure cross-check or Manchester runs: about never
}

TEST(Tpms, SettingsAreConsistent) {
  for (int a = 0; a < AIRS; a++) {
    EXPECT_GT(air(a).sync_bits, 0);
    EXPECT_LE(air(a).sync_bits, 40);
    EXPECT_LE(air(a).pkt_bytes, 26);
    EXPECT_NE(0, air(a).protos);
  }
  EXPECT_TRUE(air(7).ook);   // GM
  EXPECT_STREQ("Ford", protoName(P_FORD));
  EXPECT_STREQ("GM", protoName(P_GM));
  EXPECT_EQ(0xF4, crc8((const uint8_t*) "123456789", 9, 0x07, 0x00));   // CRC-8/SMBUS check value
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
