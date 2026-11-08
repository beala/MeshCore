// Utility meter frames (src/helpers/meters), as the radio hands them over after the sync word.
// The vectors are made by tools/bench/meters.py, whose reader decodes real meters' frames from an
// RTL-SDR recording the same way rtl_433 does (made-up meters here: real readings are someone's).
#include <gtest/gtest.h>
#include <string.h>
#include <helpers/meters/Meters.h>
#include "vectors.inc"

using namespace meters;

TEST(Meters, R900WaterMeterWithItsLeakFlags) {
  Reading r;
  ASSERT_TRUE(readR900(R900_LEAK, sizeof(R900_LEAK), &r));
  EXPECT_EQ(KIND_R900, r.kind);
  EXPECT_EQ(UTIL_WATER, r.utility);
  EXPECT_EQ(12345678u, r.id);
  EXPECT_EQ(1234567u, r.total);
  EXPECT_EQ(3, r.type);
  EXPECT_EQ(3, r.leak_days);
  EXPECT_EQ(1, r.leak_now);
  EXPECT_EQ(1, r.backflow);
  EXPECT_EQ(2, r.no_use);
}

TEST(Meters, R900TotalUsesTheWrapBits) {
  Reading r;
  ASSERT_TRUE(readR900(R900_BIG, sizeof(R900_BIG), &r));
  EXPECT_EQ(3000000001u, r.id);
  EXPECT_EQ(0x7FFFFFFu, r.total);   // 27 bits: 3 of them in the wrap field
}

TEST(Meters, ScmPlusGasAndElectric) {
  Reading r;
  ASSERT_TRUE(readScmPlus(SCMPLUS_GAS, sizeof(SCMPLUS_GAS), &r));
  EXPECT_EQ(KIND_SCMPLUS, r.kind);
  EXPECT_EQ(UTIL_GAS, r.utility);
  EXPECT_EQ(87654321u, r.id);
  EXPECT_EQ(98765u, r.total);
  EXPECT_EQ(0xFC, r.type);
  EXPECT_EQ(0x1208, r.tamper);
  ASSERT_TRUE(readScmPlus(SCMPLUS_ELECTRIC, sizeof(SCMPLUS_ELECTRIC), &r));
  EXPECT_EQ(UTIL_ELECTRIC, r.utility);
  EXPECT_EQ(55500011u, r.id);
  EXPECT_EQ(4000000u, r.total);
}

TEST(Meters, ScmGasAndElectric) {
  Reading r;
  ASSERT_TRUE(readScm(SCM_GAS, sizeof(SCM_GAS), &r));
  EXPECT_EQ(KIND_SCM, r.kind);
  EXPECT_EQ(UTIL_GAS, r.utility);
  EXPECT_EQ(23456789u, r.id);
  EXPECT_EQ(345678u, r.total);
  EXPECT_EQ(12, r.type);
  ASSERT_TRUE(readScm(SCM_ELECTRIC, sizeof(SCM_ELECTRIC), &r));
  EXPECT_EQ(UTIL_ELECTRIC, r.utility);
  EXPECT_EQ(41234567u, r.id);
  EXPECT_EQ(16000000u, r.total);
  EXPECT_EQ((1 << 2) | 2, r.tamper);
}

TEST(Meters, ReadPicksTheKind) {
  Reading r;
  EXPECT_TRUE(read(KIND_R900, R900_LEAK, sizeof(R900_LEAK), &r));
  EXPECT_TRUE(read(KIND_SCMPLUS, SCMPLUS_GAS, sizeof(SCMPLUS_GAS), &r));
  EXPECT_TRUE(read(KIND_SCM, SCM_GAS, sizeof(SCM_GAS), &r));
  EXPECT_FALSE(read(KIND_SCM, SCMPLUS_GAS, sizeof(SCMPLUS_GAS), &r));
  EXPECT_FALSE(read(0, R900_LEAK, sizeof(R900_LEAK), &r));
}

TEST(Meters, AnyChangedChipIsRejected) {
  // every single chip flipped: the frame fails (R900 by its codes, the Itron ones by Manchester or CRC)
  struct { uint8_t kind; const uint8_t* v; int n; } all[] = {
    { KIND_R900, R900_LEAK, (int) sizeof(R900_LEAK) },
    { KIND_SCMPLUS, SCMPLUS_GAS, (int) sizeof(SCMPLUS_GAS) },
    { KIND_SCM, SCM_GAS, (int) sizeof(SCM_GAS) },
  };
  for (auto& a : all) {
    int used = a.kind == KIND_R900 ? 168 : a.kind == KIND_SCMPLUS ? 208 : 152;
    for (int i = 0; i < used; i++) {
      uint8_t c[32];
      memcpy(c, a.v, a.n);
      c[i >> 3] ^= 0x80 >> (i & 7);
      Reading r;
      EXPECT_FALSE(read(a.kind, c, a.n, &r)) << kindName(a.kind) << " chip " << i;
    }
  }
}

TEST(Meters, ShortOrEmptyIsRejected) {
  Reading r;
  uint8_t zero[32] = {};
  for (uint8_t k = 1; k <= KINDS; k++) {
    EXPECT_FALSE(read(k, zero, sizeof(zero), &r));
    EXPECT_FALSE(read(k, R900_LEAK, 10, &r));
  }
  EXPECT_FALSE(readR900(R900_LEAK, sizeof(R900_LEAK) - 1, &r));
  EXPECT_FALSE(readScmPlus(SCMPLUS_GAS, sizeof(SCMPLUS_GAS) - 1, &r));
}

TEST(Meters, AirSettingsMatchTheFraming) {
  // R900's preamble 1010.. and sync; SCM+'s Manchester 16 A3 1E; SCM's 1F2A60
  EXPECT_EQ(0x5555, air(KIND_R900).pattern);
  EXPECT_EQ(21, air(KIND_R900).pkt_bytes);
  EXPECT_EQ(0x966A, air(KIND_SCMPLUS).pattern);
  EXPECT_EQ(26, air(KIND_SCMPLUS).pkt_bytes);
  EXPECT_EQ(0x6955, air(KIND_SCM).pattern);
  EXPECT_EQ(19, air(KIND_SCM).pkt_bytes);
  for (uint8_t k = 1; k <= KINDS; k++) {
    // the datasheet: the pattern's first two chips must differ
    EXPECT_TRUE((air(k).pattern & 3) == 1 || (air(k).pattern & 3) == 2);
    EXPECT_LE(air(k).sync_len, 4);
  }
}

TEST(Meters, ChannelsCoverWhereTheyWereHeard) {
  // R900 channels seen in a recording: 912.000, 912.129, 912.266, 912.396, 912.520, 912.656, 912.915
  const float r900[] = { 912.000f, 912.129f, 912.266f, 912.396f, 912.520f, 912.656f, 912.915f, 913.045f };
  for (float f : r900) {
    float best = 1e9f;
    for (int i = 0; i < channels(KIND_R900); i++) { float d = channelMHz(KIND_R900, i) - f; if (d < 0) d = -d; if (d < best) best = d; }
    EXPECT_LT(best, 0.010f) << f;   // well inside the receiver's +-77 kHz
  }
  EXPECT_NEAR(910.30f, channelMHz(KIND_R900, 0), 0.01f);
  EXPECT_NEAR(920.35f, channelMHz(KIND_R900, channels(KIND_R900) - 1), 0.01f);
  EXPECT_NEAR(910.0f, channelMHz(KIND_SCMPLUS, 0), 0.001f);   // one was heard at 910.0
  EXPECT_NEAR(920.0f, channelMHz(KIND_SCMPLUS, channels(KIND_SCMPLUS) - 1), 0.001f);
  EXPECT_NEAR(910.3f, channelMHz(KIND_R900, -5), 0.01f);    // clamped
  EXPECT_EQ(14000u, periodMs(KIND_R900));
  EXPECT_EQ(15000u, periodMs(KIND_SCMPLUS));
}

TEST(Meters, R900HopSequence) {
  // 50 different channels, all on the grid; a channel's place and the place's channel agree
  bool seen[78] = {};
  for (int p = 0; p < R900_HOPS; p++) {
    int ch = r900HopChannel(p);
    ASSERT_GE(ch, 0);
    ASSERT_LT(ch, channels(KIND_R900));
    EXPECT_FALSE(seen[ch]) << ch;
    seen[ch] = true;
    EXPECT_EQ(p, r900HopPos(ch));
  }
  EXPECT_EQ(-1, r900HopPos(0));   // not in the sequence
  EXPECT_EQ(r900HopChannel(3), r900HopChannel(53));
  EXPECT_EQ(r900HopChannel(49), r900HopChannel(-1));
  // a meter seen in the recordings: channels 11, 21, 17 (as indexes from 910.3035) 2 and 4 sends apart
  int p = r900HopPos(11);
  ASSERT_GE(p, 0);
  EXPECT_EQ(21, r900HopChannel(p + 2));
  EXPECT_EQ(17, r900HopChannel(p + 6));
}

TEST(Meters, Names) {
  EXPECT_STREQ("water", utilityName(UTIL_WATER));
  EXPECT_STREQ("gas", utilityName(ertUtility(0xFC)));
  EXPECT_STREQ("electric", utilityName(ertUtility(7)));
  EXPECT_STREQ("water", utilityName(ertUtility(11)));
  EXPECT_STREQ("meter", utilityName(ertUtility(6)));
  EXPECT_STREQ("SCM+", kindName(KIND_SCMPLUS));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
