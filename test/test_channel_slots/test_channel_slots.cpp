#include <gtest/gtest.h>
#include "../../examples/companion_radio/ChannelSlots.h"

using namespace channel_slots;

TEST(ChannelSlots, PlanKeepsOrderAndClosesGaps) {
  bool used[8] = { true, false, true, true, false, false, true, false };
  uint8_t remap[8];
  EXPECT_EQ(plan(used, 8, remap), 4);
  EXPECT_EQ(remap[0], 0);
  EXPECT_EQ(remap[1], GONE);
  EXPECT_EQ(remap[2], 1);
  EXPECT_EQ(remap[3], 2);
  EXPECT_EQ(remap[6], 3);
  EXPECT_EQ(remap[7], GONE);
}

TEST(ChannelSlots, PlanAlreadyCompact) {
  bool used[4] = { true, true, false, false };
  uint8_t remap[4];
  EXPECT_EQ(plan(used, 4, remap), 2);
  EXPECT_EQ(remap[0], 0);
  EXPECT_EQ(remap[1], 1);
}

TEST(ChannelSlots, ReportedSlotsHasOneEmptyUpToMax) {
  EXPECT_EQ(reportedSlots(0, 40), 1);
  EXPECT_EQ(reportedSlots(5, 40), 6);
  EXPECT_EQ(reportedSlots(39, 40), 40);
  EXPECT_EQ(reportedSlots(40, 40), 40);
  EXPECT_EQ(reportedSlots(1, 1), 1);
}

TEST(ChannelSlots, RemapRegularAndSynthetic) {
  bool used[40] = { true, false, true };
  uint8_t remap[40];
  int n = plan(used, 40, remap);
  int new_base = reportedSlots(n, 40);    // 2 channels + 1 empty = 3
  EXPECT_EQ(new_base, 3);
  // first boot after upgrade: synthetic slots were at 40..45
  EXPECT_EQ(remapIdx(0, remap, 40, new_base), 0);
  EXPECT_EQ(remapIdx(1, remap, 40, new_base), -1);   // deleted
  EXPECT_EQ(remapIdx(2, remap, 40, new_base), 1);
  EXPECT_EQ(remapIdx(40, remap, 40, new_base), 3);   // Meshtastic
  EXPECT_EQ(remapIdx(41, remap, 40, new_base), 4);   // Weather
  EXPECT_EQ(remapIdx(0xFF, remap, 40, new_base), 0xFF);
}

TEST(ChannelSlots, RemapAfterAddGrowsBase) {
  // 3 channels in 0..2, empty slot 3, synthetic from 4; the app added one in slot 3
  bool used[40] = { true, true, true, true };
  uint8_t remap[40];
  int n = plan(used, 40, remap);
  int new_base = reportedSlots(n, 40);
  EXPECT_EQ(new_base, 5);
  EXPECT_EQ(remapIdx(3, remap, 4, new_base), 3);     // the new channel stays put
  EXPECT_EQ(remapIdx(4, remap, 4, new_base), 5);     // Meshtastic moves up one
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
