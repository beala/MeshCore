#include <gtest/gtest.h>
#include "helpers/CloneCoordinator.h"

static CloneCoordinator radio(uint32_t tag, uint8_t role = CLONE_ROLE_SOLO, uint32_t epoch = 0) {
  CloneCoordinator c;
  c.load(role, epoch, tag);
  return c;
}

TEST(CloneCoordinator, TakeoverMakesOtherRadioBackup) {
  CloneCoordinator a = radio(100), b = radio(200);
  a.takeover(1700000000);
  EXPECT_EQ(a.role(), CLONE_ROLE_MAIN);
  uint8_t claim[16];
  int len = a.writeClaim(claim);
  EXPECT_TRUE(b.onClaim(claim, len));
  EXPECT_EQ(b.role(), CLONE_ROLE_BACKUP);
  EXPECT_EQ(b.epoch(), 1700000000u);
  EXPECT_FALSE(b.onClaim(claim, len));   // the same claim again (a replay) changes nothing
}

TEST(CloneCoordinator, OwnClaimIgnored) {
  CloneCoordinator a = radio(100);
  a.takeover(1700000000);
  uint8_t claim[16];
  int len = a.writeClaim(claim);
  CloneCoordinator a_after_reboot = radio(100, CLONE_ROLE_MAIN, 0);
  EXPECT_FALSE(a_after_reboot.onClaim(claim, len));
  EXPECT_EQ(a_after_reboot.role(), CLONE_ROLE_MAIN);
}

TEST(CloneCoordinator, OlderClaimIgnored_TakeBack) {
  CloneCoordinator a = radio(100), b = radio(200);
  uint8_t claim[16];
  a.takeover(1700000000);
  int len = a.writeClaim(claim);
  b.onClaim(claim, len);

  b.takeover(1700000100);   // the user takes over on b later
  len = b.writeClaim(claim);
  EXPECT_TRUE(a.onClaim(claim, len));
  EXPECT_EQ(a.role(), CLONE_ROLE_BACKUP);
  EXPECT_EQ(b.role(), CLONE_ROLE_MAIN);

  uint8_t old_claim[16];
  CloneCoordinator stale = radio(100);
  stale.takeover(1700000000);
  len = stale.writeClaim(old_claim);
  EXPECT_FALSE(b.onClaim(old_claim, len));   // older than b's: b stays main
  EXPECT_EQ(b.role(), CLONE_ROLE_MAIN);
}

TEST(CloneCoordinator, TakeoverWithSlowClockStillNewer) {
  CloneCoordinator a = radio(100), b = radio(200);
  uint8_t claim[16];
  a.takeover(1800000000);
  b.onClaim(claim, a.writeClaim(claim));
  uint32_t e = b.takeover(1700000000);   // b's clock is behind a's
  EXPECT_GT(e, 1800000000u);
  EXPECT_TRUE(a.onClaim(claim, b.writeClaim(claim)));
}

TEST(CloneCoordinator, NotAClaim) {
  CloneCoordinator b = radio(200);
  uint8_t data[9] = { 1, 2, 3, 4, 0x00, 5, 6, 7, 8 };
  EXPECT_FALSE(b.onClaim(data, 9));
  data[4] = CLONE_CLAIM_CODE;
  EXPECT_FALSE(b.onClaim(data, 8));   // too short
  EXPECT_EQ(b.role(), CLONE_ROLE_SOLO);
}

TEST(CloneCoordinator, OnlyBackupStaysQuiet) {
  CloneCoordinator solo = radio(100), main = radio(200, CLONE_ROLE_MAIN, 5), backup = radio(300, CLONE_ROLE_BACKUP, 5);
  EXPECT_TRUE(solo.allowReply());
  EXPECT_TRUE(main.allowReply());
  EXPECT_FALSE(backup.allowReply());
  EXPECT_FALSE(backup.allowReply());
  EXPECT_EQ(backup.silenced(), 2u);
  EXPECT_EQ(main.silenced(), 0u);
}

TEST(CloneCoordinator, BackupAnswersAgainAfterTakeoverOrOff) {
  CloneCoordinator b = radio(300, CLONE_ROLE_BACKUP, 5);
  b.takeover(1700000000);
  EXPECT_TRUE(b.allowReply());
  CloneCoordinator c = radio(400, CLONE_ROLE_BACKUP, 5);
  c.setSolo();
  EXPECT_TRUE(c.allowReply());
}

TEST(CloneCoordinator, PromptOnlyOnBackup_RateLimited) {
  CloneCoordinator main = radio(200, CLONE_ROLE_MAIN, 5), b = radio(300, CLONE_ROLE_BACKUP, 5);
  EXPECT_FALSE(main.promptDue(1000));
  EXPECT_TRUE(b.promptDue(1000));
  EXPECT_FALSE(b.promptDue(2000));
  EXPECT_TRUE(b.promptDue(1000 + CLONE_ALERT_INTERVAL));
}

TEST(CloneCoordinator, NewClaimPromptsAgain) {
  CloneCoordinator a = radio(100), b = radio(300, CLONE_ROLE_BACKUP, 5);
  EXPECT_TRUE(b.promptDue(1000));
  b.takeover(1700000000);   // the user said yes
  uint8_t claim[16];
  a.takeover(1700000100);   // later, another radio takes over again
  EXPECT_TRUE(b.onClaim(claim, a.writeClaim(claim)));
  EXPECT_TRUE(b.promptDue(2000));   // so the next message sent from b asks again
}

TEST(CloneCoordinator, AlertRateLimited) {
  CloneCoordinator a = radio(100);
  EXPECT_TRUE(a.alertDue(5000));
  EXPECT_FALSE(a.alertDue(6000));
  EXPECT_FALSE(a.alertDue(5000 + CLONE_ALERT_INTERVAL - 1));
  EXPECT_TRUE(a.alertDue(5000 + CLONE_ALERT_INTERVAL));
}

TEST(CloneCoordinator, LoadSanitises) {
  CloneCoordinator c;
  c.load(9, 0, 1);
  EXPECT_EQ(c.role(), CLONE_ROLE_SOLO);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
