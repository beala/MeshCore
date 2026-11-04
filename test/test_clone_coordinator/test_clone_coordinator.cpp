#include <gtest/gtest.h>
#include "helpers/CloneCoordinator.h"

static const uint8_t BOB[6]   = { 1, 2, 3, 4, 5, 6 };
static const uint8_t CAROL[6] = { 9, 8, 7, 6, 5, 4 };
static const uint8_t ACK1[4]  = { 0x11, 0x22, 0x33, 0x44 };
static const uint8_t ACK2[4]  = { 0x55, 0x66, 0x77, 0x88 };

static void hashOf(uint8_t* h, uint8_t seed) { for (int i = 0; i < MAX_HASH_SIZE; i++) h[i] = seed + i; }

static CloneCoordinator radio(uint32_t tag, uint8_t role = CLONE_ROLE_SOLO, uint32_t epoch = 0) {
  CloneCoordinator c;
  c.load(role, epoch, tag, 0);
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

TEST(CloneCoordinator, BackupDropsHeldReplyWhenMainAnswers) {
  CloneCoordinator b = radio(200, CLONE_ROLE_BACKUP, 5);
  uint8_t h[MAX_HASH_SIZE], cancel[MAX_HASH_SIZE];
  hashOf(h, 7);
  b.hold(h, BOB, ACK1, 1000);
  EXPECT_FALSE(b.onSibling(CAROL, ACK1, 1200, cancel));   // other contact
  EXPECT_FALSE(b.onSibling(BOB, ACK2, 1300, cancel));     // other message
  EXPECT_TRUE(b.onSibling(BOB, ACK1, 1400, cancel));
  EXPECT_EQ(memcmp(cancel, h, MAX_HASH_SIZE), 0);
  EXPECT_FALSE(b.onSibling(BOB, ACK1, 1500, cancel));     // already dropped
  EXPECT_EQ(b.getStats().dropped, 1u);
}

TEST(CloneCoordinator, ResponseMatchedByContact) {
  CloneCoordinator b = radio(200, CLONE_ROLE_BACKUP, 5);
  uint8_t h[MAX_HASH_SIZE], cancel[MAX_HASH_SIZE];
  hashOf(h, 3);
  b.hold(h, BOB, NULL, 1000);
  EXPECT_FALSE(b.onSibling(BOB, ACK1, 1100, cancel));   // an ACK doesn't answer a request
  EXPECT_TRUE(b.onSibling(BOB, NULL, 1200, cancel));
}

TEST(CloneCoordinator, HeldReplyExpires) {
  CloneCoordinator b = radio(200, CLONE_ROLE_BACKUP, 5);
  uint8_t h[MAX_HASH_SIZE], cancel[MAX_HASH_SIZE];
  hashOf(h, 1);
  b.hold(h, BOB, ACK1, 1000);
  EXPECT_FALSE(b.onSibling(BOB, ACK1, 1000 + CLONE_DEFAULT_WAIT_MS + 6000, cancel));
}

TEST(CloneCoordinator, MainAnsweredBeforeWeGotTheMessage) {
  CloneCoordinator b = radio(200, CLONE_ROLE_BACKUP, 5);
  uint8_t cancel[MAX_HASH_SIZE];
  b.onSibling(BOB, ACK1, 1000, cancel);
  EXPECT_TRUE(b.alreadyAnswered(BOB, ACK1, 2000));
  EXPECT_FALSE(b.alreadyAnswered(BOB, ACK2, 2000));
  EXPECT_FALSE(b.alreadyAnswered(CAROL, ACK1, 2000));
  EXPECT_FALSE(b.alreadyAnswered(BOB, NULL, 2000));
  EXPECT_FALSE(b.alreadyAnswered(BOB, ACK1, 1000 + CLONE_RECENT_MS + 1));
}

TEST(CloneCoordinator, HoldWhenFullStillWorks) {
  CloneCoordinator b = radio(200, CLONE_ROLE_BACKUP, 5);
  uint8_t h[MAX_HASH_SIZE], cancel[MAX_HASH_SIZE];
  for (int i = 0; i < CLONE_HELD_SLOTS + 2; i++) { hashOf(h, i); b.hold(h, BOB, ACK1, 1000); }
  EXPECT_TRUE(b.onSibling(BOB, ACK1, 1100, cancel));
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
  c.load(9, 0, 1, 0);
  EXPECT_EQ(c.role(), CLONE_ROLE_SOLO);
  EXPECT_EQ(c.waitMs(), CLONE_DEFAULT_WAIT_MS);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
