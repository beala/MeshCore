#include <gtest/gtest.h>
#include <helpers/FreqPrint.h>
#include <stdlib.h>

using namespace freqprint;

static const uint8_t HILL[4] = { 0x88, 0xA1, 0x10, 0x20 };   // a repeater's key
static const uint8_t RIDGE[4] = { 0x7A, 0x3C, 0x01, 0x02 };
static const uint8_t OTHER7A[4] = { 0x7A, 0x99, 0x05, 0x06 };
static const int GOOD = 13 * 4;   // SNR x4

// a reading near hz, scattered like the bench: +-4 Hz
static int32_t near(int32_t hz) { return hz + (rand() % 9) - 4; }

TEST(FreqPrint, SignedAdvertMakesACertainRow) {
  Table t;
  int i = t.add(HILL, 4, true, -1125, GOOD, 1000);
  ASSERT_GE(i, 0);
  EXPECT_TRUE(t.rows[i].certain);
  EXPECT_EQ(4, t.rows[i].idn);
  for (int k = 0; k < 20; k++) EXPECT_EQ(i, t.add(HILL, 4, true, near(-1125), GOOD, 2000 + k));
  EXPECT_NEAR(-1125, t.rows[i].mean_x16 / 16, 3);
  EXPECT_EQ(1, t.used());
}

TEST(FreqPrint, OneByteIdAtTheSameFrequencyIsThatRadio) {
  Table t;
  int i = t.add(HILL, 4, true, -1125, GOOD, 1000);
  // a repeater's 1-byte path hash, at its frequency: the same radio, and it learns from it
  for (int k = 0; k < 10; k++) EXPECT_EQ(i, t.add(HILL, 1, false, near(-1125), GOOD, 2000 + k));
  EXPECT_EQ(1, t.used());
  EXPECT_EQ(11, t.rows[i].learned);
}

TEST(FreqPrint, OneByteIdNeverNamesARadioOnItsOwn) {
  Table t;
  int i = t.add(RIDGE, 1, false, 300, GOOD, 1000);
  ASSERT_GE(i, 0);
  EXPECT_FALSE(t.rows[i].certain);
  EXPECT_EQ(1, t.rows[i].idn);
}

TEST(FreqPrint, LaterSignedAdvertConfirmsAnUnnamedRow) {
  Table t;
  int i = t.add(RIDGE, 1, false, 300, GOOD, 1000);
  for (int k = 0; k < 5; k++) t.add(RIDGE, 1, false, near(300), GOOD, 1100 + k);
  // now its advert, signed, at the same frequency
  EXPECT_EQ(i, t.add(RIDGE, 4, true, near(300), GOOD, 2000));
  EXPECT_TRUE(t.rows[i].certain);
  EXPECT_EQ(4, t.rows[i].idn);
  EXPECT_EQ(1, t.used());
}

TEST(FreqPrint, TwoRadiosShareAOneByteId) {
  Table t;
  t.add(RIDGE, 4, true, 300, GOOD, 1000);
  // another radio whose key also starts 7a, 1400 Hz away
  int j = t.add(OTHER7A, 1, false, -1100, GOOD, 1100);
  for (int k = 0; k < 5; k++) EXPECT_EQ(j, t.add(OTHER7A, 1, false, near(-1100), GOOD, 1200 + k));
  EXPECT_EQ(2, t.radiosOn(0x7A));
  EXPECT_FALSE(t.rows[j].certain);
  // a 1-byte "7a" packet goes to whichever fits its frequency
  const uint8_t b7a[1] = { 0x7A };
  EXPECT_EQ(j, t.whoSent(b7a, 1, near(-1100), GOOD, 2000, false));
  EXPECT_NE(j, t.whoSent(b7a, 1, near(300), GOOD, 2000, false));
  EXPECT_GE(t.whoSent(b7a, 1, near(300), GOOD, 2000, false), 0);
}

TEST(FreqPrint, PacketWithNoIdIsPlacedByFrequency) {
  Table t;
  int h = t.add(HILL, 4, true, -1125, GOOD, 1000);
  int r = t.add(RIDGE, 4, true, 300, GOOD, 1000);
  EXPECT_EQ(h, t.whoSent(NULL, 0, -1120, GOOD, 2000, false));
  EXPECT_EQ(r, t.whoSent(NULL, 0, 310, GOOD, 2000, false));
  EXPECT_EQ(-1, t.whoSent(NULL, 0, -400, GOOD, 2000, false));   // no radio there
  // no ID never teaches a row
  EXPECT_EQ(h, t.add(NULL, 0, false, -1110, GOOD, 3000));
  EXPECT_EQ(1, t.rows[h].learned);
  EXPECT_EQ(1, t.rows[h].matched);
}

TEST(FreqPrint, TwoRadiosTooCloseAreNotGuessed) {
  Table t;
  t.add(HILL, 4, true, -1125, GOOD, 1000);
  t.add(RIDGE, 4, true, -1110, GOOD, 1000);   // 15 Hz apart: both bands hold a reading between
  EXPECT_EQ(-1, t.whoSent(NULL, 0, -1118, GOOD, 2000, false));
}

TEST(FreqPrint, WeakReadingsOnlyMatch) {
  Table t;
  int h = t.add(HILL, 4, true, -1125, GOOD, 1000);
  EXPECT_EQ(h, t.add(HILL, 1, false, -1180, -10 * 4, 2000));   // 55 Hz off, at -10 dB: still it
  EXPECT_EQ(1, t.rows[h].learned);                             // but not learned from
  EXPECT_EQ(-1, t.add(HILL, 1, false, -1125 + 488, -10 * 4, 2000));   // a whole bin off: nobody
  EXPECT_EQ(1, t.used());
}

TEST(FreqPrint, FollowsSlowDrift) {
  Table t;
  int h = t.add(HILL, 4, true, -1125, GOOD, 1000);
  // warming up: 150 Hz over 60 packets (the Heltec after two minutes of sending)
  for (int k = 0; k <= 60; k++) EXPECT_EQ(h, t.add(HILL, 1, false, near(-1125 + k * 150 / 60), GOOD, 2000 + k));
  EXPECT_NEAR(-975, t.rows[h].mean_x16 / 16, 25);
  EXPECT_EQ(1, t.used());
}

TEST(FreqPrint, FullTableDropsAnUnnamedRowFirst) {
  Table t;
  t.add(HILL, 4, true, -1125, GOOD, 1);   // certain, and the oldest
  for (int k = 0; k < ROWS - 1; k++) {
    uint8_t id[1] = { (uint8_t)(k + 1) };
    t.add(id, 1, false, k * 100, GOOD, 10 + k);
  }
  EXPECT_EQ(ROWS, t.used());
  uint8_t id[1] = { 0xEE };
  t.add(id, 1, false, 5000, GOOD, 100);
  bool hill = false;
  for (const auto& r : t.rows) if (r.idn == 4 && r.id[0] == 0x88) hill = true;
  EXPECT_TRUE(hill);
}

TEST(FreqPrint, RandomInputsStayInBounds) {
  Table t;
  srand(7);
  for (int k = 0; k < 20000; k++) {
    uint8_t id[4] = { (uint8_t)(rand() % 6), (uint8_t) rand(), (uint8_t) rand(), (uint8_t) rand() };
    int idn = rand() % 5;
    int32_t err = (rand() % 40001) - 20000;
    int snr = (rand() % 160) - 80;
    int i = (rand() % 3) ? t.add(id, idn, idn >= 2 && (rand() & 1), err, snr, k)
                         : t.whoSent(id, idn, err, snr, k, rand() & 1);
    ASSERT_GE(i, -1);
    ASSERT_LT(i, ROWS);
  }
  for (const auto& r : t.rows) ASSERT_LE(r.idn, ID_MAX);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
