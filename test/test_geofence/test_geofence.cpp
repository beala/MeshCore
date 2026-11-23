#include <gtest/gtest.h>
#include "helpers/GeoFence.h"

static const uint32_t S = 1000, M = 60000;

// Home: one AP with two SSIDs that differ only in the first byte
static const GeoScanAp HOME_A = { { 0x98, 0x03, 0x8E, 0xFA, 0x2B, 0x9A }, -50 };
static const GeoScanAp HOME_A_IOT = { { 0xA2, 0x03, 0x8E, 0xFA, 0x2B, 0x9A }, -52 };
static const GeoScanAp HOME_B = { { 0x98, 0x03, 0x8E, 0xFA, 0x2B, 0xB6 }, -70 };
static const GeoScanAp NEIGHBOUR = { { 0x60, 0xDB, 0x98, 0x6B, 0xA6, 0xBC }, -83 };
static const GeoScanAp CAFE = { { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, -40 };

struct Rig {
  GeoFencePrefs p;
  GeoFence geo{p};
  uint32_t now = 1000;

  Rig(bool with_home = true, uint32_t start = 1000) : now(start) {
    p.setDefaults();
    if (with_home) {
      GeoScanAp aps[] = { HOME_A, HOME_B };
      geo.setHome(aps, 2, -85);
      p.enabled = 1;
    }
    geo.begin(now);
  }
  // Advance time, running every due scan with the given result
  int run(uint32_t ms, GeoFence::ScanResult r, uint32_t step = S) {
    int scans = 0;
    for (uint32_t t = 0; t < ms; t += step) {
      now += step;
      if (geo.scanDue(now)) { geo.onScan(now, r); scans++; }
    }
    return scans;
  }
  // Park at home from AWAY: still, two home scans
  void parkHome() {
    run(p.still_secs * S + 2 * M, GeoFence::SAW_HOME);
  }
};

TEST(GeoFence, OffWithoutHomeAPs) {
  Rig r(false);
  EXPECT_EQ(GeoFence::OFF, r.geo.state());
  EXPECT_TRUE(r.geo.radioOn(r.now));
  EXPECT_EQ(0, r.run(60 * M, GeoFence::SAW_HOME));
}

TEST(GeoFence, OffWhenDisabled) {
  Rig r;
  r.p.enabled = 0;
  r.geo.begin(r.now);
  EXPECT_EQ(GeoFence::OFF, r.geo.state());
  EXPECT_EQ(0, r.run(60 * M, GeoFence::SAW_HOME));
}

TEST(GeoFence, NoScanWhileMoving) {
  Rig r;
  for (int i = 0; i < 600; i++) {   // motion every 10 s for 100 minutes
    r.now += 10 * S;
    r.geo.onMotion(r.now);
    EXPECT_FALSE(r.geo.scanDue(r.now));
  }
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
}

TEST(GeoFence, ParksHomeAfterStillAndTwoScans) {
  Rig r;
  r.run(179 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(0u, r.geo.stats().scans);           // not still long enough yet
  r.run(1 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(1u, r.geo.stats().scans);           // first scan at 180 s
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
  EXPECT_TRUE(r.geo.radioOn(r.now));
  r.run(59 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());     // confirm scan 60 s later
  r.run(1 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
  EXPECT_FALSE(r.geo.radioOn(r.now));
  EXPECT_EQ(1u, r.geo.stats().to_home);
}

TEST(GeoFence, MotionBetweenScansStartsOver) {
  Rig r;
  r.run(180 * S, GeoFence::SAW_HOME);           // one home scan
  r.geo.onMotion(r.now);
  r.run(179 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(1u, r.geo.stats().scans);           // waits for stillness again
  r.run(61 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::HOME, r.geo.state());     // and needs two fresh scans
  EXPECT_EQ(3u, r.geo.stats().scans);
}

TEST(GeoFence, ParkedElsewhereRescansEvery15Minutes) {
  Rig r;
  int scans = r.run(180 * S + 60 * M, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
  EXPECT_TRUE(r.geo.radioOn(r.now));
  EXPECT_EQ(5, scans);                          // at 3 min, then every 15 min
}

TEST(GeoFence, MissThenHitStillNeedsTwoHits) {
  Rig r;
  r.run(180 * S, GeoFence::MISSED);
  r.run(15 * M, GeoFence::SAW_HOME);            // one hit
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
  r.run(60 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
}

TEST(GeoFence, HomeBackupScanHourly) {
  Rig r;
  r.parkHome();
  ASSERT_EQ(GeoFence::HOME, r.geo.state());
  uint32_t before = r.geo.stats().scans;
  int scans = r.run(5 * 60 * M, GeoFence::SAW_HOME);
  EXPECT_EQ(5, scans);
  EXPECT_EQ(before + 5, r.geo.stats().scans);
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
}

TEST(GeoFence, MotionAtHomeLeavesAfterTwoMisses) {
  Rig r;
  r.parkHome();
  r.now += S;
  r.geo.onMotion(r.now);
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());
  EXPECT_FALSE(r.geo.radioOn(r.now));           // still asleep while checking
  EXPECT_TRUE(r.geo.scanDue(r.now));            // scans at once
  r.geo.onScan(r.now, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());
  r.run(29 * S, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());
  r.run(1 * S, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
  EXPECT_TRUE(r.geo.radioOn(r.now));
  EXPECT_EQ(1u, r.geo.stats().to_away);
}

TEST(GeoFence, BumpAtHomeGoesBackToSleep) {
  Rig r;
  r.parkHome();
  r.geo.onMotion(r.now);
  r.run(179 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());  // seen home, but not still long enough
  r.run(31 * S, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
  EXPECT_FALSE(r.geo.radioOn(r.now));
}

TEST(GeoFence, OneMissAmongHitsDoesNotWake) {
  Rig r;
  r.parkHome();
  r.geo.onMotion(r.now);
  r.geo.scanDue(r.now);
  r.geo.onScan(r.now, GeoFence::MISSED);        // one bad scan
  r.run(30 * S, GeoFence::SAW_HOME);
  r.run(30 * S, GeoFence::MISSED);              // not in a row
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());
  r.run(5 * M, GeoFence::SAW_HOME);
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
}

TEST(GeoFence, HourlyMissGoesToLeaving) {
  Rig r;
  r.parkHome();
  r.run(58 * M, GeoFence::MISSED);              // parkHome() ended a minute after arriving
  EXPECT_EQ(GeoFence::HOME, r.geo.state());     // backup scan is due 60 min after arriving
  r.run(1 * M, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());
  EXPECT_EQ(1u, r.geo.stats().to_leaving);
  r.run(30 * S, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
}

TEST(GeoFence, FailedScansRetryAndNeverCount) {
  Rig r;
  r.parkHome();
  r.geo.onMotion(r.now);
  for (int i = 0; i < 20; i++) {
    r.run(10 * S, GeoFence::FAILED);
  }
  EXPECT_EQ(GeoFence::LEAVING, r.geo.state());
  EXPECT_EQ(20u, r.geo.stats().failed);
}

TEST(GeoFence, ButtonKeepsRadioOn) {
  Rig r;
  r.parkHome();
  ASSERT_FALSE(r.geo.radioOn(r.now));
  r.geo.onButton(r.now);
  EXPECT_TRUE(r.geo.radioOn(r.now));
  r.run(10 * M - S, GeoFence::SAW_HOME);
  EXPECT_TRUE(r.geo.radioOn(r.now));
  r.run(S, GeoFence::SAW_HOME);
  EXPECT_FALSE(r.geo.radioOn(r.now));
  EXPECT_EQ(GeoFence::HOME, r.geo.state());     // the button does not change the state
}

TEST(GeoFence, ForceHomePinsWithoutScans) {
  Rig r;
  r.geo.force(GeoFence::HOME, r.now);
  EXPECT_TRUE(r.geo.pinned());
  EXPECT_FALSE(r.geo.radioOn(r.now));
  r.geo.onMotion(r.now);
  EXPECT_EQ(0, r.run(24 * 60 * M, GeoFence::MISSED, 10 * S));
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
  r.geo.force(GeoFence::OFF, r.now);            // auto
  EXPECT_FALSE(r.geo.pinned());
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
}

TEST(GeoFence, WorksAcrossMillisWrap) {
  Rig r(true, 0xFFFFFFFFu - 100 * S);
  r.parkHome();
  EXPECT_EQ(GeoFence::HOME, r.geo.state());
  r.geo.onMotion(r.now);
  r.run(2 * M, GeoFence::MISSED);
  EXPECT_EQ(GeoFence::AWAY, r.geo.state());
}

TEST(GeoFence, AsleepTimeCounted) {
  Rig r;
  r.parkHome();
  const uint32_t parked = r.now;
  const uint32_t before = r.geo.homeMillis(r.now);   // parkHome() ran a minute past arriving
  r.run(120 * M, GeoFence::SAW_HOME);
  EXPECT_EQ(before + (r.now - parked), r.geo.homeMillis(r.now));
  r.geo.onMotion(r.now);
  r.run(2 * M, GeoFence::MISSED);                     // left: the count stops
  const uint32_t total = r.geo.homeMillis(r.now);
  r.run(30 * M, GeoFence::MISSED);
  EXPECT_EQ(total, r.geo.homeMillis(r.now));
}

TEST(GeoFenceHome, MatchIgnoresFirstByte) {
  Rig r;
  EXPECT_TRUE(r.geo.isHome(HOME_A.mac));
  EXPECT_TRUE(r.geo.isHome(HOME_A_IOT.mac));
  EXPECT_FALSE(r.geo.isHome(NEIGHBOUR.mac));
  GeoScanAp seen[] = { NEIGHBOUR, HOME_A_IOT };
  EXPECT_EQ(GeoFence::SAW_HOME, r.geo.judge(seen, 2));
  EXPECT_EQ(GeoFence::MISSED, r.geo.judge(seen, 1));
  EXPECT_EQ(GeoFence::MISSED, r.geo.judge(seen, 0));
}

TEST(GeoFenceHome, SetKeepsStrongDistinctAps) {
  Rig r(false);
  GeoScanAp aps[] = { NEIGHBOUR, HOME_A_IOT, HOME_B, HOME_A };
  EXPECT_EQ(2, r.geo.setHome(aps, 4, -75));     // neighbour too weak; A once
  EXPECT_EQ(2, r.p.num_home);
  EXPECT_EQ(0, memcmp(r.p.home[0], HOME_A.mac + 1, 5));   // strongest first
  EXPECT_EQ(0, memcmp(r.p.home[1], HOME_B.mac + 1, 5));
  EXPECT_FALSE(r.geo.isHome(NEIGHBOUR.mac));
}

TEST(GeoFenceHome, SetNothingKeepsOldList) {
  Rig r;
  GeoScanAp aps[] = { NEIGHBOUR };
  EXPECT_EQ(0, r.geo.setHome(aps, 1, -60));
  EXPECT_EQ(2, r.p.num_home);
}

TEST(GeoFenceHome, AddKeepsSavedAps) {
  Rig r(false);
  GeoScanAp first[] = { HOME_A };
  EXPECT_EQ(1, r.geo.setHome(first, 1, -80));
  GeoScanAp second[] = { HOME_A_IOT, HOME_B, NEIGHBOUR };
  EXPECT_EQ(2, r.geo.setHome(second, 3, -80, true));   // A already saved, neighbour too weak
  EXPECT_EQ(2, r.p.num_home);
  EXPECT_TRUE(r.geo.isHome(HOME_B.mac));
  EXPECT_EQ(0, r.geo.setHome(second, 1, -80, true));   // nothing new: unchanged
  EXPECT_EQ(2, r.p.num_home);
}

TEST(GeoFenceHome, SetCapsAtMax) {
  Rig r(false);
  GeoScanAp aps[20];
  for (int i = 0; i < 20; i++) {
    aps[i] = CAFE;
    aps[i].mac[5] = i;
    aps[i].rssi = -40 - i;
  }
  EXPECT_EQ(GEO_MAX_HOME, r.geo.setHome(aps, 20, -100));
  EXPECT_EQ(0, r.p.home[GEO_MAX_HOME - 1][4] - (GEO_MAX_HOME - 1));
}

TEST(GeoFencePrefs, DefaultsAreValid) {
  GeoFencePrefs p;
  p.setDefaults();
  EXPECT_TRUE(p.isValid());
  p.num_home = GEO_MAX_HOME + 1;
  EXPECT_FALSE(p.isValid());
  p.setDefaults();
  p.version = 0;
  EXPECT_FALSE(p.isValid());
}

// --- CLI ---

struct Cli : Rig {
  char reply[160];
  bool changed, restart;
  bool cmd(const char* c) {
    reply[0] = 0;
    return handleGeoCommand(geo, p, c, now, reply, changed, restart);
  }
};

TEST(GeoFenceCli, NotOurs) {
  Cli c;
  EXPECT_FALSE(c.cmd("get name"));
  EXPECT_FALSE(c.cmd("geography"));
  EXPECT_FALSE(c.cmd("geo home set"));          // the caller's: needs a scan
  EXPECT_FALSE(c.cmd("geo scan"));
}

TEST(GeoFenceCli, Status) {
  Cli c;
  EXPECT_TRUE(c.cmd("geo"));
  EXPECT_NE(nullptr, strstr(c.reply, "away"));
  EXPECT_NE(nullptr, strstr(c.reply, "2 home APs"));
  EXPECT_NE(nullptr, strstr(c.reply, "radio on"));
}

TEST(GeoFenceCli, OnNeedsHome) {
  Cli c;
  c.cmd("geo home clear");
  EXPECT_TRUE(c.changed);
  EXPECT_EQ(0, c.p.enabled);
  c.cmd("geo on");
  EXPECT_EQ(0, strncmp(c.reply, "Error", 5));
  EXPECT_FALSE(c.changed);
}

TEST(GeoFenceCli, OnOff) {
  Cli c;
  c.cmd("geo off");
  EXPECT_EQ(0, c.p.enabled);
  EXPECT_TRUE(c.restart);
  c.cmd("geo on");
  EXPECT_EQ(1, c.p.enabled);
  EXPECT_STREQ("OK", c.reply);
}

TEST(GeoFenceCli, HomeList) {
  Cli c;
  c.cmd("geo home");
  EXPECT_STREQ("> 2: ??038EFA2B9A ??038EFA2BB6", c.reply);
}

TEST(GeoFenceCli, Numbers) {
  Cli c;
  c.cmd("geo still 300");
  EXPECT_EQ(300, c.p.still_secs);
  EXPECT_TRUE(c.changed);
  for (const char* bad : { "geo still 9", "geo still 3601", "geo still x", "geo still 30x",
                           "geo check 4", "geo awake 0", "geo awake 241", "geo still -5" }) {
    EXPECT_TRUE(c.cmd(bad)) << bad;
    EXPECT_EQ(0, strncmp(c.reply, "Error", 5)) << bad << " -> " << c.reply;
    EXPECT_FALSE(c.changed) << bad;
  }
  c.cmd("geo still");
  EXPECT_STREQ("> 300 s", c.reply);
  c.cmd("geo check 30");
  EXPECT_EQ(30, c.p.check_mins);
  c.cmd("geo awake 5");
  EXPECT_EQ(5, c.p.awake_mins);
  EXPECT_TRUE(c.p.isValid());
}

TEST(GeoFenceCli, Force) {
  Cli c;
  c.cmd("geo force home");
  EXPECT_EQ(GeoFence::HOME, c.geo.state());
  EXPECT_TRUE(c.geo.pinned());
  c.cmd("geo");
  EXPECT_NE(nullptr, strstr(c.reply, "(forced)"));
  c.cmd("geo force auto");
  EXPECT_EQ(GeoFence::AWAY, c.geo.state());
  c.cmd("geo force sideways");
  EXPECT_EQ(0, strncmp(c.reply, "Error", 5));
}

TEST(GeoFenceCli, StatsFits) {
  Cli c;
  c.cmd("geo stats");
  EXPECT_EQ(0, strncmp(c.reply, "> scans", 7));
  EXPECT_LT(strlen(c.reply), 160u);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
