// Runs every repeater/room CLI command, with many kinds of arguments, under AddressSanitizer.
// Each reply goes into a heap buffer of exactly the size the firmware gives it (160 bytes), so a
// reply that runs past the end fails the test instead of overwriting the radio's stack.

#include <gtest/gtest.h>
#include <vector>

#include "cli_rig.h"
#include <helpers/StatsFormatHelper.h>


namespace {

// command words, from the strings CommonCLI and CommonRadioPrefs compare against
const char* const WORDS[] = {
  "adc.multiplier", "advert", "advert.interval", "advert.zerohop", "allow.read.only", "board",
  "bootloader.ver", "bridge.baud", "bridge.channel", "bridge.delay", "bridge.enabled", "bridge.secret",
  "bridge.source", "bridge.type", "clear stats", "clock", "clock sync", "extra.sf", "fem_rxgain", "fem_txgain",
  "flood.advert.interval", "flood.max", "flood.max.advert", "flood.max.unscoped", "freq", "af",
  "agc.reset.interval", "cad", "direct.txdelay", "dutycycle", "flood.retry", "flood.retry.stats",
  "flood.retry.wait", "int.thresh", "multi.acks", "path.hash.mode", "radio", "radio.rxgain", "rxdelay", "tx",
  "txdelay", "gps", "gps advert", "gps diag", "gps off", "gps on", "gps setloc", "gps sync", "guest.password",
  "lat", "lon", "log", "loop.detect", "name", "neighbor.remove", "neighbors", "owner.info", "password",
  "powersaving", "powersaving off", "powersaving on", "prv.key", "public.key", "pwrmgt.bootmv",
  "pwrmgt.bootreason", "pwrmgt.source", "pwrmgt.support", "region", "region def", "region home",
  "region list", "region put", "region remove", "region load", "region save", "region allowf",
  "region denyf", "repeat", "role", "sensor get", "sensor list", "sensor set", "stats-core",
  "stats-packets", "stats-radio", "tempradio", "time", "ver", "prefs", "share", "rx", "power",
};

const char* const PREFIXES[] = { "", "set ", "get " };

std::vector<std::string> args() {
  return {
    "", "0", "1", "-1", "255", "65535", "4294967295", "4294967296", "-2147483649", "99999999999999999999",
    "1e308", "-1e308", "nan", "inf", "0.000001", "908.0,62.5,7,5", "908,62.5,7,5,99", ",,,,,", "on", "off",
    "%s%s%s%n%n", "%99999d", "a b c d e f g", std::string(150, 'A'), std::string(158, '9'),
    // 40 two-byte and 40 four-byte UTF-8 characters
    [] { std::string s; for (int i = 0; i < 40; i++) s += "\xC3\xA9"; return s; }(),
    [] { std::string s; for (int i = 0; i < 40; i++) s += "\xF0\x9F\x93\xBB"; return s; }(),
    "*", "#", "[]", "\\", "abc:def", "parent.child.grandchild.too-long-region-name-for-the-field",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef",
  };
}

}  // namespace

TEST(CommonCLI, EveryCommandFitsTheReplyBuffer) {
  Rig rig;
  int runs = 0;
  for (const char* prefix : PREFIXES) {
    for (const char* word : WORDS) {
      for (const std::string& arg : args()) {
        std::string command = std::string(prefix) + word + (arg.empty() ? "" : " " + arg);
        std::string reply = rig.run(command);
        EXPECT_LT(reply.size(), REPLY_SIZE) << command;
        runs++;
      }
    }
  }
  EXPECT_GT(runs, 5000);
}

TEST(CommonCLI, RegionsFillUpWithoutOverrun) {
  Rig rig;
  for (int i = 0; i < 100; i++) {
    std::string name = "region-" + std::to_string(i) + "-with-a-long-name";
    rig.run("region put " + name);
    rig.run("region put " + name + ".child " + name);
  }
  EXPECT_LT(rig.run("region list").size(), REPLY_SIZE);
  EXPECT_LT(rig.run("region").size(), REPLY_SIZE);
  EXPECT_LT(rig.run("get region").size(), REPLY_SIZE);
}

TEST(CommonCLI, LongNamesAndPasswordsRoundTrip) {
  Rig rig;
  rig.run("set name " + std::string(100, 'N'));
  rig.run("set owner.info " + std::string(150, 'O'));
  rig.run("set password " + std::string(100, 'P'));
  rig.run("set guest.password " + std::string(100, 'G'));
  EXPECT_LT(rig.run("get name").size(), REPLY_SIZE);
  EXPECT_LT(rig.run("get owner.info").size(), REPLY_SIZE);
  EXPECT_LT(rig.run("get password").size(), REPLY_SIZE);
  EXPECT_LT(rig.run("get guest.password").size(), REPLY_SIZE);
}

namespace {
class FullPacketManager : public mesh::PacketManager {
public:
  mesh::Packet* allocNew() override { return nullptr; }
  void free(mesh::Packet*) override { }
  void queueOutbound(mesh::Packet*, uint8_t, uint32_t) override { }
  mesh::Packet* getNextOutbound(uint32_t) override { return nullptr; }
  int getOutboundCount(uint32_t) const override { return 2147483647; }
  int getOutboundTotal() const override { return 2147483647; }
  int getFreeCount() const override { return 0; }
  mesh::Packet* getOutboundByIdx(int) override { return nullptr; }
  mesh::Packet* removeOutboundByIdx(int) override { return nullptr; }
  void queueInbound(mesh::Packet*, uint32_t) override { }
  mesh::Packet* getNextInbound(uint32_t) override { return nullptr; }
};
}  // namespace

TEST(StatsFormatHelper, CoreStatsFitWithLargestValues) {
  TestBoard board;
  TestMillis ms;
  FullPacketManager mgr;
  char* reply = (char*) malloc(REPLY_SIZE);
  StatsFormatHelper::formatCoreStats(reply, board, ms, 0xFFFF, &mgr);
  EXPECT_LT(strlen(reply), REPLY_SIZE);
  free(reply);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
