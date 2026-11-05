#pragma once
// A CommonCLI wired to stand-in board, clock, filesystem and callbacks, with command and reply buffers
// of the firmware's sizes. Used by test/test_common_cli and test/fuzz/fuzz_cli.cpp. Include once per
// program (it defines the RNG stand-in).

#include <RNG.h>   // first: MeshCore.h #defines SEED_SIZE, which RNG.h uses as a name
#include <cstdlib>
#include <cstring>
#include <string>

#include <helpers/CommonCLI.h>

// rweather's RNG reads hardware noise; the keys made here only need to be keys
RNGClass::RNGClass() { }
RNGClass::~RNGClass() { }
void RNGClass::rand(uint8_t* data, size_t len) { for (size_t i = 0; i < len; i++) data[i] = (uint8_t) std::rand(); }
RNGClass RNG;

static const size_t REPLY_SIZE = 160;     // simple_repeater: char reply[160]; remote CLI has 161
static const size_t COMMAND_SIZE = 160;   // simple_repeater: static char command[160]


class TestBoard : public mesh::MainBoard {
public:
  uint16_t getBattMilliVolts() override { return 65535; }
  const char* getManufacturerName() const override { return "A board with a fairly long manufacturer name"; }
  void reboot() override { }
  uint8_t getStartupReason() const override { return 0; }
  bool getBootloaderVersion(char* version, size_t max_len) override {
    snprintf(version, max_len, "%s", "0.9.9-a-long-bootloader-version-string");
    return true;
  }
};

class TestClock : public mesh::RTCClock {
  uint32_t _now = 4000000000u;   // year 2096: widest numbers
public:
  uint32_t getCurrentTime() override { return _now; }
  void setCurrentTime(uint32_t t) override { _now = t; }
};

class TestMillis : public mesh::MillisecondClock {
public:
  unsigned long getMillis() override { return 4294967295ul; }
};

class TestCallbacks : public CommonCLICallbacks {
  mesh::LocalIdentity _id;
public:
  void savePrefs() override { }
  const char* getFirmwareVer() override { return "v1.18.0-a-long-firmware-version-dev-beala"; }
  const char* getBuildDate() override { return "15 Oct 2026"; }
  const char* getRole() override { return "repeater"; }
  bool formatFileSystem() override { return true; }
  void sendSelfAdvertisement(int, bool) override { }
  void updateAdvertTimer() override { }
  void updateFloodAdvertTimer() override { }
  void setLoggingOn(bool) override { }
  void eraseLogFile() override { }
  void dumpLogFile() override { }
  void setTxPower(int8_t) override { }
  void formatNeighborsReply(char* reply) override { strcpy(reply, "-none-"); }
  void formatStatsReply(char* reply) override { strcpy(reply, "{}"); }
  void formatRadioStatsReply(char* reply) override { strcpy(reply, "{}"); }
  void formatPacketStatsReply(char* reply) override { strcpy(reply, "{}"); }
  mesh::LocalIdentity& getSelfId() override { return _id; }
  void saveIdentity(const mesh::LocalIdentity&) override { }
  void clearStats() override { }
  void applyTempRadioParams(float, float, uint8_t, uint8_t, int) override { }
};

struct Rig {
  TestBoard board;
  TestClock rtc;
  SensorManager sensors;
  TransportKeyStore keys;
  RegionMap regions{keys};
  ClientACL acl;
  NodePrefs prefs;
  TestCallbacks callbacks;
  CommonCLI cli{board, rtc, sensors, regions, acl, &prefs, &callbacks};

  // command and reply in heap buffers of the firmware's sizes (simple_repeater: command[160],
  // reply[160]); the command buffer has old junk after the text, as on the radio
  std::string run(std::string command) {
    if (command.size() > COMMAND_SIZE - 1) command.resize(COMMAND_SIZE - 1);
    char* cmd = (char*) malloc(COMMAND_SIZE);
    memset(cmd, 'x', COMMAND_SIZE);
    memcpy(cmd, command.c_str(), command.size() + 1);
    char* reply = (char*) malloc(REPLY_SIZE);
    memset(reply, 0, REPLY_SIZE);
    cli.handleCommand(0, cmd, reply);
    std::string out(reply, strnlen(reply, REPLY_SIZE));
    free(reply);
    free(cmd);
    return out;
  }
};
