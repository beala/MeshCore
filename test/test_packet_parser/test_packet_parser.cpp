#include <gtest/gtest.h>
#include <Packet.h>
#include <Dispatcher.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>

using mesh::Packet;

TEST(PacketParser, RejectsNullAndEmptyInput) {
  Packet packet;
  EXPECT_FALSE(packet.readFrom(nullptr, 0));
  EXPECT_FALSE(packet.readFrom(nullptr, 255));
  const uint8_t byte = ROUTE_TYPE_FLOOD;
  EXPECT_FALSE(packet.readFrom(&byte, 0));
}

TEST(PacketParser, ChecksEveryRoutePathEncodingAndFrameLength) {
  // Allocate exactly the advertised length so ASan detects even short overreads.
  for (uint8_t route = 0; route < 4; ++route) {
    const size_t path_offset = (route == ROUTE_TYPE_TRANSPORT_FLOOD ||
                               route == ROUTE_TYPE_TRANSPORT_DIRECT) ? 5 : 1;
    for (unsigned encoding = 0; encoding < 256; ++encoding) {
      for (unsigned len = 1; len < 256; ++len) {
        auto raw = std::unique_ptr<uint8_t[]>(new uint8_t[len]);
        std::fill_n(raw.get(), len, 0xA5);
        raw[0] = route | (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT);
        if (len > path_offset) raw[path_offset] = encoding;
        const size_t path_bytes = (encoding & 63) * ((encoding >> 6) + 1);
        const size_t payload_offset = path_offset + 1 + path_bytes;
        const bool valid = len > path_offset && (encoding >> 6) != 3 &&
                           path_bytes <= MAX_PATH_SIZE && len > payload_offset &&
                           len - payload_offset <= MAX_PACKET_PAYLOAD;
        Packet packet;
        const bool accepted = packet.readFrom(raw.get(), len);
        ASSERT_EQ(valid, accepted) << "route=" << unsigned(route)
                                  << " path=" << encoding << " len=" << len;
        if (accepted) {
          ASSERT_EQ(path_bytes, packet.getPathByteLen());
          ASSERT_EQ(len - payload_offset, packet.payload_len);
          uint8_t encoded[MAX_TRANS_UNIT];
          ASSERT_EQ(len, packet.writeTo(encoded));
          ASSERT_EQ(0, memcmp(raw.get(), encoded, len));
        }
      }
    }
  }
}

TEST(PacketParser, FailedParsePreservesPreviousPacket) {
  const uint8_t valid[] = {ROUTE_TYPE_DIRECT, 1, 0x42, 0x99};
  Packet packet;
  ASSERT_TRUE(packet.readFrom(valid, sizeof(valid)));
  const uint8_t truncated[] = {ROUTE_TYPE_TRANSPORT_DIRECT, 0x12};
  EXPECT_FALSE(packet.readFrom(truncated, sizeof(truncated)));
  uint8_t encoded[MAX_TRANS_UNIT];
  ASSERT_EQ(sizeof(valid), packet.writeTo(encoded));
  EXPECT_EQ(0, memcmp(valid, encoded, sizeof(valid)));
}

TEST(PacketParser, ClearsTransportCodesWhenParsingPlainRoute) {
  Packet packet;
  const uint8_t transport[] = {ROUTE_TYPE_TRANSPORT_DIRECT, 1, 2, 3, 4, 0, 0x99};
  ASSERT_TRUE(packet.readFrom(transport, sizeof(transport)));
  const uint8_t plain[] = {ROUTE_TYPE_FLOOD, 0, 0x99};
  ASSERT_TRUE(packet.readFrom(plain, sizeof(plain)));
  EXPECT_EQ(0, packet.transport_codes[0]);
  EXPECT_EQ(0, packet.transport_codes[1]);
}

namespace {
class Clock : public mesh::MillisecondClock {
public:
  unsigned long getMillis() override { return 0; }
};
class Radio : public mesh::Radio {
public:
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 0; }
  float packetScore(float, int) override { return 0; }
  bool startSendRaw(const uint8_t*, int) override { return false; }
  bool isSendComplete() override { return false; }
  bool isInRecvMode() const override { return true; }
  void onSendFinished() override {}
};
class Manager : public mesh::PacketManager {
public:
  Packet* allocNew() override { return nullptr; }
  void free(Packet*) override {}
  void queueOutbound(Packet*, uint8_t, uint32_t) override {}
  Packet* getNextOutbound(uint32_t) override { return nullptr; }
  int getOutboundCount(uint32_t) const override { return 0; }
  int getOutboundTotal() const override { return 0; }
  int getFreeCount() const override { return 0; }
  Packet* getOutboundByIdx(int) override { return nullptr; }
  Packet* removeOutboundByIdx(int) override { return nullptr; }
  void queueInbound(Packet*, uint32_t) override {}
  Packet* getNextInbound(uint32_t) override { return nullptr; }
};
class Dispatcher : public mesh::Dispatcher {
public:
  Dispatcher(Radio& radio, Clock& clock, Manager& manager)
    : mesh::Dispatcher(radio, clock, manager) {}
  mesh::DispatcherAction onRecvPacket(Packet*) override { return ACTION_RELEASE; }
};
}

TEST(PacketParser, RadioParserRejectsInvalidLengthsVersionsAndTruncatedFrames) {
  Radio radio;
  Clock clock;
  Manager manager;
  Dispatcher dispatcher(radio, clock, manager);
  Packet packet;
  EXPECT_FALSE(dispatcher.tryParsePacket(&packet, nullptr, 3));
  const uint8_t valid[] = {ROUTE_TYPE_FLOOD, 0, 0x99};
  EXPECT_FALSE(dispatcher.tryParsePacket(nullptr, valid, sizeof(valid)));
  for (int len : {-1, 0, 1, 256, 65539}) {
    EXPECT_FALSE(dispatcher.tryParsePacket(&packet, valid, len));
  }
  for (unsigned route = 0; route < 4; ++route) {
    const unsigned header_size = (route == 0 || route == 3) ? 6 : 2;
    for (unsigned len = 1; len <= header_size; ++len) {
      std::vector<uint8_t> truncated(len, 0);
      truncated[0] = route;
      EXPECT_FALSE(dispatcher.tryParsePacket(&packet, truncated.data(), len));
    }
  }
  for (unsigned version = 1; version < 4; ++version) {
    const uint8_t raw[] = {uint8_t(ROUTE_TYPE_FLOOD | (version << PH_VER_SHIFT)), 0, 0x99};
    EXPECT_FALSE(dispatcher.tryParsePacket(&packet, raw, sizeof(raw)));
  }
  EXPECT_TRUE(dispatcher.tryParsePacket(&packet, valid, sizeof(valid)));
  EXPECT_EQ(1, packet.payload_len);
  EXPECT_EQ(0x99, packet.payload[0]);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
