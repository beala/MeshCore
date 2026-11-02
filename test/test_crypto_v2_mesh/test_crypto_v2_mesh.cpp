// End-to-end tests of v1/v2 packet encryption through the real Mesh and BaseChatMesh
// receive paths, with real AES/SHA256/Ed25519. Run: pio test -e native_crypto
#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>
#include <ed_25519.h>

#include "Dispatcher.cpp"
#include "Mesh.cpp"
#include "helpers/AdvertDataHelpers.cpp"
#include "helpers/BaseChatMesh.cpp"
#include "helpers/CryptoPolicyTable.h"

void StrHelper::strncpy(char* dest, const char* src, size_t buf_sz) {
  if (buf_sz == 0) return;
  std::strncpy(dest, src, buf_sz - 1);
  dest[buf_sz - 1] = 0;
}

namespace mesh {
Identity::Identity() { memset(pub_key, 0, sizeof(pub_key)); }
bool Identity::verify(const uint8_t*, const uint8_t*, int) const { return true; }
LocalIdentity::LocalIdentity() : Identity() { memset(prv_key, 0, sizeof(prv_key)); }
LocalIdentity::LocalIdentity(RNG* rng) {
  uint8_t seed[32];
  rng->random(seed, sizeof(seed));
  ed25519_create_keypair(pub_key, prv_key, seed);
}
void LocalIdentity::sign(uint8_t* sig, const uint8_t*, int) const { memset(sig, 0, SIGNATURE_SIZE); }
void LocalIdentity::calcSharedSecret(uint8_t* secret, const uint8_t* other_pub_key) const {
  ed25519_key_exchange(secret, other_pub_key, prv_key);
}
}  // namespace mesh

namespace {

class DummyRadio : public mesh::Radio {
public:
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 10; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override { return true; }
  bool isSendComplete() override { return true; }
  void onSendFinished() override {}
  bool isInRecvMode() const override { return true; }
};
class DummyMillisecondClock : public mesh::MillisecondClock {
public:
  unsigned long getMillis() override { return 1000; }
};
class CounterRNG : public mesh::RNG {
  uint8_t n = 1;
public:
  void random(uint8_t* dest, size_t len) override { for (size_t i = 0; i < len; i++) dest[i] = n++; }
};
class DummyRTCClock : public mesh::RTCClock {
  uint32_t _now = 1700000000;
public:
  uint32_t getCurrentTime() override { return _now; }
  void setCurrentTime(uint32_t time) override { _now = time; }
};
// hands out heap packets so create*() works; nothing is queued
class HeapPacketManager : public mesh::PacketManager {
public:
  std::vector<mesh::Packet*> sent;   // outbound packets, owned by the test
  ~HeapPacketManager() { for (auto p : sent) delete p; }
  mesh::Packet* allocNew() override { return new mesh::Packet(); }
  void free(mesh::Packet* p) override { delete p; }
  void queueOutbound(mesh::Packet* p, uint8_t, uint32_t) override { sent.push_back(p); }
  mesh::Packet* getNextOutbound(uint32_t) override { return nullptr; }
  int getOutboundCount(uint32_t) const override { return 0; }
  int getOutboundTotal() const override { return 0; }
  int getFreeCount() const override { return 16; }
  mesh::Packet* getOutboundByIdx(int) override { return nullptr; }
  mesh::Packet* removeOutboundByIdx(int) override { return nullptr; }
  void queueInbound(mesh::Packet*, uint32_t) override {}
  mesh::Packet* getNextInbound(uint32_t) override { return nullptr; }
};
class DummyMeshTables : public mesh::MeshTables {
public:
  bool wasSeen(const mesh::Packet*) override { return false; }
  void markSeen(const mesh::Packet*) override {}
  void clear(const mesh::Packet*) override {}
};

class Node : public BaseChatMesh {
public:
  CryptoPolicyTable policies;
  std::vector<std::string> messages;
  std::vector<std::string> group_messages;
  int upgrades = 0;
  int path_extra_len = -1;
  uint8_t path_extra[256];
  int signed_received = 0;
  mesh::GroupChannel channel;
  bool has_channel = false;

  Node(mesh::Radio& radio, mesh::MillisecondClock& ms, mesh::RNG& rng, mesh::RTCClock& rtc,
       mesh::PacketManager& mgr, mesh::MeshTables& tables)
      : BaseChatMesh(radio, ms, rng, rtc, mgr, tables) {}

  // same behaviour as the companion firmware's MyMesh
  uint8_t getCryptoPolicy(const uint8_t* secret) override { return policies.get(secret); }
  void onPeerCryptoV2Recv(int, const uint8_t* secret) override {
    if (policies.get(secret) == CRYPTO_POLICY_LEGACY && policies.set(secret, CRYPTO_POLICY_V2)) upgrades++;
  }

  int searchChannelsByHash(const uint8_t* hash, mesh::GroupChannel dest[], int max) override {
    if (!has_channel || channel.hash[0] != hash[0] || max < 1) return 0;
    dest[0] = channel;
    return 1;
  }
  void onGroupDataRecv(mesh::Packet*, uint8_t, const mesh::GroupChannel&, uint8_t* data, size_t len) override {
    group_messages.push_back(std::string((const char*)&data[5], strnlen((const char*)&data[5], len - 5)));
  }
  bool onPeerPathRecv(mesh::Packet*, int, const uint8_t*, uint8_t*, uint8_t, uint8_t, uint8_t* extra, uint8_t extra_len) override {
    path_extra_len = extra_len;
    memcpy(path_extra, extra, extra_len);
    return false;
  }

  void onDiscoveredContact(ContactInfo&, bool, uint8_t, const uint8_t*) override {}
  ContactInfo* processAck(const uint8_t*) override { return nullptr; }
  void onContactPathUpdated(const ContactInfo&) override {}
  void onMessageRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char* text) override { messages.push_back(text); }
  void onCommandDataRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char*) override {}
  void onCLICommandRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char*, char*) override {}
  void onSignedMessageRecv(const ContactInfo&, mesh::Packet*, uint32_t, const uint8_t*, const char*) override { signed_received++; }
  void onChannelMessageRecv(const mesh::GroupChannel&, mesh::Packet*, uint32_t, const char*) override {}
  uint8_t onContactRequest(const ContactInfo&, uint32_t, const uint8_t*, uint8_t, uint8_t*) override { return 0; }
  void onContactResponse(const ContactInfo&, const uint8_t*, uint8_t) override {}
  uint32_t calcFloodTimeoutMillisFor(uint32_t) const override { return 1000; }
  uint32_t calcDirectTimeoutMillisFor(uint32_t, uint8_t) const override { return 1000; }
  void onSendTimeout() override {}

  using mesh::Mesh::onRecvPacket;
};

struct NodeFx {
  DummyRadio radio; DummyMillisecondClock ms; CounterRNG rng; DummyRTCClock rtc;
  HeapPacketManager mgr; DummyMeshTables tables;
  Node node{radio, ms, rng, rtc, mgr, tables};

  NodeFx(uint8_t seed_byte, const char* name) {
    struct FixedRNG : mesh::RNG {
      uint8_t b;
      void random(uint8_t* dest, size_t len) override { memset(dest, b, len); }
    } seed;
    seed.b = seed_byte;
    node.self_id = mesh::LocalIdentity(&seed);
    (void)name;
  }
  void addContact(const NodeFx& other, const char* name) {
    ContactInfo c;
    memset(&c, 0, sizeof(c));
    c.id = other.node.self_id;   // copies pub_key
    c.type = ADV_TYPE_CHAT;
    c.lastmod = 1700000100;
    strcpy(c.name, name);
    ASSERT_TRUE(node.addContact(c));
  }
  void secretWith(const NodeFx& other, uint8_t secret[PUB_KEY_SIZE]) const {
    node.self_id.calcSharedSecret(secret, other.node.self_id.pub_key);
  }
};

struct Pair : ::testing::Test {
  NodeFx alice{0x11, "Alice"};
  NodeFx bob{0x22, "Bob"};
  uint8_t a2b[PUB_KEY_SIZE], b2a[PUB_KEY_SIZE];

  void SetUp() override {
    alice.addContact(bob, "Bob");
    bob.addContact(alice, "Alice");
    alice.secretWith(bob, a2b);
    bob.secretWith(alice, b2a);
    ASSERT_EQ(0, memcmp(a2b, b2a, PUB_KEY_SIZE));
  }

  mesh::Packet* dm(const char* text, uint8_t type = PAYLOAD_TYPE_TXT_MSG) {
    uint8_t data[200];
    uint32_t ts = 1700000500;
    memcpy(data, &ts, 4);
    data[4] = 0;   // TXT_TYPE_PLAIN, attempt 0
    int len = 5 + strlen(text);
    memcpy(&data[5], text, strlen(text));
    mesh::Packet* p = alice.node.createDatagram(type, bob.node.self_id, a2b, data, len);
    if (p) p->header |= ROUTE_TYPE_FLOOD;
    return p;
  }
  int envLen(const mesh::Packet* p) const { return p->payload_len - 2; }
  void deliver(mesh::Packet* p) { bob.node.onRecvPacket(p); delete p; }
};

TEST_F(Pair, LegacyByDefault) {
  mesh::Packet* p = dm("hello v1");
  ASSERT_NE(nullptr, p);
  EXPECT_TRUE(mesh::CryptoV2::isLegacyEnvelope(envLen(p)));
  deliver(p);
  ASSERT_EQ(1u, bob.node.messages.size());
  EXPECT_EQ("hello v1", bob.node.messages[0]);
  EXPECT_EQ(0, bob.node.upgrades);
}

TEST_F(Pair, V2DeliveredAndReceiverAutoUpgrades) {
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  mesh::Packet* p = dm("hello v2");
  ASSERT_NE(nullptr, p);
  EXPECT_FALSE(mesh::CryptoV2::isLegacyEnvelope(envLen(p)));
  EXPECT_EQ(16 + 5 + 8, envLen(p));   // exact length, no block padding
  deliver(p);
  ASSERT_EQ(1u, bob.node.messages.size());
  EXPECT_EQ("hello v2", bob.node.messages[0]);
  EXPECT_EQ(1, bob.node.upgrades);
  EXPECT_EQ(CRYPTO_POLICY_V2, bob.node.policies.get(b2a));   // Bob now sends v2 to Alice
}

TEST_F(Pair, OldFirmwareAlwaysRejectsV2) {
  // what v1-only firmware does with every encrypted payload: Utils::MACThenDecrypt
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  std::string text;
  for (int n = 1; n <= MAX_TEXT_LEN; n++) {
    text += (char)('a' + n % 26);
    mesh::Packet* p = dm(text.c_str());
    ASSERT_NE(nullptr, p) << n;
    uint8_t out[MAX_PACKET_PAYLOAD];
    EXPECT_EQ(0, mesh::Utils::MACThenDecrypt(b2a, out, &p->payload[2], envLen(p))) << n;
    delete p;
  }
}

TEST_F(Pair, V2OnlyRejectsV1) {
  bob.node.policies.set(b2a, CRYPTO_POLICY_V2_ONLY);
  deliver(dm("sneaky v1"));
  EXPECT_TRUE(bob.node.messages.empty());

  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  deliver(dm("proper v2"));
  ASSERT_EQ(1u, bob.node.messages.size());
  EXPECT_EQ("proper v2", bob.node.messages[0]);
  EXPECT_EQ(CRYPTO_POLICY_V2_ONLY, bob.node.policies.get(b2a));   // never lowered
}

TEST_F(Pair, TamperedOrRetypedV2Rejected) {
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  for (int i = 2; i < 2 + 16 + 13; i++) {
    mesh::Packet* p = dm("hello tamper");
    p->payload[i] ^= 0x04;
    deliver(p);
  }
  mesh::Packet* p = dm("hello retype");
  p->header = (p->header & ~(PH_TYPE_MASK << PH_TYPE_SHIFT)) | (PAYLOAD_TYPE_REQ << PH_TYPE_SHIFT);
  deliver(p);
  EXPECT_TRUE(bob.node.messages.empty());
  EXPECT_EQ(0, bob.node.upgrades);
}

TEST_F(Pair, MaxLengthMessagesFitInV2) {
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  std::string text(MAX_TEXT_LEN, 'x');
  mesh::Packet* p = dm(text.c_str());
  ASSERT_NE(nullptr, p);
  EXPECT_LE(p->payload_len, MAX_PACKET_PAYLOAD);
  deliver(p);
  ASSERT_EQ(1u, bob.node.messages.size());
  EXPECT_EQ(text, bob.node.messages[0]);
}

TEST_F(Pair, PathReturnExtraLengthIsExact) {
  uint8_t path[3] = { 0x01, 0x02, 0x03 };
  uint8_t extra[4] = { 9, 8, 7, 6 };
  mesh::Packet* p = alice.node.createPathReturn(bob.node.self_id, a2b, path, 3, PAYLOAD_TYPE_ACK, extra, 4);
  deliver(p);
  EXPECT_EQ(11, bob.node.path_extra_len);   // v1: 9 data bytes padded to 16, so 7 zero bytes leak into extra

  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  p = alice.node.createPathReturn(bob.node.self_id, a2b, path, 3, PAYLOAD_TYPE_ACK, extra, 4);
  deliver(p);
  EXPECT_EQ(4, bob.node.path_extra_len);    // v2: exact
}

TEST_F(Pair, ChannelV2AndV2Only) {
  mesh::GroupChannel ch;
  memset(&ch, 0, sizeof(ch));
  for (int i = 0; i < 16; i++) ch.secret[i] = (uint8_t)(0x30 + i);
  mesh::Utils::sha256(ch.hash, sizeof(ch.hash), ch.secret, 16);
  bob.node.channel = ch;
  bob.node.has_channel = true;

  auto send = [&](const char* text) {
    uint8_t data[100];
    memset(data, 0, 5);
    memcpy(&data[5], text, strlen(text));
    mesh::Packet* p = alice.node.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, ch, data, 5 + strlen(text));
    p->header |= ROUTE_TYPE_FLOOD;
    return p;
  };

  deliver(send("Alice: v1 hi"));
  alice.node.policies.set(ch.secret, CRYPTO_POLICY_V2);
  mesh::Packet* p = send("Alice: v2 hi");
  EXPECT_FALSE(mesh::CryptoV2::isLegacyEnvelope(p->payload_len - 1));
  deliver(p);
  ASSERT_EQ(2u, bob.node.group_messages.size());
  EXPECT_EQ("Alice: v1 hi", bob.node.group_messages[0]);
  EXPECT_EQ("Alice: v2 hi", bob.node.group_messages[1]);
  EXPECT_EQ(CRYPTO_POLICY_LEGACY, bob.node.policies.get(ch.secret));   // channels never auto-upgrade

  bob.node.policies.set(ch.secret, CRYPTO_POLICY_V2_ONLY);
  alice.node.policies.set(ch.secret, CRYPTO_POLICY_LEGACY);
  deliver(send("Alice: v1 again"));
  EXPECT_EQ(2u, bob.node.group_messages.size());
}

// ---- malformed / edge-case plaintexts (an authenticated sender can still send garbage) ----

struct Malformed : Pair {
  // seal an arbitrary plaintext from Alice to Bob as the given type, and deliver it
  void sendRaw(uint8_t type, const uint8_t* p, int len) {
    mesh::Packet* pkt = new mesh::Packet();
    pkt->header = ROUTE_TYPE_FLOOD | (type << PH_TYPE_SHIFT);
    pkt->path_len = 0;
    pkt->payload[0] = bob.node.self_id.pub_key[0];
    pkt->payload[1] = alice.node.self_id.pub_key[0];
    uint8_t ctx[3] = { type, pkt->payload[0], pkt->payload[1] };
    int n = mesh::CryptoV2::seal(a2b, &pkt->payload[2], p, len, ctx, 3);
    ASSERT_GT(n, 0);
    pkt->payload_len = 2 + n;
    deliver(pkt);
  }
  // the ACK Bob sends back for a text message: Bob replies to a flood message with a PATH carrying the ACK
  bool ackFromBob(uint8_t out[6]) {
    for (auto p : bob.mgr.sent) {
      if (p->getPayloadType() != PAYLOAD_TYPE_PATH) continue;
      alice.node.path_extra_len = -1;
      alice.node.onRecvPacket(p);
      if (alice.node.path_extra_len == 6) { memcpy(out, alice.node.path_extra, 6); return true; }
    }
    return false;
  }
};

TEST_F(Malformed, AckAttemptByteIsZeroForNormalMessages) {
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  bob.node.policies.set(b2a, CRYPTO_POLICY_V2);
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  deliver(dm("ordinary"));
  uint8_t ack[6];
  ASSERT_TRUE(ackFromBob(ack));
  EXPECT_EQ(0, ack[4]);
}

TEST_F(Malformed, AckCarriesExtendedAttemptByte) {
  alice.node.policies.set(a2b, CRYPTO_POLICY_V2);
  bob.node.policies.set(b2a, CRYPTO_POLICY_V2);
  // composeMsgPacket() layout for attempt > 3: timestamp, flags, text, NUL, attempt
  uint8_t p[32];
  uint32_t ts = 1700000600;
  memcpy(p, &ts, 4);
  p[4] = 5 & 3;
  memcpy(&p[5], "retry", 5);
  p[10] = 0;
  p[11] = 5;
  sendRaw(PAYLOAD_TYPE_TXT_MSG, p, 12);
  uint8_t ack[6];
  ASSERT_TRUE(ackFromBob(ack));
  EXPECT_EQ(5, ack[4]);
}

TEST_F(Malformed, TruncatedPathRejected) {
  uint8_t p[8] = { 10, 0x01, 0x02 };   // claims 10 one-byte hashes, carries 2
  sendRaw(PAYLOAD_TYPE_PATH, p, 3);
  EXPECT_EQ(-1, bob.node.path_extra_len);
  uint8_t q[8] = { 3, 0x01, 0x02, 0x03 };   // path fits exactly but no extra_type byte
  sendRaw(PAYLOAD_TYPE_PATH, q, 4);
  EXPECT_EQ(-1, bob.node.path_extra_len);
  uint8_t r[8] = { 3, 0x01, 0x02, 0x03, PAYLOAD_TYPE_ACK };   // shortest valid: empty extra
  sendRaw(PAYLOAD_TYPE_PATH, r, 5);
  EXPECT_EQ(0, bob.node.path_extra_len);
}

TEST_F(Malformed, ShortSignedMessageDropped) {
  uint8_t p[8] = { 1, 2, 3, 4, (uint8_t)(TXT_TYPE_SIGNED_PLAIN << 2), 'x' };
  sendRaw(PAYLOAD_TYPE_TXT_MSG, p, 6);
  EXPECT_EQ(0, bob.node.signed_received);
}

TEST_F(Malformed, RandomPlaintextsOfEveryTypeAreHandledSafely) {
  // runs under AddressSanitizer: any read past the plaintext buffer fails the build's test run
  bob.node.has_channel = true;
  memset(&bob.node.channel, 0, sizeof(bob.node.channel));
  for (int i = 0; i < 16; i++) bob.node.channel.secret[i] = (uint8_t)(0x50 + i);
  mesh::Utils::sha256(bob.node.channel.hash, 1, bob.node.channel.secret, 16);

  uint32_t x = 12345;
  auto rnd = [&]() { x = x * 1103515245u + 12345u; return (uint8_t)(x >> 16); };
  const uint8_t types[] = { PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE, PAYLOAD_TYPE_PATH };
  uint8_t p[170];
  for (int round = 0; round < 20; round++) {
    for (int len = 1; len <= 165; len += 1 + round % 7) {
      for (int i = 0; i < len; i++) p[i] = rnd();
      if (len > 4) p[4] = (uint8_t)((rnd() % 4) << 2);   // exercise each text sub-type
      for (uint8_t t : types) sendRaw(t, p, len);

      mesh::Packet* g = new mesh::Packet();
      g->header = ROUTE_TYPE_FLOOD | ((round & 1 ? PAYLOAD_TYPE_GRP_DATA : PAYLOAD_TYPE_GRP_TXT) << PH_TYPE_SHIFT);
      g->path_len = 0;
      g->payload[0] = bob.node.channel.hash[0];
      uint8_t ctx[2] = { g->getPayloadType(), g->payload[0] };
      g->payload_len = 1 + mesh::CryptoV2::seal(bob.node.channel.secret, &g->payload[1], p, len, ctx, 2);
      deliver(g);
    }
  }
  SUCCEED();
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
