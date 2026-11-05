// libFuzzer: packets from the radio into a chat node (Dispatcher -> Mesh -> BaseChatMesh), the input
// anyone in range controls. Built with pass-through crypto (test/fuzz/mocks): encrypted payloads are
// their own plaintext, MACs are 00 00 and signatures always check, so the fuzzer reaches the parsers
// behind them. The node knows one contact and one channel.
//
// Input: a series of packets, each a length byte then that many raw radio bytes. See build.sh.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <deque>
#include <vector>

#include <Dispatcher.h>
#include <Mesh.h>
#include <helpers/BaseChatMesh.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>

namespace mesh {
// no real keys: every signature checks, every shared secret is the same
Identity::Identity() { memset(pub_key, 0, sizeof(pub_key)); }
Identity::Identity(const char* pub_hex) { (void) pub_hex; memset(pub_key, 0, sizeof(pub_key)); }
bool Identity::verify(const uint8_t*, const uint8_t*, int) const { return true; }
bool Identity::readFrom(Stream&) { return false; }
bool Identity::writeTo(Stream&) const { return false; }
void Identity::printTo(Stream&) const { }
LocalIdentity::LocalIdentity() { memset(prv_key, 0, sizeof(prv_key)); }
void LocalIdentity::sign(uint8_t* sig, const uint8_t*, int) const { memset(sig, 0, SIGNATURE_SIZE); }
void LocalIdentity::calcSharedSecret(uint8_t* secret, const uint8_t*) const { memset(secret, 0x5A, PUB_KEY_SIZE); }
}  // namespace mesh

// Every allocation starts as the same junk, as RAM does on a radio, so a field nobody initializes
// reads the same each run and a finding replays from its input alone (FUZZ_JUNK=<byte> to vary it)
static int junk_byte() { static int b = getenv("FUZZ_JUNK") ? atoi(getenv("FUZZ_JUNK")) : 0xA5; return b; }
void* operator new(size_t n) { void* p = malloc(n ? n : 1); if (!p) abort(); memset(p, junk_byte(), n); return p; }
void* operator new[](size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { free(p); }
void operator delete[](void* p) noexcept { free(p); }
void operator delete(void* p, size_t) noexcept { free(p); }
void operator delete[](void* p, size_t) noexcept { free(p); }

namespace {

const int POOL_SIZE = 16;
std::deque<std::vector<uint8_t>> g_frames;   // what the radio "hears" next
unsigned long g_millis = 1000;

class FuzzRadio : public mesh::Radio {
public:
  int recvRaw(uint8_t* bytes, int sz) override {
    if (g_frames.empty()) return 0;
    std::vector<uint8_t> f = g_frames.front();
    g_frames.pop_front();
    int n = (int) f.size() < sz ? (int) f.size() : sz;
    if (n > 0) memcpy(bytes, f.data(), n);
    return n;
  }
  uint32_t getEstAirtimeFor(int len) override { return 10 + len; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override { return true; }
  bool isSendComplete() override { return true; }
  void onSendFinished() override { }
  bool isInRecvMode() const override { return true; }
  float getLastRSSI() const override { return -80; }
  float getLastSNR() const override { return 5; }
};

class FuzzMillis : public mesh::MillisecondClock {
public:
  unsigned long getMillis() override { return g_millis; }
};

class FuzzRNG : public mesh::RNG {
  uint32_t _x = 1;
public:
  void random(uint8_t* dest, size_t len) override { for (size_t i = 0; i < len; i++) dest[i] = (uint8_t) (_x = _x * 1103515245 + 12345) >> 16; }
};

class FuzzRTC : public mesh::RTCClock {
  uint32_t _now = 1700000000;
public:
  uint32_t getCurrentTime() override { return _now; }
  void setCurrentTime(uint32_t t) override { _now = t; }
};

// how often each callback ran, printed at exit when FUZZ_STATS is set (to check the fuzzer gets deep)
int g_hits[12];
const char* const HIT_NAMES[12] = { "contact", "ack", "path", "msg", "cmd", "cli", "signed", "channel",
                                    "request", "response", "", "" };
void printHits() {
  for (int i = 0; i < 10; i++) fprintf(stderr, "%s=%d ", HIT_NAMES[i], g_hits[i]);
  fprintf(stderr, "\n");
}

// touch every byte the node hands over, so a missing terminator or bad length shows up here
void touch(const char* text) { volatile size_t n = strlen(text); (void) n; }
void touch(const uint8_t* data, size_t len) { volatile uint8_t x = 0; for (size_t i = 0; i < len; i++) x ^= data[i]; }

class FuzzChat : public BaseChatMesh {
public:
  FuzzChat(mesh::Radio& radio, mesh::MillisecondClock& ms, mesh::RNG& rng, mesh::RTCClock& rtc,
           mesh::PacketManager& mgr, mesh::MeshTables& tables)
      : BaseChatMesh(radio, ms, rng, rtc, mgr, tables) { }

  void onDiscoveredContact(ContactInfo& c, bool, uint8_t path_len, const uint8_t* path) override {
    g_hits[0]++; touch(c.name); touch(path, path_len & 63);
  }
  ContactInfo* processAck(const uint8_t* data) override { g_hits[1]++; touch(data, 4); return nullptr; }
  void onContactPathUpdated(const ContactInfo& c) override { g_hits[2]++; touch(c.name); }
  void onMessageRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char* text) override { g_hits[3]++; touch(text); }
  void onCommandDataRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char* text) override { g_hits[4]++; touch(text); }
  void onCLICommandRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char* text, char* reply) override {
    g_hits[5]++; touch(text); strcpy(reply, "ok");
  }
  void onSignedMessageRecv(const ContactInfo&, mesh::Packet*, uint32_t, const uint8_t* prefix, const char* text) override {
    g_hits[6]++; touch(prefix, 4); touch(text);
  }
  void onChannelMessageRecv(const mesh::GroupChannel&, mesh::Packet*, uint32_t, const char* text) override { g_hits[7]++; touch(text); }
  uint8_t onContactRequest(const ContactInfo&, uint32_t, const uint8_t* data, uint8_t len, uint8_t* reply) override {
    g_hits[8]++; touch(data, len); memset(reply, 0xAB, 16); return 16;
  }
  void onContactResponse(const ContactInfo&, const uint8_t* data, uint8_t len) override { g_hits[9]++; touch(data, len); }
  uint32_t calcFloodTimeoutMillisFor(uint32_t t) const override { return 500 + t; }
  uint32_t calcDirectTimeoutMillisFor(uint32_t t, uint8_t) const override { return 500 + t; }
  void onSendTimeout() override { }
};

struct Node {
  FuzzRadio radio;
  FuzzMillis ms;
  FuzzRNG rng;
  FuzzRTC rtc;
  StaticPoolPacketManager mgr{POOL_SIZE};
  SimpleMeshTables tables;
  FuzzChat chat{radio, ms, rng, rtc, mgr, tables};

  Node() {
    chat.self_id.pub_key[0] = 0x42;
    chat.begin();
    ContactInfo c;
    memset((void*) &c, 0, sizeof(c));
    for (int i = 0; i < PUB_KEY_SIZE; i++) c.id.pub_key[i] = (uint8_t) (0x11 + i);
    strcpy(c.name, "Friend");
    c.type = ADV_TYPE_CHAT;
    c.out_path_len = 0;
    chat.addContact(c);
    chat.addChannel("Public", "izOH6cXN6mrJ5e26oRXNcg==");   // the well-known public channel key
  }
};

// A second node set up as the known contact ("Friend"), which builds one valid packet of each kind
// addressed to the fuzzed node: a starting corpus, so the fuzzer begins inside every handler.
class SeedWriter : public FuzzChat {
  std::string _dir;
  int _n = 0;
public:
  using FuzzChat::FuzzChat;

  void save(mesh::Packet* pkt, uint8_t route) {
    if (!pkt) return;
    pkt->header = (pkt->header & ~PH_ROUTE_MASK) | route;
    uint8_t raw[MAX_TRANS_UNIT + 1];
    raw[0] = pkt->writeTo(&raw[1]);
    std::string path = _dir + "/seed" + std::to_string(_n++);
    FILE* f = fopen(path.c_str(), "wb");
    if (f) { fwrite(raw, 1, raw[0] + 1, f); fclose(f); }
    releasePacket(pkt);
  }

  void writeAll(const char* dir, const mesh::Identity& target, const mesh::GroupChannel& channel) {
    _dir = dir;
    uint8_t secret[PUB_KEY_SIZE];
    memset(secret, 0x5A, sizeof(secret));
    uint32_t ts = 1700000100;
    uint8_t buf[180];

    for (uint8_t txt_type : { TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA, TXT_TYPE_SIGNED_PLAIN, TXT_TYPE_CLI_COMMAND }) {
      memcpy(buf, &ts, 4); ts++;
      buf[4] = txt_type << 2;
      int n = 5;
      if (txt_type == TXT_TYPE_SIGNED_PLAIN) { memcpy(&buf[n], self_id.pub_key, 4); n += 4; }
      n += sprintf((char*) &buf[n], "hello there");
      save(createDatagram(PAYLOAD_TYPE_TXT_MSG, target, secret, buf, n), ROUTE_TYPE_FLOOD);
      save(createDatagram(PAYLOAD_TYPE_TXT_MSG, target, secret, buf, n), ROUTE_TYPE_DIRECT);
    }
    memcpy(buf, &ts, 4); ts++;
    buf[4] = 0;
    int n = 5 + sprintf((char*) &buf[5], "Friend: hi all");
    save(createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, channel, buf, n), ROUTE_TYPE_FLOOD);
    save(createGroupDatagram(PAYLOAD_TYPE_GRP_DATA, channel, buf, n), ROUTE_TYPE_FLOOD);
    for (uint8_t type : { PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE }) {
      memcpy(buf, &ts, 4); ts++;
      memset(&buf[4], 0x01, 8);
      save(createDatagram(type, target, secret, buf, 12), ROUTE_TYPE_FLOOD);
    }
    uint8_t path[3] = { 0x21, 0x22, 0x23 };
    uint32_t ack = 0x12345678;
    save(createPathReturn(target, secret, path, 3, PAYLOAD_TYPE_ACK, (uint8_t*) &ack, 4), ROUTE_TYPE_FLOOD);
    save(createPathReturn(target, secret, path, 3, 0, NULL, 0), ROUTE_TYPE_DIRECT);
    memcpy(buf, &ts, 4); ts++;
    memcpy(&buf[4], "password", 8);
    save(createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, self_id, target, secret, buf, 12), ROUTE_TYPE_FLOOD);
    uint8_t app_data[MAX_ADVERT_DATA_SIZE];
    AdvertDataBuilder adv(ADV_TYPE_CHAT, "Friend", 47.6, -122.3);
    uint8_t app_len = adv.encodeTo(app_data);
    save(createAdvert(self_id, app_data, app_len), ROUTE_TYPE_FLOOD);
    save(createAck(ack), ROUTE_TYPE_FLOOD);
    save(createMultiAck(ack, 2), ROUTE_TYPE_DIRECT);
    save(createTrace(1, 2, 0), ROUTE_TYPE_DIRECT);
    memset(buf, 0x80, 8);
    save(createControlData(buf, 8), ROUTE_TYPE_DIRECT);
    save(createRawData(buf, 8), ROUTE_TYPE_DIRECT);
    fprintf(stderr, "wrote %d seeds to %s\n", _n, dir);
  }
};

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  const char* dir = getenv("FUZZ_WRITE_SEEDS");   // FUZZ_WRITE_SEEDS=<dir>: write the starting corpus
  if (dir) {
    Node target;
    FuzzRadio radio;
    FuzzMillis ms;
    FuzzRNG rng;
    FuzzRTC rtc;
    StaticPoolPacketManager mgr(32);
    SimpleMeshTables tables;
    SeedWriter friend_node(radio, ms, rng, rtc, mgr, tables);
    for (int i = 0; i < PUB_KEY_SIZE; i++) friend_node.self_id.pub_key[i] = (uint8_t) (0x11 + i);
    ChannelDetails ch;
    target.chat.getChannel(0, ch);
    friend_node.writeAll(dir, target.chat.self_id, ch.channel);
    exit(0);
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool stats = getenv("FUZZ_STATS") && !atexit(printHits);
  (void) stats;
  // a fresh node for every input, so any finding replays from its input alone
  g_millis = 1000;   // before the node: it reads the clock as it starts
  Node* node = new Node();

  size_t i = 0;
  while (i < size) {
    size_t len = data[i++];
    if (len > size - i) len = size - i;
    g_frames.emplace_back(data + i, data + i + len);
    i += len;
  }
  for (int k = 0; k < 64 && (!g_frames.empty() || k < 8); k++) {   // receive, then let queued work run
    node->chat.loop();
    g_millis += 250;
  }
  g_frames.clear();
  for (int k = 0; k < 400; k++) {   // let sends, retries and timeouts finish, so held packets go back
    node->chat.loop();
    g_millis += 1000;
  }
  // every packet should be back in the pool or waiting to go out by now; one missing is a packet the
  // mesh code lost, which on a radio slowly empties the pool until it can't receive
  int held = POOL_SIZE - node->mgr.getFreeCount() - node->mgr.getOutboundTotal();
  if (held != 0) {
    fprintf(stderr, "lost %d packet(s): free %d, queued to send %d\n", held, node->mgr.getFreeCount(),
            node->mgr.getOutboundTotal());
    abort();
  }
  delete node;
  return 0;
}
