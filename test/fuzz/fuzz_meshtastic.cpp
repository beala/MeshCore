// libFuzzer harness: Meshtastic packets into the decoder (src/helpers/meshtastic), with the real AES.
//
// The first byte picks what the rest is:
//   0: packets heard on the air, each a length byte then that many bytes
//   1: packets given as plaintext: to, from, id (12 bytes), flags (1), then the Data protobuf; the
//      harness adds the channel hash and encrypts it, so the fuzzer reaches the protobuf parser
//   2: a User protobuf for parseUser()
//   3: text for nextPart(), split as the companion does
// Every text found is split into channel messages the way MyMeshMeshtastic.cpp does it, into a
// buffer of exactly a frame's size, so a part that doesn't fit shows up as an overflow.
//
// FUZZ_WRITE_SEEDS=<dir> writes a few valid inputs of each kind (from test_meshtastic/vectors.h).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "helpers/meshtastic/MeshtasticRx.h"
#include "../test_meshtastic/vectors.h"

using namespace meshtastic;

static const int FRAME_TEXT = 176 - 11;   // MAX_FRAME_SIZE minus the channel message header

static void showText(const Message& m) {
  const char* text = m.text;
  int left = m.text_len;
  int parts = 0;
  while (left > 0) {
    char* msg = (char*) malloc(FRAME_TEXT + 1);   // the exact size, so ASAN sees any overrun
    int n = snprintf(msg, FRAME_TEXT + 1, "%s: ", m.sender);
    if (n < 0 || n > 60) n = 0;
    int room = FRAME_TEXT - n;
    if (room > 140) room = 140;
    int cut = nextPart(text, left, room);
    if (cut < 1 || cut > room) abort();
    memcpy(&msg[n], text, cut);
    msg[n + cut] = 0;
    free(msg);
    text += cut;
    left -= cut;
    while (left > 0 && (*text == ' ' || *text == '\n')) { text++; left--; }
    if (++parts > 300) abort();   // must always make progress
  }
}

static Receiver* receiver() {
  static Receiver* r = nullptr;
  if (!r) r = new Receiver();
  r->reset();
  uint8_t key = 1;
  r->setChannel("LongFast", &key, 1);
  return r;
}

static void writeSeed(const char* dir, const char* name, const std::vector<uint8_t>& data) {
  std::string path = std::string(dir) + "/" + name;
  FILE* f = fopen(path.c_str(), "wb");
  if (!f) return;
  fwrite(data.data(), 1, data.size(), f);
  fclose(f);
}

static void addPacket(std::vector<uint8_t>& v, const char* p, int len) {
  v.push_back((uint8_t) len);
  v.insert(v.end(), p, p + len);
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  const char* dir = getenv("FUZZ_WRITE_SEEDS");
  if (!dir) return 0;
  std::vector<uint8_t> air = { 0 };
  addPacket(air, PKT_NODEINFO, PKT_NODEINFO_LEN);
  addPacket(air, PKT_TEXT, PKT_TEXT_LEN);
  addPacket(air, PKT_RELAYED, PKT_RELAYED_LEN);
  addPacket(air, PKT_LONG, PKT_LONG_LEN);
  addPacket(air, PKT_DM, PKT_DM_LEN);
  addPacket(air, PKT_POSITION, PKT_POSITION_LEN);
  writeSeed(dir, "air", air);

  // plaintext: a NodeInfo, then a text from the same node
  std::vector<uint8_t> plain = { 1 };
  auto item = [&](uint32_t id, std::vector<uint8_t> data) {
    std::vector<uint8_t> it = { 0xFF, 0xFF, 0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12 };
    for (int i = 0; i < 4; i++) it.push_back((uint8_t)(id >> (8 * i)));
    it.push_back(0x63);
    it.insert(it.end(), data.begin(), data.end());
    plain.push_back((uint8_t) it.size());
    plain.insert(plain.end(), it.begin(), it.end());
  };
  std::vector<uint8_t> user = { 0x0A, 0x09, '!', '1', '2', '3', '4', '5', '6', '7', '8',
                                0x12, 0x04, 'N', 'a', 'm', 'e', 0x1A, 0x02, 'N', 'm' };
  std::vector<uint8_t> ni = { 0x08, 0x04, 0x12, (uint8_t) user.size() };
  ni.insert(ni.end(), user.begin(), user.end());
  item(1, ni);
  std::string t = "hello \xF0\x9F\x93\xBB " + std::string(150, 'x');
  std::vector<uint8_t> text = { 0x08, 0x01, 0x12, (uint8_t)(0x80 | (t.size() & 0x7F)), (uint8_t)(t.size() >> 7) };
  text.insert(text.end(), t.begin(), t.end());
  item(2, text);
  writeSeed(dir, "plain", plain);

  std::vector<uint8_t> u = { 2 };
  u.insert(u.end(), user.begin(), user.end());
  writeSeed(dir, "user", u);
  std::vector<uint8_t> words = { 3 };
  words.insert(words.end(), t.begin(), t.end());
  writeSeed(dir, "split", words);
  exit(0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  uint8_t mode = data[0] & 3;
  data++; size--;

  if (mode == 2) {
    User u;
    parseUser(data, size, &u);
    if (strlen(u.long_name) >= sizeof(u.long_name) || strlen(u.short_name) >= sizeof(u.short_name)) abort();
    return 0;
  }
  if (mode == 3) {
    Message m;
    memset(&m, 0, sizeof(m));
    std::vector<char> copy(data, data + size);   // exact size: nextPart may not read past it
    m.text = copy.data();
    m.text_len = (int) size;
    m.sender = "!a1b2c3d4";
    if (size > 0) showText(m);
    return 0;
  }

  Receiver* r = receiver();
  size_t i = 0;
  while (i < size) {
    int len = data[i++];
    if ((size_t) len > size - i) len = (int)(size - i);
    std::vector<uint8_t> pkt;
    if (mode == 0) {
      pkt.assign(data + i, data + i + len);
    } else {
      if (len < 13) { i += len; continue; }
      pkt.assign(data + i, data + i + 13);
      pkt.push_back(r->getChannelHash());
      pkt.push_back(0);
      pkt.push_back(data[i + 4]);
      pkt.insert(pkt.end(), data + i + 13, data + i + len);
      uint8_t key[MAX_KEY], idx = 1;
      int klen = expandKey(&idx, 1, key);
      uint32_t from = pkt[4] | (pkt[5] << 8) | (pkt[6] << 16) | ((uint32_t) pkt[7] << 24);
      uint32_t id = pkt[8] | (pkt[9] << 8) | (pkt[10] << 16) | ((uint32_t) pkt[11] << 24);
      ctrCrypt(key, klen, from, id, &pkt[16], (int) pkt.size() - 16);
    }
    i += len;
    Message m;
    if (r->handle(pkt.empty() ? nullptr : pkt.data(), (int) pkt.size(), &m) == TEXT) {
      if (m.text_len < 0 || m.text_len > Receiver::MAX_PACKET) abort();
      showText(m);
    }
  }
  return 0;
}
