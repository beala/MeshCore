// Reading damaged packets (src/helpers/DamagedRx, docs/damaged_packets.md), with the real rweather AES
// and SHA-256: pio test -e native_crypto
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <random>
#include <string.h>
#include "helpers/DamagedRx.h"
#include "Utils.h"

using namespace damaged;

static const uint32_t NOW = 1762400000;   // Nov 2025

static void secretFor(uint8_t seed, uint8_t* s) {   // channel secret: 16-byte key, zero-padded to 32
  memset(s, 0, 32);
  for (int i = 0; i < 16; i++) s[i] = (uint8_t)(seed * 31 + i * 7 + 1);
}

// A flood GRP_TXT packet: header, path, channel hash, MAC, then the encrypted timestamp, flags, text
static std::vector<uint8_t> channelPacket(const uint8_t* secret, const char* text, uint32_t ts, int hops = 2) {
  uint8_t plain[200];
  memcpy(plain, &ts, 4);
  plain[4] = 0;
  int n = 5 + (int)strlen(text);
  memcpy(&plain[5], text, strlen(text));
  std::vector<uint8_t> p;
  p.push_back((uint8_t)(TYPE_GRP_TXT << 2 | 1));
  p.push_back((uint8_t)hops);
  for (int i = 0; i < hops; i++) p.push_back((uint8_t)(0xA0 + i));
  p.push_back(0x11);   // channel hash
  uint8_t enc[220];
  int e = mesh::Utils::encryptThenMAC(secret, enc, plain, n);
  p.insert(p.end(), enc, enc + e);
  return p;
}

static std::string shown(const Result& r, Kind k) {
  char out[400];
  showText(r, k, out, sizeof(out));
  return out;
}

TEST(DamagedText, PiecesOfText) {
  EXPECT_TRUE(isTextPiece((const uint8_t*)"hello there, you", 16));
  const uint8_t pad[16] = { 'h', 'i', 0 };
  EXPECT_TRUE(isTextPiece(pad, 16));
  const uint8_t badpad[16] = { 'h', 'i', 0, 'x' };
  EXPECT_FALSE(isTextPiece(badpad, 16));
  // an emoji cut at both ends of the piece
  const uint8_t cut[16] = { 0x9F, 0x98, 0x80, ' ', 'o', 'k', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 0xF0, 0x9F };
  EXPECT_TRUE(isTextPiece(cut, 16));
  const uint8_t ctl[16] = { 'a', 0x07, 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o' };
  EXPECT_FALSE(isTextPiece(ctl, 16));
}

TEST(DamagedText, NoiseRarelyPasses) {
  std::mt19937 rng(7);
  int pass = 0, first = 0;
  const int N = 2000000;
  uint8_t p[16];
  for (int i = 0; i < N; i++) {
    for (auto& b : p) b = (uint8_t)rng();
    pass += isTextPiece(p, 16);
    first += isFirstPiece(p, KIND_CHANNEL, NOW);
  }
  EXPECT_LT(pass, 60);    // about 1 in 87,000
  EXPECT_EQ(first, 0);
}

TEST(DamagedDecode, IntactPacketReadsWhole) {
  uint8_t s[32]; secretFor(1, s);
  auto p = channelPacket(s, "Alice: the quick brown fox jumps over the lazy dog", NOW - 5);
  Layout l = parseHeader(p.data(), (int)p.size());
  ASSERT_TRUE(l.ok);
  EXPECT_EQ(TYPE_GRP_TXT, l.type);
  Result r;
  int n = decode(s, p.data(), (int)p.size(), KIND_CHANNEL, l.payload_off + 3, NOW, r);
  EXPECT_EQ(4, r.n);
  EXPECT_EQ(4, n);
  EXPECT_TRUE(r.first);
  EXPECT_EQ(NOW - 5, timestampOf(r));
  EXPECT_EQ("Alice: the quick brown fox jumps over the lazy dog", shown(r, KIND_CHANNEL));
}

TEST(DamagedDecode, BadPieceIsMarkedAndTheRestReads) {
  uint8_t s[32]; secretFor(2, s);
  auto p = channelPacket(s, "Bob: alpha bravo charlie delta echo foxtrot golf hotel", NOW);
  int ct = (int)p.size() - 4 * 16;
  p[ct + 16 + 3] ^= 0x40;            // a bad byte in the second piece
  Result r;
  int n = decode(s, p.data(), (int)p.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_EQ(3, n);
  EXPECT_EQ(0x0D, r.good);
  std::string t = shown(r, KIND_CHANNEL);
  EXPECT_EQ(0u, t.find("Bob: alpha "));
  EXPECT_NE(std::string::npos, t.find("\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92"));
  EXPECT_NE(std::string::npos, t.find("golf hotel"));
}

TEST(DamagedDecode, BadHeaderStillFindsTheMessage) {
  uint8_t s[32]; secretFor(3, s);
  auto p = channelPacket(s, "Carol: header bytes got hit but the text did not", NOW, 3);
  p[1] = 0x3F;                       // path length garbled
  Layout l = parseHeader(p.data(), (int)p.size());
  EXPECT_FALSE(l.ok);
  Result r;
  decode(s, p.data(), (int)p.size(), KIND_CHANNEL, -1, NOW, r);
  EXPECT_TRUE(r.first);
  EXPECT_EQ("Carol: header bytes got hit but the text did not", shown(r, KIND_CHANNEL));
}

TEST(DamagedDecode, WrongKeyReadsNothing) {
  uint8_t s[32], other[32]; secretFor(4, s); secretFor(5, other);
  auto p = channelPacket(s, "Dave: you can't read this with another key at all", NOW);
  Result r;
  int n = decode(other, p.data(), (int)p.size(), KIND_CHANNEL, -1, NOW, r);
  EXPECT_FALSE(r.first);
  EXPECT_LT(n, 2);
}

TEST(DamagedRepair, OneBitIsFixedByTheMac) {
  uint8_t s[32]; secretFor(6, s);
  auto p = channelPacket(s, "Erin: one flipped bit gets found again", NOW);
  auto orig = p;
  int ct = (int)p.size() - 3 * 16;
  p[ct + 20] ^= 0x08;
  Result r;
  decode(s, p.data(), (int)p.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_EQ(0x05, r.good);
  EXPECT_TRUE(repair(s, p.data(), (int)p.size(), r, KIND_CHANNEL));
  EXPECT_EQ(orig, p);
  EXPECT_EQ(0x07, r.good);
  EXPECT_EQ("Erin: one flipped bit gets found again", shown(r, KIND_CHANNEL));
}

TEST(DamagedRepair, BadMacAloneIsFixed) {
  uint8_t s[32]; secretFor(7, s);
  auto p = channelPacket(s, "Frank: the MAC took the hit", NOW);
  auto orig = p;
  int ct = (int)p.size() - 2 * 16;
  p[ct - 1] ^= 0x80;
  Result r;
  decode(s, p.data(), (int)p.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_TRUE(repair(s, p.data(), (int)p.size(), r, KIND_CHANNEL));
  EXPECT_EQ(orig, p);
}

TEST(DamagedRepair, TwoBadBytesAreNotGuessed) {
  uint8_t s[32]; secretFor(8, s);
  auto p = channelPacket(s, "Grace: too much damage to repair here", NOW);
  int ct = (int)p.size() - 3 * 16;
  p[ct + 17] ^= 0x11;
  Result r;
  decode(s, p.data(), (int)p.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_FALSE(repair(s, p.data(), (int)p.size(), r, KIND_CHANNEL));
  EXPECT_EQ(0x05, r.good);
}

TEST(DamagedShow, CutCharactersAreDropped) {
  uint8_t s[32]; secretFor(9, s);
  // "Hal: " + 9 x 'a' fills piece 0 after the timestamp and flags (5 + 11 = 16); then an emoji split
  // across pieces 1 and 2
  std::string text = "Hal: aaaaaa";
  text += "bbbbbbbbbbbbbb\xF0\x9F";   // piece 1: 14 + the first 2 bytes of 😀
  text += "\x98\x80 end of the message";
  auto p = channelPacket(s, text.c_str(), NOW);
  auto q = p;
  int ct = (int)p.size() - 4 * 16;
  p[ct + 16] ^= 1;                      // lose piece 1: the emoji's tail in piece 2 must go
  Result r;
  decode(s, p.data(), (int)p.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_EQ(0x0D, r.good);
  EXPECT_EQ("Hal: aaaaaa\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92 end of the message", shown(r, KIND_CHANNEL));
  q[ct + 32] ^= 1;                      // lose piece 2: the emoji's start in piece 1 must go
  decode(s, q.data(), (int)q.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_EQ(0x0B, r.good);
  EXPECT_EQ("Hal: aaaaaabbbbbbbbbbbbbb\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92ssage", shown(r, KIND_CHANNEL));
}

TEST(DamagedMatch, DamagedCopyMatchesTheIntactOne) {
  uint8_t s[32]; secretFor(10, s);
  auto p = channelPacket(s, "Ivan: heard twice, once damaged and once whole", NOW, 1);
  auto q = channelPacket(s, "Ivan: heard twice, once damaged and once whole", NOW, 1);
  ASSERT_EQ(p, q);
  q[2] = 0x55;   // another repeater: different path byte
  Fingerprint pr;
  fingerprint(q.data(), (int)q.size(), pr);
  int ct = (int)p.size() - 3 * 16;
  p[ct + 40] ^= 0x20;
  Result r;
  decode(s, p.data(), (int)p.size(), KIND_CHANNEL, ct, NOW, r);
  EXPECT_TRUE(sameMessage(pr, p.data(), (int)p.size(), r));
  auto other = channelPacket(s, "Ivan: something else that day, the same length!", NOW + 9, 1);
  fingerprint(other.data(), (int)other.size(), pr);
  EXPECT_FALSE(sameMessage(pr, p.data(), (int)p.size(), r));
}

TEST(DamagedDecode, NoiseWithManyKeysIsNotTakenForAMessage) {
  std::mt19937 rng(11);
  uint8_t keys[20][32];
  for (int k = 0; k < 20; k++) secretFor((uint8_t)(100 + k), keys[k]);
  int accepted = 0;
  for (int i = 0; i < 3000; i++) {
    uint8_t raw[120];
    for (auto& b : raw) b = (uint8_t)rng();
    for (int k = 0; k < 20; k++) {
      Result r;
      int n = decode(keys[k], raw, sizeof(raw), KIND_CHANNEL, -1, NOW, r);
      if (r.first || n >= 2) accepted++;
    }
  }
  EXPECT_EQ(0, accepted);
}

// Two copies through different repeaters (different paths), each with its own damage
// n_ct: how many pieces the message has (the header may be garbled)
static Copy readCopy(const uint8_t* s, std::vector<uint8_t> p, std::vector<int> bad_pieces, int n_ct, int hdr_hint = 1) {
  int len = (int)p.size();
  Layout l = parseHeader(p.data(), len);
  int hint = l.ok && hdr_hint ? l.payload_off + 3 : -1;
  for (int b : bad_pieces) p[len - (n_ct - b) * 16 + 5] ^= 0x21;
  Result r;
  decode(s, p.data(), len, KIND_CHANNEL, hint, NOW, r);
  Copy c;
  takeCopy(p.data(), r, false, c);
  return c;
}

TEST(DamagedMerge, CopiesFillEachOthersGaps) {
  uint8_t s[32]; secretFor(12, s);
  auto p = channelPacket(s, "Bench: twice 4 delta bravo hotel hotel delta echo", NOW, 0);
  auto q = channelPacket(s, "Bench: twice 4 delta bravo hotel hotel delta echo", NOW, 1);
  Copy a = readCopy(s, p, { 2 }, 4);
  Copy b = readCopy(s, q, { 0, 2 }, 4);
  EXPECT_EQ(4, a.r.n);
  EXPECT_EQ(4, b.r.n);
  EXPECT_TRUE(merge(a, b, s));
  EXPECT_EQ(0x0B, a.r.good);            // piece 2 lost in both
  EXPECT_FALSE(a.fixed);
  Copy c = readCopy(s, q, { 1 }, 4);
  EXPECT_TRUE(merge(a, c, s));
  EXPECT_EQ(0x0F, a.r.good);
  EXPECT_TRUE(a.fixed);                 // whole, and the MAC matches
  EXPECT_EQ("Bench: twice 4 delta bravo hotel hotel delta echo", shown(a.r, KIND_CHANNEL));
}

TEST(DamagedMerge, NoSharedPieceButSameMacJoins) {
  uint8_t s[32]; secretFor(13, s);
  auto p = channelPacket(s, "Bench: complementary damage, two copies", NOW, 0);
  auto q = channelPacket(s, "Bench: complementary damage, two copies", NOW, 2);
  Copy a = readCopy(s, p, { 1 }, 3);    // pieces 0 and 2 read
  Copy b = readCopy(s, q, { 0, 2 }, 3);    // piece 1 read
  EXPECT_TRUE(merge(a, b, s));
  EXPECT_EQ(0x07, a.r.good);
  EXPECT_TRUE(a.fixed);
}

TEST(DamagedMerge, StartLostInOneCopyStillLinesUp) {
  uint8_t s[32]; secretFor(14, s);
  auto p = channelPacket(s, "Bench: the header of one copy got hit, alpha bravo", NOW, 0);
  auto q = channelPacket(s, "Bench: the header of one copy got hit, alpha bravo", NOW, 3);
  q[1] = 0x3F;                          // path length garbled: no hint, and its piece 0 is lost too
  Copy a = readCopy(s, p, { 2 }, 4);
  Copy b = readCopy(s, q, { 0 }, 4, 0);
  EXPECT_LT(b.r.n, a.r.n);              // b starts at its first readable piece
  EXPECT_EQ("header of one copy got hit, alpha bravo", shown(b.r, KIND_CHANNEL));
  EXPECT_TRUE(merge(b, a, s));          // either way round
  EXPECT_EQ(a.r.n, b.r.n);
  EXPECT_TRUE(b.r.first);
  EXPECT_TRUE(b.fixed);
  EXPECT_EQ("Bench: the header of one copy got hit, alpha bravo", shown(b.r, KIND_CHANNEL));
}

TEST(DamagedMerge, DifferentMessagesDontJoin) {
  uint8_t s[32]; secretFor(15, s);
  auto p = channelPacket(s, "Bench: first message here, lol", NOW, 0);
  auto q = channelPacket(s, "Bench: other message there, lol", NOW + 3, 0);
  Copy a = readCopy(s, p, {}, 3);
  Copy b = readCopy(s, q, {}, 3);
  EXPECT_FALSE(merge(a, b, s));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
