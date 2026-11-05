// Meshtastic decoding (src/helpers/meshtastic) against packets made by another implementation:
// lr2021-re-public's tools/meshtastic_node.py, whose packets the Meshtastic protobufs parse.
// vectors.h was generated with its packet() and nodeinfo() functions.

#include <gtest/gtest.h>
#include <string>
#include <string.h>
#include "helpers/meshtastic/MeshtasticRx.h"
#include "vectors.h"

using namespace meshtastic;

namespace {

std::vector<uint8_t> bytes(const char* p, int len) { return std::vector<uint8_t>(p, p + len); }

Receiver longFast() {
  Receiver r;
  uint8_t key = 1;   // "AQ==": the default key
  EXPECT_TRUE(r.setChannel("LongFast", &key, 1));
  return r;
}

}  // namespace

TEST(Meshtastic, ChannelHashAndFrequency) {
  uint8_t key[MAX_KEY];
  uint8_t idx = 1;
  ASSERT_EQ(expandKey(&idx, 1, key), 16);
  EXPECT_EQ(channelHash("LongFast", key, 16), 0x08);
  EXPECT_EQ(channelHash("MediumFast", key, 16), 31);
  EXPECT_NEAR(usFrequency("LongFast", 250), 906.875, 0.0005);
  EXPECT_NEAR(usFrequency("MediumFast", 250), 913.125, 0.0005);
}

TEST(Meshtastic, Keys) {
  uint8_t psk[MAX_KEY], key[MAX_KEY];
  EXPECT_EQ(parseKeyBase64("AQ==", psk), 1);
  EXPECT_EQ(psk[0], 1);
  EXPECT_EQ(parseKeyBase64("1PG7OiApB1nwvP+rz05pAQ==", psk), 16);
  EXPECT_EQ(psk[0], 0xd4);
  EXPECT_EQ(psk[15], 0x01);
  EXPECT_EQ(parseKeyBase64(std::string(43, 'A').append("=").c_str(), psk), 32);
  EXPECT_EQ(parseKeyBase64("AQI=", psk), -1);            // 2 bytes
  EXPECT_EQ(parseKeyBase64("A*==", psk), -1);
  EXPECT_EQ(parseKeyBase64("AQ==x", psk), -1);
  EXPECT_EQ(parseKeyBase64(std::string(200, 'A').c_str(), psk), -1);   // too long: no overrun

  uint8_t idx = 0;
  EXPECT_EQ(expandKey(&idx, 1, key), 0);                 // encryption off
  idx = 2;
  ASSERT_EQ(expandKey(&idx, 1, key), 16);
  EXPECT_EQ(key[15], 0x02);                              // default key, last byte + 1
  idx = 11;
  EXPECT_EQ(expandKey(&idx, 1, key), -1);
  EXPECT_EQ(expandKey(psk, 5, key), -1);
}

TEST(Meshtastic, Text) {
  Receiver r = longFast();
  auto p = bytes(PKT_TEXT, PKT_TEXT_LEN);
  Message m;
  ASSERT_EQ(r.handle(p.data(), p.size(), &m), TEXT);
  EXPECT_EQ(std::string(m.text, m.text_len), "hello from meshtastic");
  EXPECT_STREQ(m.sender, "!a1b2c3d4");
  EXPECT_EQ(m.hdr.from, 0xa1b2c3d4u);
  EXPECT_EQ(m.hdr.id, 0x01020304u);
  EXPECT_EQ(m.hdr.hopStart(), 3);
  EXPECT_EQ(m.hdr.hopLimit(), 3);
}

TEST(Meshtastic, RelayedCopyIsARepeat) {
  Receiver r = longFast();
  auto a = bytes(PKT_TEXT, PKT_TEXT_LEN), b = bytes(PKT_RELAYED, PKT_RELAYED_LEN);
  Message m;
  EXPECT_EQ(r.handle(a.data(), a.size(), &m), TEXT);
  EXPECT_EQ(r.handle(b.data(), b.size(), &m), DUPLICATE);
  EXPECT_EQ(r.stats().duplicate, 1u);
}

TEST(Meshtastic, NodeInfoNamesTheSender) {
  Receiver r = longFast();
  auto ni = bytes(PKT_NODEINFO, PKT_NODEINFO_LEN), t = bytes(PKT_LONG, PKT_LONG_LEN);
  Message m;
  EXPECT_EQ(r.handle(ni.data(), ni.size(), &m), NODEINFO);
  ASSERT_EQ(r.handle(t.data(), t.size(), &m), TEXT);
  EXPECT_STREQ(m.sender, "Bench Tastic");
  EXPECT_EQ(m.text_len, 225);
}

TEST(Meshtastic, NotShown) {
  Receiver r = longFast();
  auto dm = bytes(PKT_DM, PKT_DM_LEN), other = bytes(PKT_MEDIUMFAST, PKT_MEDIUMFAST_LEN),
       pos = bytes(PKT_POSITION, PKT_POSITION_LEN);
  Message m;
  EXPECT_EQ(r.handle(dm.data(), dm.size(), &m), NOT_FOR_US);
  EXPECT_EQ(r.handle(other.data(), other.size(), &m), OTHER_CHANNEL);
  EXPECT_EQ(r.handle(pos.data(), pos.size(), &m), NONE);
}

TEST(Meshtastic, WrongKeyOrDamage) {
  Receiver r;
  uint8_t key = 2;   // another default-derived key: same name, different hash
  ASSERT_TRUE(r.setChannel("LongFast", &key, 1));
  auto p = bytes(PKT_TEXT, PKT_TEXT_LEN);
  Message m;
  EXPECT_EQ(r.handle(p.data(), p.size(), &m), OTHER_CHANNEL);

  Receiver ok = longFast();
  for (size_t cut = 0; cut < p.size(); cut++) {   // every truncation: no crash, no over-read
    std::vector<uint8_t> t(p.begin(), p.begin() + cut);
    ok.reset();
    uint8_t k = 1;
    ok.setChannel("LongFast", &k, 1);
    Kind kind = ok.handle(t.empty() ? nullptr : t.data(), t.size(), &m);
    if (kind == TEXT) EXPECT_LE(m.text_len, (int)cut);
  }
  std::vector<uint8_t> big(400, 0xAA);
  EXPECT_EQ(ok.handle(big.data(), big.size(), &m), UNDECODABLE);
}

TEST(Meshtastic, Protobuf) {
  Data d;
  const uint8_t data[] = { 0x08, 0x01, 0x12, 0x02, 'h', 'i', 0x18, 0x01 };
  ASSERT_TRUE(parseData(data, sizeof(data), &d));
  EXPECT_EQ(d.portnum, 1u);
  EXPECT_EQ(d.payload_len, 2);
  const uint8_t bad_len[] = { 0x08, 0x01, 0x12, 0x7F, 'h' };
  EXPECT_FALSE(parseData(bad_len, sizeof(bad_len), &d));
  const uint8_t huge_varint[] = { 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
  EXPECT_FALSE(parseData(huge_varint, sizeof(huge_varint), &d));
  const uint8_t group[] = { 0x0B };
  EXPECT_FALSE(parseData(group, sizeof(group), &d));

  User u;
  std::string longname(100, 'N');
  std::vector<uint8_t> user = { 0x12, (uint8_t)longname.size() };
  user.insert(user.end(), longname.begin(), longname.end());
  user.insert(user.end(), { 0x1A, 0x03, 'B', '\n', 'T' });
  ASSERT_TRUE(parseUser(user.data(), user.size(), &u));
  EXPECT_EQ(strlen(u.long_name), sizeof(u.long_name) - 1);
  EXPECT_STREQ(u.short_name, "B T");   // control characters become spaces

  // a name cut in the middle of a 4-byte character keeps whole characters only
  std::vector<uint8_t> emoji = { 0x12, 40 };
  for (int i = 0; i < 10; i++) emoji.insert(emoji.end(), { 0xF0, 0x9F, 0x93, 0xBB });
  ASSERT_TRUE(parseUser(emoji.data(), emoji.size(), &u));
  EXPECT_EQ(strlen(u.long_name), 36u);
}

TEST(Meshtastic, NextPart) {
  std::string s = "word ";
  std::string text;
  for (int i = 0; i < 60; i++) text += s;
  int left = text.size(), total = 0;
  const char* p = text.c_str();
  while (left > 0) {
    int cut = nextPart(p, left, 140);
    ASSERT_GE(cut, 1);
    ASSERT_LE(cut, 140);
    p += cut; left -= cut; total += cut;
  }
  EXPECT_EQ(total, (int)text.size());

  std::string emoji;
  for (int i = 0; i < 60; i++) emoji += "\xF0\x9F\x93\xBB";
  int cut = nextPart(emoji.c_str(), emoji.size(), 141);
  EXPECT_EQ(cut % 4, 0);   // never inside a character
  EXPECT_EQ(nextPart("abc", 3, 140), 3);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
