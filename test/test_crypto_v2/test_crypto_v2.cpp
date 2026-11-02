// Tests for AES-SIV (RFC 5297) and the MeshCore v2 envelope (docs/crypto_v2.md).
// Runs against the real rweather Crypto library: pio test -e native_crypto
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "AesSiv.h"
#include "CryptoV2.h"

using namespace mesh;

static std::vector<uint8_t> H(const char* hex) {
  std::vector<uint8_t> v;
  for (const char* p = hex; p[0] && p[1]; p += 2) {
    unsigned b; sscanf(p, "%2x", &b); v.push_back((uint8_t)b);
  }
  return v;
}

// ---- RFC 4493 AES-CMAC ----

TEST(AesCmac, Rfc4493Examples) {
  auto k = H("2b7e151628aed2a6abf7158809cf4f3c");
  uint8_t mac[16];
  AesSiv::cmac(k.data(), NULL, 0, mac);
  EXPECT_EQ(H("bb1d6929e95937287fa37d129b756746"), std::vector<uint8_t>(mac, mac + 16));
  auto m = H("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
  AesSiv::cmac(k.data(), m.data(), 16, mac);
  EXPECT_EQ(H("070a16b46b4d4144f79bdd9dd04a287c"), std::vector<uint8_t>(mac, mac + 16));
  AesSiv::cmac(k.data(), m.data(), 40, mac);
  EXPECT_EQ(H("dfa66747de9ae63030ca32611497c827"), std::vector<uint8_t>(mac, mac + 16));
}

// ---- RFC 5297 AES-SIV ----

TEST(AesSiv, Rfc5297A1Deterministic) {
  auto k = H("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  auto ad = H("101112131415161718191a1b1c1d1e1f2021222324252627");
  auto p = H("112233445566778899aabbccddee");
  auto expect = H("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
  const uint8_t* ads[] = { ad.data() };
  size_t adl[] = { ad.size() };
  uint8_t out[64], dec[64];
  ASSERT_EQ((int)expect.size(), AesSiv::seal(k.data(), ads, adl, 1, p.data(), p.size(), out));
  EXPECT_EQ(expect, std::vector<uint8_t>(out, out + expect.size()));
  ASSERT_EQ((int)p.size(), AesSiv::open(k.data(), ads, adl, 1, out, expect.size(), dec));
  EXPECT_EQ(p, std::vector<uint8_t>(dec, dec + p.size()));
}

TEST(AesSiv, Rfc5297A2NonceBased) {
  auto k = H("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
  auto ad1 = H("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
  auto ad2 = H("102030405060708090a0");
  auto nonce = H("09f911029d74e35bd84156c5635688c0");
  auto p = H("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");
  auto expect = H("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");
  const uint8_t* ads[] = { ad1.data(), ad2.data(), nonce.data() };
  size_t adl[] = { ad1.size(), ad2.size(), nonce.size() };
  uint8_t out[128];
  ASSERT_EQ((int)expect.size(), AesSiv::seal(k.data(), ads, adl, 3, p.data(), p.size(), out));
  EXPECT_EQ(expect, std::vector<uint8_t>(out, out + expect.size()));
}

TEST(AesSiv, RejectsAnyBitFlipAndWipesOutput) {
  auto k = H("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  uint8_t p[40], out[64], dec[64];
  for (int i = 0; i < 40; i++) p[i] = (uint8_t)i;
  int n = AesSiv::seal(k.data(), NULL, NULL, 0, p, sizeof(p), out);
  for (int bit = 0; bit < n * 8; bit++) {
    out[bit / 8] ^= (uint8_t)(1 << (bit % 8));
    memset(dec, 0xAA, sizeof(dec));
    EXPECT_LT(AesSiv::open(k.data(), NULL, NULL, 0, out, n, dec), 0) << "bit " << bit;
    for (int i = 0; i < 40; i++) ASSERT_EQ(0, dec[i]);
    out[bit / 8] ^= (uint8_t)(1 << (bit % 8));
  }
}

// ---- MeshCore v2 envelope: vectors produced by an independent Python implementation
//      (cryptography.AESSIV + hmac HKDF), see docs/crypto_v2.md ----

struct Vec { const char* secret; const char* ctx; const char* p; const char* env; };
static const char* DM_SECRET = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* CH_SECRET = "8b3387e9c5cdea6ac9e5edbaa115cd7200000000000000000000000000000000";
static const Vec VECS[] = {
  { DM_SECRET, "02abcd", "010203040068656c6c6f",
    "43d8ef705e43ef0a7701aad7e7ac509ef67110b835789d6d3561" },
  { DM_SECRET, "02abcd", "010203040030313233343536373839616263",   // L % 16 == 2: padded
    "7011ef3aea99ae36f9cf7e0eff9bdb0212ac7fe36294d60b98cd7cbefeb0d6f1057800" },
  { CH_SECRET, "0511", "0a0b0c0d00416c6963653a2068692074686572652065766572796f6e652c206c6f6e67206d7367",
    "6f4adb014482402dbb31b8e6412f6095b41370de30d0038453d4a4c21ae53682c54d0ff19ece929e79859ca3c0902de99c3c75c32362a2" },
};

TEST(CryptoV2, KeyDerivationAndPolicyId) {
  auto s = H(DM_SECRET);
  uint8_t key[32], id[8];
  CryptoV2::deriveKey(s.data(), key);
  EXPECT_EQ(H("dbb80697d72a9f61ae29ba20e4586bddc1a5e402188d26bcf3b703dcd4c75fd4"), std::vector<uint8_t>(key, key + 32));
  CryptoV2::policyId(s.data(), id);
  EXPECT_EQ(H("94378da118ec4565"), std::vector<uint8_t>(id, id + 8));
}

TEST(CryptoV2, MatchesReferenceVectors) {
  for (const Vec& v : VECS) {
    auto s = H(v.secret), c = H(v.ctx), p = H(v.p), e = H(v.env);
    uint8_t out[200], dec[200];
    int n = CryptoV2::seal(s.data(), out, p.data(), p.size(), c.data(), c.size());
    ASSERT_EQ((int)e.size(), n);
    EXPECT_EQ(e, std::vector<uint8_t>(out, out + n));
    ASSERT_EQ((int)p.size(), CryptoV2::open(s.data(), dec, e.data(), e.size(), c.data(), c.size()));
    EXPECT_EQ(p, std::vector<uint8_t>(dec, dec + p.size()));
  }
}

TEST(CryptoV2, NeverInLegacyLengthClassAndExactLength) {
  auto s = H(DM_SECRET);
  uint8_t ctx[3] = { 2, 1, 2 }, p[170], out[200], dec[200];
  for (int i = 0; i < (int)sizeof(p); i++) p[i] = (uint8_t)(i * 7);
  for (int L = 1; L <= 167; L++) {
    int n = CryptoV2::seal(s.data(), out, p, L, ctx, 3);
    EXPECT_FALSE(CryptoV2::isLegacyEnvelope(n)) << L;
    EXPECT_EQ(16 + L + (L % 16 == 2 ? 1 : 0), n) << L;
    ASSERT_EQ(L, CryptoV2::open(s.data(), dec, out, n, ctx, 3)) << L;   // exact length, no padding leaks out
    EXPECT_EQ(0, memcmp(dec, p, L)) << L;
  }
}

TEST(CryptoV2, BindsContextAndKey) {
  auto s = H(DM_SECRET), s2 = H(CH_SECRET);
  uint8_t ctx[3] = { 2, 0xAB, 0xCD }, p[20] = "hello there", out[64], dec[64];
  int n = CryptoV2::seal(s.data(), out, p, sizeof(p), ctx, 3);
  uint8_t other_type[3] = { 0, 0xAB, 0xCD }, swapped[3] = { 2, 0xCD, 0xAB };
  EXPECT_EQ(0, CryptoV2::open(s.data(), dec, out, n, other_type, 3));
  EXPECT_EQ(0, CryptoV2::open(s.data(), dec, out, n, swapped, 3));
  EXPECT_EQ(0, CryptoV2::open(s.data(), dec, out, n, ctx, 2));
  EXPECT_EQ(0, CryptoV2::open(s2.data(), dec, out, n, ctx, 3));
}

TEST(CryptoV2, PaddingByteIsNotMalleable) {
  auto s = H(DM_SECRET);
  auto e = H(VECS[1].env), c = H(VECS[1].ctx);
  uint8_t dec[64];
  e.back() = 0x01;   // padding must be exactly 0x00
  EXPECT_EQ(0, CryptoV2::open(s.data(), dec, e.data(), e.size(), c.data(), c.size()));
}

TEST(CryptoV2, LegacyLengthClass) {
  for (int blocks = 1; blocks <= 11; blocks++) EXPECT_TRUE(CryptoV2::isLegacyEnvelope(2 + 16 * blocks));
  EXPECT_FALSE(CryptoV2::isLegacyEnvelope(17));
  EXPECT_FALSE(CryptoV2::isLegacyEnvelope(35));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
