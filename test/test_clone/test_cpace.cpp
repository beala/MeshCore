// CPace (src/helpers/CPace) against the vectors of draft-irtf-cfrg-cpace-21, appendix B.1
// (CPACE-X25519-SHA512), and X25519 against RFC 7748 section 5.2.
#include <gtest/gtest.h>
#include <helpers/CPace.h>
#include <string>
#include <vector>
#include <string.h>

static std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> v;
  for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
    unsigned int b;
    sscanf(&s[i], "%2x", &b);
    v.push_back((uint8_t)b);
  }
  return v;
}

static std::string tohex(const uint8_t* b, size_t n) {
  std::string s;
  char t[3];
  for (size_t i = 0; i < n; i++) { snprintf(t, sizeof(t), "%02x", b[i]); s += t; }
  return s;
}

TEST(X25519, Rfc7748Vectors) {
  auto k = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  auto u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  uint8_t out[32];
  ASSERT_TRUE(cpace::x25519(out, k.data(), u.data()));
  EXPECT_EQ(tohex(out, 32), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  auto k2 = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
  auto u2 = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");   // top bit set: ignored
  ASSERT_TRUE(cpace::x25519(out, k2.data(), u2.data()));
  EXPECT_EQ(tohex(out, 32), "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

static const char* PRS = "Password";
static const uint8_t CI[] = "\x0b" "A_initiator" "\x0b" "B_responder";

TEST(CPace, Generator) {
  auto sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");
  uint8_t g[32];
  cpace::generator(g, (const uint8_t*)PRS, strlen(PRS), CI, sizeof(CI) - 1, sid.data(), sid.size());
  EXPECT_EQ(tohex(g, 32), "d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f");
}

TEST(CPace, Elligator2) {
  auto r = hex("03998087bdb1a2617bbe25ef5a7c18cd4f84f902328701790958755ee4aed153");
  uint8_t g[32];
  cpace::elligator2(g, r.data());
  EXPECT_EQ(tohex(g, 32), "d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f");
}

TEST(CPace, ExchangeAndIsk) {
  auto sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");
  auto g = hex("d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f");
  auto ya = hex("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080");
  auto yb = hex("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a");
  uint8_t Ya[32], Yb[32];
  cpace::share(Ya, ya.data(), g.data());
  cpace::share(Yb, yb.data(), g.data());
  EXPECT_EQ(tohex(Ya, 32), "1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32");
  EXPECT_EQ(tohex(Yb, 32), "248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623");
  uint8_t K[32];
  ASSERT_TRUE(cpace::x25519(K, ya.data(), Yb));
  EXPECT_EQ(tohex(K, 32), "5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b");

  const uint8_t ADa[] = { 'A', 'D', 'a' }, ADb[] = { 'A', 'D', 'b' };
  uint8_t isk_a[64], isk_b[64];
  ASSERT_TRUE(cpace::isk(isk_a, ya.data(), Yb, sid.data(), sid.size(), Ya, ADa, 3, Yb, ADb, 3));
  ASSERT_TRUE(cpace::isk(isk_b, yb.data(), Ya, sid.data(), sid.size(), Ya, ADa, 3, Yb, ADb, 3));
  const char* want = "6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4d5e53bb2"
                     "aa82c300bea7b65d2b671da71922ddf6472301b79bc270adfa8bf413285f2263";
  EXPECT_EQ(tohex(isk_a, 64), want);
  EXPECT_EQ(tohex(isk_b, 64), want);

  // key confirmation: the two tags differ, and each side computes the other's
  uint8_t ta[64], tb[64], ta2[64];
  cpace::confirmTag(ta, isk_a, sid.data(), sid.size(), Ya, ADa, 3);
  cpace::confirmTag(tb, isk_b, sid.data(), sid.size(), Yb, ADb, 3);
  cpace::confirmTag(ta2, isk_b, sid.data(), sid.size(), Ya, ADa, 3);
  EXPECT_TRUE(cpace::equal(ta, ta2, 64));
  EXPECT_FALSE(cpace::equal(ta, tb, 64));
}

TEST(CPace, WrongPasswordDisagrees) {
  auto sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");
  auto ya = hex("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080");
  auto yb = hex("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a");
  uint8_t ga[32], gb[32], Ya[32], Yb[32], ia[64], ib[64];
  cpace::generator(ga, (const uint8_t*)"123456", 6, CI, sizeof(CI) - 1, sid.data(), sid.size());
  cpace::generator(gb, (const uint8_t*)"123457", 6, CI, sizeof(CI) - 1, sid.data(), sid.size());
  cpace::share(Ya, ya.data(), ga);
  cpace::share(Yb, yb.data(), gb);
  ASSERT_TRUE(cpace::isk(ia, ya.data(), Yb, sid.data(), sid.size(), Ya, NULL, 0, Yb, NULL, 0));
  ASSERT_TRUE(cpace::isk(ib, yb.data(), Ya, sid.data(), sid.size(), Ya, NULL, 0, Yb, NULL, 0));
  EXPECT_FALSE(cpace::equal(ia, ib, 64));
}

TEST(CPace, LowOrderPointsAbort) {
  // B.1.10: these must give the neutral element (abort); the others must not
  auto s = hex("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff");
  const char* abort_pts[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  };
  uint8_t q[32];
  for (const char* p : abort_pts) {
    auto u = hex(p);
    EXPECT_FALSE(cpace::x25519(q, s.data(), u.data())) << p;
  }
  struct { const char* u; const char* q; } ok[] = {
    { "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806" },
    { "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38" },
    { "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456" },
    { "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a" },
    { "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175" },
  };
  for (auto& t : ok) {
    auto u = hex(t.u);
    ASSERT_TRUE(cpace::x25519(q, s.data(), u.data())) << t.u;
    EXPECT_EQ(tohex(q, 32), t.q);
  }
}
