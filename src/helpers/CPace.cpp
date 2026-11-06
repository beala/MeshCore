#include "CPace.h"
#include <SHA512.h>
#include <string.h>

extern "C" {
#include <fe.h>   // GF(2^255-19) from lib/ed25519 (ref10)
}

namespace cpace {

static const uint8_t DSI[] = { 'C', 'P', 'a', 'c', 'e', '2', '5', '5' };
static const uint8_t DSI_ISK[] = { 'C', 'P', 'a', 'c', 'e', '2', '5', '5', '_', 'I', 'S', 'K' };
static const uint8_t MAC_LABEL[] = { 'C', 'P', 'a', 'c', 'e', 'M', 'a', 'c' };
static const size_t S_IN_BYTES = 128;   // SHA-512 input block

bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d == 0;
}

// prepend_len: LEB128 of the length, then the bytes
static size_t leb128(uint8_t* out, size_t len) {
  size_t n = 0;
  do {
    uint8_t b = len & 0x7f;
    len >>= 7;
    out[n++] = len ? (uint8_t)(b | 0x80) : b;
  } while (len);
  return n;
}

static void hashLv(SHA512& h, const uint8_t* b, size_t len) {
  uint8_t pre[10];
  h.update(pre, leb128(pre, len));
  if (len) h.update(b, len);
}

static bool isZero(const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= b[i];
  return d == 0;
}

bool x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]) {
  uint8_t e[32];
  memcpy(e, scalar, 32);
  e[0] &= 248;   // decodeScalar25519
  e[31] &= 127;
  e[31] |= 64;

  fe x1, x2, z2, x3, z3, tmp0, tmp1;
  fe_frombytes(x1, u);   // decodeUCoordinate: the top bit is ignored
  fe_1(x2);
  fe_0(z2);
  fe_copy(x3, x1);
  fe_1(z3);
  unsigned int swap = 0;
  for (int pos = 254; pos >= 0; --pos) {   // the RFC 7748 Montgomery ladder (ref10 form)
    unsigned int b = (e[pos / 8] >> (pos & 7)) & 1;
    swap ^= b;
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    swap = b;
    fe_sub(tmp0, x3, z3);
    fe_sub(tmp1, x2, z2);
    fe_add(x2, x2, z2);
    fe_add(z2, x3, z3);
    fe_mul(z3, tmp0, x2);
    fe_mul(z2, z2, tmp1);
    fe_sq(tmp0, tmp1);
    fe_sq(tmp1, x2);
    fe_add(x3, z3, z2);
    fe_sub(z2, z3, z2);
    fe_mul(x2, tmp1, tmp0);
    fe_sub(tmp1, tmp1, tmp0);
    fe_sq(z2, z2);
    fe_mul121666(z3, tmp1);
    fe_sq(x3, x3);
    fe_add(tmp0, tmp0, z3);
    fe_mul(z3, x1, z2);
    fe_mul(z2, tmp1, tmp0);
  }
  fe_cswap(x2, x3, swap);
  fe_cswap(z2, z3, swap);
  fe_invert(z2, z2);
  fe_mul(x2, x2, z2);
  fe_tobytes(out, x2);
  memset(e, 0, sizeof(e));
  return !isZero(out, 32);
}

// 1 if x is a square or zero (x^((p-1)/2) is 1 or 0), else 0. (p-1)/2 = 4 * (2^252 - 3) + 2.
static unsigned int isSquare(const fe x) {
  fe t, x2;
  fe_pow22523(t, x);
  fe_sq(t, t);
  fe_sq(t, t);
  fe_sq(x2, x);
  fe_mul(t, t, x2);
  uint8_t b[32];
  fe_tobytes(b, t);
  static const uint8_t one[32] = { 1 };
  return (unsigned int)(equal(b, one, 32) | isZero(b, 32));
}

void elligator2(uint8_t out[32], const uint8_t r[32]) {
  static const uint8_t A_BYTES[32] = { 0x06, 0x6d, 0x07 };   // 486662
  fe A, u, t, x1, x2, gx1, one;
  fe_frombytes(A, A_BYTES);
  fe_frombytes(u, r);
  fe_1(one);
  // x1 = -A / (1 + 2 u^2). The divisor is never zero: -1/2 is not a square mod p.
  fe_sq(t, u);
  fe_add(t, t, t);
  fe_add(t, t, one);
  fe_invert(t, t);
  fe_mul(x1, A, t);
  fe_neg(x1, x1);
  // gx1 = x1^3 + A x1^2 + x1 = x1 (x1 (x1 + A) + 1)
  fe_add(t, x1, A);
  fe_mul(t, t, x1);
  fe_add(t, t, one);
  fe_mul(gx1, t, x1);
  // x2 = -x1 - A; pick x1 if gx1 is square, without branching
  fe_add(x2, x1, A);
  fe_neg(x2, x2);
  fe_cmov(x2, x1, isSquare(gx1));
  fe_tobytes(out, x2);
}

void generator(uint8_t g[32], const uint8_t* prs, size_t prs_len, const uint8_t* ci, size_t ci_len,
               const uint8_t* sid, size_t sid_len) {
  uint8_t pre[10];
  size_t used = leb128(pre, prs_len) + prs_len + leb128(pre, sizeof(DSI)) + sizeof(DSI) + 1;   // len(prepend_len(PRS)) + len(prepend_len(DSI)) + 1
  size_t zpad = S_IN_BYTES > used ? S_IN_BYTES - used : 0;
  SHA512 h;
  h.reset();
  hashLv(h, DSI, sizeof(DSI));
  hashLv(h, prs, prs_len);
  h.update(pre, leb128(pre, zpad));
  static const uint8_t zeros[16] = { 0 };
  for (size_t left = zpad; left; ) {
    size_t n = left < sizeof(zeros) ? left : sizeof(zeros);
    h.update(zeros, n);
    left -= n;
  }
  hashLv(h, ci, ci_len);
  hashLv(h, sid, sid_len);
  uint8_t full[64];
  h.finalize(full, sizeof(full));
  full[31] &= 0x7f;   // decodeUCoordinate of the first 32 bytes, 255 bits
  elligator2(g, full);
  memset(full, 0, sizeof(full));
}

void share(uint8_t Y[32], const uint8_t y[32], const uint8_t g[32]) {
  x25519(Y, y, g);
}

bool isk(uint8_t out[64], const uint8_t y[32], const uint8_t peer_Y[32],
         const uint8_t* sid, size_t sid_len,
         const uint8_t Ya[32], const uint8_t* ADa, size_t ADa_len,
         const uint8_t Yb[32], const uint8_t* ADb, size_t ADb_len) {
  uint8_t K[32];
  if (!x25519(K, y, peer_Y)) return false;   // K = I: abort
  SHA512 h;
  h.reset();
  hashLv(h, DSI_ISK, sizeof(DSI_ISK));
  hashLv(h, sid, sid_len);
  hashLv(h, K, sizeof(K));
  hashLv(h, Ya, 32);       // transcript_ir = lv_cat(Ya, ADa) || lv_cat(Yb, ADb)
  hashLv(h, ADa, ADa_len);
  hashLv(h, Yb, 32);
  hashLv(h, ADb, ADb_len);
  h.finalize(out, 64);
  memset(K, 0, sizeof(K));
  return true;
}

void confirmTag(uint8_t out[64], const uint8_t isk_[64], const uint8_t* sid, size_t sid_len,
                const uint8_t Y[32], const uint8_t* AD, size_t AD_len) {
  uint8_t mac_key[64];
  SHA512 h;
  h.reset();
  h.update(MAC_LABEL, sizeof(MAC_LABEL));
  h.update(sid, sid_len);
  h.update(isk_, 64);
  h.finalize(mac_key, sizeof(mac_key));
  h.resetHMAC(mac_key, sizeof(mac_key));
  hashLv(h, Y, 32);
  hashLv(h, AD, AD_len);
  h.finalizeHMAC(mac_key, sizeof(mac_key), out, 64);
  memset(mac_key, 0, sizeof(mac_key));
}

}  // namespace cpace
