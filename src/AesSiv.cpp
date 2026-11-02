#include "AesSiv.h"
#include <AES.h>
#include <string.h>

namespace mesh {

// doubling in GF(2^128), as used by CMAC subkeys and S2V
static void dbl(uint8_t b[16]) {
  uint8_t carry = b[0] >> 7;
  for (int i = 0; i < 15; i++) {
    b[i] = (uint8_t)((b[i] << 1) | (b[i + 1] >> 7));
  }
  b[15] = (uint8_t)((b[15] << 1) ^ (carry ? 0x87 : 0x00));
}

// Streaming AES-CMAC (RFC 4493)
class Cmac {
  AES128 aes;
  uint8_t k1[16], k2[16];
  uint8_t x[16];     // running chain value
  uint8_t buf[16];   // pending (not yet processed) input
  uint8_t pos;
public:
  explicit Cmac(const uint8_t key[16]) {
    aes.setKey(key, 16);
    uint8_t zero[16];
    memset(zero, 0, 16);
    aes.encryptBlock(k1, zero);
    dbl(k1);
    memcpy(k2, k1, 16);
    dbl(k2);
    reset();
  }
  ~Cmac() {
    memset(k1, 0, 16); memset(k2, 0, 16); memset(x, 0, 16); memset(buf, 0, 16);
  }
  void reset() {
    memset(x, 0, 16);
    pos = 0;
  }
  void update(const uint8_t* data, size_t len) {
    while (len > 0) {
      if (pos == 16) {   // only process a full block once we know more data follows it
        for (int i = 0; i < 16; i++) x[i] ^= buf[i];
        aes.encryptBlock(x, x);
        pos = 0;
      }
      size_t n = 16 - pos;
      if (n > len) n = len;
      memcpy(&buf[pos], data, n);
      pos += n; data += n; len -= n;
    }
  }
  void finalize(uint8_t mac[16]) {
    if (pos == 16) {
      for (int i = 0; i < 16; i++) x[i] ^= buf[i] ^ k1[i];
    } else {
      buf[pos] = 0x80;
      for (int i = pos + 1; i < 16; i++) buf[i] = 0;
      for (int i = 0; i < 16; i++) x[i] ^= buf[i] ^ k2[i];
    }
    aes.encryptBlock(mac, x);
    reset();
  }
};

void AesSiv::cmac(const uint8_t key[16], const uint8_t* msg, size_t len, uint8_t mac[16]) {
  Cmac c(key);
  c.update(msg, len);
  c.finalize(mac);
}

void AesSiv::s2v(const uint8_t k1[16], const uint8_t* const ad[], const size_t ad_len[], int num_ad,
                 const uint8_t* p, size_t p_len, uint8_t v[16]) {
  Cmac c(k1);
  uint8_t d[16], t[16];

  memset(t, 0, 16);
  c.update(t, 16);
  c.finalize(d);                    // D = CMAC(K, <zero>)

  for (int i = 0; i < num_ad; i++) {
    dbl(d);
    c.update(ad[i], ad_len[i]);
    c.finalize(t);
    for (int j = 0; j < 16; j++) d[j] ^= t[j];   // D = dbl(D) xor CMAC(K, Si)
  }

  if (p_len >= 16) {                // T = Sn xorend D
    c.update(p, p_len - 16);
    for (int j = 0; j < 16; j++) t[j] = p[p_len - 16 + j] ^ d[j];
    c.update(t, 16);
  } else {                          // T = dbl(D) xor pad(Sn)
    dbl(d);
    memset(t, 0, 16);
    memcpy(t, p, p_len);
    t[p_len] = 0x80;
    for (int j = 0; j < 16; j++) t[j] ^= d[j];
    c.update(t, 16);
  }
  c.finalize(v);

  memset(d, 0, 16);
  memset(t, 0, 16);
}

// AES-CTR with the counter block Q = V with bits 31 and 63 cleared (RFC 5297 section 2.5).
// The counter is incremented as a 128-bit big-endian integer.
static void sivCtr(const uint8_t k2[16], const uint8_t v[16], uint8_t* out, const uint8_t* in, size_t len) {
  AES128 aes;
  aes.setKey(k2, 16);

  uint8_t q[16], ks[16];
  memcpy(q, v, 16);
  q[8] &= 0x7F;
  q[12] &= 0x7F;

  while (len > 0) {
    aes.encryptBlock(ks, q);
    size_t n = len < 16 ? len : 16;
    for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
    out += n; in += n; len -= n;

    for (int i = 15; i >= 0; i--) {   // increment
      if (++q[i] != 0) break;
    }
  }
  memset(ks, 0, 16);
}

int AesSiv::seal(const uint8_t key[KEY_SIZE], const uint8_t* const ad[], const size_t ad_len[], int num_ad,
                 const uint8_t* p, size_t p_len, uint8_t* out) {
  if (num_ad < 0 || num_ad > MAX_AD) return -1;

  uint8_t v[16];
  s2v(key, ad, ad_len, num_ad, p, p_len, v);
  memcpy(out, v, 16);
  sivCtr(&key[16], v, &out[16], p, p_len);
  memset(v, 0, 16);
  return TAG_SIZE + (int)p_len;
}

int AesSiv::open(const uint8_t key[KEY_SIZE], const uint8_t* const ad[], const size_t ad_len[], int num_ad,
                 const uint8_t* in, size_t in_len, uint8_t* out) {
  if (num_ad < 0 || num_ad > MAX_AD) return -1;
  if (in_len < TAG_SIZE) return -1;

  size_t p_len = in_len - TAG_SIZE;
  sivCtr(&key[16], in, out, &in[16], p_len);

  uint8_t t[16];
  s2v(key, ad, ad_len, num_ad, out, p_len, t);
  bool ok = equalsCT(t, in, 16);
  memset(t, 0, 16);

  if (!ok) {
    memset(out, 0, p_len);   // never release unverified plaintext
    return -1;
  }
  return (int)p_len;
}

bool AesSiv::equalsCT(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

}
