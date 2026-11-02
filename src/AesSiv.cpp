#include "AesSiv.h"
#include <AES.h>
#include <string.h>

#ifdef USE_CC310_HW_CRYPTO
  #include <Adafruit_nRFCrypto.h>
  #include "nrf_cc310/include/ssi_aes.h"
#endif

namespace mesh {

// ---- AES-128 block encryption ----
// nRF52: the CryptoCell CC310 engine (no lookup tables, so no secret-dependent memory access, and faster).
// ESP32: rweather's AES128 already uses the chip's AES hardware. Elsewhere: rweather's software AES.
// The CC310 path is checked against the RFC 5297 A.1 vector on first use; if that fails, or a CC310
// call fails, software AES is used instead, so a hardware problem can't produce wrong output.

#ifdef USE_CC310_HW_CRYPTO
static int8_t g_hw_aes = -1;   // -1 untested, 0 use software, 1 use CC310
static bool g_hw_fell_back = false;   // a CC310 call failed and software AES was used instead
static void runHwSelfTest();
#endif

class AesBlock {
  uint8_t key[16];
  AES128 sw;
  bool sw_keyed = false;
#ifdef USE_CC310_HW_CRYPTO
  SaSiAesUserContext_t ctx;
  bool use_hw = false;
#endif

  void swEncrypt(uint8_t* out, const uint8_t* in, size_t n_blocks) {
    if (!sw_keyed) { sw.setKey(key, 16); sw_keyed = true; }
    for (size_t i = 0; i < n_blocks; i++) sw.encryptBlock(&out[16 * i], &in[16 * i]);
  }

public:
  explicit AesBlock(const uint8_t k[16]) {
    memcpy(key, k, 16);
#ifdef USE_CC310_HW_CRYPTO
    if (g_hw_aes < 0) runHwSelfTest();
    if (g_hw_aes == 1) {
      SaSiAesUserKeyData_t keyData = { key, 16 };
      use_hw = SaSi_AesInit(&ctx, SASI_AES_ENCRYPT, SASI_AES_MODE_ECB, SASI_AES_PADDING_NONE) == SASI_OK
        && SaSi_AesSetKey(&ctx, SASI_AES_USER_KEY, &keyData, sizeof(keyData)) == SASI_OK;
      if (!use_hw) g_hw_fell_back = true;
    }
#endif
    if (!hw()) { sw.setKey(key, 16); sw_keyed = true; }
  }
  ~AesBlock() {
#ifdef USE_CC310_HW_CRYPTO
    if (use_hw) {
      size_t dummy = 0;
      SaSi_AesFinish(&ctx, 0, NULL, 0, NULL, &dummy);
      SaSi_AesFree(&ctx);
    }
#endif
    if (sw_keyed) sw.clear();
    memset(key, 0, sizeof(key));
  }
  bool hw() const {
#ifdef USE_CC310_HW_CRYPTO
    return use_hw;
#else
    return false;
#endif
  }

  /** ECB-encrypt n_blocks consecutive 16-byte blocks. out and in may be the same buffer. */
  void encrypt(uint8_t* out, const uint8_t* in, size_t n_blocks) {
#ifdef USE_CC310_HW_CRYPTO
    if (use_hw) {
      uint8_t buf[16 * 12];   // DMA from a RAM copy (in may be const data in flash)
      while (n_blocks > 0) {
        size_t n = n_blocks < 12 ? n_blocks : 12;
        memcpy(buf, in, 16 * n);
        if (SaSi_AesBlock(&ctx, buf, 16 * n, buf) == SASI_OK) {
          memcpy(out, buf, 16 * n);
        } else {
          g_hw_fell_back = true;
          swEncrypt(out, in, n);
        }
        out += 16 * n; in += 16 * n; n_blocks -= n;
      }
      memset(buf, 0, sizeof(buf));
      return;
    }
#endif
    swEncrypt(out, in, n_blocks);
  }
};

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
  AesBlock aes;
  uint8_t k1[16], k2[16];
  uint8_t x[16];     // running chain value
  uint8_t buf[16];   // pending (not yet processed) input
  uint8_t pos;
public:
  explicit Cmac(const uint8_t key[16]) : aes(key) {
    uint8_t zero[16];
    memset(zero, 0, 16);
    aes.encrypt(k1, zero, 1);
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
        aes.encrypt(x, x, 1);
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
    aes.encrypt(mac, x, 1);
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
  AesBlock aes(k2);

  uint8_t q[16];
  memcpy(q, v, 16);
  q[8] &= 0x7F;
  q[12] &= 0x7F;

  uint8_t ks[16 * 12];   // keystream for up to 12 blocks per pass (a whole MeshCore packet)
  while (len > 0) {
    size_t n_blocks = (len + 15) / 16;
    if (n_blocks > 12) n_blocks = 12;
    for (size_t b = 0; b < n_blocks; b++) {
      memcpy(&ks[16 * b], q, 16);
      for (int i = 15; i >= 0; i--) {   // increment as a 128-bit big-endian integer
        if (++q[i] != 0) break;
      }
    }
    aes.encrypt(ks, ks, n_blocks);
    size_t n = len < 16 * n_blocks ? len : 16 * n_blocks;
    for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
    out += n; in += n; len -= n;
  }
  memset(ks, 0, sizeof(ks));
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
  // volatile: keeps the compiler from turning this into an early-exit compare
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

bool AesSiv::usingHardwareAes() {
#ifdef USE_CC310_HW_CRYPTO
  if (g_hw_aes < 0) runHwSelfTest();
  return g_hw_aes == 1;
#elif defined(ESP32)
  return true;   // rweather's AES128 uses the ESP32 AES peripheral
#else
  return false;
#endif
}

#ifdef USE_CC310_HW_CRYPTO
// RFC 5297 A.1
static void runHwSelfTest() {
  static const uint8_t key[32] = {
    0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff };
  static const uint8_t ad[24] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27 };
  static const uint8_t pt[14] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee };
  static const uint8_t expect[30] = {
    0x85,0x63,0x2d,0x07,0xc6,0xe8,0xf3,0x7f,0x95,0x0a,0xcd,0x32,0x0a,0x2e,0xcc,0x93,
    0x40,0xc0,0x2b,0x96,0x90,0xc4,0xdc,0x04,0xda,0xef,0x7f,0x6a,0xfe,0x5c };
  g_hw_aes = 1;   // try the hardware path
  g_hw_fell_back = false;
  const uint8_t* ads[1] = { ad };
  size_t adl[1] = { sizeof(ad) };
  uint8_t out[30];
  int n = AesSiv::seal(key, ads, adl, 1, pt, sizeof(pt), out);
  // pass only if the output is right AND the hardware actually produced it
  g_hw_aes = (n == 30 && memcmp(out, expect, 30) == 0 && !g_hw_fell_back) ? 1 : 0;
}
#endif

}
