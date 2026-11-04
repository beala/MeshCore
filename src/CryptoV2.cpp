#include "CryptoV2.h"
#include "AesSiv.h"
#include "MeshCore.h"
#include <SHA256.h>
#include <string.h>

namespace mesh {

static const uint8_t AD_PROTOCOL[] = "MeshCore AEAD v2";        // 16 bytes, NUL not included
static const uint8_t KDF_INFO[]    = "MeshCore AES-SIV v2 key";  // NUL not included
static const uint8_t ID_LABEL[]    = "MeshCore policy id";       // NUL not included

void CryptoV2::deriveKey(const uint8_t* secret, uint8_t key[32]) {
  // HKDF-SHA256 (RFC 5869), salt = 32 zero bytes, IKM = secret, L = 32 (a single expand block)
  uint8_t salt[32], prk[32];
  memset(salt, 0, sizeof(salt));
  SHA256 sha;
  sha.resetHMAC(salt, sizeof(salt));
  sha.update(secret, PUB_KEY_SIZE);
  sha.finalizeHMAC(salt, sizeof(salt), prk, sizeof(prk));

  uint8_t one = 0x01;
  sha.resetHMAC(prk, sizeof(prk));
  sha.update(KDF_INFO, sizeof(KDF_INFO) - 1);
  sha.update(&one, 1);
  sha.finalizeHMAC(prk, sizeof(prk), key, 32);
  memset(prk, 0, sizeof(prk));
}

void CryptoV2::policyId(const uint8_t* secret, uint8_t id[8]) {
  SHA256 sha;
  sha.update(ID_LABEL, sizeof(ID_LABEL) - 1);
  sha.update(secret, PUB_KEY_SIZE);
  sha.finalize(id, 8);
}

int CryptoV2::seal(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int src_len, const uint8_t* ctx, int ctx_len) {
  if (src_len <= 0 || ctx_len < 0 || ctx_len > CTX_MAX) return 0;

  uint8_t key[32];
  deriveKey(secret, key);
  const uint8_t* ad[2] = { AD_PROTOCOL, ctx };
  size_t ad_len[2] = { sizeof(AD_PROTOCOL) - 1, (size_t)ctx_len };
  int len = AesSiv::seal(key, ad, ad_len, 2, src, src_len, dest);
  memset(key, 0, sizeof(key));
  if (len <= 0) return 0;

  if (isLegacyEnvelope(len)) dest[len++] = 0;   // keep out of the v1 length class
  return len;
}

int CryptoV2::open(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int src_len, const uint8_t* ctx, int ctx_len) {
  if (src_len <= AesSiv::TAG_SIZE || isLegacyEnvelope(src_len)) return 0;
  if (ctx_len < 0 || ctx_len > CTX_MAX || src_len > MAX_PACKET_PAYLOAD) return 0;

  uint8_t key[32];
  deriveKey(secret, key);
  const uint8_t* ad[2] = { AD_PROTOCOL, ctx };
  size_t ad_len[2] = { sizeof(AD_PROTOCOL) - 1, (size_t)ctx_len };

  uint8_t tmp[MAX_PACKET_PAYLOAD];
  int len = AesSiv::open(key, ad, ad_len, 2, src, src_len, tmp);
  if (len < 0 && src_len % 16 == 3 && src[src_len - 1] == 0) {
    // could be a padded envelope: the plaintext was (L % 16 == 2), so one 0x00 byte was appended
    len = AesSiv::open(key, ad, ad_len, 2, src, src_len - 1, tmp);
  }
  memset(key, 0, sizeof(key));

  if (len <= 0) return 0;
  memcpy(dest, tmp, len);
  memset(tmp, 0, len);
  return len;
}

}
