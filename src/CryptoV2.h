#pragma once

#include <stdint.h>
#include <stddef.h>

namespace mesh {

// Per-contact / per-channel encryption policy
#define CRYPTO_POLICY_LEGACY    0   // send v1 (AES-ECB + 2-byte MAC), accept v1 and v2
#define CRYPTO_POLICY_V2        1   // send v2 (AES-SIV), accept v1 and v2
#define CRYPTO_POLICY_V2_ONLY   2   // send v2, accept v2 only

/**
 * The v2 encrypted envelope (see docs/crypto_v2.md for the full spec).
 *
 *   envelope = V(16) || C(L) [ || 0x00 ]
 *
 * V and C are RFC 5297 AES-SIV (AES-128) over the plaintext, with associated data
 * [ "MeshCore AEAD v2", ctx ]. The key is HKDF-SHA256 of the existing 32-byte
 * shared/channel secret. A single 0x00 byte is appended only when the envelope would
 * otherwise fall in the legacy length class (len % 16 == 2), so v1 and v2 are told
 * apart by length alone, and v1 firmware always rejects v2 envelopes.
 */
class CryptoV2 {
public:
  static const int OVERHEAD_MAX = 17;   // tag + possible padding byte
  static const int CTX_MAX = 40;

  /** true if an envelope of this length is a legacy (v1) one: 2-byte MAC + whole AES blocks */
  static bool isLegacyEnvelope(int env_len) { return env_len % 16 == 2; }

  /** \returns  envelope length written to dest (at most src_len + OVERHEAD_MAX), or 0 on error */
  static int seal(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int src_len, const uint8_t* ctx, int ctx_len);

  /** \returns  plaintext length (> 0) on success, or 0 if the envelope doesn't verify. dest is untouched on failure. */
  static int open(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int src_len, const uint8_t* ctx, int ctx_len);

  /** 8-byte identifier of a secret, used as a key for stored policies (doesn't reveal the secret) */
  static void policyId(const uint8_t* secret, uint8_t id[8]);

  /** the 32-byte AES-SIV key derived from a 32-byte MeshCore secret (exposed for test vectors) */
  static void deriveKey(const uint8_t* secret, uint8_t key[32]);
};

}
