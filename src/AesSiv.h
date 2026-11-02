#pragma once

#include <stdint.h>
#include <stddef.h>

namespace mesh {

/**
 * AES-SIV as specified in RFC 5297, with AES-128 (AEAD_AES_SIV_CMAC_256).
 *
 * The 32-byte key is K1 || K2: K1 keys S2V (AES-CMAC), K2 keys AES-CTR.
 * Sealed output is V || C, where V is the 16-byte synthetic IV / tag and C is
 * exactly as long as the plaintext.
 */
class AesSiv {
public:
  static const int KEY_SIZE = 32;
  static const int TAG_SIZE = 16;
  static const int MAX_AD = 4;

  /**
   * \param ad, ad_len  associated data components (each is one S2V input string), up to MAX_AD
   * \param out  receives V || C (TAG_SIZE + p_len bytes). May not overlap p.
   * \returns  bytes written, or -1 on bad arguments
   */
  static int seal(const uint8_t key[KEY_SIZE], const uint8_t* const ad[], const size_t ad_len[], int num_ad,
                  const uint8_t* p, size_t p_len, uint8_t* out);

  /**
   * Decrypts into 'out' and verifies the tag. On failure 'out' is wiped.
   * \param in  V || C. May not overlap out.
   * \returns  plaintext length, or -1 if the tag doesn't verify
   */
  static int open(const uint8_t key[KEY_SIZE], const uint8_t* const ad[], const size_t ad_len[], int num_ad,
                  const uint8_t* in, size_t in_len, uint8_t* out);

  /** S2V from RFC 5297 section 2.4 (exposed for test vectors). */
  static void s2v(const uint8_t k1[16], const uint8_t* const ad[], const size_t ad_len[], int num_ad,
                  const uint8_t* p, size_t p_len, uint8_t v[16]);

  /** AES-CMAC (RFC 4493) of a single string (exposed for test vectors). */
  static void cmac(const uint8_t key[16], const uint8_t* msg, size_t len, uint8_t mac[16]);

  /** Constant-time comparison. Returns true if equal. */
  static bool equalsCT(const uint8_t* a, const uint8_t* b, size_t len);
};

}
