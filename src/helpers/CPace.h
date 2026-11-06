#pragma once
// CPace (draft-irtf-cfrg-cpace-21), ciphersuite CPACE-X25519-SHA512, initiator-responder mode: a
// password-authenticated key exchange. Two parties who share a short code (PRS) get a strong shared
// key (ISK). Someone listening learns nothing they could test guesses of the code against offline;
// an active attacker gets one guess per run. Tested against the draft's vectors (test/test_clone).
//
//   g  = calculate_generator(PRS, CI, sid)      (Elligator2 of a SHA-512 hash, RFC 9380)
//   Ya = X25519(ya, g), Yb = X25519(yb, g)      (RFC 7748)
//   K  = X25519(ya, Yb) = X25519(yb, Ya)        (abort if all zero: low-order point)
//   ISK = SHA-512(lv_cat("CPace255_ISK", sid, K) || lv_cat(Ya, ADa) || lv_cat(Yb, ADb))
//
// Key confirmation (draft section 10.4): mac_key = SHA-512("CPaceMac" || sid || ISK), tags
// Ta = HMAC-SHA-512(mac_key, lv_cat(Ya, ADa)) and Tb = HMAC-SHA-512(mac_key, lv_cat(Yb, ADb)).

#include <stdint.h>
#include <stddef.h>

namespace cpace {

static const int POINT_LEN = 32;
static const int SCALAR_LEN = 32;
static const int ISK_LEN = 64;
static const int MAC_LEN = 64;

// RFC 7748 X25519 (the scalar is clamped as decodeScalar25519). \returns false if the result is
// the all-zero point, which CPace must abort on.
bool x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]);

// RFC 9380 map_to_curve_elligator2 for curve25519 (Z = 2): the u-coordinate only
void elligator2(uint8_t out[32], const uint8_t r[32]);

// the generator for a code, channel identifier and session id
void generator(uint8_t g[32], const uint8_t* prs, size_t prs_len, const uint8_t* ci, size_t ci_len,
               const uint8_t* sid, size_t sid_len);

// Y = X25519(y, g). y: 32 random bytes.
void share(uint8_t Y[32], const uint8_t y[32], const uint8_t g[32]);

// ISK for the initiator-responder transcript. \returns false if K is the neutral element (abort).
bool isk(uint8_t out[64], const uint8_t y[32], const uint8_t peer_Y[32],
         const uint8_t* sid, size_t sid_len,
         const uint8_t Ya[32], const uint8_t* ADa, size_t ADa_len,
         const uint8_t Yb[32], const uint8_t* ADb, size_t ADb_len);

// the key-confirmation tag for one side: HMAC-SHA-512(mac_key, lv_cat(Y, AD))
void confirmTag(uint8_t out[64], const uint8_t isk[64], const uint8_t* sid, size_t sid_len,
                const uint8_t Y[32], const uint8_t* AD, size_t AD_len);

// constant-time compare of n bytes
bool equal(const uint8_t* a, const uint8_t* b, size_t n);

}  // namespace cpace
