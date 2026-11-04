#pragma once

#include <CryptoV2.h>
#include <string.h>

#ifndef MAX_CRYPTO_POLICIES
  #define MAX_CRYPTO_POLICIES  128
#endif

/**
 * Non-legacy encryption policies, keyed by CryptoV2::policyId() of the contact's shared
 * secret or the channel secret. Anything not in the table is CRYPTO_POLICY_LEGACY.
 */
class CryptoPolicyTable {
public:
  struct Entry {
    uint8_t id[8];
    uint8_t policy;
  };

private:
  Entry _entries[MAX_CRYPTO_POLICIES];
  int _num = 0;

  int find(const uint8_t id[8]) const {
    for (int i = 0; i < _num; i++) {
      if (memcmp(_entries[i].id, id, 8) == 0) return i;
    }
    return -1;
  }

public:
  uint8_t get(const uint8_t* secret) const {
    uint8_t id[8];
    mesh::CryptoV2::policyId(secret, id);
    int i = find(id);
    return i >= 0 ? _entries[i].policy : CRYPTO_POLICY_LEGACY;
  }

  /** \returns  false if the table is full */
  bool set(const uint8_t* secret, uint8_t policy) {
    uint8_t id[8];
    mesh::CryptoV2::policyId(secret, id);
    return setById(id, policy);
  }

  bool setById(const uint8_t id[8], uint8_t policy) {
    int i = find(id);
    if (policy == CRYPTO_POLICY_LEGACY) {   // legacy is the default, so just remove it
      if (i >= 0) _entries[i] = _entries[--_num];
      return true;
    }
    if (policy > CRYPTO_POLICY_V2_ONLY) return false;
    if (i < 0) {
      if (_num >= MAX_CRYPTO_POLICIES) return false;
      i = _num++;
      memcpy(_entries[i].id, id, 8);
    }
    _entries[i].policy = policy;
    return true;
  }

  void clear() { _num = 0; }
  int count() const { return _num; }
  const Entry& entry(int i) const { return _entries[i]; }

  static const char* name(uint8_t policy) {
    switch (policy) {
      case CRYPTO_POLICY_V2: return "v2";
      case CRYPTO_POLICY_V2_ONLY: return "v2only";
      default: return "legacy";
    }
  }
  /** \returns  policy, or -1 if not a valid name */
  static int parse(const char* s) {
    if (strcmp(s, "legacy") == 0) return CRYPTO_POLICY_LEGACY;
    if (strcmp(s, "v2") == 0) return CRYPTO_POLICY_V2;
    if (strcmp(s, "v2only") == 0) return CRYPTO_POLICY_V2_ONLY;
    return -1;
  }
};
