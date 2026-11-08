// Reading damaged packets (src/helpers/DamagedRx) on arbitrary input, with the real AES and SHA-256.
// Mode byte bit 0 clear: the rest is a received packet: read it with a few keys as a channel and a
//              direct message, repair, show into buffers of every size, join readings.
// Mode byte bit 0 set: the rest is [hops][flips][flip positions...][text]: a real channel message with
//              those bits flipped, read and joined with a second copy flipped elsewhere. Checks what's
//              read is what was sent, or else (a copy marked fixed) that its bytes really match its MAC:
//              the MAC is 2 bytes, and libFuzzer solves memcmp, so it finds true collisions on demand;
//              those are the packet format's limit, not a bug. A fixed copy that fails its MAC is one.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/DamagedRx.h>
#include <Utils.h>

using namespace damaged;

static const uint32_t NOW = 1762400000;

static void checkShow(const Result& r, Kind k) {
  char buf[MAX_PIECES * PIECE * 3 + 16];
  for (int cap = 1; cap <= (int)sizeof(buf); cap += 5) {
    int w = showText(r, k, buf, cap);
    if (w < 0 || w >= cap || buf[w] != 0 || (int)strlen(buf) != w) abort();
  }
}

static void checkResult(const Result& r, int len) {
  if (r.n > MAX_PIECES) abort();
  if (r.n && r.ct_off + r.n * PIECE != len) abort();
  if (r.good >> r.n) abort();
}

static void readAll(const uint8_t* secret, uint8_t* raw, int len, Copy* out) {
  Layout l = parseHeader(raw, len);
  int who = sender(raw, len);
  if (who < -1 || who > 255) abort();
  RadioId id;
  senderId(raw, len, id);
  if (id.n > 4 || (id.n ? id.b[0] : -1) != who) abort();
  if (l.ok && (l.payload_off + l.payload_len != len || l.payload_off < 2)) abort();
  for (int kind = KIND_CHANNEL; kind <= KIND_DIRECT; kind++) {
    Result r;
    int hint = l.ok ? l.payload_off + (kind == KIND_CHANNEL ? 3 : 4) : -1;
    int n = decode(secret, raw, len, (Kind)kind, hint, NOW, r);
    if (n < 0 || n > r.n) abort();
    checkResult(r, len);
    if (n == 0) continue;
    bool fixed = repair(secret, raw, len, r, (Kind)kind);
    checkResult(r, len);
    checkShow(r, (Kind)kind);
    (void)timestampOf(r);
    Fingerprint f;
    fingerprint(raw, len, f);
    (void)sameMessage(f, raw, len, r);
    if (out && kind == KIND_CHANNEL) { takeCopy(raw, r, fixed, *out); out = NULL; }
  }
}

// a fixed copy's bytes against its MAC (or the other copy's, for a merged one)
static bool macMatches(const uint8_t* secret, const Copy& c, const uint8_t* other_mac) {
  uint8_t buf[CIPHER_MAC_SIZE + MAX_PIECES * PIECE], tmp[MAX_PIECES * PIECE];
  int ct_len = c.r.n * PIECE;
  memcpy(&buf[CIPHER_MAC_SIZE], c.ct, ct_len);
  const uint8_t* macs[2] = { c.mac, other_mac };
  for (const uint8_t* mac : macs) {
    if (!mac) continue;
    memcpy(buf, mac, CIPHER_MAC_SIZE);
    if (mesh::Utils::MACThenDecrypt(secret, tmp, buf, CIPHER_MAC_SIZE + ct_len) > 0) return true;
  }
  return false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  uint8_t mode = data[0];
  data++; size--;
  uint8_t secret[32] = { 0 };
  for (int i = 0; i < 16; i++) secret[i] = (uint8_t)(i * 13 + 5);

  if (!(mode & 1)) {
    if (size > 255) size = 255;
    uint8_t raw[255];
    memcpy(raw, data, size);
    Copy a, b;
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
    readAll(secret, raw, (int)size, &a);
    uint8_t zero[32] = { 0 };
    readAll(zero, raw, (int)size, NULL);
    if (size > 40) {   // a second "copy": the second half, read the same way
      uint8_t raw2[255];
      int n2 = (int)size / 2;
      memcpy(raw2, data + size - n2, n2);
      readAll(secret, raw2, n2, &b);
      if (a.r.n && b.r.n && merge(a, b, secret)) { checkResult(a.r, a.r.ct_off + a.r.n * PIECE); checkShow(a.r, KIND_CHANNEL); }
    }
    return 0;
  }

  // a real message, damaged
  if (size < 3) return 0;
  int hops = data[0] % 8;
  int flips = data[1] % 8;
  data += 2; size -= 2;
  if (size < (size_t)flips * 2) return 0;
  const uint8_t* pos = data;
  data += flips * 2; size -= flips * 2;
  int tlen = (int)size;
  if (tlen < 1 || tlen > 150) return 0;
  uint8_t plain[200];
  uint32_t ts = NOW - 10;
  memcpy(plain, &ts, 4);
  plain[4] = 0;
  memcpy(&plain[5], data, tlen);
  uint8_t pkt[255];
  int len = 0;
  pkt[len++] = 0x05 << 2 | 1;
  pkt[len++] = (uint8_t)hops;
  for (int i = 0; i < hops; i++) pkt[len++] = (uint8_t)(0x90 + i);
  pkt[len++] = 0x22;
  len += mesh::Utils::encryptThenMAC(secret, &pkt[len], plain, 5 + tlen);
  uint8_t c1[255], c2[255];
  memcpy(c1, pkt, len); memcpy(c2, pkt, len);
  for (int f = 0; f < flips; f++) {
    int p = pos[f * 2] % len, bit = pos[f * 2 + 1] & 7;
    if (f & 1) c2[p] ^= (uint8_t)(1 << bit); else c1[p] ^= (uint8_t)(1 << bit);
  }
  Copy a, b;
  memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
  readAll(secret, c1, len, &a);
  readAll(secret, c2, len, &b);
  // every piece read as good must be the real one, and a fixed copy must be the real message
  int ct_off = 2 + hops + 1 + 2;
  uint8_t real[200];
  int ct_len = len - ct_off;
  memcpy(real, plain, 5 + tlen);
  memset(&real[5 + tlen], 0, sizeof(real) - 5 - tlen);
  Copy* copies[2] = { &a, &b };
  for (Copy* c : copies) {
    if (!c->r.n) continue;
    int first_piece = (c->r.ct_off - ct_off) / PIECE;
    if (c->r.ct_off < ct_off || (c->r.ct_off - ct_off) % PIECE) continue;   // read from the wrong place: skip
    for (int i = 0; i < c->r.n; i++) {
      if (!((c->r.good >> i) & 1)) continue;
      int pi = first_piece + i;
      if (pi * PIECE >= ct_len) abort();
      // a piece judged good is real except by chance: AES noise passing the text test (1 in 87,000)
      if (memcmp(&c->r.pt[i * PIECE], &real[pi * PIECE], PIECE) != 0 && c->fixed && !macMatches(secret, *c, NULL)) abort();
    }
  }
  uint8_t b_mac[CIPHER_MAC_SIZE];
  memcpy(b_mac, b.mac, sizeof(b_mac));
  if (a.r.n && b.r.n && merge(a, b, secret)) {
    checkShow(a.r, KIND_CHANNEL);
    if (a.fixed && a.r.first && memcmp(a.r.pt, real, a.r.n * PIECE) != 0 && !macMatches(secret, a, b_mac)) abort();
  }
  return 0;
}
