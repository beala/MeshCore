#include "Meters.h"
#include <string.h>

namespace meters {

static inline int chipAt(const uint8_t* c, int i) { return (c[i >> 3] >> (7 - (i & 7))) & 1; }

uint16_t crc16(const uint8_t* data, int len, uint16_t poly, uint16_t init) {
  uint16_t c = init;
  for (int i = 0; i < len; i++) {
    c ^= (uint16_t) data[i] << 8;
    for (int b = 0; b < 8; b++) c = (c & 0x8000) ? (uint16_t)((c << 1) ^ poly) : (uint16_t)(c << 1);
  }
  return c;
}

// Manchester, data 1 = chips 10: n bits from chip `at` into out (MSB first). False on a 00 or 11.
static bool unManchester(const uint8_t* chips, int at, int n, uint8_t* out) {
  memset(out, 0, (n + 7) / 8);
  for (int i = 0; i < n; i++) {
    int a = chipAt(chips, at + 2 * i), b = chipAt(chips, at + 2 * i + 1);
    if (a == b) return false;
    if (a) out[i >> 3] |= 0x80 >> (i & 7);
  }
  return true;
}

static const Air AIR[KINDS] = {
  { 0x5555, 16, { 0xA9, 0x66, 0x69, 0x65 }, 4, 21 },   // R900
  { 0x6955, 16, { 0x66, 0x5A, 0x55 }, 3, 19 },         // SCM
  { 0x966A, 16, { 0x99, 0x5A, 0x56, 0xA9 }, 4, 26 },   // SCM+
};

int channels(uint8_t kind) { return kind == KIND_R900 ? 78 : 51; }

// R900 channel numbers (910.3035 + 0.1305 * n MHz) in hop order, from an hour of RTL-SDR recordings
// at 910.1-919.7 MHz (2026-11-07): 6 meters, 49 places seen (place 8, channel 8, fills the gap in its
// run 6-10). From each meter's first frame it gives the channel of all 328 of its later ones.
static const int8_t R900_SEQ[R900_HOPS] = {
  17, 54, 39, 64, 12, 49, 22, 59,  8, 45,
  18, 55, 40, 65, 13, 50, 35, 60,  9, 46,
  19, 56, 41, 66, 14, 51, 36, 61, 10, 47,
  20, 57, 42, 67, 15, 52, 37, 62,  6, 43,
  16, 53, 38, 63, 11, 48, 21, 58,  7, 44,
};

int r900HopChannel(int pos) {
  pos %= R900_HOPS;
  if (pos < 0) pos += R900_HOPS;
  return R900_SEQ[pos];
}

int r900HopPos(int ch) {
  for (int i = 0; i < R900_HOPS; i++) if (R900_SEQ[i] == ch) return i;
  return -1;
}

float channelMHz(uint8_t kind, int i) {
  if (i < 0) i = 0;
  int n = channels(kind);
  if (i >= n) i = n - 1;
  return kind == KIND_R900 ? 910.3035f + 0.1305f * i : 910.0f + 0.2f * i;
}

uint32_t periodMs(uint8_t kind) { return kind == KIND_R900 ? 14000 : 15000; }

const Air& air(uint8_t kind) { return AIR[(kind >= 1 && kind <= KINDS ? kind : 1) - 1]; }

const char* kindName(uint8_t kind) {
  return kind == KIND_R900 ? "R900" : kind == KIND_SCM ? "SCM" : kind == KIND_SCMPLUS ? "SCM+" : "?";
}

bool read(uint8_t kind, const uint8_t* chips, int n_bytes, Reading* r) {
  switch (kind) {
    case KIND_R900: return readR900(chips, n_bytes, r);
    case KIND_SCM: return readScm(chips, n_bytes, r);
    case KIND_SCMPLUS: return readScmPlus(chips, n_bytes, r);
    default: return false;
  }
}

uint8_t ertUtility(uint8_t type) {
  switch (type & 0x0F) {
    case 4: case 5: case 7: case 8: return UTIL_ELECTRIC;
    case 0: case 1: case 2: case 9: case 12: return UTIL_GAS;
    case 3: case 11: case 13: return UTIL_WATER;
    default: return UTIL_UNKNOWN;
  }
}

const char* utilityName(uint8_t u) {
  switch (u) {
    case UTIL_WATER: return "water";
    case UTIL_GAS: return "gas";
    case UTIL_ELECTRIC: return "electric";
    default: return "meter";
  }
}

// R900: 42 groups of 4 chips, each one of six codes (a base-6 digit). Two digits make a number up
// to 35 that carries 5 bits (above 31: not a frame), 21 of them 105 bits: the first 104 are the
// message. There's no CRC; a stray frame passes all 42 code checks about once in 10^18.
bool readR900(const uint8_t* chips, int n_bytes, Reading* r) {
  if (n_bytes * 8 < 168) return false;
  static const int8_t digit[16] = { -1, -1, -1, 0, -1, 1, 2, -1, -1, 5, 4, -1, 3, -1, -1, -1 };
  uint8_t b[14] = {};
  int bit = 0;
  for (int g = 0; g < 21; g++) {
    int v = 0;
    for (int h = 0; h < 2; h++) {
      int code = 0;
      for (int k = 0; k < 4; k++) code = (code << 1) | chipAt(chips, g * 8 + h * 4 + k);
      if (digit[code] < 0) return false;
      v = v * 6 + digit[code];
    }
    if (v > 31) return false;
    for (int k = 4; k >= 0; k--, bit++) if ((v >> k) & 1) b[bit >> 3] |= 0x80 >> (bit & 7);
  }
  memset(r, 0, sizeof(*r));
  r->kind = KIND_R900;
  r->utility = UTIL_WATER;
  r->id = (uint32_t) b[0] << 24 | (uint32_t) b[1] << 16 | (uint32_t) b[2] << 8 | b[3];
  r->type = b[4] & 0x0F;
  r->no_use = (b[5] >> 2) & 7;
  r->backflow = b[5] & 3;
  r->total = (uint32_t)(b[9] >> 5) << 24 | (uint32_t) b[6] << 16 | (uint32_t) b[7] << 8 | b[8];
  r->leak_days = (b[9] >> 2) & 7;
  r->leak_now = b[9] & 3;
  return r->id != 0;
}

// SCM+: after 16 A3 1E: endpoint type, id (4), consumption (4), tamper (2), CRC-16/CCITT (init 0x0971)
// of 1E and the 11 bytes after it
bool readScmPlus(const uint8_t* chips, int n_bytes, Reading* r) {
  if (n_bytes * 8 < 208) return false;
  uint8_t b[14];
  b[0] = 0x1E;
  if (!unManchester(chips, 0, 104, &b[1])) return false;
  if (crc16(b, 12, 0x1021, 0x0971) != ((uint16_t) b[12] << 8 | b[13])) return false;
  memset(r, 0, sizeof(*r));
  r->kind = KIND_SCMPLUS;
  r->type = b[1];
  r->utility = ertUtility(b[1]);
  r->id = (uint32_t) b[2] << 24 | (uint32_t) b[3] << 16 | (uint32_t) b[4] << 8 | b[5];
  r->total = (uint32_t) b[6] << 24 | (uint32_t) b[7] << 16 | (uint32_t) b[8] << 8 | b[9];
  r->tamper = (uint16_t) b[10] << 8 | b[11];
  return r->id != 0;
}

// SCM: 96 bits in all, the first 21 the sync (1F2A60). The chips here start at its last bit (a 0),
// then the 75 others: CRC poly 0x6F63 over bytes 2-11 comes out 0.
bool readScm(const uint8_t* chips, int n_bytes, Reading* r) {
  if (n_bytes * 8 < 152) return false;
  uint8_t d[10];
  if (!unManchester(chips, 0, 76, d)) return false;
  if (d[0] & 0x80) return false;   // the sync's last bit
  uint8_t b[12] = {};
  for (int at = 0; at < 96; at++) {
    int i = at - 20;   // d's bit
    int bit = at < 20 ? (int)((0x1F2A60UL >> (20 - at)) & 1) : (d[i >> 3] >> (7 - (i & 7))) & 1;
    if (bit) b[at >> 3] |= 0x80 >> (at & 7);
  }
  if (crc16(&b[2], 10, 0x6F63, 0) != 0) return false;
  bool any = false;
  for (int i = 2; i < 10; i++) any |= b[i] != 0;
  if (!any) return false;
  memset(r, 0, sizeof(*r));
  r->kind = KIND_SCM;
  r->type = (b[3] >> 2) & 0x0F;
  r->utility = ertUtility(r->type);
  r->id = (uint32_t)(b[2] & 0x06) << 23 | (uint32_t) b[7] << 16 | (uint32_t) b[8] << 8 | b[9];
  r->total = (uint32_t) b[4] << 16 | (uint32_t) b[5] << 8 | b[6];
  r->tamper = (uint16_t)((b[3] >> 6) << 2 | (b[3] & 3));
  return r->id != 0;
}

}  // namespace meters
