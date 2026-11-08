#include "Tpms.h"
#include <string.h>

namespace tpms {

// ---- bit rows, as rtl_433's bitbuffer (MSB first) ----

static const int ROW_BYTES = 32;   // 256 bits: the longest radio packet (21 bytes) and its sync word
struct Row {
  uint8_t b[ROW_BYTES];
  int n;
};

static inline int bitAt(const Row& r, int i) { return (r.b[i >> 3] >> (7 - (i & 7))) & 1; }
static inline void addBit(Row& r, int v) {
  if (r.n >= ROW_BYTES * 8) return;
  if (v) r.b[r.n >> 3] |= 0x80 >> (r.n & 7);
  else r.b[r.n >> 3] &= ~(0x80 >> (r.n & 7));
  r.n++;
}

// first position at or after start where the plen-bit pattern matches, or r.n
static int search(const Row& r, int start, const uint8_t* pat, int plen) {
  for (int p = start; p + plen <= r.n; p++) {
    bool ok = true;
    for (int i = 0; i < plen && ok; i++) ok = bitAt(r, p + i) == ((pat[i >> 3] >> (7 - (i & 7))) & 1);
    if (ok) return p;
  }
  return r.n;
}

// IEEE 802.3 Manchester (01 = 1, 10 = 0) from start, at most max bits, stopping at a 00 or 11.
// Returns the position reached (as rtl_433's bitbuffer_manchester_decode).
static int manchester(const Row& in, int start, Row& out, int max) {
  memset(&out, 0, sizeof(out));
  int len = in.n;
  if (max && len > start + max * 2) len = start + max * 2;
  int i = start;
  while (i < len) {
    int b1 = i < in.n ? bitAt(in, i) : 0; i++;
    int b2 = i < in.n ? bitAt(in, i) : 0; i++;
    if (b1 == b2) break;
    addBit(out, b2);
  }
  return i;
}

// Differential Manchester, as rtl_433's bitbuffer_differential_manchester_decode
static int diffManchester(const Row& in, int start, Row& out, int max) {
  memset(&out, 0, sizeof(out));
  int len = in.n;
  if (max && len > start + max * 2) len = start + max * 2;
  int i = start;
  int b1, b2 = 0;
  auto at = [&](int k) { return k < in.n ? bitAt(in, k) : 0; };
  while (i < len) {   // the first long pulse sets the clock; skip a short one to get in step
    b1 = at(i++);
    b2 = at(i++);
    int b3 = at(i);
    if (b1 != b2) {
      if (b2 != b3) {
        addBit(out, 0);
      } else {
        b2 = b1;
        i -= 1;
        break;
      }
    } else {
      b2 = 1 - b1;
      i -= 2;
      break;
    }
  }
  while (i < len) {
    b1 = at(i++);
    if (b1 == b2) break;   // clock missing
    b2 = at(i++);
    addBit(out, b1 == b2 ? 1 : 0);
  }
  return i;
}

static void extract(const Row& r, int start, uint8_t* out, int nbits) {
  memset(out, 0, (nbits + 7) / 8);
  for (int i = 0; i < nbits && start + i < r.n; i++) {
    if (bitAt(r, start + i)) out[i >> 3] |= 0x80 >> (i & 7);
  }
}

uint8_t crc8(const uint8_t* b, int n, uint8_t poly, uint8_t init) {
  uint8_t c = init;
  for (int i = 0; i < n; i++) {
    c ^= b[i];
    for (int k = 0; k < 8; k++) c = (c & 0x80) ? (uint8_t)((c << 1) ^ poly) : (uint8_t)(c << 1);
  }
  return c;
}

static int16_t psiTo(float psi) { return (int16_t)(psi * 68.9476f + (psi >= 0 ? 0.5f : -0.5f)); }   // tenths of a kPa
static int16_t kpaTo(float kpa) { return (int16_t)(kpa * 10.0f + (kpa >= 0 ? 0.5f : -0.5f)); }

static void start(Reading* r, uint8_t proto) {
  memset(r, 0, sizeof(*r));
  r->proto = proto;
  r->kpa10 = -1;
}

// ---- the decoders: rtl_433's tpms_*.c on a row ----

// Ford (tpms_ford.c): inverted, aa a9, 64 bits Manchester, a sum of 7 bytes
static bool ford(const Row& row, Reading* r) {
  static const uint8_t pat[2] = { 0xaa, 0xa9 };
  for (int pos = 0; (pos = search(row, pos, pat, 16)) + 144 <= row.n; pos += 15) {
    Row p;
    manchester(row, pos + 16, p, 160);
    if (p.n < 64) continue;
    const uint8_t* b = p.b;
    if (((b[0] + b[1] + b[2] + b[3] + b[4] + b[5] + b[6]) & 0xff) != b[7]) continue;
    start(r, P_FORD);
    r->id = (uint32_t) b[0] << 24 | (uint32_t) b[1] << 16 | (uint32_t) b[2] << 8 | b[3];
    r->kpa10 = psiTo((((b[6] & 0x20) << 3) | b[4]) * 0.25f);
    if (!(b[5] & 0x80)) { r->has_temp = true; r->temp_c = (int16_t)((b[5] & 0x7f) - 56); }
    r->moving = (b[6] & 0x4c) == 0x44;
    r->weak_check = true;
    return true;
  }
  return false;
}

// Jeep (tpms_jeep.c; the same frames as tpms_citroen.c): inverted, aa a9, 80 bits Manchester,
// XOR of bytes 1-9 is 0; pressure 2.728 kPa a step
static bool jeep(const Row& row, Reading* r) {
  static const uint8_t pat[2] = { 0xaa, 0xa9 };
  for (int pos = 0; (pos = search(row, pos, pat, 16)) + 178 <= row.n; pos += 2) {
    Row p;
    manchester(row, pos + 16, p, 88);
    if (p.n < 80) continue;
    const uint8_t* b = p.b;
    if (b[6] == 0 || b[7] == 0) continue;
    if ((b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[6] ^ b[7] ^ b[8] ^ b[9]) != 0) continue;
    start(r, P_JEEP);
    r->id = (uint32_t) b[1] << 24 | (uint32_t) b[2] << 16 | (uint32_t) b[3] << 8 | b[4];
    r->kpa10 = kpaTo(b[6] * 2.728f);
    r->has_temp = true;
    r->temp_c = (int16_t)(b[7] - 50);
    r->weak_check = true;
    return true;
  }
  return false;
}

// Hyundai/VDO (tpms_hyundai_vdo.c): aa aa aa a9, 80 bits Manchester, CRC-8 0x07 init 0xaa
static bool hyundai(const Row& row, Reading* r) {
  static const uint8_t pat[4] = { 0xaa, 0xaa, 0xaa, 0xa9 };
  for (int pos = 0; (pos = search(row, pos, pat, 32)) + 80 <= row.n; pos += 2) {
    Row p;
    manchester(row, pos + 32, p, 80);
    if (p.n < 80) continue;
    const uint8_t* b = p.b;
    if (crc8(b, 9, 0x07, 0xaa) != b[9]) continue;
    start(r, P_HYUNDAI);
    r->id = (uint32_t) b[1] << 24 | (uint32_t) b[2] << 16 | (uint32_t) b[3] << 8 | b[4];
    r->kpa10 = psiTo(b[6] / 5.0f);
    r->has_temp = true;
    r->temp_c = (int16_t)(b[7] - 50);
    return true;
  }
  return false;
}

// Toyota PMV-C210 (tpms_toyota.c): 0101 0101 0011 11, 72 bits differential Manchester, CRC-8 0x07
// init 0x80, the pressure twice (once inverted)
static bool toyota(const Row& row, Reading* r) {
  static const uint8_t pat[2] = { 0xa9, 0xe0 };
  for (int pos = 0; (pos = search(row, pos, pat, 12)) + 156 <= row.n; pos += 2) {
    Row p;
    int at = pos + 11;
    int end = diffManchester(row, at, p, 80);
    if (end - at < 144) continue;
    const uint8_t* b = p.b;
    if (crc8(b, 8, 0x07, 0x80) != b[8]) continue;
    unsigned p1 = (b[4] & 0x7f) << 1 | b[5] >> 7;
    unsigned temp = (b[5] & 0x7f) << 1 | b[6] >> 7;
    unsigned p2 = b[7] ^ 0xff;
    if (p1 != p2) continue;
    start(r, P_TOYOTA);
    r->id = (uint32_t) b[0] << 24 | (uint32_t) b[1] << 16 | (uint32_t) b[2] << 8 | b[3];
    r->kpa10 = psiTo(p1 * 0.25f - 7.0f);
    r->has_temp = true;
    r->temp_c = (int16_t)(temp - 40);
    return true;
  }
  return false;
}

// Toyota PMV-107J (tpms_pmv107j.c): 11111 10, 66 bits differential Manchester, CRC-8 0x13
static bool pmv107j(const Row& row, Reading* r) {
  static const uint8_t pat[1] = { 0xf8 };
  for (int pos = 0; (pos = search(row, pos, pat, 6)) + 67 * 2 <= row.n; pos += 2) {
    Row p;
    int at = pos + 6;
    int end = diffManchester(row, at, p, 70);
    if (end - at < 67 * 2) continue;
    uint8_t b[9];
    b[0] = p.b[0] >> 6;
    extract(p, 2, b + 1, 64);
    if (crc8(b, 8, 0x13, 0x00) != b[8]) continue;
    unsigned p1 = b[5], p2 = b[6] ^ 0xff;
    if (p1 != p2) continue;
    start(r, P_PMV107J);
    r->id = (uint32_t) b[0] << 26 | (uint32_t) b[1] << 18 | (uint32_t) b[2] << 10 | (uint32_t) b[3] << 2 | b[4] >> 6;
    r->battery_low = (b[4] & 0x20) != 0;
    r->kpa10 = kpaTo((p1 - 40.0f) * 2.48f);
    r->has_temp = true;
    r->temp_c = (int16_t)(b[7] - 40);
    return true;
  }
  return false;
}

// Kia (tpms_kia.c): ed 71, 138 bits of Manchester (154 in all), CRC-8 0x07 init 0x76 on 5 bits
static bool kia(const Row& row, Reading* r) {
  static const uint8_t pat[2] = { 0xed, 0x71 };
  for (int pos = 0; (pos = search(row, pos, pat, 16)) + 154 <= row.n; pos += 2) {
    Row p;
    int at = pos + 16;
    int end = manchester(row, at, p, 154 - 16);
    if (end - at < 154 - 16) continue;
    const uint8_t* b = p.b;
    uint8_t crc = b[8] & ~0x7;
    if (crc8(b, 8, 0x07, 0x76) != crc) continue;
    start(r, P_KIA);
    uint8_t pressure = (uint8_t)(b[0] << 4 | b[1] >> 4);
    uint8_t temperature = (uint8_t)(b[1] << 4 | b[2] >> 4);
    r->id = (uint32_t) b[2] << 28 | (uint32_t) b[3] << 20 | (uint32_t) b[4] << 12 | (uint32_t) b[5] << 4 | b[6] >> 4;
    r->kpa10 = psiTo(pressure / 5.0f);
    r->has_temp = true;
    r->temp_c = (int16_t)(temperature - 50);
    return true;
  }
  return false;
}

// Honda (tpms_honda.c): a 23-bit marker at the start, 64 bits Manchester, CRC-8 0x07
static bool honda(const Row& row, Reading* r) {
  static const uint8_t marker[3] = { 0xda, 0xe3, 0x54 };
  if (search(row, 0, marker, 23) != 0) return false;
  if (23 + 128 > row.n) return false;
  Row p;
  manchester(row, 23, p, 64);
  if (p.n < 64) return false;
  const uint8_t* b = p.b;
  if (crc8(b, 7, 0x07, 0x00) != b[7]) return false;
  if (b[0] > 0 && b[0] < 50) return false;   // as rtl_433: TRW GQ4-44T frames can look like these
  start(r, P_HONDA);
  r->id = (uint32_t) b[2] << 24 | (uint32_t) b[3] << 16 | (uint32_t) b[4] << 8 | b[5];
  r->kpa10 = psiTo(b[0] * 0.2f);
  r->has_temp = true;
  r->temp_c = (int16_t)(b[1] - 50);
  return true;
}

// Nissan (tpms_nissan.c): f5 55 55 55 e, 37 bits Manchester inverted, a 2-bit check
static uint8_t nissanCheck(const uint8_t* b) {
  uint8_t chk = 0;
  for (int i = 0; i < 4; i++) {
    chk += b[i] >> 7;
    chk += b[i] >> 5;
    chk += b[i] >> 3;
    chk += b[i] >> 1;
    chk += (uint8_t)(b[i] << 1);
  }
  chk += b[4] >> 7;
  chk += b[4] >> 5;
  chk += b[4] >> 3;
  return ~chk & 0x03;
}

static bool nissan(const Row& row, Reading* r) {
  static const uint8_t pat[5] = { 0xf5, 0x55, 0x55, 0x55, 0xe0 };
  for (int pos = 0; (pos = search(row, pos, pat, 36)) + 77 <= row.n; pos += 1) {
    Row p;
    manchester(row, pos + 36, p, 113);
    if (p.n < 37) continue;
    uint8_t b[ROW_BYTES];
    for (int i = 0; i < ROW_BYTES; i++) b[i] = (uint8_t) ~p.b[i];   // G.E. Thomas
    if (nissanCheck(b) != 0) continue;
    start(r, P_NISSAN);
    r->id = (uint32_t)((b[0] & 0x1F) << 19) | (uint32_t)(b[1] << 11) | (uint32_t)(b[2] << 3) | (uint32_t)(b[3] >> 5);
    int raw = ((b[3] & 0x1F) << 3) | (b[4] >> 5);
    r->kpa10 = psiTo(raw / 4.0f - 3.0f);
    r->weak_check = true;
    return true;
  }
  return false;
}

// GM, Schrader EG53MA4 (schraeder.c): OOK, Manchester (data 1 = chips 10). After a 1010.. preamble,
// 80 bits: flags (4, the first 4c), ID (3), pressure (25 mbar a step), temperature (F), the sum of
// the 9 bytes before. The radio's sync word is the preamble's end and the 4c.
static bool gm(const Row& row, Reading* r) {
  static const uint8_t pat[3] = { 0x55, 0x65, 0xa5 };
  for (int pos = 0; (pos = search(row, pos, pat, 24)) + 8 + 160 <= row.n; pos += 2) {
    Row p;
    manchester(row, pos + 8, p, 80);
    if (p.n < 80) continue;
    uint8_t b[10];
    for (int i = 0; i < 10; i++) b[i] = (uint8_t) ~p.b[i];   // 10 = 1 (the IEEE decoder reads 01 = 1)
    if (!b[1] && !b[2] && !b[4] && !b[5] && !b[7] && !b[8]) continue;
    uint8_t sum = 0;
    for (int i = 0; i < 9; i++) sum += b[i];
    if (sum != b[9]) continue;
    start(r, P_GM);
    r->id = (uint32_t) b[4] << 16 | (uint32_t) b[5] << 8 | b[6];
    r->kpa10 = (int16_t)(b[7] * 25);   // 25 mbar = 2.5 kPa
    r->has_temp = true;
    r->temp_c = (int16_t)((b[8] - 32) * 5 / 9);
    r->weak_check = true;
    return true;
  }
  return false;
}

bool decodeRow(uint8_t proto, const uint8_t* bits, int nbits, Reading* r) {
  if (nbits < 0) return false;
  Row row;
  memset(&row, 0, sizeof(row));
  if (nbits > ROW_BYTES * 8) nbits = ROW_BYTES * 8;
  memcpy(row.b, bits, (nbits + 7) / 8);
  row.n = nbits;
  bool inverted = proto == P_FORD || proto == P_JEEP;   // as rtl_433, which inverts these rows first
  if (inverted) for (int i = 0; i < ROW_BYTES; i++) row.b[i] = (uint8_t) ~row.b[i];
  switch (proto) {
    case P_TOYOTA: return toyota(row, r);
    case P_PMV107J: return pmv107j(row, r);
    case P_FORD: return ford(row, r);
    case P_JEEP: return jeep(row, r);
    case P_HYUNDAI: return hyundai(row, r);
    case P_KIA: return kia(row, r);
    case P_HONDA: return honda(row, r);
    case P_NISSAN: return nissan(row, r);
    case P_GM: return gm(row, r);
    default: return false;
  }
}

// ---- the radio settings ----

static const Air AIRS_[AIRS] = {
  // name         kbps     sync (first sync_bits bits)          bits pkt invert protocols                    ook  pre listen
  { "Ford/Jeep",  19.231f, { 0x55, 0x56 }, 16, 21, true, (1 << P_FORD) | (1 << P_JEEP), false, 8, true },
  { "Hyundai",    19.231f, { 0xaa, 0xaa, 0xaa, 0xa9 }, 32, 20, false, 1 << P_HYUNDAI, false, 8, true },
  { "Toyota",     19.231f, { 0xa9, 0xe0 }, 11, 19, false, 1 << P_TOYOTA, false, 8, true },
  { "Kia",        20.0f,   { 0xed, 0x71 }, 16, 18, false, 1 << P_KIA, false, 0, true },
  { "Honda",      20.0f,   { 0xda, 0xe3, 0x54 }, 23, 16, false, 1 << P_HONDA, false, 0, true },   // no preamble
  // Nissan: its frames came through garbled on the bench (8.33 kbps): read in tests only, for now
  { "Nissan",     8.333f,  { 0xf5, 0x55, 0x55, 0x55, 0xe0 }, 36, 10, false, 1 << P_NISSAN, false, 8, false },
  { "PMV-107J",   10.0f,   { 0xfc }, 8, 18, false, 1 << P_PMV107J, false, 8, true },
  { "GM",         8.130f,  { 0x55, 0x65, 0xa5 }, 24, 18, false, 1 << P_GM, true, 0, true },
};

const Air& air(int i) { return AIRS_[i >= 0 && i < AIRS ? i : 0]; }

bool read(int i, const uint8_t* chips, int n_bytes, Reading* r) {
  if (i < 0 || i >= AIRS || n_bytes < 0) return false;
  const Air& a = AIRS_[i];
  // the row as rtl_433 would have it: the sync word, then the chips (Ford/Jeep: the sync word as
  // sent; decodeRow inverts the whole row)
  uint8_t row[ROW_BYTES] = {};
  int n = 0;
  for (int k = 0; k < a.sync_bits; k++, n++) {
    if ((a.sync[k >> 3] >> (7 - (k & 7))) & 1) row[n >> 3] |= 0x80 >> (n & 7);
  }
  for (int k = 0; k < n_bytes * 8 && n < ROW_BYTES * 8; k++, n++) {
    if ((chips[k >> 3] >> (7 - (k & 7))) & 1) row[n >> 3] |= 0x80 >> (n & 7);
  }
  for (uint8_t p = 1; p < P_COUNT; p++) {
    if ((a.protos & (1 << p)) && decodeRow(p, row, n, r)) return true;
  }
  return false;
}

const char* protoName(uint8_t p) {
  switch (p) {
    case P_TOYOTA: return "Toyota";
    case P_PMV107J: return "Toyota PMV-107J";
    case P_FORD: return "Ford";
    case P_JEEP: return "Jeep";
    case P_HYUNDAI: return "Hyundai";
    case P_KIA: return "Kia";
    case P_HONDA: return "Honda";
    case P_NISSAN: return "Nissan";
    case P_GM: return "GM";
    default: return "?";
  }
}

}  // namespace tpms
