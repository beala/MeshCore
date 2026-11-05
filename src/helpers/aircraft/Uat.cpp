#include "Uat.h"
#include <string.h>
#include <math.h>

namespace uat {

// ---- GF(256), x^8 + x^7 + x^2 + x + 1 ----

static uint8_t EXP_[512], LOG_[256];
static bool gf_ready = false;

static void gfInit() {
  if (gf_ready) return;
  unsigned x = 1;
  for (int i = 0; i < 255; i++) {
    EXP_[i] = (uint8_t)x;
    LOG_[x] = (uint8_t)i;
    x <<= 1;
    if (x & 0x100) x ^= 0x187;
  }
  for (int i = 255; i < 512; i++) EXP_[i] = EXP_[i - 255];
  LOG_[0] = 0;
  gf_ready = true;
}

static inline uint8_t mul(uint8_t a, uint8_t b) { return (a && b) ? EXP_[LOG_[a] + LOG_[b]] : 0; }
static inline uint8_t inv(uint8_t a) { return EXP_[255 - LOG_[a]]; }
static inline uint8_t powa(int e) { e %= 255; if (e < 0) e += 255; return EXP_[e]; }

static const int FCR = 120;
static const int MAXR = 20;

// Byte j of the codeword (j = 0 first) is the coefficient of x^(n-1-j).
int rsDecode(uint8_t* cw, int n, int nroots) {
  gfInit();
  if (n <= nroots || n > 255 || nroots > MAXR || nroots < 2) return -1;
  uint8_t S[MAXR];
  bool clean = true;
  for (int i = 0; i < nroots; i++) {   // syndromes: r(alpha^(FCR + i)), by Horner
    uint8_t root = powa(FCR + i), s = 0;
    for (int j = 0; j < n; j++) s = mul(s, root) ^ cw[j];
    S[i] = s;
    if (s) clean = false;
  }
  if (clean) return 0;

  // Berlekamp-Massey: error locator sigma(x)
  uint8_t sigma[MAXR + 1] = { 1 }, B[MAXR + 1] = { 1 }, T[MAXR + 1];
  int L = 0, m = 1;
  uint8_t b = 1;
  for (int r = 0; r < nroots; r++) {
    uint8_t d = S[r];
    for (int i = 1; i <= L; i++) d ^= mul(sigma[i], S[r - i]);
    if (d == 0) { m++; continue; }
    memcpy(T, sigma, sizeof(T));
    uint8_t coef = mul(d, inv(b));
    for (int i = 0; i + m <= nroots; i++) sigma[i + m] ^= mul(coef, B[i]);
    if (2 * L <= r) {
      L = r + 1 - L;
      memcpy(B, T, sizeof(B));
      b = d;
      m = 1;
    } else {
      m++;
    }
  }
  if (L == 0 || L > nroots / 2) return -1;

  // Chien search over the positions that exist (shortened code): position p = power of x
  int pos[MAXR], nerr = 0;
  for (int p = 0; p < n; p++) {
    uint8_t xinv = powa(-p), v = 0;   // sigma(alpha^-p)
    for (int i = L; i >= 0; i--) v = mul(v, xinv) ^ sigma[i];
    if (v == 0) {
      if (nerr == MAXR) return -1;
      pos[nerr++] = p;
    }
  }
  if (nerr != L) return -1;

  // Forney: omega(x) = S(x) sigma(x) mod x^nroots; e = X^(1-FCR) omega(X^-1) / sigma'(X^-1)
  uint8_t omega[MAXR];
  for (int i = 0; i < nroots; i++) {
    uint8_t v = 0;
    for (int j = 0; j <= i && j <= L; j++) v ^= mul(sigma[j], S[i - j]);
    omega[i] = v;
  }
  for (int k = 0; k < nerr; k++) {
    int p = pos[k];
    uint8_t xinv = powa(-p);
    uint8_t num = 0;
    for (int i = nroots - 1; i >= 0; i--) num = mul(num, xinv) ^ omega[i];
    uint8_t den = 0;   // sigma'(x): odd terms only
    for (int i = 1; i <= L; i += 2) den ^= mul(sigma[i], powa(-p * (i - 1)));
    if (den == 0) return -1;
    uint8_t e = mul(mul(num, inv(den)), powa(p * (1 - FCR)));
    cw[n - 1 - p] ^= e;
  }
  // check
  for (int i = 0; i < nroots; i++) {
    uint8_t root = powa(FCR + i), s = 0;
    for (int j = 0; j < n; j++) s = mul(s, root) ^ cw[j];
    if (s) return -1;
  }
  return nerr;
}

int correct(uint8_t* buf, int len, int* fixed) {
  if (fixed) *fixed = 0;
  if (len >= LONG_BYTES) {
    uint8_t t[LONG_BYTES];
    memcpy(t, buf, LONG_BYTES);
    int f = rsDecode(t, LONG_BYTES, LONG_BYTES - LONG_DATA);
    // a long message's payload type is 1-10 (0 is basic); don't accept a basic one this way
    if (f >= 0 && (t[0] >> 3) != 0) {
      memcpy(buf, t, LONG_BYTES);
      if (fixed) *fixed = f;
      return LONG_DATA;
    }
  }
  if (len >= SHORT_BYTES) {
    uint8_t t[SHORT_BYTES];
    memcpy(t, buf, SHORT_BYTES);
    int f = rsDecode(t, SHORT_BYTES, SHORT_BYTES - SHORT_DATA);
    if (f >= 0 && (t[0] >> 3) == 0) {
      memcpy(buf, t, SHORT_BYTES);
      if (fixed) *fixed = f;
      return SHORT_DATA;
    }
  }
  return 0;
}

// Bits first..last, counted from 1 at the MSB of byte 1 (the numbering DO-282 uses)
static uint32_t bits(const uint8_t* b, int fbyte, int fbit, int lbyte, int lbit) {
  int f = (fbyte - 1) * 8 + fbit - 1, l = (lbyte - 1) * 8 + lbit - 1;
  uint32_t v = 0;
  for (int i = f; i <= l; i++) v = v << 1 | ((b[i >> 3] >> (7 - (i & 7))) & 1);
  return v;
}

// atan2 in whole degrees (0..359) from integer components, good to ~1 degree
static uint16_t heading(int32_t north, int32_t east) {
  double a = atan2((double)east, (double)north) * 180.0 / M_PI;
  if (a < 0) a += 360.0;
  int d = (int)(a + 0.5);
  return (uint16_t)(d % 360);
}

bool decode(const uint8_t* p, int len, Report* r) {
  if (!p || !r || (len != SHORT_DATA && len != LONG_DATA)) return false;
  memset(r, 0, sizeof(*r));
  r->payload_type = (uint8_t)bits(p, 1, 1, 1, 5);
  r->qualifier = (uint8_t)bits(p, 1, 6, 1, 8);
  r->address = bits(p, 2, 1, 4, 8);
  if (r->payload_type > 10) return true;   // header only

  uint32_t rlat = bits(p, 5, 1, 7, 7), rlon = bits(p, 7, 8, 10, 7), ralt = bits(p, 11, 1, 12, 4);
  uint32_t nic = bits(p, 12, 5, 12, 8);
  if (rlat || rlon || nic) {
    // 360 / 2^24 degrees per count; × 1e5 with 64-bit maths
    int64_t lat = (int64_t)rlat * 36000000LL / 16777216LL, lon = (int64_t)rlon * 36000000LL / 16777216LL;
    if (lat > 9000000) lat -= 18000000;
    if (lon > 18000000) lon -= 36000000;
    r->lat_e5 = (int32_t)lat;
    r->lon_e5 = (int32_t)lon;
    r->has_pos = true;
  }
  if (ralt) {
    r->has_alt = true;
    r->alt_ft = ((int32_t)ralt - 41) * 25;
    r->alt_geometric = bits(p, 10, 8, 10, 8) != 0;
  }
  r->ag_state = (uint8_t)bits(p, 13, 1, 13, 2);
  if (r->ag_state <= 1) {   // airborne
    int mult = r->ag_state == 1 ? 4 : 1;
    uint32_t ns = bits(p, 13, 5, 14, 6), ew = bits(p, 14, 8, 16, 1);
    if (ns && ew) {
      int32_t n = (int32_t)(ns - 1) * mult * (bits(p, 13, 4, 13, 4) ? -1 : 1);
      int32_t e = (int32_t)(ew - 1) * mult * (bits(p, 14, 7, 14, 7) ? -1 : 1);
      r->has_speed = true;
      r->speed_kt = (uint16_t)(sqrt((double)n * n + (double)e * e) + 0.5);
      r->track_deg = heading(n, e);
    }
    uint32_t vv = bits(p, 16, 4, 17, 4);
    if (vv && bits(p, 16, 2, 16, 2) <= 1) {
      r->has_vs = true;
      r->vs_fpm = (int16_t)(((int32_t)vv - 1) * 64 * (bits(p, 16, 3, 16, 3) ? -1 : 1));
    }
  } else if (r->ag_state == 2) {   // on the ground
    uint32_t gs = bits(p, 13, 5, 14, 6);
    if (gs) { r->has_speed = true; r->speed_kt = (uint16_t)(gs - 1); }
    if (bits(p, 14, 7, 14, 8) != 0) r->track_deg = (uint16_t)(bits(p, 15, 1, 16, 1) * 360 / 512);
  }

  if ((r->payload_type == 1 || r->payload_type == 3) && len == LONG_DATA) {   // mode status: callsign
    static const char B40[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ *??";
    uint32_t a = bits(p, 18, 1, 19, 8), b = bits(p, 20, 1, 21, 8), c = bits(p, 22, 1, 23, 8);
    char cs[9] = {
      B40[(a / 40) % 40], B40[a % 40], B40[(b / 1600) % 40], B40[(b / 40) % 40], B40[b % 40],
      B40[(c / 1600) % 40], B40[(c / 40) % 40], B40[c % 40], 0 };
    int n = 8;
    while (n > 0 && (cs[n - 1] == ' ' || cs[n - 1] == '*' || cs[n - 1] == '?')) cs[--n] = 0;
    bool ok = n > 0;
    for (int i = 0; i < n; i++) if (cs[i] == ' ' || cs[i] == '*' || cs[i] == '?') ok = false;
    if (ok) {
      memcpy(r->callsign, cs, sizeof(r->callsign));
      r->callsign_is_squawk = bits(p, 27, 7, 27, 7) == 0;
    }
  }
  return true;
}

void distanceBearing(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2, uint32_t* dist, uint16_t* brg) {
  double la = lat1 * 1e-5 * M_PI / 180.0;
  double dn = (lat2 - lat1) * 1e-5 * 60.0;                     // nautical miles north
  double de = (lon2 - lon1) * 1e-5 * 60.0 * cos(la);           // nautical miles east
  double mi = sqrt(dn * dn + de * de) * 1.15078;
  if (dist) *dist = (uint32_t)(mi * 10.0 + 0.5);
  if (brg) {
    double a = atan2(de, dn) * 180.0 / M_PI;
    if (a < 0) a += 360.0;
    *brg = (uint16_t)((int)(a + 0.5) % 360);
  }
}

}  // namespace uat
