#include "AdsB.h"
#include <string.h>
#include <math.h>

namespace adsb {

uint32_t crc24(const uint8_t* b, int n) {
  uint32_t c = 0;
  for (int i = 0; i < n; i++) {
    c ^= (uint32_t)b[i] << 16;
    for (int k = 0; k < 8; k++) {
      c <<= 1;
      if (c & 0x1000000) c ^= 0x1FFF409;
    }
  }
  return c & 0xFFFFFF;
}

// ME bits first..last, counted from 1 at the message's first bit (as the format documents do)
static uint32_t me(const uint8_t* m, int first, int last) {
  uint32_t v = 0;
  for (int i = first - 1; i <= last - 1; i++) v = v << 1 | ((m[i >> 3] >> (7 - (i & 7))) & 1);
  return v;
}

static uint16_t track(int32_t north, int32_t east) {
  double a = atan2((double)east, (double)north) * 180.0 / M_PI;
  if (a < 0) a += 360.0;
  return (uint16_t)((int)(a + 0.5) % 360);
}

// surface movement code -> knots
static int movementKt(uint32_t q) {
  if (q == 1) return 0;
  if (q >= 2 && q <= 8) return (int)((q - 1) * 0.125 + 0.5);
  if (q >= 9 && q <= 12) return (int)(1 + (q - 9) * 0.25 + 0.5);
  if (q >= 13 && q <= 38) return (int)(2 + (q - 13) * 0.5 + 0.5);
  if (q >= 39 && q <= 93) return (int)(15 + (q - 39));
  if (q >= 94 && q <= 108) return (int)(70 + (q - 94) * 2);
  if (q >= 109 && q <= 123) return (int)(100 + (q - 109) * 5);
  if (q == 124) return 175;
  return -1;
}

bool decode(const uint8_t* b, int len, Message* m) {
  if (!b || !m || (len != DATA_BYTES && len != FRAME_BYTES)) return false;
  if (len == FRAME_BYTES && crc24(b, DATA_BYTES) != ((uint32_t)b[11] << 16 | (uint32_t)b[12] << 8 | b[13])) return false;
  memset(m, 0, sizeof(*m));
  uat::Report* r = &m->r;
  uint8_t df = b[0] >> 3, ca = b[0] & 7;
  if (df != 17 && df != 18) return false;
  r->address = (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
  if (df == 17) r->qualifier = 0;
  else switch (ca) {   // DF 18 control field
    case 0: case 1: r->qualifier = 1; break;   // ADS-B from a non-transponder device
    case 2: case 3: case 5: r->qualifier = ca == 2 ? 2 : 3; break;   // TIS-B
    case 6: r->qualifier = 6; break;           // ADS-R (rebroadcast from 978)
    default: return false;
  }
  const uint8_t* e = &b[4];
  uint8_t tc = (uint8_t)me(e, 1, 5);
  m->type_code = tc;
  r->payload_type = tc;
  r->ag_state = 0;

  if (tc >= 1 && tc <= 4) {   // identification
    static const char CS[] = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######";
    char cs[9];
    for (int i = 0; i < 8; i++) cs[i] = CS[me(e, 9 + 6 * i, 14 + 6 * i)];
    cs[8] = 0;
    int n = 8;
    while (n > 0 && cs[n - 1] == ' ') cs[--n] = 0;
    bool ok = n > 0;
    for (int i = 0; i < n; i++) if (cs[i] == ' ' || cs[i] == '#') ok = false;
    if (ok) memcpy(r->callsign, cs, sizeof(r->callsign));
    return true;
  }
  if ((tc >= 9 && tc <= 18) || (tc >= 20 && tc <= 22)) {   // airborne position
    uint32_t alt = me(e, 9, 20);
    if (tc <= 18) {
      if (alt && (alt & 0x10)) {   // 25 ft steps; Q bit set (100 ft Gillham codes are not decoded)
        uint32_t n = ((alt & 0xFE0) >> 1) | (alt & 0x0F);
        r->has_alt = true;
        r->alt_ft = (int32_t)n * 25 - 1000;
      }
    } else if (alt) {              // GNSS height, metres
      r->has_alt = true;
      r->alt_geometric = true;
      r->alt_ft = (int32_t)(alt * 3.28084 + 0.5);
    }
    m->has_cpr = true;
    m->cpr_odd = me(e, 22, 22) != 0;
    m->cpr_lat = me(e, 23, 39);
    m->cpr_lon = me(e, 40, 56);
    return true;
  }
  if (tc >= 5 && tc <= 8) {   // surface position
    r->ag_state = 2;
    int kt = movementKt(me(e, 6, 12));
    if (kt >= 0) { r->has_speed = true; r->speed_kt = (uint16_t)kt; }
    if (me(e, 13, 13)) r->track_deg = (uint16_t)(me(e, 14, 20) * 360 / 128);
    m->surface = true;
    m->has_cpr = true;
    m->cpr_odd = me(e, 22, 22) != 0;
    m->cpr_lat = me(e, 23, 39);
    m->cpr_lon = me(e, 40, 56);
    return true;
  }
  if (tc == 19) {   // airborne velocity
    uint32_t st = me(e, 6, 8);
    if (st == 1 || st == 2) {   // over the ground
      uint32_t vew = me(e, 15, 24), vns = me(e, 26, 35);
      if (vew && vns) {
        int mult = st == 2 ? 4 : 1;
        int32_t east = (int32_t)(vew - 1) * mult * (me(e, 14, 14) ? -1 : 1);
        int32_t north = (int32_t)(vns - 1) * mult * (me(e, 25, 25) ? -1 : 1);
        r->has_speed = true;
        r->speed_kt = (uint16_t)(sqrt((double)east * east + (double)north * north) + 0.5);
        r->track_deg = track(north, east);
      }
    } else if (st == 3 || st == 4) {   // airspeed and heading
      uint32_t as = me(e, 26, 35);
      if (as && me(e, 14, 14)) {
        r->has_speed = true;
        r->speed_kt = (uint16_t)((as - 1) * (st == 4 ? 4 : 1));
        r->track_deg = (uint16_t)(me(e, 15, 24) * 360 / 1024);
      }
    } else {
      return true;
    }
    uint32_t vr = me(e, 38, 46);
    if (vr) {
      r->has_vs = true;
      r->vs_fpm = (int16_t)(((int32_t)vr - 1) * 64 * (me(e, 37, 37) ? -1 : 1));
    }
    return true;
  }
  return true;   // other type codes: address only
}

// ---- CPR ----

static const double CPR_SCALE = 131072.0;   // 2^17

// number of longitude zones at a latitude (NZ = 15)
static int NL(double lat) {
  double a = fabs(lat);
  if (a < 1e-9) return 59;
  if (fabs(a - 87.0) < 1e-9) return 2;
  if (a > 87.0) return 1;
  double c = cos(M_PI / 180.0 * lat);
  double x = 1.0 - (1.0 - cos(M_PI / 30.0)) / (c * c);
  return (int)floor(2.0 * M_PI / acos(x));
}

static double fmod360(double x, double m) {
  double r = fmod(x, m);
  return r < 0 ? r + m : r;
}

static bool toE5(double lat, double lon, int32_t* lat_e5, int32_t* lon_e5) {
  if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) return false;
  *lat_e5 = (int32_t)floor(lat * 1e5 + 0.5);
  *lon_e5 = (int32_t)floor(lon * 1e5 + 0.5);
  return true;
}

bool cprGlobal(uint32_t lat_even, uint32_t lon_even, uint32_t lat_odd, uint32_t lon_odd, bool odd_newer,
               int32_t* lat_e5, int32_t* lon_e5) {
  if (!lat_e5 || !lon_e5) return false;
  double le = lat_even / CPR_SCALE, lo = lat_odd / CPR_SCALE;
  double ge = lon_even / CPR_SCALE, go = lon_odd / CPR_SCALE;
  double j = floor(59.0 * le - 60.0 * lo + 0.5);
  double lat_e = 6.0 * (fmod360(j, 60.0) + le);
  double lat_o = 360.0 / 59.0 * (fmod360(j, 59.0) + lo);
  if (lat_e >= 270.0) lat_e -= 360.0;
  if (lat_o >= 270.0) lat_o -= 360.0;
  if (lat_e < -90.0 || lat_e > 90.0 || lat_o < -90.0 || lat_o > 90.0) return false;
  int nl = NL(lat_e);
  if (nl != NL(lat_o)) return false;   // different zones: wait for the next pair
  double lat = odd_newer ? lat_o : lat_e;
  int ni = odd_newer ? nl - 1 : nl;
  if (ni < 1) ni = 1;
  double mm = floor(ge * (nl - 1) - go * nl + 0.5);
  double lon = 360.0 / ni * (fmod360(mm, ni) + (odd_newer ? go : ge));
  if (lon >= 180.0) lon -= 360.0;
  return toE5(lat, lon, lat_e5, lon_e5);
}

bool cprLocal(uint32_t lat_cpr, uint32_t lon_cpr, bool odd, bool surface, int32_t ref_lat_e5, int32_t ref_lon_e5,
              int32_t* lat_e5, int32_t* lon_e5) {
  if (!lat_e5 || !lon_e5) return false;
  double span = surface ? 90.0 : 360.0;
  double rlat = ref_lat_e5 * 1e-5, rlon = ref_lon_e5 * 1e-5;
  double yz = lat_cpr / CPR_SCALE, xz = lon_cpr / CPR_SCALE;
  int i = odd ? 1 : 0;
  double dlat = span / (60 - i);
  double j = floor(rlat / dlat) + floor(fmod360(rlat, dlat) / dlat - yz + 0.5);
  double lat = dlat * (j + yz);
  int n = NL(lat) - i;
  if (n < 1) n = 1;
  double dlon = span / n;
  double mm = floor(rlon / dlon) + floor(fmod360(rlon, dlon) / dlon - xz + 0.5);
  double lon = dlon * (mm + xz);
  return toE5(lat, lon, lat_e5, lon_e5);
}

}  // namespace adsb
