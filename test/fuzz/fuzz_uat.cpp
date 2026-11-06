// Aircraft messages (src/helpers/aircraft) on arbitrary input: UAT Reed-Solomon correction of a
// received 48-byte frame, decoding, and the distance/bearing maths; 1090 MHz ADS-B decoding and
// CPR positions.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/aircraft/Uat.h>
#include <helpers/aircraft/AdsB.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  uint8_t buf[uat::LONG_BYTES] = {};
  memcpy(buf, data, size < sizeof(buf) ? size : sizeof(buf));
  int fixed = 0;
  int n = uat::correct(buf, size < sizeof(buf) ? (int) size : (int) sizeof(buf), &fixed);
  if (n != 0 && n != uat::SHORT_DATA && n != uat::LONG_DATA) abort();
  if (fixed < 0 || fixed > 7) abort();
  uat::Report r;
  if (n) {
    if (!uat::decode(buf, n, &r)) abort();
    if (r.callsign[8] != 0) abort();
    if (r.has_pos && (r.lat_e5 < -9000000 || r.lat_e5 > 9000000 || r.lon_e5 < -18000000 || r.lon_e5 > 18000000)) abort();
    uint32_t d; uint16_t b;
    uat::distanceBearing(4016370, -10516330, r.lat_e5, r.lon_e5, &d, &b);
    if (b >= 360) abort();
  }
  if (size >= 11) {   // ADS-B: 11 bytes as the radio hands them over, 14 with parity
    adsb::Message m;
    int len = size >= 14 ? 14 : 11;
    if (adsb::decode(data, len, &m)) {
      if (m.r.callsign[8] != 0) abort();
      if (m.has_cpr && (m.cpr_lat > 0x1FFFF || m.cpr_lon > 0x1FFFF)) abort();
    }
    adsb::decode(data, 11, &m);
  }
  if (size >= 16) {   // CPR maths on any field values and references
    uint32_t v[4];
    for (int i = 0; i < 4; i++) v[i] = ((uint32_t)data[2 * i] << 9 | (uint32_t)data[2 * i + 1] << 1 | (data[8] >> i & 1)) & 0x1FFFF;
    int32_t ref_lat = (int32_t)((uint32_t)data[9] << 16 | (uint32_t)data[10] << 8 | data[11]) % 9000001;
    int32_t ref_lon = (int32_t)((uint32_t)data[12] << 16 | (uint32_t)data[13] << 8 | data[14]) % 18000001;
    if (data[15] & 1) ref_lat = -ref_lat;
    if (data[15] & 2) ref_lon = -ref_lon;
    int32_t lat, lon;
    if (adsb::cprGlobal(v[0], v[1], v[2], v[3], data[15] & 4, &lat, &lon)) {
      if (lat < -9000000 || lat > 9000000 || lon < -18000000 || lon > 18000000) abort();
    }
    if (adsb::cprLocal(v[0], v[1], data[15] & 8, data[15] & 16, ref_lat, ref_lon, &lat, &lon)) {
      if (lat < -9000000 || lat > 9000000 || lon < -18000000 || lon > 18000000) abort();
    }
  }
  if (size >= 4) {   // the raw RS decoder on a codeword of any length
    uint8_t cw[255];
    size_t len = size - 2 < sizeof(cw) ? size - 2 : sizeof(cw);
    memcpy(cw, data + 2, len);
    int nroots = 2 + data[0] % 19;
    uat::rsDecode(cw, (int) len, nroots);
  }
  return 0;
}
