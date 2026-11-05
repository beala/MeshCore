// UAT aircraft messages (src/helpers/aircraft) on arbitrary input: Reed-Solomon correction of a
// received 48-byte frame, decoding, and the distance/bearing maths.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/aircraft/Uat.h>

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
  if (size >= 4) {   // the raw RS decoder on a codeword of any length
    uint8_t cw[255];
    size_t len = size - 2 < sizeof(cw) ? size - 2 : sizeof(cw);
    memcpy(cw, data + 2, len);
    int nroots = 2 + data[0] % 19;
    uat::rsDecode(cw, (int) len, nroots);
  }
  return 0;
}
