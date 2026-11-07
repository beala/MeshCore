// FIS-B ground station frames (src/helpers/weather/Fisb) on arbitrary input. The first byte picks:
// even, the rest is a received 552-byte frame (corrected, then read); odd, it is 432 data bytes as
// if corrected (so the parser sees every kind of information frame, APDU and DLAC text).
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/weather/Fisb.h>

static void readAll(const uint8_t* d, int len) {
  fisb::Reports r(d, len);
  fisb::Text t;
  int n = 0;
  while (r.next(&t)) {
    if (t.len < 0 || t.len > fisb::TEXT_MAX || t.product != fisb::PRODUCT_TEXT) abort();
    if (t.hours > 31 || t.minutes > 63) abort();
    char kind[8], where[8], when[10], line[140];
    fisb::words(t.text, t.len, kind, sizeof(kind), where, sizeof(where), when, sizeof(when));
    int k = fisb::oneLine(t.text, t.len, line, sizeof(line));
    if (k < 0 || k >= (int) sizeof(line) || line[k] != 0) abort();
    if (++n > 1000) abort();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  bool as_data = data[0] & 1;
  data++; size--;
  if (as_data) {
    uint8_t d[fisb::DATA_BYTES] = {};
    memcpy(d, data, size < sizeof(d) ? size : sizeof(d));
    readAll(d, sizeof(d));
    fisb::Header h;
    fisb::header(d, &h);
    if (h.lat_e5 < -9000000 || h.lat_e5 > 9000000 || h.lon_e5 < -18000000 || h.lon_e5 > 18000000) abort();
    readAll(d, (int)(size < sizeof(d) ? size : sizeof(d)));   // short too
  } else {
    uint8_t f[fisb::FRAME_BYTES] = {};
    memcpy(f, data, size < sizeof(f) ? size : sizeof(f));
    uint8_t d[fisb::DATA_BYTES];
    int fixed = -1;
    if (fisb::correct(f, d, &fixed)) {
      if (fixed < 0 || fixed > 60) abort();
      readAll(d, sizeof(d));
    }
  }
  char out[16];
  fisb::dlac(data, (int) size, out, sizeof(out));
  if (strlen(out) >= sizeof(out)) abort();
  return 0;
}
