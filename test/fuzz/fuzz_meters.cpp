// Utility meter frames (src/helpers/meters) on arbitrary chips. The first byte picks the kind; the
// rest is what the radio handed over after the sync word, of any length.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <helpers/meters/Meters.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  uint8_t kind = data[0] % (meters::KINDS + 2);   // also 0 and one past the last: not kinds
  data++; size--;
  uint8_t chips[40];
  int n = size < sizeof(chips) ? (int) size : (int) sizeof(chips);
  memcpy(chips, data, n);   // the radio's packets are fixed length: up to 26 bytes
  meters::Reading r;
  if (meters::read(kind, chips, n, &r)) {
    if (r.kind != kind || r.id == 0) abort();
    if (r.utility > meters::UTIL_ELECTRIC) abort();
    if (r.leak_days > 7 || r.leak_now > 3 || r.backflow > 3 || r.no_use > 7) abort();
    if (n < meters::air(kind).pkt_bytes) abort();   // a frame read from fewer chips than it has
    if (!meters::utilityName(r.utility)[0] || !meters::kindName(kind)[0]) abort();
  }
  for (int i = -1; i <= meters::channels(kind) && kind >= 1 && kind <= meters::KINDS; i++) {
    float f = meters::channelMHz(kind, i);
    if (f < 910.0f || f > 921.0f) abort();
  }
  return 0;
}
