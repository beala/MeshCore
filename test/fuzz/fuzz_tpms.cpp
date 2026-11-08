// Tire pressure sensor frames (src/helpers/tpms) on arbitrary chips. The first byte picks a radio
// setting (or, with its top bit set, a protocol for decodeRow on a whole bit row of any length).
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <helpers/tpms/Tpms.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  uint8_t sel = data[0];
  data++; size--;
  tpms::Reading r;
  if (sel & 0x80) {
    uint8_t proto = (uint8_t)(sel & 0x0F);   // 0 and past P_COUNT too: not protocols
    int nbits = (int)(size * 8) - (data[0] & 7);
    if (tpms::decodeRow(proto, data, nbits, &r)) {
      if (r.proto != proto || r.proto == 0 || r.proto >= tpms::P_COUNT) abort();
    }
  } else {
    int air = sel % (tpms::AIRS + 1);   // one past the last too
    uint8_t chips[40] = {};
    int n = size < sizeof(chips) ? (int) size : (int) sizeof(chips);
    memcpy(chips, data, n);
    if (tpms::read(air, chips, n, &r)) {
      if (air >= tpms::AIRS) abort();
      if (!(tpms::air(air).protos & (1 << r.proto))) abort();   // a protocol of that setting
      if (!tpms::protoName(r.proto)[0]) abort();
    }
  }
  return 0;
}
