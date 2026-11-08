// Weather sensor decoding and the listen scheduler (src/helpers/weather) on arbitrary input.
// Mode byte bit 0 clear: the input is a received packet (bit 1: La Crosse, else Fine Offset): decode,
//              then format into buffers of every size.
// Mode byte bit 0 set: the input is a script of tracker events: time steps, packets from a few sensors,
//              windows ending heard/not heard/not run. Checks the windows it asks for stay sane.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/weather/FineOffset.h>
#include <helpers/weather/SensorTracker.h>

using namespace wxsensor;

static void fuzzDecode(uint8_t proto, const uint8_t* d, size_t n) {
  Reading r;
  int cl = checkedLength(d, (int)n), crl = crcLength(d, (int)n);
  if (cl < 0 || cl > (int)n || crl < 0 || crl > (int)n) abort();
  if (!decodeAs(proto, d, (int)n, &r)) return;
  if (r.proto != proto) abort();
  char buf[200];
  for (size_t size = 0; size <= sizeof(buf); size += 7) {
    int w = format(r, size & 1, size ? buf : NULL, size);
    if (size && (w < 0 || (size_t)w >= size || buf[w] != 0)) abort();
  }
  (void)sensorKey(r);
  (void)compass(r.wind_dir);
  (void)modelName(r.model);
}

static void fuzzTracker(const uint8_t* d, size_t n) {
  Tracker t;
  uint32_t now = 0;
  if (n >= 4) { memcpy(&now, d, 4); d += 4; n -= 4; }
  t.reset(now);
  t.setSeed(now | 1);
  t.setProtocols((uint8_t)(now >> 8) & ((1 << PROTO_COUNT) - 1));
  t.scanFor(now, 1000 + (now & 0xFFFF));
  Window w = {};
  bool open = false;
  for (size_t i = 0; i + 1 < n; i += 2) {
    uint8_t op = d[i], v = d[i + 1];
    switch (op & 7) {
      case 0: now += v * 97u; break;                       // time passes
      case 1: now += (uint32_t)v << 16; break;              // a long gap (and wraps)
      case 2: case 3: {                                     // a packet from one of 8 sensors
        Reading r;
        memset(&r, 0, sizeof(r));
        r.model = 1 + (v % (MODEL_COUNT - 1));
        r.id = v >> 3;
        t.onPacket(now, r, -(int16_t)v);
        break;
      }
      case 4:
        if (!open && t.nextWindow(now, &w)) {
          if ((int32_t)(w.start - now) < 0) abort();       // never in the past
          if (w.len > 0x7FFFFFFFu) abort();
          open = true;
        }
        break;
      case 5:
        if (open) { t.windowDone(now, w, v & 1, v & 2); open = false; }
        break;
      case 6: t.huntFor(now, v * 1000u); break;
      case 7: t.scanFor(now, v * 1000u); break;
    }
    if (t.count() < 0 || t.count() > Tracker::MAX_SENSORS) abort();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  if (data[0] & 1) fuzzTracker(data + 1, size - 1);
  else fuzzDecode((uint8_t)((data[0] >> 1) % PROTO_COUNT), data + 1, size - 1);
  return 0;
}
