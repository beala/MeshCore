// Car geofence (src/helpers/GeoFence.h) on arbitrary input: a script of operations, one byte each
// plus arguments: a CLI command (from the mesh: any text), time jumps (wrapping millis), motion,
// button, scan results, home sets from made-up scans. Checks every reply is NUL-terminated within
// 160 bytes, the prefs stay valid, and the state machine's promises hold:
//   - the radio is on in OFF and AWAY, and while the button's awake time runs
//   - no scan is due while OFF or pinned
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <helpers/GeoFence.h>

static void checkReply(const char* reply) {
  // the reply buffer is 160 bytes, filled with 0x55 before each call: the NUL must be inside
  if (memchr(reply, 0, 160) == NULL) abort();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  GeoFencePrefs p;
  p.setDefaults();
  GeoFence geo(p);
  uint32_t now = 0;
  if (size >= 4) { memcpy(&now, data, 4); data += 4; size -= 4; }   // any start time, wrap included
  geo.begin(now);

  size_t i = 0;
  while (i < size) {
    const uint8_t op = data[i++];
    switch (op % 8) {
      case 0: {   // a command: up to the next 0 byte
        char cmd[200];
        size_t n = 0;
        while (i < size && data[i] != 0 && n < sizeof(cmd) - 1) cmd[n++] = (char)data[i++];
        if (i < size) i++;
        cmd[n] = 0;
        char reply[160];
        memset(reply, 0x55, sizeof(reply));
        bool changed = false, restart = false;
        if (handleGeoCommand(geo, p, cmd, now, reply, changed, restart)) checkReply(reply);
        if (!p.isValid()) abort();
        if (restart) geo.begin(now);
        break;
      }
      case 1: {   // time jump: 1 byte, scaled
        uint32_t step = i < size ? data[i++] : 1;
        now += step * ((op >> 3) == 0 ? 1000u : (op >> 3) * 60000u);
        break;
      }
      case 2: geo.onMotion(now); break;
      case 3: geo.onButton(now); break;
      case 4: {   // a scan, if one is due, with the result the input says
        if (geo.scanDue(now)) {
          if (geo.state() == GeoFence::OFF || geo.pinned()) abort();
          geo.onScan(now, (GeoFence::ScanResult)((op >> 3) % 3));
        }
        break;
      }
      case 5: {   // home set/add from a made-up scan: [n] then n x 7 bytes
        uint8_t n = i < size ? data[i++] % 40 : 0;
        GeoScanAp aps[40];
        int got = 0;
        while (got < n && i + 7 <= size) {
          memcpy(aps[got].mac, data + i, 6);
          aps[got].rssi = (int8_t)data[i + 6];
          i += 7;
          got++;
        }
        geo.setHome(aps, got, (int8_t)(op | 0x80), (op >> 3) & 1);
        if (p.num_home > GEO_MAX_HOME) abort();
        if (!p.isValid()) abort();
        break;
      }
      case 6: geo.force((GeoFence::State)((op >> 3) % 4), now); break;
      case 7: {   // judge a made-up scan
        GeoScanAp ap;
        if (i + 6 <= size) { memcpy(ap.mac, data + i, 6); i += 6; } else memset(ap.mac, 0, 6);
        ap.rssi = -50;
        GeoFence::ScanResult r = geo.judge(&ap, 1);
        if (r != GeoFence::SAW_HOME && r != GeoFence::MISSED) abort();
        break;
      }
    }
    const GeoFence::State s = geo.state();
    if ((s == GeoFence::OFF || s == GeoFence::AWAY) && !geo.radioOn(now)) abort();
    if (geo.awake(now) && !geo.radioOn(now)) abort();
    if ((s == GeoFence::OFF || geo.pinned()) && geo.scanDue(now)) abort();
  }
  return 0;
}
