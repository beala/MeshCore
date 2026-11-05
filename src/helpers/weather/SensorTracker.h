#pragma once
// Decides when the radio should leave MeshCore to listen for weather sensors.
//
// Each sensor sends a ~15 ms packet at a fixed interval (16 s for a WH65, 61 s for a WH31, ...). The
// radio can't listen all the time without going deaf to the mesh, so the tracker learns each
// sensor's interval and then listens only around the moment its next packet is due.
// - A scan (scanFor, when the feature is switched on) listens without a break, long enough to hear
//   every sensor at least once.
// - A sensor whose interval isn't known yet, or that went quiet, is hunted: short windows at random
//   gaps, which sooner or later overlap one of its packets.
// Times are millis(); all arithmetic is wrap-safe.

#include <stdint.h>
#include "FineOffset.h"

namespace wxsensor {

struct Window {
  uint32_t start;   // millis() when the radio should start listening
  uint32_t len;     // how long, ms
  uint32_t key;     // the sensor it is for (0 = hunting)
};

class Tracker {
public:
  static constexpr int MAX_SENSORS = 12;
  static constexpr uint32_t HUNT_LEN = 400;          // ms per hunting window
  static constexpr uint32_t HUNT_GAP_MIN = 1500;     // ms between hunting windows: random in [min, max)
  static constexpr uint32_t HUNT_GAP_MAX = 4500;
  static constexpr uint32_t SCAN_LEN = 85000;     // a scan: longer than the slowest common sensor's interval
  static constexpr uint32_t MARGIN = 150;            // ms either side of an expected packet
  static constexpr uint32_t MARGIN_STEP = 150;       // added per missed packet
  static constexpr uint8_t MAX_MISSES = 4;           // then the sensor is hunted again
  static constexpr uint32_t PACKET_MS = 40;          // longest packet on the air (WS90: 32 bytes + preamble)

  struct Sensor {
    uint32_t key;
    Reading last;
    uint32_t heard_at;     // millis() of the last packet
    uint32_t period;       // ms between packets, 0 while unknown
    uint32_t next_due;     // millis() when the next packet should start (when period is known)
    uint32_t count;        // packets heard
    int16_t rssi;
    uint8_t misses;        // expected packets not heard in a row
    uint32_t posted_at;    // for the app: when it last showed this sensor
    bool posted;
  };

  Tracker() { reset(0); }
  void reset(uint32_t now);

  // A packet was decoded. Returns the sensor's entry (new or updated), or NULL if the table is full.
  Sensor* onPacket(uint32_t now, const Reading& r, int16_t rssi);

  // The next window to listen in, from now on. Returns false if nothing needs listening.
  bool nextWindow(uint32_t now, Window* w);

  // A window ended. heard_target: the sensor it was for was heard in it. ran: the radio actually
  // listened (false if the mesh kept it busy, which isn't held against the sensor).
  void windowDone(uint32_t now, const Window& w, bool heard_target, bool ran);

  // Listen without a break for ms from now (finds every sensor that sends at least that often)
  void scanFor(uint32_t now, uint32_t ms = SCAN_LEN);
  bool scanning(uint32_t now) const;
  // Hunt with random windows for at least ms
  void huntFor(uint32_t now, uint32_t ms);

  bool hunting(uint32_t now) const;
  int count() const { return _n; }
  Sensor* get(int i) { return i >= 0 && i < _n ? &_s[i] : NULL; }
  Sensor* find(uint32_t key);
  void setSeed(uint32_t seed) { _rng = seed ? seed : 1; }

  // nominal interval for a model, or 0 if unknown
  static uint32_t nominalPeriod(uint8_t model);

private:
  Sensor _s[MAX_SENSORS];
  int _n;
  uint32_t _hunt_until;      // hunt at least until then
  uint32_t _scan_until;      // listen without a break until then
  uint32_t _next_hunt;       // start of the next hunting window
  uint32_t _rng = 0x9E3779B9u;
  uint32_t rand32();
  void catchUp(Sensor& s, uint32_t now);
};

}  // namespace wxsensor
