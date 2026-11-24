#pragma once

// Car-repeater geofence: when the car is parked at home the repeater stops repeating and its
// radio sleeps; when the car leaves home it repeats again. "Home" is a set of Wi-Fi access
// points (BSSIDs) heard by a passive scan; motion (an accelerometer) tells when to scan.
//
//   AWAY     repeating. Once the car has been still for `still` seconds, scan: home -> HOME.
//            A miss is tried once more AWAY_RETRY_SECS later, then every AWAY_RESCAN_MINS (while
//            still); motion starts the wait for stillness again. Driving: no scans at all.
//   HOME     radio asleep, not repeating. A backup scan every `check` minutes; a miss -> LEAVING.
//            Motion -> LEAVING.
//   LEAVING  radio still asleep. Scan at once (but at most one scan per HOME_GAP_SECS, so a car
//            jostled at home doesn't scan on every bump), then every LEAVE_SCAN_SECS: home ->
//            HOME; LEAVE_MISSES misses in a row -> AWAY.
//
// Home Wi-Fi never goes out (the user's rule), so "home not heard" always means "not at home".
// A scan that could not run (radio busy, error) is retried and never counts as a miss.
// The button keeps the radio on for `awake` minutes (admin over LoRa) whatever the state.
//
// Pure logic: no Arduino, no radio. The caller feeds it time, motion, button and scan results,
// and does what radioOn() and scanDue() say. All times are millis(), wrap-safe.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GEO_MAX_HOME 8

struct GeoFencePrefs {
  uint8_t version;
  uint8_t enabled;
  uint8_t num_home;
  uint8_t home[GEO_MAX_HOME][5];   // BSSID bytes 1-5: the first byte differs between the SSIDs of one AP
  uint16_t still_secs;             // still this long before deciding "parked"
  uint16_t check_mins;             // HOME: backup scan period
  uint16_t awake_mins;             // button: radio on this long

  static const uint8_t VERSION = 1;

  void setDefaults() {
    memset(this, 0, sizeof(*this));
    version = VERSION;
    still_secs = 180;
    check_mins = 60;
    awake_mins = 10;
  }
  // Loaded bytes may be from another version or damaged: anything out of range -> defaults
  bool isValid() const {
    return version == VERSION && enabled <= 1 && num_home <= GEO_MAX_HOME &&
           still_secs >= 10 && still_secs <= 3600 &&
           check_mins >= 5 && check_mins <= 1440 &&
           awake_mins >= 1 && awake_mins <= 240;
  }
};

struct GeoScanAp {
  uint8_t mac[6];
  int8_t rssi;
};

class GeoFence {
public:
  enum State : uint8_t { OFF, AWAY, HOME, LEAVING };
  enum ScanResult : uint8_t { SAW_HOME, MISSED, FAILED };

  static const uint32_t AWAY_RETRY_SECS = 60;    // AWAY, still: one more try after the first miss
  static const uint32_t AWAY_RESCAN_MINS = 15;   // AWAY, still, home missed twice: scan again after
  static const uint32_t HOME_GAP_SECS = 120;     // HOME, moved: at most one scan per this
  static const uint32_t LEAVE_SCAN_SECS = 30;
  static const uint8_t LEAVE_MISSES = 2;
  static const uint32_t RETRY_SECS = 10;         // a scan that could not run

  struct Stats {
    uint32_t scans, saw_home, missed, failed;
    uint32_t to_home, to_leaving, to_away;
    uint32_t motion, button;
    uint32_t home_ms;      // time spent in HOME and LEAVING (radio asleep unless awake)
  };

private:
  GeoFencePrefs* _p;
  State _state = OFF;
  bool _pinned = false;          // "geo force home": stay HOME, no scans (battery soak away from home)
  uint32_t _last_motion = 0;
  bool _scan_set = false;
  uint32_t _scan_at = 0;
  uint8_t _misses = 0;           // AWAY, LEAVING: misses in a row
  bool _scanned = false;         // a scan has finished (_last_scan is set)
  uint32_t _last_scan = 0;
  bool _awake = false;
  uint32_t _awake_until = 0;
  uint32_t _state_since = 0;
  uint32_t _home_since = 0;      // for Stats::home_ms
  Stats _stats;

  static bool reached(uint32_t now, uint32_t at) { return (int32_t)(now - at) >= 0; }
  bool still(uint32_t now) const { return now - _last_motion >= (uint32_t)_p->still_secs * 1000; }
  void scanAt(uint32_t at) { _scan_set = true; _scan_at = at; }
  bool asleep(State s) const { return s == HOME || s == LEAVING; }

  void enter(State s, uint32_t now) {
    if (asleep(_state) && !asleep(s)) _stats.home_ms += now - _home_since;
    if (!asleep(_state) && asleep(s)) _home_since = now;
    if (s == HOME && _state != HOME) _stats.to_home++;
    if (s == LEAVING) _stats.to_leaving++;
    if (s == AWAY && _state != AWAY && _state != OFF) _stats.to_away++;
    _state = s;
    _state_since = now;
    _misses = 0;
    _scan_set = false;
    if (s == HOME) scanAt(now + (uint32_t)_p->check_mins * 60000);
    if (s == LEAVING) {   // first scan at once, unless one ran within HOME_GAP_SECS (moving about at home)
      const uint32_t gap = HOME_GAP_SECS * 1000;
      scanAt(_scanned && now - _last_scan < gap ? _last_scan + gap : now);
    }
  }

public:
  explicit GeoFence(GeoFencePrefs& prefs) : _p(&prefs) { memset(&_stats, 0, sizeof(_stats)); }

  // Call after the prefs are loaded or changed (enabled on/off)
  void begin(uint32_t now) {
    _last_motion = now;    // assume moving at boot: wait for stillness before the first scan
    _pinned = false;
    enter(_p->enabled && _p->num_home > 0 ? AWAY : OFF, now);
  }

  State state() const { return _state; }
  bool pinned() const { return _pinned; }
  uint32_t stateSince() const { return _state_since; }
  const Stats& stats() const { return _stats; }
  uint32_t homeMillis(uint32_t now) const { return _stats.home_ms + (asleep(_state) ? now - _home_since : 0); }
  bool awake(uint32_t now) const { return _awake && !reached(now, _awake_until); }
  uint32_t lastMotion() const { return _last_motion; }

  static const char* stateName(State s) {
    switch (s) {
      case AWAY: return "away";
      case HOME: return "home";
      case LEAVING: return "leaving";
      default: return "off";
    }
  }

  // Repeat (radio on) unless parked at home. The button keeps it on for a while.
  bool radioOn(uint32_t now) const { return !asleep(_state) || awake(now); }

  void onMotion(uint32_t now) {
    _stats.motion++;
    _last_motion = now;
    if (_pinned) return;
    if (_state == AWAY) {          // moving: wait for stillness again
      _misses = 0;
      _scan_set = false;
    } else if (_state == HOME) {
      enter(LEAVING, now);
    }
  }

  void onButton(uint32_t now) {
    _stats.button++;
    _awake = true;
    _awake_until = now + (uint32_t)_p->awake_mins * 60000;
  }
  void endAwake() { _awake = false; }

  // Is a Wi-Fi scan due now? Run it and report with onScan().
  bool scanDue(uint32_t now) {
    if (_state == OFF || _pinned) return false;
    if (_state == AWAY && !_scan_set && still(now)) scanAt(now);
    return _scan_set && reached(now, _scan_at);
  }

  // When the next scan is due (for status); false if none is planned
  bool nextScan(uint32_t& at) const {
    if (_state == OFF || _pinned || !_scan_set) return false;
    at = _scan_at;
    return true;
  }

  void onScan(uint32_t now, ScanResult r) {
    if (_state == OFF || _pinned) return;
    if (r == FAILED) {
      _stats.failed++;
      scanAt(now + RETRY_SECS * 1000);
      return;
    }
    _stats.scans++;
    _scanned = true;
    _last_scan = now;
    const bool saw = r == SAW_HOME;
    if (saw) _stats.saw_home++; else _stats.missed++;
    switch (_state) {
      case AWAY:   // still for still_secs: one hit is home; a miss is tried once more, then every 15 min
        if (saw) enter(HOME, now);
        else if (++_misses == 1) scanAt(now + AWAY_RETRY_SECS * 1000);
        else scanAt(now + AWAY_RESCAN_MINS * 60000);
        break;
      case HOME:
        if (saw) {
          scanAt(now + (uint32_t)_p->check_mins * 60000);
        } else {
          enter(LEAVING, now);
          _misses = 1;
          scanAt(now + LEAVE_SCAN_SECS * 1000);
        }
        break;
      case LEAVING:
        if (saw) {
          enter(HOME, now);   // moving again re-checks, at most once per HOME_GAP_SECS
          break;
        } else if (++_misses >= LEAVE_MISSES) {
          enter(AWAY, now);
          break;
        }
        scanAt(now + LEAVE_SCAN_SECS * 1000);
        break;
      default:
        break;
    }
  }

  // Force a state: HOME pins it there (no scans, motion ignored) for a battery soak anywhere;
  // AWAY starts over from AWAY; OFF (or "auto") unpins.
  void force(State s, uint32_t now) {
    if (_state == OFF && s != OFF) return;   // geofence off: nothing to force
    _pinned = s == HOME;
    if (s == OFF) {
      _pinned = false;
      _last_motion = now;
      enter(AWAY, now);
    } else {
      enter(s, now);
      if (_pinned) _scan_set = false;
    }
  }

  // --- home access points ---

  static bool sameAp(const uint8_t mac[6], const uint8_t saved[5]) { return memcmp(mac + 1, saved, 5) == 0; }

  bool isHome(const uint8_t mac[6]) const {
    for (int i = 0; i < _p->num_home; i++) {
      if (sameAp(mac, _p->home[i])) return true;
    }
    return false;
  }

  // Does this scan see home? (any saved AP, any signal)
  ScanResult judge(const GeoScanAp* aps, int n) const {
    for (int i = 0; i < n; i++) {
      if (isHome(aps[i].mac)) return SAW_HOME;
    }
    return MISSED;
  }

  // Saves the access points of a scan made at home: those at or above min_rssi, strongest
  // first, one entry per AP (SSIDs of one AP differ only in the first byte), at most GEO_MAX_HOME.
  // Returns how many were saved; 0 leaves the old list alone. add: keep the saved APs first and
  // add new ones after them (returns the new total).
  int setHome(const GeoScanAp* aps, int n, int8_t min_rssi, bool add = false) {
    uint8_t home[GEO_MAX_HOME][5];
    int count = 0;
    if (add) {
      memcpy(home, _p->home, sizeof(home));
      count = _p->num_home;
    }
    const int kept = count;
    bool used[64] = { false };
    if (n > 64) n = 64;
    while (count < GEO_MAX_HOME) {
      int best = -1;
      for (int i = 0; i < n; i++) {
        if (used[i] || aps[i].rssi < min_rssi) continue;
        if (best < 0 || aps[i].rssi > aps[best].rssi) best = i;
      }
      if (best < 0) break;
      used[best] = true;
      bool dup = false;
      for (int j = 0; j < count; j++) dup |= sameAp(aps[best].mac, home[j]);
      if (!dup) memcpy(home[count++], aps[best].mac + 1, 5);
    }
    if (count == kept) return 0;
    memcpy(_p->home, home, sizeof(home));
    _p->num_home = count;
    return count;
  }

  void clearHome() { _p->num_home = 0; memset(_p->home, 0, sizeof(_p->home)); }
};

// CLI for what needs no radio: the caller handles "geo home set/add", "geo scan" and "geo log".
//   geo                         state, next scan, awake
//   geo on | off                (on needs home APs)
//   geo home                    list the saved home APs ("?" for the ignored first byte)
//   geo home clear
//   geo still [10-3600]         seconds still before "parked" (no number: show it; same below)
//   geo check <5-1440>          minutes between backup scans at home
//   geo awake <1-240>           minutes the button keeps the radio on
//   geo force home|away|auto    home = pinned asleep with no scans (battery soak)
//   geo stats
// changed: a pref changed (caller saves). restart: the caller should call begin() (on/off).
// Returns true if it was a geo command.
inline bool handleGeoCommand(GeoFence& geo, GeoFencePrefs& p, const char* cmd, uint32_t now,
                             char* reply, bool& changed, bool& restart) {
  changed = restart = false;
  if (strncmp(cmd, "geo", 3) != 0 || (cmd[3] != 0 && cmd[3] != ' ')) return false;
  const char* a = cmd[3] ? cmd + 4 : "";

  auto number = [](const char* s, long lo, long hi, long& out) {
    if (!*s) return false;
    char* end;
    out = strtol(s, &end, 10);
    return *end == 0 && out >= lo && out <= hi;
  };
  long v;

  if (*a == 0) {
    int len = snprintf(reply, 160, "> %s%s, %u home APs", GeoFence::stateName(geo.state()),
                       geo.pinned() ? " (forced)" : "", (unsigned)p.num_home);
    len += snprintf(reply + len, 160 - len, ", %s %lus", geo.radioOn(now) ? "radio on" : "radio asleep",
                    (unsigned long)((now - geo.stateSince()) / 1000));
    uint32_t at;
    if (geo.nextScan(at) && len < 160) {
      long secs = (long)(int32_t)(at - now) / 1000;
      len += snprintf(reply + len, 160 - len, ", scan in %lds", secs < 0 ? 0 : secs);
    }
    if (geo.awake(now) && len < 160) snprintf(reply + len, 160 - len, ", awake (button)");
    return true;
  }
  if (strcmp(a, "on") == 0 || strcmp(a, "off") == 0) {
    const bool on = a[1] == 'n';
    if (on && p.num_home == 0) {
      strcpy(reply, "Error: no home APs: park at home and run 'geo home set'");
      return true;
    }
    p.enabled = on;
    changed = restart = true;
    strcpy(reply, "OK");
    return true;
  }
  if (strcmp(a, "home") == 0) {
    int len = snprintf(reply, 160, "> %u:", (unsigned)p.num_home);
    for (int i = 0; i < p.num_home && len < 140; i++) {
      const uint8_t* m = p.home[i];
      len += snprintf(reply + len, 160 - len, " ??%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3], m[4]);
    }
    return true;
  }
  if (strcmp(a, "home clear") == 0) {
    geo.clearHome();
    p.enabled = 0;
    changed = restart = true;
    strcpy(reply, "OK, geofence off");
    return true;
  }
  if (strcmp(a, "still") == 0) { snprintf(reply, 160, "> %u s", (unsigned)p.still_secs); return true; }
  if (strcmp(a, "check") == 0) { snprintf(reply, 160, "> %u min", (unsigned)p.check_mins); return true; }
  if (strcmp(a, "awake") == 0) { snprintf(reply, 160, "> %u min", (unsigned)p.awake_mins); return true; }
  if (strncmp(a, "still ", 6) == 0) {
    if (!number(a + 6, 10, 3600, v)) { strcpy(reply, "Error: still 10-3600 seconds"); return true; }
    p.still_secs = (uint16_t)v;
    changed = true;
    strcpy(reply, "OK");
    return true;
  }
  if (strncmp(a, "check ", 6) == 0) {
    if (!number(a + 6, 5, 1440, v)) { strcpy(reply, "Error: check 5-1440 minutes"); return true; }
    p.check_mins = (uint16_t)v;
    changed = true;
    strcpy(reply, "OK");
    return true;
  }
  if (strncmp(a, "awake ", 6) == 0) {
    if (!number(a + 6, 1, 240, v)) { strcpy(reply, "Error: awake 1-240 minutes"); return true; }
    p.awake_mins = (uint16_t)v;
    changed = true;
    strcpy(reply, "OK");
    return true;
  }
  if (strncmp(a, "force ", 6) == 0) {
    const char* s = a + 6;
    if (geo.state() == GeoFence::OFF) { strcpy(reply, "Error: geofence is off"); return true; }
    if (strcmp(s, "home") == 0) geo.force(GeoFence::HOME, now);
    else if (strcmp(s, "away") == 0) geo.force(GeoFence::AWAY, now);
    else if (strcmp(s, "auto") == 0) geo.force(GeoFence::OFF, now);
    else { strcpy(reply, "Error: force home|away|auto"); return true; }
    strcpy(reply, "OK");
    return true;
  }
  if (strcmp(a, "stats") == 0) {
    const GeoFence::Stats& s = geo.stats();
    snprintf(reply, 160, "> scans %lu home %lu miss %lu fail %lu, to home %lu leaving %lu away %lu, motion %lu btn %lu, asleep %lum",
             (unsigned long)s.scans, (unsigned long)s.saw_home, (unsigned long)s.missed, (unsigned long)s.failed,
             (unsigned long)s.to_home, (unsigned long)s.to_leaving, (unsigned long)s.to_away,
             (unsigned long)s.motion, (unsigned long)s.button, (unsigned long)(geo.homeMillis(now) / 60000));
    return true;
  }
  return false;   // "geo home set/add", "geo scan", "geo log", or unknown: the caller's
}
