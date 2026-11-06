#include "SensorTracker.h"
#include <string.h>

namespace wxsensor {

static bool before(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }

uint32_t Tracker::nominalPeriod(uint8_t model) {
  switch (model) {
    case WH65: return 16000;
    case WH31: return 61000;
    case WS80: return 4750;
    case WS90: return 8800;
    case WH40: return 49000;
    case WH51: return 70000;
    case WH57: return 79000;
    case LTV_TH: return 30000;
    case LTV_WSDTH: return 31000;
    default: return 0;
  }
}

uint8_t Tracker::maxMisses(uint8_t model) {
  return protocolOf(model) == PROTO_LACROSSE ? MAX_MISSES_SKIPPY : MAX_MISSES;
}

int Tracker::protocolCount() const {
  int n = 0;
  for (int p = 0; p < PROTO_COUNT; p++) if (_protos & (1 << p)) n++;
  return n;
}

uint8_t Tracker::nthProto(int n) const {
  for (int p = 0; p < PROTO_COUNT; p++) {
    if (_protos & (1 << p)) {
      if (n == 0) return (uint8_t)p;
      n--;
    }
  }
  return PROTO_FINEOFFSET;
}

void Tracker::reset(uint32_t now) {
  memset(_s, 0, sizeof(_s));
  _n = 0;
  _hunt_until = now;
  _scan_until = now;
  _scan_start = now;
  _scan_each = SCAN_LEN;
  _scan_forever = false;
  _next_hunt = now;
  if (_rng == 0) _rng = 0x9E3779B9u;
}

uint32_t Tracker::rand32() {   // xorshift32
  _rng ^= _rng << 13;
  _rng ^= _rng >> 17;
  _rng ^= _rng << 5;
  return _rng;
}

Tracker::Sensor* Tracker::find(uint32_t key) {
  for (int i = 0; i < _n; i++) if (_s[i].key == key) return &_s[i];
  return NULL;
}

void Tracker::scanFor(uint32_t now, uint32_t ms) {
  if (ms == 0) { _scan_until = now; return; }   // no scan
  int n = protocolCount();
  _scan_start = now;
  _scan_each = ms;
  _scan_until = now + ms * (uint32_t)n;
}

bool Tracker::scanning(uint32_t now) const {
  return _scan_forever || before(now, _scan_until);
}

void Tracker::scanForever(uint32_t now, bool on) {
  _scan_forever = on;
  _scan_start = now;
  _scan_each = SCAN_SLICE;
  _scan_until = now;
}

void Tracker::huntFor(uint32_t now, uint32_t ms) {
  if (before(_hunt_until, now + ms)) _hunt_until = now + ms;
  _next_hunt = now;
}

bool Tracker::hunting(uint32_t now) const {
  if (before(now, _hunt_until)) return true;
  for (int i = 0; i < _n; i++) if (_s[i].period == 0) return true;
  return false;
}

Tracker::Sensor* Tracker::onPacket(uint32_t now, const Reading& r, int16_t rssi) {
  uint32_t key = sensorKey(r);
  Sensor* s = find(key);
  if (!s) {
    if (_n == MAX_SENSORS) return NULL;
    s = &_s[_n++];
    memset(s, 0, sizeof(*s));
    s->key = key;
    s->period = nominalPeriod(r.model);   // a first guess, checked by the next packet; 0 = hunt for it
  } else if (s->count > 0) {
    uint32_t d = now - s->heard_at;
    if (d > 1000) {   // a repeat within a second (some models send twice) says nothing about the period
      uint32_t nom = nominalPeriod(r.model);
      uint32_t est = d;
      if (nom) {   // d may span several intervals: divide by the nearest whole number of nominal ones
        uint32_t k = (d + nom / 2) / nom;
        if (k >= 1) {
          uint32_t p = d / k;
          if (p > nom - nom / 7 && p < nom + nom / 7) est = p;
        }
      }
      if (s->period == 0) {
        // back after being lost (or first heard while hunting): a gap that isn't a whole number of
        // nominal intervals means the sensor restarted on a new schedule, so start from the nominal one
        s->period = (nom && est == d && d > nom + nom / 7) ? nom : est;
      } else {
        uint32_t k = (d + s->period / 2) / s->period;
        if (k == 0) {
          s->period = d;   // faster than we thought (eg. a WH51 sends every 10 s while the soil changes)
        } else {
          uint32_t p = d / k;
          if (p > s->period - s->period / 10 && p < s->period + s->period / 10) {
            s->period = (s->period * 3 + p) / 4;   // follow slow drift
          } else if (est < s->period) {
            s->period = est;   // a shorter interval: the old one was a multiple
          }
        }
      }
    }
  }
  s->last = r;
  s->heard_at = now;
  s->next_due = now + s->period;
  s->count++;
  s->rssi = rssi;
  s->misses = 0;
  return s;
}

// Moves next_due past packets whose windows are already over (missed or skipped)
void Tracker::catchUp(Sensor& s, uint32_t now) {
  uint32_t m = MARGIN + MARGIN_STEP * (s.misses < MARGIN_MISSES ? s.misses : MARGIN_MISSES);
  if (before(s.next_due + m, now)) {
    uint32_t behind = now - (s.next_due + m);
    s.next_due += (behind / s.period + 1) * s.period;
  }
}

bool Tracker::nextWindow(uint32_t now, Window* w) {
  if (scanning(now)) {
    uint32_t k = (now - _scan_start) / _scan_each;   // which format's turn
    w->start = now;
    w->len = _scan_start + (k + 1) * _scan_each - now;
    w->key = 0;
    w->proto = nthProto((int)(_scan_forever ? k % (uint32_t)protocolCount() : k));
    return true;
  }
  bool found = false;
  for (int i = 0; i < _n; i++) {
    Sensor& s = _s[i];
    if (s.period == 0) continue;
    catchUp(s, now);
    uint32_t m = MARGIN + MARGIN_STEP * (s.misses < MARGIN_MISSES ? s.misses : MARGIN_MISSES);
    uint32_t start = s.next_due - m;
    if (!found || before(start, w->start)) {
      w->start = start;
      w->len = 2 * m + PACKET_MS;
      w->key = s.key;
      w->proto = protocolOf(s.last.model);
      found = true;
    }
  }
  if (hunting(now)) {
    if (!found || before(_next_hunt, w->start)) {
      w->start = _next_hunt;
      w->len = HUNT_LEN;
      w->key = 0;
      w->proto = nthProto(_hunt_turn % protocolCount());
      found = true;
    }
  }
  if (found && before(w->start, now)) {   // late: keep what's left of it
    uint32_t late = now - w->start;
    w->len = late < w->len ? w->len - late : 0;
    w->start = now;
    if (w->len < PACKET_MS) {   // too little left to hear a packet: skip it
      if (w->key) {
        Sensor* s = find(w->key);
        if (s) s->next_due += s->period;
      } else {
        _next_hunt = now + HUNT_GAP_MIN;
      }
      return false;
    }
  }
  return found;
}

void Tracker::windowDone(uint32_t now, const Window& w, bool heard_target, bool ran) {
  if (w.key == 0) {
    if (!scanning(now)) _hunt_turn++;
    _next_hunt = now + HUNT_GAP_MIN + rand32() % (HUNT_GAP_MAX - HUNT_GAP_MIN);
    return;
  }
  Sensor* s = find(w.key);
  if (!s || heard_target) return;
  // not heard: the next window is for the packet after
  if (s->period) {
    s->next_due += s->period;
    if (ran && ++s->misses >= maxMisses(s->last.model)) {
      s->period = 0;   // lost it: hunt again
      s->misses = 0;
    }
  }
}

}  // namespace wxsensor
