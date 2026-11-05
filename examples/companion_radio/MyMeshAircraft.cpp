// Aircraft in the MeshCore app (docs/aircraft.md).
//
// Light aircraft in the US report their position on 978 MHz (UAT ADS-B) about once a second. The
// LR2021 steps away from the mesh for short FSK listens (CustomLR2021Wrapper), the messages are
// error-corrected and decoded (src/helpers/aircraft/Uat.*), and each aircraft shows in the app as
// a post in an "Aircraft" channel: when first heard, then every few minutes while it's around.
// Receive only: nothing is ever sent on 978 MHz.

#include "MyMesh.h"

#define AIR_WINDOW_MS   300      // one listen, when sharing the radio with the mesh
#define AIR_FOREVER_MS  5000     // one listen when listening all the time
#define AIR_REPLY_MAX   140
#define AIR_GONE_MS     (5 * 60000UL)   // an aircraft not heard for this long is dropped

// 'air dbg' overrides for receiver experiments (not saved): sync bits, preamble detect, rx bw, deviation, kbps
static struct { uint8_t sync_bits, pre_det; float rxbw, dev, kbps; bool on; } dbg = {};

static mesh::Radio::FskListen uatListen(float freq) {
  mesh::Radio::FskListen cfg = {};
  cfg.freq = freq;
  cfg.kbps = 1041.667f;
  cfg.dev_khz = 312.5f;
  cfg.rxbw_khz = 2222.0f;   // datasheet: 2 x 312.5 kHz deviation + 1041.7 kbit/s + crystal error, about 1.7 MHz
  // 36-bit sync word 0xEACDDA4E2, as the last 36 bits of 5 bytes; UAT sends no preamble
  cfg.sync[0] = 0x0E; cfg.sync[1] = 0xAC; cfg.sync[2] = 0xDD; cfg.sync[3] = 0xA4; cfg.sync[4] = 0xE2;
  cfg.sync_len = 5;
  cfg.sync_bits = 36;
  cfg.no_preamble = true;
  cfg.pkt_len = uat::LONG_BYTES;
  if (dbg.on) {
    if (dbg.sync_bits) cfg.sync_bits = dbg.sync_bits;
    cfg.pre_det_bits = dbg.pre_det;
    if (dbg.pre_det) cfg.no_preamble = false;
    if (dbg.rxbw > 0) cfg.rxbw_khz = dbg.rxbw;
    if (dbg.dev > 0) cfg.dev_khz = dbg.dev;
    if (dbg.kbps > 0) cfg.kbps = dbg.kbps;
  }
  return cfg;
}

bool MyMesh::isAircraftChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _air_active && idx == MAX_GROUP_CHANNELS + (_mt_active ? 1 : 0) + (_wx_active ? 1 : 0);
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::applyAircraft() {
  bool was = _air_active;
  if (!_prefs.air.en) {
    if (_air_listening) _radio->stopFskListen();
    _air_active = _air_listening = _air_forever = false;
    return;
  }
  _air_active = _radio->startFskListen(uatListen(_prefs.air.freq), 1);   // probe: radios without FSK listens say no
  _radio->stopFskListen();
  _air_listening = false;
  if (_air_active && !was) {
    _n_planes = 0;
    _air_heard = _air_bad = _air_fixed = _air_shown = _air_listen_ms = 0;
    _air_since = millis();
    _air_next = millis();
  }
}

static void fmtThousands(char* out, size_t n, int32_t v) {
  if (v < 0) { snprintf(out, n, "%ld", (long) v); return; }
  if (v >= 1000) snprintf(out, n, "%ld,%03ld", (long)(v / 1000), (long)(v % 1000));
  else snprintf(out, n, "%ld", (long) v);
}

// eg. "N123AB 5,800 ft, 1.3 mi NNW, 79 kt heading 299, climbing" (or the address, or lat/lon if this
// radio has no location set)
void MyMesh::describePlane(const Plane& p, char* out, size_t n) {
  const uat::Report& r = p.last;
  int m = snprintf(out, n, "%s", p.callsign[0] ? p.callsign : "");
  if (m < 0 || (size_t) m >= n) return;
  m += snprintf(&out[m], n - m, "%s%06lx", p.callsign[0] ? " " : "", (unsigned long) p.address);
  if (r.qualifier == 2 || r.qualifier == 3) m += snprintf(&out[m], n - m, " (via radar)");
  if ((size_t) m >= n) return;
  if (r.ag_state == 2) m += snprintf(&out[m], n - m, " on the ground");
  else if (r.has_alt) {
    char a[16];
    fmtThousands(a, sizeof(a), r.alt_ft);
    m += snprintf(&out[m], n - m, " %s ft", a);
  }
  if ((size_t) m >= n) return;
  if (r.has_pos) {
    if (_prefs.node_lat != 0 || _prefs.node_lon != 0) {
      uint32_t d; uint16_t b;
      uat::distanceBearing((int32_t)(_prefs.node_lat * 1e5), (int32_t)(_prefs.node_lon * 1e5), r.lat_e5, r.lon_e5, &d, &b);
      m += snprintf(&out[m], n - m, ", %lu.%lu mi %s", (unsigned long)(d / 10), (unsigned long)(d % 10), wxsensor::compass(b));
    } else {
      m += snprintf(&out[m], n - m, ", %ld.%04ld,%s%ld.%04ld", (long)(r.lat_e5 / 100000), (long)(labs(r.lat_e5) % 100000 / 10),
                    r.lon_e5 < 0 && r.lon_e5 > -100000 ? "-" : "", (long)(r.lon_e5 / 100000), (long)(labs(r.lon_e5) % 100000 / 10));
    }
  }
  if ((size_t) m >= n) return;
  if (r.has_speed && r.ag_state != 2) m += snprintf(&out[m], n - m, ", %u kt heading %u", r.speed_kt, r.track_deg);
  if ((size_t) m >= n) return;
  if (r.has_vs && r.vs_fpm >= 300) snprintf(&out[m], n - m, ", climbing");
  else if (r.has_vs && r.vs_fpm <= -300) snprintf(&out[m], n - m, ", descending");
}

void MyMesh::aircraftLoop() {
  if (!_air_active) return;
  uint32_t now = millis();

  uint8_t buf[uat::LONG_BYTES];
  float rssi = 0;
  for (int k = 0; k < 4 && _fsk_owner == 2; k++) {
    int len = _radio->recvFsk(buf, sizeof(buf), &rssi);
    if (len <= 0) break;
    _air_heard++;
    int fixed = 0;
    int n = uat::correct(buf, len, &fixed);
    uat::Report r;
    if (n == 0 || !uat::decode(buf, n, &r)) { _air_bad++; continue; }
    if (fixed) _air_fixed++;
    Plane* p = NULL;
    for (int i = 0; i < _n_planes; i++) if (_planes[i].address == r.address) { p = &_planes[i]; break; }
    bool is_new = p == NULL;
    if (is_new) {
      if (_n_planes < MAX_PLANES) {
        p = &_planes[_n_planes++];
      } else {   // replace the one heard longest ago
        p = &_planes[0];
        for (int i = 1; i < _n_planes; i++) if ((int32_t)(_planes[i].heard_at - p->heard_at) < 0) p = &_planes[i];
      }
      memset(p, 0, sizeof(*p));
      p->address = r.address;
    }
    // keep the last known position/altitude when a message doesn't carry them
    uat::Report merged = r;
    if (!is_new) {
      if (!r.has_pos) { merged.has_pos = p->last.has_pos; merged.lat_e5 = p->last.lat_e5; merged.lon_e5 = p->last.lon_e5; }
      if (!r.has_alt) { merged.has_alt = p->last.has_alt; merged.alt_ft = p->last.alt_ft; }
      if (!r.has_speed) { merged.has_speed = p->last.has_speed; merged.speed_kt = p->last.speed_kt; merged.track_deg = p->last.track_deg; }
    }
    p->last = merged;
    if (r.callsign[0] && !r.callsign_is_squawk) memcpy(p->callsign, r.callsign, sizeof(p->callsign));
    p->heard_at = now;
    p->count++;
    p->rssi = (int16_t) rssi;

    bool in_range = true;
    if (_prefs.air.range && merged.has_pos && (_prefs.node_lat != 0 || _prefs.node_lon != 0)) {
      uint32_t d;
      uat::distanceBearing((int32_t)(_prefs.node_lat * 1e5), (int32_t)(_prefs.node_lon * 1e5), merged.lat_e5, merged.lon_e5, &d, NULL);
      in_range = d <= (uint32_t) _prefs.air.range * 10;
    }
    char text[MAX_FRAME_SIZE];
    if (is_new && _air_forever) {
      int m = snprintf(text, sizeof(text), "New aircraft, %d dBm: ", (int) rssi);
      if (m > 0 && m < (int) sizeof(text)) describePlane(*p, &text[m], sizeof(text) - m);
      ChatRef to;
      memset(&to, 0, sizeof(to));
      to.kind = CHAT_CONSOLE;
      postToChat(to, text);
    }
    // post once it has a position (the first message may not carry one)
    bool due = !p->posted || (_prefs.air.every && now - p->posted_at >= (uint32_t) _prefs.air.every * 60000UL);
    if (in_range && merged.has_pos && due) {
      describePlane(*p, text, sizeof(text));
#ifdef MAX_GROUP_CHANNELS
      int idx = MAX_GROUP_CHANNELS + (_mt_active ? 1 : 0) + (_wx_active ? 1 : 0);
      pushChannelText(idx, getRTCClock()->getCurrentTimeUnique(), 0, 0, text, strlen(text));
#endif
      _air_shown++;
      p->posted = true;
      p->posted_at = now;
    }
  }

  // forget aircraft long gone
  for (int i = 0; i < _n_planes;) {
    if (now - _planes[i].heard_at > AIR_GONE_MS) _planes[i] = _planes[--_n_planes];
    else i++;
  }

  // the radio's listen: weather's tracked windows come first
  int st = _radio->fskListenState();
  if (_air_listening) {
    if (st == 0 || _fsk_owner != 2) {
      if (_fsk_owner == 2) _air_listen_ms += _radio->lastFskListenMillis();
      _air_listening = false;
      uint32_t gap = _air_forever ? 0 : (uint32_t) AIR_WINDOW_MS * (100 - _prefs.air.duty) / (_prefs.air.duty ? _prefs.air.duty : 1);
      _air_next = now + gap;
    }
    return;
  }
  if (st != 0 || _wx_win_open) return;
  if ((int32_t)(now - _air_next) < 0) return;
  if (_radio->startFskListen(uatListen(_prefs.air.freq), _air_forever ? AIR_FOREVER_MS : AIR_WINDOW_MS)) {
    _fsk_owner = 2;
    _air_listening = true;
  }
}

static bool airOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}

bool MyMesh::handleAircraftCommand(const char* command, char* reply) {
  bool on;
  if (strcmp(command, "air") == 0 || strcmp(command, "get air") == 0) {
    char listen[24], range[16];
    if (_air_forever) strcpy(listen, "all the time");
    else snprintf(listen, sizeof(listen), "%u%% of the time", _prefs.air.duty);
    if (_prefs.air.range) snprintf(range, sizeof(range), "%u mi", _prefs.air.range);
    else strcpy(range, "any");
    sprintf(reply, "> Aircraft %s: %.3f MHz UAT, listening %s, posts every %u min, range %s",
            _prefs.air.en ? (_air_active ? "on" : "on, but the radio can't") : "off", _prefs.air.freq,
            listen, _prefs.air.every, range);
    return true;
  }
  if (strcmp(command, "get air.planes") == 0) {
    if (_n_planes == 0) { strcpy(reply, "> none heard in the last 5 min"); return true; }
    int n = sprintf(reply, ">");
    uint32_t now = millis();
    for (int i = 0; i < _n_planes; i++) {
      char d[96];
      describePlane(_planes[i], d, sizeof(d));
      int room = AIR_REPLY_MAX - n;
      int w = snprintf(&reply[n], room, "%s %s (%lus)", i ? ";" : "", d, (unsigned long)((now - _planes[i].heard_at) / 1000));
      if (w < 0 || w >= room) { reply[n] = 0; break; }
      n += w;
    }
    return true;
  }
  if (strcmp(command, "get air.stats") == 0) {
    uint32_t up = millis() - _air_since;
    unsigned pct10 = up ? (unsigned)((uint64_t)_air_listen_ms * 1000 / up) : 0;
    sprintf(reply, "> %lu messages (%lu corrected, %lu bad), %d aircraft now, %lu posts, listening %u.%u%% of the time",
            (unsigned long)_air_heard, (unsigned long)_air_fixed, (unsigned long)_air_bad, _n_planes,
            (unsigned long)_air_shown, pct10 / 10, pct10 % 10);
    return true;
  }
  if (strncmp(command, "air dbg", 7) == 0) {   // air dbg <sync bits> <preamble detect bits> <rx bw kHz> <dev kHz> <kbps> | air dbg off
    if (strcmp(command, "air dbg off") == 0) { dbg.on = false; strcpy(reply, "OK - defaults"); return true; }
    // whole numbers: newlib-nano's sscanf has no %f. Rates in bit/s, bandwidth and deviation in Hz
    long sb = 0, pd = 0, bw = 0, dv = 0, kb = 0;
    sscanf(&command[7], "%ld %ld %ld %ld %ld", &sb, &pd, &bw, &dv, &kb);
    dbg.sync_bits = (uint8_t) sb; dbg.pre_det = (uint8_t) pd; dbg.rxbw = bw / 1000.0f; dbg.dev = dv / 1000.0f;
    dbg.kbps = kb / 1000.0f; dbg.on = true;
    sprintf(reply, "OK - sync %ld bits, preamble detect %ld, rx bw %ld Hz, dev %ld Hz, %ld bit/s", sb, pd, bw, dv, kb);
    return true;
  }
  if (strcmp(command, "air scan on") == 0 || strcmp(command, "air scan off") == 0) {
    if (!_air_active) { strcpy(reply, "Error: aircraft is off ('air on')"); return true; }
    _air_forever = command[9] == 'o' && command[10] == 'n';
    strcpy(reply, _air_forever ? "OK - listening on 978 MHz all the time; each new aircraft shows here. The mesh can't "
                                 "be heard until 'air scan off' (sending still works)"
                               : "OK - back to sharing the radio");
    return true;
  }
  const char* arg = NULL;
  if (strncmp(command, "air ", 4) == 0 && airOnOff(&command[4], &on)) arg = &command[4];
  else if (strncmp(command, "set air ", 8) == 0 && airOnOff(&command[8], &on)) arg = &command[8];
  if (arg) {
    _prefs.air.en = on ? 1 : 0;
    applyAircraft();
    if (on && !_air_active) {
      _prefs.air.en = 0;
      strcpy(reply, "Error: this radio can't listen to aircraft (needs an LR2021)");
    } else {
      savePrefs();
      strcpy(reply, on ? "OK - Aircraft on. Reconnect the app to see the channel" : "OK - Aircraft off");
    }
    return true;
  }
  if (strncmp(command, "set air.", 8) != 0) return false;
  const char* setting = &command[8];
  if (strncmp(setting, "every ", 6) == 0) {
    int m = atoi(&setting[6]);
    if (m < 0 || m > 1440) { strcpy(reply, "Error: minutes, 0-1440 (0 = first sighting only)"); return true; }
    _prefs.air.every = (uint16_t) m;
  } else if (strncmp(setting, "range ", 6) == 0) {
    int m = atoi(&setting[6]);
    if (m < 0 || m > 500) { strcpy(reply, "Error: miles, 0-500 (0 = all)"); return true; }
    _prefs.air.range = (uint16_t) m;
  } else if (strncmp(setting, "freq ", 5) == 0) {   // for bench tests; aircraft are on 978
    float f = (float) atof(&setting[5]);
    if (f < 150 || f > 1100) { strcpy(reply, "Error: frequency in MHz"); return true; }
    _prefs.air.freq = f;
  } else if (strncmp(setting, "duty ", 5) == 0) {
    int m = atoi(&setting[5]);
    if (m < 1 || m > 50) { strcpy(reply, "Error: percent of the time, 1-50"); return true; }
    _prefs.air.duty = (uint8_t) m;
  } else {
    return false;
  }
  savePrefs();
  strcpy(reply, "OK");
  return true;
}
