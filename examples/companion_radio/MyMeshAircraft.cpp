// Aircraft in the MeshCore app (docs/aircraft.md).
//
// Aircraft report their position about once a second: light aircraft in the US on 978 MHz (UAT),
// airliners and most others on 1090 MHz (Mode S extended squitter). The LR2021 steps away from the
// mesh for short listens (CustomLR2021Wrapper), taking turns between the two; the messages are
// checked and decoded (src/helpers/aircraft/Uat.*, AdsB.*), and each aircraft shows in the app as
// a post in an "Aircraft" channel: when first heard, then every few minutes while it's around.
// Receive only: nothing is ever sent on 978 or 1090 MHz.

#include "MyMesh.h"

#define AIR_WINDOW_MS   300      // one listen, when sharing the radio with the mesh
#define AIR_FOREVER_MS  5000     // one listen when listening all the time
#define AIR_REPLY_MAX   140
#define AIR_GONE_MS     (5 * 60000UL)   // an aircraft not heard for this long is dropped

// 'air dbg' overrides for receiver experiments (not saved): sync bits, preamble detect, rx bw, deviation, kbps
static struct { uint8_t sync_bits, pre_det; float rxbw, dev, kbps; bool on; } dbg = {};
// 'air adsb' overrides: detection threshold above the noise (dB), fixed gain step, rx bw
static struct { uint8_t thresh, gain; float rxbw; } dbg1090 = {};

static mesh::Radio::FskListen adsbListen() {
  mesh::Radio::FskListen cfg = {};
  cfg.modem = mesh::Radio::MODEM_ADSB;
  cfg.freq = 1090.0f;
  cfg.rxbw_khz = dbg1090.rxbw > 0 ? dbg1090.rxbw : 3076.0f;   // as RadioLib's ADS-B example
  cfg.pkt_len = adsb::DATA_BYTES;
  cfg.thresh_db = dbg1090.thresh;
  cfg.gain = dbg1090.gain;
  return cfg;
}

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

bool MyMesh::isVirtualChannelSlot(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return idx >= MAX_GROUP_CHANNELS && idx < MAX_GROUP_CHANNELS + virtualChannelCount();
#else
  (void)idx;
  return false;
#endif
}

bool MyMesh::isAircraftChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _air_active && idx == MAX_GROUP_CHANNELS + VCH_AIRCRAFT;
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
    _air_heard = _air_heard_1090 = _air_bad = _air_fixed = _air_shown = _air_listen_ms = 0;
    _air_since = millis();
    _air_next = millis();
    _air_digest_from = millis();
    _air_digest_at = millis() + 120000UL;   // the first digest once there's been time to hear some
  }
}

static void fmtThousands(char* out, size_t n, int32_t v) {
  if (v < 0) { snprintf(out, n, "%ld", (long) v); return; }
  if (v >= 1000) snprintf(out, n, "%ld,%03ld", (long)(v / 1000), (long)(v % 1000));
  else snprintf(out, n, "%ld", (long) v);
}

// eg. "N123AB: 5,800 ft, 1.3 mi NNW, 79 kt heading 299, climbing". The app shows channel texts as
// "sender: text", so the callsign (or the address, until a callsign is heard) comes first, then a colon.
// Without a location set on this radio, the position shows as lat,lon.
void MyMesh::describePlane(const Plane& p, char* out, size_t n) {
  const uat::Report& r = p.last;
  int m;
  if (p.callsign[0]) m = snprintf(out, n, "%s:", p.callsign);
  else m = snprintf(out, n, "%06lx:", (unsigned long) p.address);
  if (m < 0 || (size_t) m >= n) return;
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
  char* c = strstr(out, ":,");   // no altitude: "N123AB: 1.3 mi NNW", not "N123AB:, 1.3 mi"
  if (c) memmove(c + 1, c + 2, strlen(c + 2) + 1);
}

// A 1090 MHz position message carries half the position (CPR): decode it next to the aircraft's last
// position, else from an even/odd pair, else next to this radio's location. Sets r's position.
bool MyMesh::adsbPosition(Plane& p, const adsb::Message& m, uint32_t now, uat::Report* r) {
  int i = m.cpr_odd ? 1 : 0;
  p.cpr_lat[i] = m.cpr_lat;
  p.cpr_lon[i] = m.cpr_lon;
  p.cpr_at[i] = now;
  int32_t lat, lon;
  bool ok = false;
  if (p.last.has_pos && p.pos_at && now - p.pos_at < 60000) {
    ok = adsb::cprLocal(m.cpr_lat, m.cpr_lon, m.cpr_odd, m.surface, p.last.lat_e5, p.last.lon_e5, &lat, &lon);
  }
  if (!ok && !m.surface && p.cpr_at[1 - i] && now - p.cpr_at[1 - i] < 10000) {
    ok = adsb::cprGlobal(p.cpr_lat[0], p.cpr_lon[0], p.cpr_lat[1], p.cpr_lon[1], m.cpr_odd, &lat, &lon);
  }
  if (!ok && (_prefs.node_lat != 0 || _prefs.node_lon != 0)) {
    ok = adsb::cprLocal(m.cpr_lat, m.cpr_lon, m.cpr_odd, m.surface, (int32_t)(_prefs.node_lat * 1e5),
                        (int32_t)(_prefs.node_lon * 1e5), &lat, &lon);
  }
  if (!ok) return false;
  r->has_pos = true;
  r->lat_e5 = lat;
  r->lon_e5 = lon;
  p.pos_at = now;
  return true;
}

// Whether an aircraft goes in the channel: a known position, within air.range miles (when this radio
// has a location) and below air.below feet. *dist: tenths of a mile, or UINT32_MAX without a location.
bool MyMesh::aircraftWanted(const Plane& p, uint32_t* dist) const {
  uint32_t d = UINT32_MAX;
  if (!p.last.has_pos) return false;
  if (_prefs.node_lat != 0 || _prefs.node_lon != 0) {
    uat::distanceBearing((int32_t)(_prefs.node_lat * 1e5), (int32_t)(_prefs.node_lon * 1e5), p.last.lat_e5, p.last.lon_e5, &d, NULL);
    if (_prefs.air.range && d > (uint32_t) _prefs.air.range * 10) return false;
  }
  if (_prefs.air.below && p.last.has_alt && p.last.ag_state != 2 && p.last.alt_ft > (int32_t) _prefs.air.below) return false;
  if (dist) *dist = d;
  return true;
}

// One post for the aircraft heard since the last one, closest (or lowest) first:
// "Nearby: N713SA 5,300 ft 2.1 mi N; N25430 6,100 ft 4.0 mi NE (+12 higher or farther)"
void MyMesh::postAircraftDigest(uint32_t now) {
  int idx[MAX_PLANES], n = 0, others = 0;
  uint32_t key[MAX_PLANES];
  for (int i = 0; i < _n_planes; i++) {
    const Plane& p = _planes[i];
    if ((int32_t)(p.heard_at - _air_digest_from) < 0) continue;   // not heard since the last digest
    uint32_t d;
    if (!aircraftWanted(p, &d)) { others++; continue; }
    idx[n] = i;
    key[n] = d != UINT32_MAX ? d : (uint32_t)(p.last.has_alt ? p.last.alt_ft + 2000 : 0);
    n++;
  }
  if (n == 0) return;   // nothing nearby: stay quiet
  for (int a = 1; a < n; a++) {   // closest first
    for (int b = a; b > 0 && key[b] < key[b - 1]; b--) {
      int ti = idx[b]; idx[b] = idx[b - 1]; idx[b - 1] = ti;
      uint32_t tk = key[b]; key[b] = key[b - 1]; key[b - 1] = tk;
    }
  }
  const int MAX_TEXT = 150;
  char text[MAX_FRAME_SIZE];
  int m = snprintf(text, sizeof(text), "Nearby:");
  int listed = 0;
  bool here = _prefs.node_lat != 0 || _prefs.node_lon != 0;
  for (int k = 0; k < n; k++) {
    const Plane& p = _planes[idx[k]];
    char e[64], alt[16];
    int w;
    if (p.callsign[0]) w = snprintf(e, sizeof(e), "%s %s", listed ? ";" : "", p.callsign);
    else w = snprintf(e, sizeof(e), "%s %06lx", listed ? ";" : "", (unsigned long) p.address);
    if (p.last.ag_state == 2) w += snprintf(&e[w], sizeof(e) - w, " on the ground");
    else if (p.last.has_alt) {
      fmtThousands(alt, sizeof(alt), p.last.alt_ft);
      w += snprintf(&e[w], sizeof(e) - w, " %s ft", alt);
    }
    if (here && w < (int) sizeof(e)) {
      uint32_t d; uint16_t b;
      uat::distanceBearing((int32_t)(_prefs.node_lat * 1e5), (int32_t)(_prefs.node_lon * 1e5), p.last.lat_e5, p.last.lon_e5, &d, &b);
      w += snprintf(&e[w], sizeof(e) - w, " %lu.%lu mi %s", (unsigned long)(d / 10), (unsigned long)(d % 10), wxsensor::compass(b));
    }
    if (w >= (int) sizeof(e) || m + w > MAX_TEXT - 24) { others += n - k; break; }
    memcpy(&text[m], e, w + 1);
    m += w;
    listed++;
  }
  if (others) snprintf(&text[m], sizeof(text) - m, " (+%d higher or farther)", others);
#ifdef MAX_GROUP_CHANNELS
  int ch = MAX_GROUP_CHANNELS + VCH_AIRCRAFT;
  pushChannelText(ch, getRTCClock()->getCurrentTimeUnique(), 0, 0, text, strlen(text));
#endif
  _air_shown++;
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
    uat::Report r;
    adsb::Message am;
    bool is_1090 = len == adsb::DATA_BYTES;   // the two listens hand over different lengths
    if (is_1090) {
      _air_heard_1090++;
      if (!adsb::decode(buf, len, &am)) { _air_bad++; continue; }
      r = am.r;
    } else {
      int fixed = 0;
      int n = uat::correct(buf, len, &fixed);
      if (n == 0 || !uat::decode(buf, n, &r)) { _air_bad++; continue; }
      if (fixed) _air_fixed++;
    }
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
      p->first_at = now;
    }
    p->bands |= is_1090 ? 2 : 1;
    if (is_1090 && am.has_cpr) adsbPosition(*p, am, now, &r);
    if (is_1090 && !am.has_cpr && !is_new) r.ag_state = p->last.ag_state;   // only position messages say
    // keep the last known position/altitude when a message doesn't carry them
    uat::Report merged = r;
    if (!is_new) {
      if (!r.has_pos) { merged.has_pos = p->last.has_pos; merged.lat_e5 = p->last.lat_e5; merged.lon_e5 = p->last.lon_e5; }
      if (!r.has_alt) { merged.has_alt = p->last.has_alt; merged.alt_ft = p->last.alt_ft; }
      if (!r.has_speed) { merged.has_speed = p->last.has_speed; merged.speed_kt = p->last.speed_kt; merged.track_deg = p->last.track_deg; }
      if (!r.has_vs) { merged.has_vs = p->last.has_vs; merged.vs_fpm = p->last.vs_fpm; }
    }
    p->last = merged;
    if (r.callsign[0] && !r.callsign_is_squawk) memcpy(p->callsign, r.callsign, sizeof(p->callsign));
    p->heard_at = now;
    p->count++;
    p->rssi = (int16_t) rssi;

    char text[MAX_FRAME_SIZE];
    if (is_new && _air_forever) {
      int m = snprintf(text, sizeof(text), "New aircraft (%d dBm) ", (int) rssi);
      if (m > 0 && m < (int) sizeof(text)) describePlane(*p, &text[m], sizeof(text) - m);
      ChatRef to;
      memset(&to, 0, sizeof(to));
      to.kind = CHAT_CONSOLE;
      postToChat(to, text);
    }
  }

  // the channel: a digest of the nearby aircraft every few minutes, or each one once (every = 0)
  if (_prefs.air.every) {
    if ((int32_t)(now - _air_digest_at) >= 0) {
      postAircraftDigest(now);
      _air_digest_at = now + (uint32_t) _prefs.air.every * 60000UL;
      _air_digest_from = now;
    }
  } else {
    for (int i = 0; i < _n_planes; i++) {
      Plane& p = _planes[i];
      // give the callsign up to 20 s to arrive so the post reads "N123AB: ..." rather than the address
      if (p.posted || !p.last.has_pos || (!p.callsign[0] && now - p.first_at < 20000)) continue;
      p.posted = true;
      p.posted_at = now;
      if (!aircraftWanted(p, NULL)) continue;
      char text[MAX_FRAME_SIZE];
      describePlane(p, text, sizeof(text));
#ifdef MAX_GROUP_CHANNELS
      int idx = MAX_GROUP_CHANNELS + VCH_AIRCRAFT;
      pushChannelText(idx, getRTCClock()->getCurrentTimeUnique(), 0, 0, text, strlen(text));
#endif
      _air_shown++;
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
  // take turns between the bands
  uint8_t bands = _prefs.air.bands & 3 ? _prefs.air.bands & 3 : 1;
  uint16_t band = bands == 1 ? 978 : bands == 2 ? 1090 : (_air_band == 978 ? 1090 : 978);
  mesh::Radio::FskListen cfg = band == 1090 ? adsbListen() : uatListen(_prefs.air.freq);
  if (_radio->startFskListen(cfg, _air_forever ? AIR_FOREVER_MS : AIR_WINDOW_MS)) {
    _air_band = band;
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
    char listen[24], range[16], bands[40];
    if (_air_forever) strcpy(listen, "all the time");
    else snprintf(listen, sizeof(listen), "%u%% of the time", _prefs.air.duty);
    if (_prefs.air.range) snprintf(range, sizeof(range), "%u mi", _prefs.air.range);
    else strcpy(range, "any");
    char below[16], every[32];
    if (_prefs.air.below) snprintf(below, sizeof(below), "%u ft", _prefs.air.below);
    else strcpy(below, "any");
    if (_prefs.air.every) snprintf(every, sizeof(every), "a digest every %u min", _prefs.air.every);
    else strcpy(every, "each aircraft once");
    int b = _prefs.air.bands & 3;
    if (b == 2) strcpy(bands, "1090 MHz ADS-B");
    else snprintf(bands, sizeof(bands), "%.3f MHz UAT%s", _prefs.air.freq, b == 3 ? " + 1090 MHz ADS-B" : "");
    char line[224];   // room for every part at its longest; the reply gets the first 159 characters
    snprintf(line, sizeof(line), "> Aircraft %s: %s, listening %s, posts %s, within %s, below %s",
             _prefs.air.en ? (_air_active ? "on" : "on, but the radio can't") : "off", bands,
             listen, every, range, below);
    line[159] = 0;
    strcpy(reply, line);
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
    sprintf(reply, "> %lu messages (%lu on 1090; %lu corrected, %lu bad), %d aircraft now, %lu posts, listening %u.%u%% of the time",
            (unsigned long)_air_heard, (unsigned long)_air_heard_1090, (unsigned long)_air_fixed, (unsigned long)_air_bad,
            _n_planes, (unsigned long)_air_shown, pct10 / 10, pct10 % 10);
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
  if (strncmp(command, "air adsb", 8) == 0) {   // air adsb <threshold dB> <gain step> <rx bw Hz> (0 = default)
    long th = 0, g = 0, bw = 0;
    sscanf(&command[8], "%ld %ld %ld", &th, &g, &bw);
    if (th < 0 || th > 40 || g < 0 || g > 13 || bw < 0 || bw > 3100000) { strcpy(reply, "Error: threshold 0-40 dB, gain 0-13, rx bw Hz"); return true; }
    dbg1090.thresh = (uint8_t) th; dbg1090.gain = (uint8_t) g; dbg1090.rxbw = bw / 1000.0f;
    sprintf(reply, "OK - 1090: threshold %ld dB over noise, gain %ld, rx bw %ld Hz (0 = default)", th, g, bw);
    return true;
  }
  if (strcmp(command, "air scan on") == 0 || strcmp(command, "air scan off") == 0) {
    if (!_air_active) { strcpy(reply, "Error: aircraft is off ('air on')"); return true; }
    _air_forever = command[9] == 'o' && command[10] == 'n';
    strcpy(reply, _air_forever ? "OK - listening for aircraft all the time; each new aircraft shows here. The mesh can't "
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
    if (m < 0 || m > 1440) { strcpy(reply, "Error: minutes between digests, 0-1440 (0 = a post for each aircraft)"); return true; }
    _prefs.air.every = (uint16_t) m;
    _air_digest_at = millis() + (uint32_t) m * 60000UL;
  } else if (strncmp(setting, "range ", 6) == 0) {
    int m = atoi(&setting[6]);
    if (m < 0 || m > 500) { strcpy(reply, "Error: miles, 0-500 (0 = all)"); return true; }
    _prefs.air.range = (uint16_t) m;
  } else if (strncmp(setting, "freq ", 5) == 0) {   // for bench tests; aircraft are on 978
    float f = (float) atof(&setting[5]);
    if (f < 150 || f > 1100) { strcpy(reply, "Error: frequency in MHz"); return true; }
    _prefs.air.freq = f;
  } else if (strncmp(setting, "below ", 6) == 0) {
    long ft = atol(&setting[6]);
    if (ft < 0 || ft > 60000) { strcpy(reply, "Error: feet, 0-60000 (0 = any altitude)"); return true; }
    _prefs.air.below = (uint16_t) ft;
  } else if (strncmp(setting, "band ", 5) == 0) {
    const char* b = &setting[5];
    if (strcmp(b, "978") == 0) _prefs.air.bands = 1;
    else if (strcmp(b, "1090") == 0) _prefs.air.bands = 2;
    else if (strcmp(b, "both") == 0) _prefs.air.bands = 3;
    else { strcpy(reply, "Error: 978, 1090 or both"); return true; }
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
