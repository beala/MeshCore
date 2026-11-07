// Airport weather in the MeshCore app (docs/airport_weather.md).
//
// FAA ground stations broadcast weather on 978 MHz (FIS-B, in UAT uplink frames): METARs (current
// conditions), TAFs (forecasts) and more, for many airports at once. The LR2021 steps away from the
// mesh for listens of about a second (each station sends in the first part of every UTC second),
// takes whole 552-byte frames (CustomLR2021: its 1 KB receive FIFO), and the frames are corrected and
// read (src/helpers/weather/Fisb.*). Reports for the airports chosen with 'set metar.airports' show
// in an "Airport weather" channel, each one once. Receive only: nothing is ever sent on 978 MHz.

#include "MyMesh.h"
#include <helpers/weather/Fisb.h>
#ifdef FISB_BENCH_TX
#include "target.h"
#endif

#define METAR_WINDOW_MS   1100   // one listen: a whole UTC second, so every station's slot is in it
#define METAR_FOREVER_MS  5000   // one listen when listening all the time (duty 100)
#define METAR_POST_MAX    150    // characters per post (a channel text is at most about 160)

static mesh::Radio::FskListen fisbListen(float freq) {
  mesh::Radio::FskListen cfg = {};
  cfg.freq = freq;
  cfg.kbps = 1041.667f;
  cfg.dev_khz = 312.5f;
  cfg.rxbw_khz = 2222.0f;   // as for aircraft on the same frequency (MyMeshAircraft.cpp)
  // 36-bit sync word 0x153225B1D, as the last 36 bits of 5 bytes; no preamble
  cfg.sync[0] = 0x01; cfg.sync[1] = 0x53; cfg.sync[2] = 0x22; cfg.sync[3] = 0x5B; cfg.sync[4] = 0x1D;
  cfg.sync_len = 5;
  cfg.sync_bits = 36;
  cfg.no_preamble = true;
  cfg.pkt_len = fisb::FRAME_BYTES;
  return cfg;
}

bool MyMesh::isMetarChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _metar_active && idx == MAX_GROUP_CHANNELS + VCH_METAR;
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::applyMetar() {
  bool was = _metar_active;
  if (!_prefs.metar.en) {
    if (_metar_listening) _radio->stopFskListen();
    _metar_active = _metar_listening = false;
    return;
  }
  _metar_active = _radio->startFskListen(fisbListen(_prefs.metar.freq), 1);   // probe: radios without FSK listens say no
  _radio->stopFskListen();
  _metar_listening = false;
  if (_metar_active && !was) {
    _metar_frames = _metar_fixed = _metar_bad = _metar_reports = _metar_shown = _metar_listen_ms = 0;
    _metar_posted_n = _metar_heard_n = 0;
    _metar_hinted = false;
    _metar_stn_lat = _metar_stn_lon = 0;
    _metar_since = _metar_next = millis();
  }
}

// FNV-1a: one number per report, to show each once
static uint32_t hashWords(const char* a, const char* b, const char* c) {
  uint32_t h = 2166136261UL;
  const char* parts[3] = { a, b, c };
  for (const char* p : parts) {
    for (; *p; p++) { h ^= (uint8_t)*p; h *= 16777619UL; }
    h ^= ' '; h *= 16777619UL;
  }
  return h;
}

// Is this airport in 'set metar.airports' (eg. "KLMO,KBJC", any case, spaces allowed)?
bool MyMesh::metarWanted(const char* where) const {
  const char* p = _prefs.metar.airports;
  while (*p) {
    while (*p == ',' || *p == ' ') p++;
    const char* s = p;
    while (*p && *p != ',' && *p != ' ') p++;
    int n = p - s;
    if (n > 0 && (int) strlen(where) == n) {
      bool same = true;
      for (int i = 0; i < n && same; i++) same = toupper((unsigned char) s[i]) == where[i];
      if (same) return true;
    }
  }
  return false;
}

void MyMesh::metarReport(const char* text, int len) {
  _metar_reports++;
  char kind[10], where[8], when[10];
  if (!fisb::words(text, len, kind, sizeof(kind), where, sizeof(where), when, sizeof(when))) return;
  bool is_metar = strcmp(kind, "METAR") == 0 || strcmp(kind, "SPECI") == 0;
  bool is_taf = strncmp(kind, "TAF", 3) == 0;   // TAF, TAF.AMD
  if (!is_metar && !is_taf) return;   // PIREP, WINDS, NOTAM, ...: not shown
  if (is_metar) {   // the airports heard, for 'get metar.heard'
    bool known = false;
    for (int i = 0; i < _metar_heard_n && !known; i++) known = strcmp(_metar_heard[i], where) == 0;
    if (!known && strlen(where) < sizeof(_metar_heard[0])) {
      int slot = _metar_heard_n < (int)(sizeof(_metar_heard) / sizeof(_metar_heard[0])) ? _metar_heard_n++ : (int)(_metar_reports % _metar_heard_n);
      strcpy(_metar_heard[slot], where);
    }
  }
  if (is_taf && !_prefs.metar.taf) return;
#ifdef MAX_GROUP_CHANNELS
  int ch = MAX_GROUP_CHANNELS + VCH_METAR;
  if (!_prefs.metar.airports[0]) {
    // nothing chosen yet: one hint, not a post for each of the dozens of airports a station covers
    if (!_metar_hinted && _metar_heard_n >= 1) {
      _metar_hinted = true;
      char hint[MAX_FRAME_SIZE];
      snprintf(hint, sizeof(hint), "Hearing airport weather, eg. %s. Choose airports to show: "
               "set metar.airports %s ('get metar.heard' lists the ones heard)", where, where);
      pushChannelText(ch, getRTCClock()->getCurrentTimeUnique(), 0, 0, hint, strlen(hint));
    }
    return;
  }
  if (!metarWanted(where)) return;
  uint32_t h = hashWords(kind, where, when);
  for (int i = 0; i < _metar_posted_n; i++) if (_metar_posted[i] == h) return;   // shown already
  int n_posted = sizeof(_metar_posted) / sizeof(_metar_posted[0]);
  if (_metar_posted_n < n_posted) _metar_posted[_metar_posted_n++] = h;
  else {
    memmove(_metar_posted, &_metar_posted[1], sizeof(_metar_posted) - sizeof(_metar_posted[0]));
    _metar_posted[n_posted - 1] = h;
  }

  // "KLMO: 052153Z 31012KT 10SM ..." (the app shows "sender: text"); "KLMO: SPECI ..." and
  // "KLMO: TAF ..." for the others. Long ones (TAFs) in parts.
  static char line[fisb::TEXT_MAX];
  int k = fisb::oneLine(text, len, line, sizeof(line));
  const char* body = line;
  int skip = 0;   // drop the kind and the airport from the line: they're in the prefix
  for (int w = 0; w < 2 && skip < k; w++) {
    while (skip < k && line[skip] != ' ') skip++;
    while (skip < k && line[skip] == ' ') skip++;
  }
  body = &line[skip];
  int left = k - skip;
  char post[MAX_FRAME_SIZE];
  bool first = true;
  while (left > 0) {
    int m = snprintf(post, sizeof(post), "%s%s: %s%s", where, first ? "" : " (cont.)",
                     first && strcmp(kind, "METAR") != 0 ? kind : "", first && strcmp(kind, "METAR") != 0 ? " " : "");
    int room = METAR_POST_MAX - m;
    int take = left;
    if (take > room) {   // cut at a space
      take = room;
      while (take > room / 2 && body[take] != ' ') take--;
    }
    memcpy(&post[m], body, take);
    post[m + take] = 0;
    pushChannelText(ch, getRTCClock()->getCurrentTimeUnique(), 0, 0, post, m + take);
    body += take;
    left -= take;
    while (left > 0 && *body == ' ') { body++; left--; }
    first = false;
  }
  _metar_shown++;
#endif
}

void MyMesh::metarFrame(const uint8_t* frame, int len, float rssi) {
  _metar_frames++;
  if (len != fisb::FRAME_BYTES) { _metar_bad++; return; }
  static uint8_t data[fisb::DATA_BYTES];   // static: the loop's stack is small (4 KB on nRF52)
  int fixed = 0;
  if (!fisb::correct(frame, data, &fixed)) { _metar_bad++; return; }
  if (fixed) _metar_fixed++;
  fisb::Header h;
  fisb::header(data, &h);
  // stations send their position even with the valid bit clear (as dump978 notes): take it when there
  if (h.pos_valid || h.lat_e5 || h.lon_e5) { _metar_stn_lat = h.lat_e5; _metar_stn_lon = h.lon_e5; }
  _metar_stn_slot = h.slot;
  _metar_stn_rssi = (int16_t) rssi;
  static fisb::Reports r;
  r.start(data, sizeof(data));
  fisb::Text t;
  while (r.next(&t)) metarReport(t.text, t.len);
}

void MyMesh::metarLoop() {
  if (!_metar_active) return;
  uint32_t now = millis();
  static uint8_t frame[fisb::FRAME_BYTES];
  float rssi = 0;
  int len = _radio->recvFsk(frame, sizeof(frame), &rssi);
  if (len > 0) metarFrame(frame, len, rssi);

  int st = _radio->fskListenState();
  bool forever = _prefs.metar.duty >= 100;
  if (_metar_listening) {
    if (st == 0) {
      _metar_listen_ms += _radio->lastFskListenMillis();
      _metar_listening = false;
      uint8_t duty = _prefs.metar.duty ? _prefs.metar.duty : 1;
      _metar_next = now + (forever ? 0 : (uint32_t) METAR_WINDOW_MS * (100 - duty) / duty);
    }
    return;
  }
  if (st != 0) return;
  if ((int32_t)(now - _metar_next) < 0) return;
  if (_radio->startFskListen(fisbListen(_prefs.metar.freq), forever ? METAR_FOREVER_MS : METAR_WINDOW_MS)) {
    _metar_listening = true;
  }
}

static bool metarOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}

#ifdef FISB_BENCH_TX
// Bench only (build with -D FISB_BENCH_TX; never in releases): sends a frame made by
// tools/bench/fisb.py, as a ground station would, at 902-928 MHz. Never on 978 MHz.
//   metar tx load <offset> <hex>       up to 64 bytes at a time into the frame
//   metar tx send <MHz>                sends it once (the host repeats it: tools/bench/fisb_bench.py)
static uint8_t bench_frame[fisb::FRAME_BYTES];

static bool benchTx(const char* cmd, char* reply) {
  if (strncmp(cmd, "metar tx load ", 14) == 0) {
    char* p;
    long off = strtol(&cmd[14], &p, 10);
    while (*p == ' ') p++;
    int n = 0;
    while (p[0] && p[1] && off + n < (long) sizeof(bench_frame)) {
      unsigned b;
      if (sscanf(p, "%2x", &b) != 1) break;
      bench_frame[off + n++] = (uint8_t) b;
      p += 2;
    }
    if (off < 0 || n == 0) strcpy(reply, "Error: metar tx load <offset> <hex>");
    else sprintf(reply, "OK - %d bytes at %ld", n, off);
    return true;
  }
  if (strncmp(cmd, "metar tx send ", 14) == 0) {
    float mhz = strtod(&cmd[14], NULL);
    if (mhz < 902.0f || mhz > 928.0f) { strcpy(reply, "Error: 902-928 MHz only (never 978)"); return true; }
    static const uint8_t sync[5] = { 0x01, 0x53, 0x22, 0x5B, 0x1D };
    int16_t st = radio_driver.benchFskTx(mhz, 1041.667f, 312.5f, sync, 5, 36, bench_frame, sizeof(bench_frame));
    if (st == RADIOLIB_ERR_NONE) strcpy(reply, "OK - sent");
    else sprintf(reply, "Error: %d", st);
    return true;
  }
  return false;
}
#endif

bool MyMesh::handleMetarCommand(const char* command, char* reply) {
  bool on;
#ifdef FISB_BENCH_TX
  if (benchTx(command, reply)) return true;
#endif
  if (strcmp(command, "metar") == 0 || strcmp(command, "get metar") == 0) {
    char listen[24];
    if (_prefs.metar.duty >= 100) strcpy(listen, "all the time");
    else snprintf(listen, sizeof(listen), "%u%% of the time", _prefs.metar.duty);
    snprintf(reply, 160, "> Airport weather %s: %s, listening %s, %s, TAFs %s%s", _prefs.metar.en ? "on" : "off",
             _prefs.metar.airports[0] ? _prefs.metar.airports : "no airports chosen", listen,
             _prefs.metar.freq == 978.0f ? "978 MHz" : "bench frequency", _prefs.metar.taf ? "on" : "off",
             _prefs.metar.en && !_metar_active ? " (needs an LR2021)" : "");
    return true;
  }
  if (strcmp(command, "get metar.stats") == 0) {
    uint32_t up = millis() - _metar_since;
    uint32_t pm = up ? (uint32_t)((uint64_t) _metar_listen_ms * 1000 / up) : 0;
    int k = sprintf(reply, "> %lu frames (%lu corrected, %lu bad), %lu reports, %lu posts, listening %u.%u%%",
                    (unsigned long) _metar_frames, (unsigned long) _metar_fixed, (unsigned long) _metar_bad,
                    (unsigned long) _metar_reports, (unsigned long) _metar_shown, (unsigned) (pm / 10), (unsigned) (pm % 10));
    if (_metar_frames > _metar_bad) {
      k += sprintf(&reply[k], "; station slot %u, %d dBm", _metar_stn_slot, _metar_stn_rssi);
      if (_metar_stn_lat || _metar_stn_lon) {
        if (_prefs.node_lat != 0 || _prefs.node_lon != 0) {
          uint32_t d; uint16_t b;
          uat::distanceBearing((int32_t)(_prefs.node_lat * 1e5), (int32_t)(_prefs.node_lon * 1e5), _metar_stn_lat, _metar_stn_lon, &d, &b);
          sprintf(&reply[k], ", %lu.%lu mi %s", (unsigned long)(d / 10), (unsigned long)(d % 10), wxsensor::compass(b));
        } else {
          sprintf(&reply[k], ", at %ld.%03ld,%s%ld.%03ld", (long)(_metar_stn_lat / 100000), (long)(labs(_metar_stn_lat) % 100000 / 100),
                  _metar_stn_lon < 0 && _metar_stn_lon > -100000 ? "-" : "", (long)(_metar_stn_lon / 100000),
                  (long)(labs(_metar_stn_lon) % 100000 / 100));
        }
      }
    }
    return true;
  }
  if (strcmp(command, "get metar.heard") == 0) {
    if (_metar_heard_n == 0) {
      strcpy(reply, _metar_active ? "> no METARs heard yet" : "> airport weather is off ('metar on')");
      return true;
    }
    int k = sprintf(reply, "> %d:", _metar_heard_n);
    for (int i = 0; i < _metar_heard_n && k < 150; i++) k += sprintf(&reply[k], "%s%s", i ? "," : " ", _metar_heard[i]);
    return true;
  }
  const char* arg = NULL;
  if (strncmp(command, "metar ", 6) == 0 && metarOnOff(&command[6], &on)) arg = &command[6];
  else if (strncmp(command, "set metar ", 10) == 0 && metarOnOff(&command[10], &on)) arg = &command[10];
  if (arg) {
    if (listensBusy(reply)) return true;
    char off[64] = "";
    if (on) listenOthersOff(LISTEN_METAR, off, sizeof(off));
    _prefs.metar.en = on ? 1 : 0;
    applyMetar();
    if (on && !_metar_active) {
      _prefs.metar.en = 0;
      strcpy(reply, "Error: this radio can't listen for airport weather (needs an LR2021)");
    } else {
      savePrefs();
      if (on) sprintf(reply, "OK - Airport weather on%s. Reconnect the app to see the channel", off);
      else strcpy(reply, "OK - Airport weather off");
    }
    return true;
  }
  if (strncmp(command, "set metar.", 10) != 0) return false;
  const char* opt = &command[10];
  if (strncmp(opt, "airports ", 9) == 0 || strcmp(opt, "airports") == 0) {
    const char* v = opt[8] ? &opt[9] : "";
    if (strcmp(v, "none") == 0) v = "";
    if (strlen(v) >= sizeof(_prefs.metar.airports)) {
      sprintf(reply, "Error: at most %d characters, eg. KLMO,KBJC", (int) sizeof(_prefs.metar.airports) - 1);
      return true;
    }
    for (const char* p = v; *p; p++) {
      if (!isalnum((unsigned char)*p) && *p != ',' && *p != ' ') {
        strcpy(reply, "Error: airport IDs separated by commas, eg. KLMO,KBJC");
        return true;
      }
    }
    StrHelper::strncpy(_prefs.metar.airports, v, sizeof(_prefs.metar.airports));
    for (char* p = _prefs.metar.airports; *p; p++) *p = toupper((unsigned char)*p);
    _metar_posted_n = 0;   // show the latest for the new list
    savePrefs();
    if (v[0]) sprintf(reply, "OK - showing %s", _prefs.metar.airports);
    else strcpy(reply, "OK - no airports chosen ('get metar.heard' lists the ones heard)");
    return true;
  }
  if (strncmp(opt, "taf ", 4) == 0 && metarOnOff(&opt[4], &on)) {
    _prefs.metar.taf = on ? 1 : 0;
    savePrefs();
    strcpy(reply, on ? "OK - forecasts (TAF) shown too" : "OK - current conditions (METAR, SPECI) only");
    return true;
  }
  if (strncmp(opt, "duty ", 5) == 0) {
    int d = atoi(&opt[5]);
    if (d < 1 || d > 100) { strcpy(reply, "Error: % of the time listening, 1-100 (100 = all the time: the mesh can't be heard)"); return true; }
    _prefs.metar.duty = (uint8_t) d;
    savePrefs();
    if (d >= 100) strcpy(reply, "OK - listening all the time. The mesh can't be heard until a lower duty (sending still works)");
    else sprintf(reply, "OK - listening %d%% of the time", d);
    return true;
  }
  if (strncmp(opt, "freq ", 5) == 0) {
    float f = atof(&opt[5]);
    if (f < 902.0f || f > 1000.0f) { strcpy(reply, "Error: MHz, 902-1000 (978 for FIS-B; others for bench tests)"); return true; }
    _prefs.metar.freq = f;
    savePrefs();
    sprintf(reply, "OK - listening on %s MHz", &opt[5]);
    return true;
  }
  strcpy(reply, "Error: set metar.airports <IDs>|none, metar.taf on|off, metar.duty <1-100>, metar.freq <MHz>");
  return true;
}
