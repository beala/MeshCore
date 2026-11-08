// Tire pressure in the MeshCore app (docs/tire_pressure.md).
//
// Tire pressure sensors (TPMS) send each wheel's pressure and temperature on 315 MHz (cars sold in
// the US) about once a minute while the car moves, and when the pressure changes. The LR2021 steps
// away from the mesh for short listens, one sensor make's framing at a time (src/helpers/tpms), and
// every sensor heard goes in a table ('get tpms.heard'). Only the ones chosen with 'set tpms.ids'
// show in a "Tires" channel: a passing car's sensors are its owner's. Receive only, except bench
// builds.

#include "MyMesh.h"
#include <helpers/tpms/Tpms.h>
#ifdef FISB_BENCH_TX
#include "target.h"
#endif

#define TPMS_WINDOW_MS    1000   // one listen
#define TPMS_FOREVER_MS   5000   // one listen when listening all the time (duty 100)
#define TPMS_LOCK_MS      (30UL * 60 * 1000)   // a chosen sensor heard this recently: listen only for its make
#define TPMS_TWICE_MS     15000  // a weakly checked frame counts when the same one comes again this soon

// 'set tpms.dbg <rxbw kHz> <thresh dB> <air>', for experiments (0 = the default)
static struct { float rxbw; uint8_t thresh; int8_t air; uint8_t pre_det; float dev; } tpms_dbg = { 0, 0, -1, 0, 0 };

static mesh::Radio::FskListen tpmsListen(int i, float freq) {
  const tpms::Air& a = tpms::air(i);
  mesh::Radio::FskListen cfg = {};
  cfg.freq = freq;
  cfg.kbps = a.kbps;
  // the sync word, right-aligned in whole bytes as the radio takes it
  int nbytes = (a.sync_bits + 7) / 8;
  int shift = nbytes * 8 - a.sync_bits;
  for (int k = 0; k < a.sync_bits; k++) {
    if ((a.sync[k >> 3] >> (7 - (k & 7))) & 1) {
      int at = k + shift;
      cfg.sync[at >> 3] |= 0x80 >> (at & 7);
    }
  }
  cfg.sync_len = (uint8_t) nbytes;
  cfg.pkt_len = a.pkt_bytes;
  if (a.ook) {
    cfg.modem = mesh::Radio::MODEM_OOK;
    cfg.ook_pattern = 0x5555;   // the 1010.. preamble
    cfg.ook_pattern_bits = 16;
    cfg.rxbw_khz = tpms_dbg.rxbw > 0 ? tpms_dbg.rxbw : 38.5f;   // OOK: a few times the chip rate at most
    cfg.thresh_db = tpms_dbg.thresh;
  } else {
    cfg.dev_khz = tpms_dbg.dev > 0 ? tpms_dbg.dev : a.dev_khz;
    cfg.pre_det_bits = tpms_dbg.pre_det ? tpms_dbg.pre_det : a.pre_det;
    cfg.rxbw_khz = tpms_dbg.rxbw > 0 ? tpms_dbg.rxbw : tpms::RX_BW_KHZ;
    cfg.sync_bits = a.sync_bits;
    cfg.no_preamble = true;   // not every make sends a 1010.. preamble; the sync word is enough
  }
  return cfg;
}

bool MyMesh::isTpmsChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _tpms_active && idx == MAX_GROUP_CHANNELS + VCH_TPMS;
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::applyTpms() {
  bool was = _tpms_active;
  if (!_prefs.tpms.en) {
    if (_tpms_listening) _radio->stopFskListen();
    _tpms_active = _tpms_listening = false;
    return;
  }
  _tpms_active = _radio->startFskListen(tpmsListen(0, _prefs.tpms.freq), 1);   // probe
  _radio->stopFskListen();
  _tpms_listening = false;
  if (_tpms_active && !was) {
    _tpms_frames = _tpms_bad = _tpms_shown = _tpms_listen_ms = 0;
    memset(_tpms_air_ok, 0, sizeof(_tpms_air_ok));
    _tpms_seen_n = 0;
    _tpms_turn = 0;
    _tpms_since = _tpms_next = millis();
  }
}

// Is this sensor in 'set tpms.ids' (hex, eg. "2fc871,2eaaf9")?
bool MyMesh::tpmsWanted(uint32_t id) const {
  const char* p = _prefs.tpms.ids;
  while (*p) {
    while (*p == ',' || *p == ' ') p++;
    if (!*p) break;
    char* end;
    unsigned long v = strtoul(p, &end, 16);
    if (end == p) { p++; continue; }
    if (v == id) return true;
    p = end;
  }
  return false;
}

MyMesh::TpmsSeen* MyMesh::tpmsSeen(uint8_t proto, uint32_t id) {
  for (int i = 0; i < _tpms_seen_n; i++) if (_tpms_seen[i].id == id && _tpms_seen[i].proto == proto) return &_tpms_seen[i];
  TpmsSeen* e;
  if (_tpms_seen_n < TPMS_SEEN) {
    e = &_tpms_seen[_tpms_seen_n++];
  } else {   // full: the one heard longest ago that isn't wanted
    e = NULL;
    for (int i = 0; i < _tpms_seen_n; i++) {
      TpmsSeen* s = &_tpms_seen[i];
      if (tpmsWanted(s->id)) continue;
      if (!e || (int32_t)(s->heard_at - e->heard_at) < 0) e = s;
    }
    if (!e) return NULL;
  }
  memset(e, 0, sizeof(*e));
  e->id = id;
  e->proto = proto;
  return e;
}

// "32.5 psi" or "224 kPa"; "71°F" or "22°C"
static int tpmsPressure(char* out, size_t n, int kpa10, bool us) {
  if (kpa10 < 0) return snprintf(out, n, "?");
  if (us) {
    int psi10 = (int)((kpa10 * 10L + 344) / 689);   // 6.89476 kPa a psi
    return snprintf(out, n, "%d.%d psi", psi10 / 10, psi10 % 10);
  }
  return snprintf(out, n, "%d kPa", (kpa10 + 5) / 10);
}

void MyMesh::tpmsPost(TpmsSeen& s, const tpms::Reading& r) {
#ifdef MAX_GROUP_CHANNELS
  uint32_t now = millis();
  bool us = !_prefs.wx.metric;
  int psi10 = r.kpa10 >= 0 ? (int)((r.kpa10 * 10L + 344) / 689) : -1;
  int low10 = _prefs.tpms.low * 10;
  bool low = psi10 >= 0 && low10 > 0 && psi10 < low10;
  // a fast drop: 3 psi below the last post within 10 minutes
  bool drop = s.posted_at && psi10 >= 0 && s.posted_psi10 - psi10 >= 30 && now - s.posted_at < 600000UL;
  bool changed = s.posted_at && psi10 >= 0 && abs(psi10 - s.posted_psi10) >= 10;   // a psi either way
  uint32_t every = (uint32_t)(_prefs.tpms.every ? _prefs.tpms.every : 30) * 60000UL;
  bool due = !s.posted_at || (int32_t)(now - s.posted_at - every) >= 0;
  bool alert = (low && !s.low_posted) || drop;
  if (!due && !changed && !alert) return;

  char who[20], pres[16], post[MAX_FRAME_SIZE];
  snprintf(who, sizeof(who), "Tire %04lx", (unsigned long)(r.id & 0xFFFF));   // the last 4 hex digits
  tpmsPressure(pres, sizeof(pres), r.kpa10, us);
  int k = snprintf(post, sizeof(post), "%s%s: %s", who, low ? " LOW" : drop ? " DROPPING" : "", pres);
  if (r.has_temp && k < (int) sizeof(post) - 20) {
    if (us) k += snprintf(&post[k], sizeof(post) - k, ", %d°F", r.temp_c * 9 / 5 + 32);
    else k += snprintf(&post[k], sizeof(post) - k, ", %d°C", r.temp_c);
  }
  if (r.battery_low && k < (int) sizeof(post) - 20) k += snprintf(&post[k], sizeof(post) - k, ", battery low");
  pushChannelText(MAX_GROUP_CHANNELS + VCH_TPMS, getRTCClock()->getCurrentTimeUnique(), 0, 0, post, k);
  s.posted_at = now;
  s.posted_psi10 = (int16_t) psi10;
  s.low_posted = low;
  _tpms_shown++;
#else
  (void) s; (void) r;
#endif
}

void MyMesh::tpmsFrame(int air, const uint8_t* chips, int len, float rssi) {
  _tpms_frames++;
  tpms::Reading r;
  if (!tpms::read(air, chips, len, &r)) {
    _tpms_bad++;
    _tpms_last_air = (uint8_t) air;   // for 'get tpms.last'
    _tpms_last_len = (uint8_t)(len < (int) sizeof(_tpms_last) ? len : sizeof(_tpms_last));
    memcpy(_tpms_last, chips, _tpms_last_len);
    return;
  }
  uint32_t now = millis();
  TpmsSeen* s = tpmsSeen(r.proto, r.id);
  if (!s) return;
  if (r.weak_check) {   // a sum or 2 bits: noise passes now and then, so the same frame must come twice
    bool again = s->pending_at && s->pending_kpa10 == r.kpa10 && now - s->pending_at < TPMS_TWICE_MS;
    s->pending_at = now;
    s->pending_kpa10 = r.kpa10;
    if (!again) return;   // (sensors send several in a row)
  }
  if (air >= 0 && air < tpms::AIRS && _tpms_air_ok[air] < 0xFFFF) _tpms_air_ok[air]++;
  s->kpa10 = r.kpa10;
  s->temp_c = r.has_temp ? (int8_t) r.temp_c : -128;
  s->heard_at = now;
  s->rssi = (int16_t) rssi;
  s->air = (uint8_t) air;
  if (s->count < 0xFFFF) s->count++;
  if (tpmsWanted(r.id)) tpmsPost(*s, r);
}

// Which settings to listen with: the makes of the chosen sensors heard lately, else all
uint16_t MyMesh::tpmsAirs() const {
  if (tpms_dbg.air >= 0) return 1 << tpms_dbg.air;
  uint32_t now = millis();
  uint16_t m = 0;
  for (int i = 0; i < _tpms_seen_n; i++) {
    const TpmsSeen& s = _tpms_seen[i];
    if (s.count && tpmsWanted(s.id) && now - s.heard_at < TPMS_LOCK_MS) m |= 1 << s.air;
  }
  if (m) return m;
  for (int i = 0; i < tpms::AIRS; i++) if (tpms::air(i).listen) m |= 1 << i;
  return m;
}

void MyMesh::tpmsLoop() {
  if (!_tpms_active) return;
  uint32_t now = millis();
  uint8_t chips[32];
  float rssi = 0;
  int len;
  while ((len = _radio->recvFsk(chips, sizeof(chips), &rssi)) > 0) tpmsFrame(_tpms_air, chips, len, rssi);

  int st = _radio->fskListenState();
  bool forever = _prefs.tpms.duty >= 100;
  if (_tpms_listening) {
    if (st == 0) {
      _tpms_listen_ms += _radio->lastFskListenMillis();
      _tpms_listening = false;
      uint8_t duty = _prefs.tpms.duty ? _prefs.tpms.duty : 1;
      _tpms_next = now + (forever ? 0 : (uint32_t) TPMS_WINDOW_MS * (100 - duty) / duty);
    }
    return;
  }
  if (st != 0) return;
  if ((int32_t)(now - _tpms_next) < 0) return;
  uint16_t airs = tpmsAirs();
  for (int tries = 0; tries < tpms::AIRS; tries++) {
    _tpms_turn = (uint8_t)((_tpms_turn + 1) % tpms::AIRS);
    if (airs & (1 << _tpms_turn)) break;
  }
  _tpms_air = _tpms_turn;
  if (_radio->startFskListen(tpmsListen(_tpms_air, _prefs.tpms.freq), forever ? TPMS_FOREVER_MS : TPMS_WINDOW_MS)) {
    _tpms_listening = true;
  }
}

static bool tpmsOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}

#ifdef FISB_BENCH_TX
// Bench only (-D FISB_BENCH_TX; never in releases): sends a recorded sensor frame (the chips after a
// setting's sync word, as in test/test_tpms/vectors.inc) with that setting's sync word, once, at
// 902-909 or 922-928 MHz:  tpms tx <setting 0-7> <MHz> <hex>
static bool tpmsBenchTx(const char* cmd, char* reply) {
  if (strncmp(cmd, "tpms tx ", 8) != 0) return false;
  char* p;
  long ai = strtol(&cmd[8], &p, 10);
  float mhz = strtod(p, &p);
  if (ai < 0 || ai >= tpms::AIRS) { strcpy(reply, "Error: tpms tx <setting 0-7> <MHz> <hex>"); return true; }
  if (mhz < 902.0f || mhz > 928.0f || (mhz >= 909.0f && mhz <= 922.0f)) {
    strcpy(reply, "Error: 902-909 or 922-928 MHz only");
    return true;
  }
  while (*p == ' ') p++;
  uint8_t chips[40];
  int n = 0;
  while (p[0] && p[1] && n < (int) sizeof(chips)) {
    unsigned b;
    if (sscanf(p, "%2x", &b) != 1) break;
    chips[n++] = (uint8_t) b;
    p += 2;
  }
  if (n == 0) { strcpy(reply, "Error: no chips"); return true; }
  const tpms::Air& a = tpms::air((int) ai);
  int16_t st;
  if (a.ook) {   // 32 chips of 1010, the sync word, the chips: all as raw chips
    uint8_t all[64] = { 0xAA, 0xAA, 0xAA, 0xAA };
    int bit = 32;
    for (int k = 0; k < a.sync_bits; k++, bit++) if ((a.sync[k >> 3] >> (7 - (k & 7))) & 1) all[bit >> 3] |= 0x80 >> (bit & 7);
    for (int k = 0; k < n * 8 && bit < 64 * 8; k++, bit++) if ((chips[k >> 3] >> (7 - (k & 7))) & 1) all[bit >> 3] |= 0x80 >> (bit & 7);
    st = radio_driver.benchOokTx(mhz, (uint32_t)(a.kbps * 1000.0f + 0.5f), all, (uint16_t)((bit + 7) / 8));
  } else {   // up to 32 chips of 1010 leading into the sync word (as the sensors send), the sync word, the chips
    int lead = 56 - a.sync_bits < 32 ? 56 - a.sync_bits : 32;
    int bits = lead + a.sync_bits;
    uint8_t sync[8] = {};
    int nbytes = (bits + 7) / 8, shift = nbytes * 8 - bits;
    int first = a.sync[0] >> 7;   // the lead-in alternates into the sync word's first chip
    for (int k = 0; k < bits; k++) {
      int v = k < lead ? ((lead - k) & 1) ^ first : (a.sync[(k - lead) >> 3] >> (7 - ((k - lead) & 7))) & 1;
      if (v) { int at = k + shift; sync[at >> 3] |= 0x80 >> (at & 7); }
    }
    st = radio_driver.benchFskTx(mhz, a.kbps, a.dev_khz, sync, (uint8_t) nbytes, (uint8_t) bits, chips, (uint16_t) n);
  }
  if (st == RADIOLIB_ERR_NONE) sprintf(reply, "OK - sent %s, %d bytes", a.name, n);
  else sprintf(reply, "Error: %d", st);
  return true;
}
#endif

bool MyMesh::handleTpmsCommand(const char* command, char* reply) {
  bool on;
#ifdef FISB_BENCH_TX
  if (tpmsBenchTx(command, reply)) return true;
#endif
  if (strcmp(command, "tpms") == 0 || strcmp(command, "get tpms") == 0) {
    char listen[24];
    if (_prefs.tpms.duty >= 100) strcpy(listen, "all the time");
    else snprintf(listen, sizeof(listen), "%u%% of the time", _prefs.tpms.duty);
    char low[24] = "off";
    if (_prefs.tpms.low) snprintf(low, sizeof(low), "below %u psi", _prefs.tpms.low);
    char line[256];   // then cut to the reply's 160
    snprintf(line, sizeof(line), "> Tires %s: %s, %d.%02d MHz, listening %s, a post every %u min, low alert %s%s",
             _prefs.tpms.en ? "on" : "off", _prefs.tpms.ids[0] ? _prefs.tpms.ids : "none chosen ('set tpms.ids')",
             (int) _prefs.tpms.freq, (int)(_prefs.tpms.freq * 100 + 0.5f) % 100, listen,
             _prefs.tpms.every ? _prefs.tpms.every : 30, low, _prefs.tpms.en && !_tpms_active ? " (needs an LR2021)" : "");
    StrHelper::strncpy(reply, line, 160);
    return true;
  }
  if (strcmp(command, "get tpms.stats") == 0) {
    uint32_t up = millis() - _tpms_since;
    uint32_t pm = up ? (uint32_t)((uint64_t) _tpms_listen_ms * 1000 / up) : 0;
    int k = sprintf(reply, "> %lu frames (%lu didn't read), %d sensors, %lu posts, listening %u.%u%%;",
                    (unsigned long) _tpms_frames, (unsigned long) _tpms_bad, _tpms_seen_n, (unsigned long) _tpms_shown,
                    (unsigned) (pm / 10), (unsigned) (pm % 10));
    for (int i = 0; i < tpms::AIRS && k < 140; i++) {
      if (_tpms_air_ok[i]) k += sprintf(&reply[k], " %s %u", tpms::air(i).name, _tpms_air_ok[i]);
    }
    uint16_t airs = tpmsAirs();
    uint16_t all = 0;
    for (int i = 0; i < tpms::AIRS; i++) if (tpms::air(i).listen) all |= 1 << i;
    if (airs != all && k < 140) sprintf(&reply[k], " (listening for yours only)");
    return true;
  }
  if (strcmp(command, "get tpms.last") == 0) {   // the last frame that didn't read: its raw chips
    int k = sprintf(reply, "> %s %d:", tpms::air(_tpms_last_air).name, _tpms_last_len);
    for (int i = 0; i < _tpms_last_len; i++) k += sprintf(&reply[k], "%02x", _tpms_last[i]);
    return true;
  }
  if (strncmp(command, "get tpms.list", 13) == 0 && (command[13] == 0 || command[13] == ' ')) {
    // For apps (the fluxcore app's Sensors tab): "> <sensors> <from> rec;rec..." as many as fit, in
    // the table's order (sensors heard once and waiting for a second frame left out), rec =
    // make,id hex,kPa x10,°C (empty: not sent),dBm,age s,frames,posted (0/1)
    int start = command[13] == ' ' ? atoi(&command[14]) : 0;
    if (start < 0) start = 0;
    uint8_t order[TPMS_SEEN];
    int n = 0;
    for (int i = 0; i < _tpms_seen_n; i++) if (_tpms_seen[i].count) order[n++] = (uint8_t) i;
    int k = sprintf(reply, "> %d %d", n, start);
    uint32_t now = millis();
    for (int i = start; i < n; i++) {
      const TpmsSeen& s = _tpms_seen[order[i]];
      char item[80], temp[8] = "";
      if (s.temp_c != -128) snprintf(temp, sizeof(temp), "%d", s.temp_c);
      int w = snprintf(item, sizeof(item), "%s%s,%lx,%d,%s,%d,%lu,%u,%d", i == start ? " " : ";", tpms::protoName(s.proto),
                       (unsigned long) s.id, s.kpa10, temp, s.rssi, (unsigned long)((now - s.heard_at) / 1000), s.count,
                       tpmsWanted(s.id) ? 1 : 0);
      if (w >= (int) sizeof(item) || k + w > 150) break;
      memcpy(&reply[k], item, w + 1);
      k += w;
    }
    return true;
  }
  if (strcmp(command, "get tpms.heard") == 0 || strncmp(command, "get tpms.heard ", 15) == 0) {
    if (_tpms_seen_n == 0) {
      strcpy(reply, _tpms_active ? "> no sensors heard yet" : "> tires are off ('tpms on')");
      return true;
    }
    int from = command[14] ? atoi(&command[15]) : 0;
    uint8_t order[TPMS_SEEN];
    int n = 0;
    for (int i = 0; i < _tpms_seen_n; i++) if (_tpms_seen[i].count) order[n++] = (uint8_t) i;
    for (int i = 1; i < n; i++) {   // the strongest first: your own car's are the closest
      for (int j = i; j > 0 && _tpms_seen[order[j]].rssi > _tpms_seen[order[j - 1]].rssi; j--) {
        uint8_t t = order[j]; order[j] = order[j - 1]; order[j - 1] = t;
      }
    }
    uint32_t now = millis();
    int k = sprintf(reply, "> %d:", n);
    int i = from < 0 ? 0 : from;
    for (; i < n; i++) {
      const TpmsSeen& s = _tpms_seen[order[i]];
      char pres[16];
      tpmsPressure(pres, sizeof(pres), s.kpa10, !_prefs.wx.metric);
      char item[64];
      int m = snprintf(item, sizeof(item), "%s %s %lx %s %ddBm %lum", i > from ? "," : "", tpms::protoName(s.proto),
                       (unsigned long) s.id, pres, s.rssi, (unsigned long)((now - s.heard_at) / 60000));
      if (k + m > 150) break;
      memcpy(&reply[k], item, m + 1);
      k += m;
    }
    if (i < n) sprintf(&reply[k], " (more: 'get tpms.heard %d')", i);
    return true;
  }
  const char* arg = NULL;
  if (strncmp(command, "tpms ", 5) == 0 && tpmsOnOff(&command[5], &on)) arg = &command[5];
  else if (strncmp(command, "set tpms ", 9) == 0 && tpmsOnOff(&command[9], &on)) arg = &command[9];
  if (arg) {
    if (listensBusy(reply)) return true;
    char off[64] = "";
    if (on) listenOthersOff(LISTEN_TPMS, off, sizeof(off));
    _prefs.tpms.en = on ? 1 : 0;
    applyTpms();
    if (on && !_tpms_active) {
      _prefs.tpms.en = 0;
      strcpy(reply, "Error: this radio can't listen for tire sensors (needs an LR2021)");
    } else {
      savePrefs();
      if (on) sprintf(reply, "OK - Tires on%s. Reconnect the app to see the channel", off);
      else strcpy(reply, "OK - Tires off");
    }
    return true;
  }
  if (strncmp(command, "set tpms.", 9) != 0) return false;
  const char* opt = &command[9];
  if (strncmp(opt, "ids ", 4) == 0 || strcmp(opt, "ids") == 0) {
    const char* v = opt[3] ? &opt[4] : "";
    if (strcmp(v, "none") == 0) v = "";
    if (strlen(v) >= sizeof(_prefs.tpms.ids)) {
      sprintf(reply, "Error: at most %d characters", (int) sizeof(_prefs.tpms.ids) - 1);
      return true;
    }
    for (const char* p = v; *p; p++) {
      if (!isxdigit((unsigned char)*p) && *p != ',' && *p != ' ') {
        strcpy(reply, "Error: sensor IDs in hex (as in 'get tpms.heard') separated by commas");
        return true;
      }
    }
    StrHelper::strncpy(_prefs.tpms.ids, v, sizeof(_prefs.tpms.ids));
    for (int i = 0; i < _tpms_seen_n; i++) _tpms_seen[i].posted_at = 0;   // each one's reading again
    savePrefs();
    if (v[0]) sprintf(reply, "OK - showing %s", _prefs.tpms.ids);
    else strcpy(reply, "OK - no sensors shown (the table still fills: 'get tpms.heard')");
    return true;
  }
  if (strncmp(opt, "every ", 6) == 0) {
    int m = atoi(&opt[6]);
    if (m < 1 || m > 1440) { strcpy(reply, "Error: minutes between posts, 1-1440 (a change of a psi or more, and alerts, at once)"); return true; }
    _prefs.tpms.every = (uint16_t) m;
    savePrefs();
    sprintf(reply, "OK - a post every %d min (changes and alerts at once)", m);
    return true;
  }
  if (strncmp(opt, "low ", 4) == 0) {
    int psi = atoi(&opt[4]);
    if (psi < 0 || psi > 150) { strcpy(reply, "Error: psi, 0-150 (0 = off)"); return true; }
    _prefs.tpms.low = (uint8_t) psi;
    savePrefs();
    if (psi) sprintf(reply, "OK - an alert below %d psi", psi);
    else strcpy(reply, "OK - no low pressure alert (a fast drop still alerts)");
    return true;
  }
  if (strncmp(opt, "duty ", 5) == 0) {
    int d = atoi(&opt[5]);
    if (d < 1 || d > 100) { strcpy(reply, "Error: % of the time listening, 1-100 (100 = all the time: the mesh can't be heard)"); return true; }
    _prefs.tpms.duty = (uint8_t) d;
    savePrefs();
    if (d >= 100) strcpy(reply, "OK - listening all the time. The mesh can't be heard until a lower duty (sending still works)");
    else sprintf(reply, "OK - listening %d%% of the time", d);
    return true;
  }
  if (strncmp(opt, "freq ", 5) == 0) {
    float f = (float) strtod(&opt[5], NULL);
    bool ok = (f >= 300.0f && f <= 450.0f) || (f >= 902.0f && f <= 928.0f);
    if (!ok) { strcpy(reply, "Error: MHz: 315 (US), 433.92 (Europe), or 902-928 for bench tests"); return true; }
    _prefs.tpms.freq = f;
    savePrefs();
    sprintf(reply, "OK - listening on %s MHz", &opt[5]);
    return true;
  }
  if (strncmp(opt, "dbg ", 4) == 0) {
    char* q;
    float bw = (float) strtod(&opt[4], &q);
    int th = (int) strtol(q, &q, 10);
    int ai = (int) strtol(q, &q, 10);
    int pd = (int) strtol(q, &q, 10);
    float dv = (float) strtod(q, &q);
    tpms_dbg.pre_det = (uint8_t) pd;
    tpms_dbg.dev = dv;
    tpms_dbg.rxbw = bw; tpms_dbg.thresh = (uint8_t) th;
    tpms_dbg.air = (int8_t)(ai >= 1 && ai <= tpms::AIRS ? ai - 1 : -1);
    if (_tpms_listening) _radio->stopFskListen();   // the next listen, with these, starts now
    _tpms_next = millis();
    sprintf(reply, "OK - rxbw %d kHz, threshold %d dB, setting %d, preamble %d bits, dev %d kHz (0 = default)", (int) bw, th, ai, pd, (int) dv);
    return true;
  }
  strcpy(reply, "Error: set tpms.ids <hex IDs>|none, tpms.every <min>, tpms.low <psi>, tpms.duty <1-100>, tpms.freq <MHz>");
  return true;
}
