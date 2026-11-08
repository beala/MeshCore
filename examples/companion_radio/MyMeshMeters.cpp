// Utility meters in the MeshCore app (docs/utility_meters.md).
//
// Water, gas and electric meters with a radio module send their reading every 15 s or so, around
// 915 MHz: Neptune R900 (water) and Itron ERT (SCM, SCM+: gas, electric, water). The LR2021 steps
// away from the mesh for short listens with its OOK receiver, one of the meters' channels at a time
// (see meterLoop), and the chips it hands over are read by src/helpers/meters. Every meter
// heard goes in a table ('get meter.heard'); only the ones chosen with 'set meter.ids' show in a
// "Meters" channel: a neighbour's readings are theirs. Receive only, except bench builds.

#include "MyMesh.h"
#include <helpers/meters/Meters.h>
#ifdef FISB_BENCH_TX
#include "target.h"
#endif

#define METER_WINDOW_MS   1000   // one listen
#define METER_FOREVER_MS  5000   // one listen when listening all the time (duty 100)
#define METER_CHIP_BPS    32.768f

// 'set meter.dbg <repeats+1> <rxbw kHz> <thresh dB> <kind>', for experiments (0 = the default)
static struct { uint8_t repeats; float rxbw; uint8_t thresh; uint8_t kind; } meter_dbg = {};

static mesh::Radio::FskListen meterListen(uint8_t kind, float freq) {
  const meters::Air& a = meters::air(kind);
  mesh::Radio::FskListen cfg = {};
  cfg.modem = mesh::Radio::MODEM_OOK;
  cfg.freq = freq;
  cfg.kbps = METER_CHIP_BPS;
  cfg.rxbw_khz = meter_dbg.rxbw > 0 ? meter_dbg.rxbw : meters::RX_BW_KHZ;
  cfg.pre_det_bits = meter_dbg.repeats;
  cfg.thresh_db = meter_dbg.thresh;
  cfg.ook_pattern = a.pattern;
  cfg.ook_pattern_bits = a.pattern_bits;
  memcpy(cfg.sync, a.sync, a.sync_len);
  cfg.sync_len = a.sync_len;
  cfg.pkt_len = a.pkt_bytes;
  return cfg;
}

bool MyMesh::isMeterChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _meter_active && idx == MAX_GROUP_CHANNELS + VCH_METERS;
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::applyMeters() {
  bool was = _meter_active;
  if (!_prefs.meter.en) {
    if (_meter_listening) _radio->stopFskListen();
    _meter_active = _meter_listening = false;
    return;
  }
  _meter_active = _radio->startFskListen(meterListen(meters::KIND_R900, meters::channelMHz(meters::KIND_R900, 0)), 1);   // probe
  _radio->stopFskListen();
  _meter_listening = false;
  if (_meter_active && !was) {
    _meter_frames = _meter_bad = _meter_shown = _meter_listen_ms = 0;
    memset(_meter_kind_ok, 0, sizeof(_meter_kind_ok));
    _meter_seen_n = 0;
    _meter_turn = 0;
    _meter_timed_tries = 0;
    _meter_since = _meter_next = millis();
  }
}

// Is this meter in 'set meter.ids' (eg. "1234567890,87654321")?
bool MyMesh::meterWanted(uint32_t id) const {
  const char* p = _prefs.meter.ids;
  while (*p) {
    while (*p == ',' || *p == ' ') p++;
    if (!*p) break;
    char* end;
    unsigned long v = strtoul(p, &end, 10);
    if (end == p) { p++; continue; }
    if (v == id) return true;
    p = end;
  }
  return false;
}

MyMesh::MeterSeen* MyMesh::meterSeen(uint8_t kind, uint32_t id) {
  for (int i = 0; i < _meter_seen_n; i++) if (_meter_seen[i].id == id && _meter_seen[i].kind == kind) return &_meter_seen[i];
  MeterSeen* e;
  if (_meter_seen_n < METER_SEEN) {
    e = &_meter_seen[_meter_seen_n++];
  } else {   // full: the one heard longest ago that isn't wanted
    e = NULL;
    for (int i = 0; i < _meter_seen_n; i++) {
      MeterSeen* s = &_meter_seen[i];
      if (meterWanted(s->id)) continue;
      if (!e || (int32_t)(s->heard_at - e->heard_at) < 0) e = s;
    }
    if (!e) return NULL;
  }
  memset(e, 0, sizeof(*e));
  e->id = id;
  e->kind = kind;
  e->seq_pos = 0xFF;
  return e;
}

// "1,204,511"
static int withCommas(char* out, size_t n, uint32_t v) {
  char d[12];
  int k = snprintf(d, sizeof(d), "%lu", (unsigned long) v);
  int o = 0;
  for (int i = 0; i < k && o + 1 < (int) n; i++) {
    if (i && (k - i) % 3 == 0 && o + 2 < (int) n) out[o++] = ',';
    out[o++] = d[i];
  }
  out[o] = 0;
  return o;
}

static const char* leakWords(uint8_t now) {
  return now == 2 ? "continuous (water every 15 min for a day)" : now == 1 ? "on and off (water in half the day's 15 min)" : "none";
}

static const char* daysWords(uint8_t code) {
  static const char* w[8] = { "", "1-2 days", "3-7 days", "8-14 days", "15-21 days", "22-34 days", "35+ days", "35+ days" };
  return w[code & 7];
}

void MyMesh::meterPost(MeterSeen& m, const meters::Reading& r) {
#ifdef MAX_GROUP_CHANNELS
  uint32_t now = millis();
  // "Water 0882" (the last 4 digits tell your meters apart): first letter capital
  char who[24];
  snprintf(who, sizeof(who), "%s %04lu", meters::utilityName(r.utility), (unsigned long)(r.id % 10000));
  who[0] = toupper((unsigned char) who[0]);
  char total[16];
  withCommas(total, sizeof(total), r.total);
  char post[MAX_FRAME_SIZE];
  int ch = MAX_GROUP_CHANNELS + VCH_METERS;
  bool leak_changed = r.kind == meters::KIND_R900 && m.posted_at && (r.leak_now != m.leak_now || r.backflow != m.backflow);
  uint32_t every = (uint32_t)(_prefs.meter.every ? _prefs.meter.every : 60) * 60000UL;
  bool due = !m.posted_at || (int32_t)(now - m.posted_at - every) >= 0;
  if (!due && !leak_changed) return;

  int k;
  if (!m.posted_at) {
    k = snprintf(post, sizeof(post), "%s: %s", who, total);
  } else {
    char used[16];
    withCommas(used, sizeof(used), r.total - m.posted_total);   // the register only counts up (wraps at 2^24/2^27/2^32)
    uint32_t mins = (now - m.posted_at + 30000) / 60000;
    k = snprintf(post, sizeof(post), "%s: %s, +%s in %lu min", who, total, used, (unsigned long) mins);
  }
  if (r.kind == meters::KIND_R900 && k < (int) sizeof(post) - 80) {
    if (r.leak_now) k += snprintf(&post[k], sizeof(post) - k, ". Leak: %s%s%s", leakWords(r.leak_now),
                                  r.leak_days ? ", leaking for " : "", daysWords(r.leak_days));
    else if (leak_changed && m.leak_now) k += snprintf(&post[k], sizeof(post) - k, ". Leak: none now");
    if (r.backflow) k += snprintf(&post[k], sizeof(post) - k, ". Backflow: %s", r.backflow >= 2 ? "high" : "low");
    else if (leak_changed && m.backflow) k += snprintf(&post[k], sizeof(post) - k, ". Backflow: none now");
  }
  pushChannelText(ch, getRTCClock()->getCurrentTimeUnique(), 0, 0, post, k);
  m.posted_at = now;
  m.posted_total = r.total;
  m.leak_now = r.leak_now;
  m.backflow = r.backflow;
  _meter_shown++;
#else
  (void) m; (void) r;
#endif
}

void MyMesh::meterFrame(uint8_t kind, const uint8_t* chips, int len, float rssi) {
  _meter_frames++;
  meters::Reading r;
  if (!meters::read(kind, chips, len, &r)) {
    _meter_bad++;
    _meter_last_bad_kind = kind;   // for 'get meter.last'
    _meter_last_bad_len = (uint8_t)(len < (int) sizeof(_meter_last_bad) ? len : sizeof(_meter_last_bad));
    memcpy(_meter_last_bad, chips, _meter_last_bad_len);
    return;
  }
  if (kind >= 1 && kind <= meters::KINDS) _meter_kind_ok[kind - 1]++;
  MeterSeen* m = meterSeen(kind, r.id);
  if (!m) return;
  uint32_t now = millis();
  if (m->count) {   // how often it sends: the gap since it was last heard, over the whole periods in it
    uint64_t p = m->period_us ? m->period_us : (uint64_t) meters::periodMs(kind) * 1000;
    uint64_t g = (uint64_t)(now - m->heard_at) * 1000;
    uint32_t k = (uint32_t)((g + p / 2) / p);
    if (k >= 1 && k <= 1000) {
      uint64_t est = g / k;
      uint64_t off = est > p ? est - p : p - est;
      if (off * 30 < p) m->period_us = (uint32_t)(k >= 3 || !m->period_us ? est : (p * 3 + est) / 4);
    }
    if (_meter_timed && _meter_listening && m->tries) m->hits++;
  }
  m->utility = r.utility;
  m->total = r.total;
  m->heard_at = now;
  if (kind == meters::KIND_R900 && _meter_listen_ch >= 0) {   // where it is in the hop sequence
    int p = meters::r900HopPos(_meter_listen_ch);
    if (p >= 0) m->seq_pos = (uint8_t) p;
  }
  m->rssi = (int16_t) rssi;
  if (m->count < 0xFFFF) m->count++;
  m->leak_days = r.leak_days;
  if (meterWanted(r.id)) meterPost(*m, r);
}

#ifdef FISB_BENCH_TX
// Bench only (-D FISB_BENCH_TX; never in releases): sends the chips of a meter frame made by
// tools/bench/meters.py ('chips'), once, at 902-909 or 922-928 MHz (not where meters send):
//   meter tx <MHz> <hex>
// Or like a meter, on its own clock until 'meter tx stop' (up to 2 at once):
//   meter tx every <ms> <MHz> <hex>
static struct { uint32_t every, next; float mhz; uint8_t chips[64]; int n; } bench_auto[2];

static void meterBenchAuto() {
  uint32_t now = millis();
  for (auto& b : bench_auto) {
    if (!b.every || (int32_t)(now - b.next) < 0) continue;
    radio_driver.benchOokTx(b.mhz, (uint32_t) (METER_CHIP_BPS * 1000.0f + 0.5f), b.chips, b.n);
    b.next += b.every;
    if ((int32_t)(now - b.next) > 0) b.next = now + b.every;   // fell behind: start again
  }
}

static bool meterBenchTx(const char* cmd, char* reply) {
  if (strcmp(cmd, "meter tx stop") == 0) {
    memset(bench_auto, 0, sizeof(bench_auto));
    strcpy(reply, "OK - stopped");
    return true;
  }
  if (strncmp(cmd, "meter tx ", 9) != 0) return false;
  char* p;
  uint32_t every = 0;
  if (strncmp(&cmd[9], "every ", 6) == 0) {
    every = strtoul(&cmd[15], &p, 10);
    cmd = p - 9;   // so &cmd[9] is what follows the period
  }
  float mhz = strtod(&cmd[9], &p);
  // the ISM band, away from where real meters send (910-921 MHz): a made-up meter mustn't reach a reader
  if (mhz < 902.0f || mhz > 928.0f || (mhz >= 909.0f && mhz <= 922.0f)) {
    strcpy(reply, "Error: 902-909 or 922-928 MHz only (meters use 910-921)");
    return true;
  }
  while (*p == ' ') p++;
  uint8_t chips[64];
  int n = 0;
  while (p[0] && p[1] && n < (int) sizeof(chips)) {
    unsigned b;
    if (sscanf(p, "%2x", &b) != 1) break;
    chips[n++] = (uint8_t) b;
    p += 2;
  }
  if (n == 0) { strcpy(reply, "Error: meter tx [every <ms>] <MHz> <hex>"); return true; }
  if (every) {
    int slot = bench_auto[0].every ? 1 : 0;
    if (every < 500 || bench_auto[slot].every) { strcpy(reply, "Error: 2 at most ('meter tx stop'), every 500 ms or more"); return true; }
    bench_auto[slot].every = every;
    bench_auto[slot].next = millis() + every;
    bench_auto[slot].mhz = mhz;
    memcpy(bench_auto[slot].chips, chips, n);
    bench_auto[slot].n = n;
    sprintf(reply, "OK - sending %d bytes every %lu ms", n, (unsigned long) every);
    return true;
  }
  int16_t st = radio_driver.benchOokTx(mhz, (uint32_t) (METER_CHIP_BPS * 1000.0f + 0.5f), chips, n);
  if (st == RADIOLIB_ERR_NONE) sprintf(reply, "OK - sent %d bytes", n);
  else sprintf(reply, "Error: %d", st);
  return true;
}
#endif

// The listens. A meter sends on one channel of 50-80 at a time, and the receiver takes one, so a
// listen at a random moment rarely catches a given meter. But each meter sends like clockwork
// (R900 every 14.0 s, Itron every 15.000 s): once one of yours has been heard, short listens open
// just when it's due, each on another of its channels (a few readings an hour, under 1% of the
// mesh's time per meter). Until all of yours have been heard, or with none chosen, a search also
// runs 'meter.duty' of the time, across every kind and channel in turn.

// How far off a meter's next frame may be, ms: a base, and more for each period since it was heard
static uint32_t meterSlack(uint8_t kind, uint32_t periods) {
  uint32_t w = kind == meters::KIND_R900 ? 60 + periods : 30 + periods / 4;
  return w > 500 ? 500 : w;
}

static const uint32_t METER_TRACK_MAX_MS = 3UL * 3600 * 1000;   // not heard for 3 h: search for it again

// The next timed listen: the wanted meter due soonest. False if there's none to time.
bool MyMesh::meterNextTimed(uint32_t now, int* which, uint32_t* start, uint32_t* end, uint32_t* periods) const {
  bool found = false;
  for (int i = 0; i < _meter_seen_n; i++) {
    const MeterSeen& m = _meter_seen[i];
    if (!m.count || !meterWanted(m.id)) continue;
    uint32_t since = now - m.heard_at;
    if (since > METER_TRACK_MAX_MS) continue;
    uint64_t p_us = m.period_us ? m.period_us : (uint64_t) meters::periodMs(m.kind) * 1000;
    // the first frame whose window hasn't closed yet
    uint32_t n = (uint32_t)(((uint64_t) since * 1000) / p_us);
    uint32_t t, w;
    for (;; n++) {
      t = m.heard_at + (uint32_t)(((uint64_t) n * p_us + 500) / 1000);
      w = meterSlack(m.kind, n);
      if (n > 0 && (int32_t)(t + w - now) > 5) break;
    }
    uint32_t s = t - w;
    if (!found || (int32_t)(s - *start) < 0) {
      found = true;
      *which = i;
      *start = s;
      *end = t + w;
      *periods = n;
    }
  }
  return found;
}

// Kinds to search for: none once every chosen meter has been heard lately, else all
uint8_t MyMesh::meterSearchKinds() const {
  if (meter_dbg.kind) return 1 << (meter_dbg.kind - 1);
  if (!_prefs.meter.ids[0]) return 0x07;
  uint32_t now = millis();
  const char* p = _prefs.meter.ids;
  while (*p) {
    while (*p == ',' || *p == ' ') p++;
    if (!*p) break;
    char* end;
    unsigned long v = strtoul(p, &end, 10);
    if (end == p) { p++; continue; }
    p = end;
    bool heard = false;
    for (int i = 0; i < _meter_seen_n && !heard; i++) {
      heard = _meter_seen[i].id == v && _meter_seen[i].count && now - _meter_seen[i].heard_at < METER_TRACK_MAX_MS;
    }
    if (!heard) return 0x07;
  }
  return 0;
}

void MyMesh::meterLoop() {
#ifdef FISB_BENCH_TX
  meterBenchAuto();
#endif
  if (!_meter_active) return;
  uint32_t now = millis();
  uint8_t chips[32];
  float rssi = 0;
  int len;
  while ((len = _radio->recvFsk(chips, sizeof(chips), &rssi)) > 0) meterFrame(_meter_kind, chips, len, rssi);

  int st = _radio->fskListenState();
  bool forever = _prefs.meter.duty >= 100;
  if (_meter_listening) {
    if (st == 0) {
      _meter_listen_ms += _radio->lastFskListenMillis();
      _meter_listening = false;
      if (!_meter_timed) {
        uint8_t duty = _prefs.meter.duty ? _prefs.meter.duty : 1;
        _meter_next = now + (forever ? 0 : _meter_last_win * (100 - duty) / duty);
      }
    }
    return;
  }
  if (st != 0) return;

  // a chosen meter due: its listen first
  int which = -1;
  uint32_t t_start = 0, t_end = 0, periods = 0;
  bool timed = meterNextTimed(now, &which, &t_start, &t_end, &periods);
  if (timed && (int32_t)(t_start - now) <= 0) {
    MeterSeen& m = _meter_seen[which];
    int ch;
    if (m.kind == meters::KIND_R900 && m.seq_pos != 0xFF) {   // where its hop sequence says it'll be
      ch = meters::r900HopChannel(m.seq_pos + (int) periods);
    } else {   // a channel in turn: one try in 50-78
      int nch = meters::channels(m.kind);
      m.ch_turn = (uint8_t)((m.ch_turn + 11) % nch);   // 11: no common factor with 51 or 78
      ch = m.ch_turn;
    }
    _meter_kind = m.kind;
    _meter_listen_ch = (int16_t)(_meter_center > 0 ? -1 : ch);
    float freq = _meter_center > 0 ? _meter_center : meters::channelMHz(m.kind, ch);
    if (_radio->startFskListen(meterListen(m.kind, freq), t_end - now)) {
      _meter_listening = true;
      _meter_timed = true;
      _meter_timed_tries++;
      if (m.tries < 0xFFFF) m.tries++;
    }
    return;
  }

  // else the search, between timed listens
  uint8_t kinds = meterSearchKinds();
  if (!kinds) return;
  if ((int32_t)(now - _meter_next) < 0) return;
  uint32_t win = forever ? METER_FOREVER_MS : METER_WINDOW_MS;
  if (timed) {
    int32_t room = (int32_t)(t_start - now) - 10;
    if (room < 50) return;
    if ((uint32_t) room < win) win = (uint32_t) room;
  }
  for (int tries = 0; tries < meters::KINDS; tries++) {
    _meter_turn = (uint8_t)((_meter_turn + 1) % meters::KINDS);
    if (kinds & (1 << _meter_turn)) break;
  }
  uint8_t kind = (uint8_t)(_meter_turn + 1);
  int nch = meters::channels(kind);
  _meter_search_ch[_meter_turn] = (uint8_t)((_meter_search_ch[_meter_turn] + 7) % nch);
  float freq = _meter_center > 0 ? _meter_center : meters::channelMHz(kind, _meter_search_ch[_meter_turn]);
  _meter_listen_ch = (int16_t)(_meter_center > 0 ? -1 : _meter_search_ch[_meter_turn]);
  _meter_kind = kind;
  if (_radio->startFskListen(meterListen(kind, freq), win)) {
    _meter_listening = true;
    _meter_timed = false;
    _meter_last_win = win;
  }
}

static bool meterOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}


bool MyMesh::handleMeterCommand(const char* command, char* reply) {
  bool on;
#ifdef FISB_BENCH_TX
  if (meterBenchTx(command, reply)) return true;
#endif
  if (strcmp(command, "meter") == 0 || strcmp(command, "get meter") == 0) {
    char listen[24];
    if (_prefs.meter.duty >= 100) strcpy(listen, "all the time");
    else snprintf(listen, sizeof(listen), "%u%% of the time", _prefs.meter.duty);
    snprintf(reply, 160, "> Meters %s: %s, listening %s, a post every %u min%s", _prefs.meter.en ? "on" : "off",
             _prefs.meter.ids[0] ? _prefs.meter.ids : "none chosen ('set meter.ids')", listen,
             _prefs.meter.every ? _prefs.meter.every : 60, _prefs.meter.en && !_meter_active ? " (needs an LR2021)" : "");
    return true;
  }
  if (strcmp(command, "get meter.stats") == 0) {
    uint32_t up = millis() - _meter_since;
    uint32_t pm = up ? (uint32_t)((uint64_t) _meter_listen_ms * 1000 / up) : 0;
    uint32_t hits = 0;
    for (int i = 0; i < _meter_seen_n; i++) hits += _meter_seen[i].hits;
    sprintf(reply, "> %lu frames (%lu bad; R900 %lu, SCM %lu, SCM+ %lu), %d meters, %lu posts, timed %lu/%lu, listening %u.%u%%%s",
            (unsigned long) _meter_frames, (unsigned long) _meter_bad, (unsigned long) _meter_kind_ok[0],
            (unsigned long) _meter_kind_ok[1], (unsigned long) _meter_kind_ok[2], _meter_seen_n,
            (unsigned long) _meter_shown, (unsigned long) hits, (unsigned long) _meter_timed_tries,
            (unsigned) (pm / 10), (unsigned) (pm % 10), meterSearchKinds() ? ", searching" : "");
    return true;
  }
  if (strcmp(command, "get meter.last") == 0) {   // the last frame that didn't read: its raw chips
    int k = sprintf(reply, "> %s %d:", meters::kindName(_meter_last_bad_kind), _meter_last_bad_len);
    for (int i = 0; i < _meter_last_bad_len; i++) k += sprintf(&reply[k], "%02x", _meter_last_bad[i]);
    return true;
  }
  if (strcmp(command, "get meter.heard") == 0 || strncmp(command, "get meter.heard ", 16) == 0) {
    if (_meter_seen_n == 0) {
      strcpy(reply, _meter_active ? "> no meters heard yet" : "> meters are off ('meter on')");
      return true;
    }
    // the strongest first: your own meters are the closest
    int from = command[15] ? atoi(&command[16]) : 0;
    uint8_t order[METER_SEEN];
    for (int i = 0; i < _meter_seen_n; i++) order[i] = (uint8_t) i;
    for (int i = 1; i < _meter_seen_n; i++) {
      for (int j = i; j > 0 && _meter_seen[order[j]].rssi > _meter_seen[order[j - 1]].rssi; j--) {
        uint8_t t = order[j]; order[j] = order[j - 1]; order[j - 1] = t;
      }
    }
    uint32_t now = millis();
    int k = sprintf(reply, "> %d:", _meter_seen_n);
    int i = from < 0 ? 0 : from;
    for (; i < _meter_seen_n; i++) {
      const MeterSeen& m = _meter_seen[order[i]];
      char total[16];
      withCommas(total, sizeof(total), m.total);
      char item[64];
      int n = snprintf(item, sizeof(item), "%s %s %lu %s %ddBm %lum", i > from ? "," : "", meters::utilityName(m.utility),
                       (unsigned long) m.id, total, m.rssi, (unsigned long)((now - m.heard_at) / 60000));
      if (k + n > 150) break;
      memcpy(&reply[k], item, n + 1);
      k += n;
    }
    if (i < _meter_seen_n) sprintf(&reply[k], " (more: 'get meter.heard %d')", i);
    return true;
  }
  const char* arg = NULL;
  if (strncmp(command, "meter ", 6) == 0 && meterOnOff(&command[6], &on)) arg = &command[6];
  else if (strncmp(command, "set meter ", 10) == 0 && meterOnOff(&command[10], &on)) arg = &command[10];
  if (arg) {
    if (listensBusy(reply)) return true;
    char off[64] = "";
    if (on) listenOthersOff(LISTEN_METERS, off, sizeof(off));
    _prefs.meter.en = on ? 1 : 0;
    applyMeters();
    if (on && !_meter_active) {
      _prefs.meter.en = 0;
      strcpy(reply, "Error: this radio can't listen for meters (needs an LR2021)");
    } else {
      savePrefs();
      if (on) sprintf(reply, "OK - Meters on%s. Reconnect the app to see the channel", off);
      else strcpy(reply, "OK - Meters off");
    }
    return true;
  }
  if (strncmp(command, "set meter.", 10) != 0) return false;
  const char* opt = &command[10];
  if (strncmp(opt, "ids ", 4) == 0 || strcmp(opt, "ids") == 0) {
    const char* v = opt[3] ? &opt[4] : "";
    if (strcmp(v, "none") == 0) v = "";
    if (strlen(v) >= sizeof(_prefs.meter.ids)) {
      sprintf(reply, "Error: at most %d characters", (int) sizeof(_prefs.meter.ids) - 1);
      return true;
    }
    for (const char* p = v; *p; p++) {
      if (!isdigit((unsigned char)*p) && *p != ',' && *p != ' ') {
        strcpy(reply, "Error: meter IDs (numbers, as in 'get meter.heard') separated by commas");
        return true;
      }
    }
    StrHelper::strncpy(_prefs.meter.ids, v, sizeof(_prefs.meter.ids));
    for (int i = 0; i < _meter_seen_n; i++) _meter_seen[i].posted_at = 0;   // each one's reading again
    savePrefs();
    if (v[0]) sprintf(reply, "OK - showing %s", _prefs.meter.ids);
    else strcpy(reply, "OK - no meters shown (the table still fills: 'get meter.heard')");
    return true;
  }
  if (strncmp(opt, "every ", 6) == 0) {
    int m = atoi(&opt[6]);
    if (m < 1 || m > 1440) { strcpy(reply, "Error: minutes between posts, 1-1440 (a leak is posted at once)"); return true; }
    _prefs.meter.every = (uint16_t) m;
    savePrefs();
    sprintf(reply, "OK - a post every %d min (a leak at once)", m);
    return true;
  }
  if (strncmp(opt, "center ", 7) == 0) {   // for tests, until reboot: one centre instead of four
    float f = strcmp(&opt[7], "auto") == 0 ? 0 : atof(&opt[7]);
    if (f != 0 && (f < 902.0f || f > 928.0f)) { strcpy(reply, "Error: set meter.center <MHz 902-928>|auto"); return true; }
    _meter_center = f;
    if (f > 0) sprintf(reply, "OK - listening around %s MHz only (until reboot)", &opt[7]);
    else strcpy(reply, "OK - listening across 910-921 MHz");
    return true;
  }
  if (strncmp(opt, "dbg ", 4) == 0) {
    char* q;   // (no float sscanf in newlib nano)
    int rp = (int) strtol(&opt[4], &q, 10);
    float bw = strtod(q, &q);
    int th = (int) strtol(q, &q, 10);
    int kd = (int) strtol(q, &q, 10);
    meter_dbg.repeats = (uint8_t) rp; meter_dbg.rxbw = bw; meter_dbg.thresh = (uint8_t) th;
    meter_dbg.kind = kd >= 1 && kd <= meters::KINDS ? (uint8_t) kd : 0;
    sprintf(reply, "OK - repeats %d, rxbw %d kHz, threshold %d dB, kind %d (0 = default)", rp, (int) bw, th, meter_dbg.kind);
    return true;
  }
  if (strncmp(opt, "duty ", 5) == 0) {
    int d = atoi(&opt[5]);
    if (d < 1 || d > 100) { strcpy(reply, "Error: % of the time listening, 1-100 (100 = all the time: the mesh can't be heard)"); return true; }
    _prefs.meter.duty = (uint8_t) d;
    savePrefs();
    if (d >= 100) strcpy(reply, "OK - listening all the time. The mesh can't be heard until a lower duty (sending still works)");
    else sprintf(reply, "OK - listening %d%% of the time", d);
    return true;
  }
  strcpy(reply, "Error: set meter.ids <IDs>|none, meter.every <min>, meter.duty <1-100>");
  return true;
}
