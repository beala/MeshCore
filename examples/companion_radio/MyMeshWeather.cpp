// Weather sensors in the MeshCore app (docs/weather_sensors.md).
//
// Ecowitt, Ambient Weather and other Fine Offset sensors send short FSK packets at a fixed interval.
// An LR2021 can step away from the mesh for a moment to hear them (CustomLR2021Wrapper's FSK
// listen). wxsensor::Tracker learns each sensor's interval and asks for a listen only around the
// moment its next packet is due, so the radio stays on the mesh nearly all the time. Readings show
// in the app as an extra, receive-only channel after the real ones (and after Meshtastic's).

#include "MyMesh.h"
#ifdef FISB_BENCH_TX
#include "target.h"
#endif

#define WX_PKT_LEN   32       // the longest packet (WS90)
#define WX_REPLY_MAX 140      // CLI replies go into a 166 byte buffer, after an optional prefix
#define WX_CONFIRM_MS (15 * 60000UL)   // a weakly checked new sensor's second packet, within

bool MyMesh::isWeatherChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _wx_active && idx == MAX_GROUP_CHANNELS + VCH_WEATHER;
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::getWeatherChannel(ChannelDetails& ch) {
  memset(&ch, 0, sizeof(ch));
  strcpy(ch.name, "Weather");
  // the app wants a secret for every channel: one that matches no MeshCore channel
  uint8_t h[32];
  const char* tag = "weather sensors channel";
  mesh::Utils::sha256(h, sizeof(h), (const uint8_t*) tag, strlen(tag));
  memcpy(ch.channel.secret, h, 16);
}

// Listen settings per radio format. The LR2021's FSK receiver takes a bit rate only within about
// 0.1-0.3% of its setting (measured on the bench with an SX1262 sending), a deviation within about
// 20% of its setting, and a sync word that starts where the preamble ends: each group of senders
// gets a format, at the rates and deviations measured on rtl_433's recordings of real sensors. The
// receiver bandwidth leaves room for the sensors' crystal error (±20 ppm is ±18 kHz).
mesh::Radio::FskListen MyMesh::weatherListen(uint8_t proto) const {
  mesh::Radio::FskListen cfg = {};
  cfg.freq = _prefs.wx.freq;
  cfg.dev_khz = 35.0f;   // the receiver's demodulator expects this deviation (about ±20%)
  // Some La Crosse models sit at 914.938 MHz: a wider receiver covers both
  cfg.rxbw_khz = 238.1f;
  cfg.pkt_len = 13;
  static const uint8_t SYNC_LTV[4] = { 0xD2, 0xAA, 0x2D, 0xD4 }, SYNC_TP[4] = { 0xD2, 0x55, 0x2D, 0xD4 };
  switch (proto) {
    case wxsensor::PROTO_LACROSSE:   // La Crosse View: up to 11 bytes
    case wxsensor::PROTO_LTV_SLOW:
    case wxsensor::PROTO_LTV_W1:
      cfg.kbps = proto == wxsensor::PROTO_LACROSSE ? 9.606f : proto == wxsensor::PROTO_LTV_SLOW ? 9.362f : 9.329f;
      memcpy(cfg.sync, SYNC_LTV, 4); cfg.sync_len = 4;
      break;
    case wxsensor::PROTO_ITPLUS:     // IT+: 5 bytes after AA AA 2D D4, ±20 kHz
      cfg.kbps = 9.577f;
      cfg.dev_khz = 20.0f;
      cfg.sync[0] = 0x2D; cfg.sync[1] = 0xD4; cfg.sync_len = 2;
      cfg.pre_det_bits = 8;
      break;
    case wxsensor::PROTO_TX22U:      // TX22U-IT: up to 13 bytes, after only 16 bits of preamble
      cfg.kbps = 8.624f;
      cfg.sync[0] = 0x2D; cfg.sync[1] = 0xD4; cfg.sync_len = 2;
      cfg.pre_det_bits = 8;
      break;
    case wxsensor::PROTO_TX7B:       // ThermoPro TX-7B: 9 bytes
      cfg.kbps = 9.26f;
      memcpy(cfg.sync, SYNC_TP, 4); cfg.sync_len = 4;
      break;
    case wxsensor::PROTO_FO_WIDE:    // Fine Offset WH25, La Crosse TX29-IT: ±60 kHz
      cfg.kbps = 17.235f;
      cfg.dev_khz = 55.0f;
      cfg.sync[0] = 0x2D; cfg.sync[1] = 0xD4; cfg.sync_len = 2;
      cfg.pkt_len = WX_PKT_LEN;
      break;
    default:                         // Fine Offset: up to 32 bytes (WS90), ±27-36 kHz
      cfg.kbps = 17.22f;
      cfg.dev_khz = 32.0f;
      cfg.rxbw_khz = 153.8f;
      cfg.sync[0] = 0x2D; cfg.sync[1] = 0xD4; cfg.sync_len = 2;
      cfg.pkt_len = WX_PKT_LEN;
      break;
  }
  if (_wx_dbg_kbps > 0) cfg.kbps = _wx_dbg_kbps;
  if (_wx_dbg_rxbw > 0) cfg.rxbw_khz = _wx_dbg_rxbw;
  if (_wx_dbg_dev > 0) cfg.dev_khz = _wx_dbg_dev;
  if (_wx_dbg_pre == 255) { cfg.no_preamble = true; cfg.pre_det_bits = 0; }
  else if (_wx_dbg_pre) cfg.pre_det_bits = _wx_dbg_pre;
  if (_wx_dbg_sync_len) { memcpy(cfg.sync, _wx_dbg_sync, sizeof(cfg.sync)); cfg.sync_len = _wx_dbg_sync_len; }
  return cfg;
}

void MyMesh::applyWeather() {
  bool was = _wx_active;
  _radio->stopFskListen();
  _wx_win_open = false;
  if (!_prefs.wx.en) {
    _wx_active = false;
    return;
  }
  // probe: a radio without FSK listens says no straight away
  _wx_active = _radio->startFskListen(weatherListen(wxsensor::PROTO_FINEOFFSET), 1);
  _radio->stopFskListen();
  _wx.setProtocols(weatherProtocols());
  if (_wx_active && !was) {
    _wx.setSeed(millis() ^ 0xA5A5u);
    _wx.reset(millis());
    _wx.scanFor(millis());   // find the sensors in range: one listen without a break per format
    _wx_scan_report = true;
    _wx_since = millis();
    _wx_heard = _wx_bad = _wx_shown = _wx_windows = _wx_listen_ms = 0;
  }
}

static void sensorLabel(const wxsensor::Reading& r, char* out, size_t n) {
  if (r.model == wxsensor::WH31) snprintf(out, n, "ch%u", r.channel);
  else snprintf(out, n, "%lx", (unsigned long) r.id);
}

// 'set wx.only' filter: the sensor's label (as shown in its posts) is in the list
bool MyMesh::weatherShown(const wxsensor::Reading& r) const {
  if (_prefs.wx.only[0] == 0) return true;
  char label[12];
  sensorLabel(r, label, sizeof(label));
  size_t ln = strlen(label);
  const char* p = _prefs.wx.only;
  while (*p) {
    while (*p == ' ' || *p == ',') p++;
    const char* e = p;
    while (*e && *e != ',' && *e != ' ') e++;
    if ((size_t)(e - p) == ln && strncasecmp(p, label, ln) == 0) return true;
    p = e;
  }
  return false;
}

void MyMesh::showWeather(const char* text, int8_t snr_x4) {
#ifdef MAX_GROUP_CHANNELS
  int idx = MAX_GROUP_CHANNELS + VCH_WEATHER;
  pushChannelText(idx, getRTCClock()->getCurrentTimeUnique(), snr_x4, 0, text, strlen(text));
  _wx_shown++;
#endif
}

uint8_t MyMesh::weatherProtocols() const {
  uint8_t k = _prefs.wx.kinds & 3, m = 0;
  if (k & 1) m |= wxsensor::PROTOS_ECOWITT;
  if (k & 2) m |= wxsensor::PROTOS_LACROSSE;
  return m ? m : wxsensor::PROTOS_ECOWITT;
}

bool MyMesh::weatherConfirmed(const wxsensor::Reading& r, uint32_t now) {
  uint32_t key = wxsensor::sensorKey(r);
  if (!r.weak || _wx.find(key)) return true;
  int oldest = 0;
  for (int i = 0; i < (int)(sizeof(_wx_pending) / sizeof(_wx_pending[0])); i++) {
    WxPending& p = _wx_pending[i];
    if (p.key == key && p.at && now - p.at < WX_CONFIRM_MS) { p.key = 0; p.at = 0; return true; }
    if (p.at == 0 || (int32_t)(p.at - _wx_pending[oldest].at) < 0) oldest = i;
  }
  _wx_pending[oldest].key = key;
  _wx_pending[oldest].at = now ? now : 1;
  return false;
}

// A packet that didn't decode. If it still checks out the way its format's packets do, it's
// probably a model this firmware doesn't know: kept for 'get wx.unknown'. Else a bad packet.
void MyMesh::weatherUnknown(const uint8_t* buf, int n, float rssi, uint32_t now) {
  int len;
  bool strong = _wx_rx_proto == wxsensor::PROTO_FINEOFFSET || _wx_rx_proto == wxsensor::PROTO_FO_WIDE;
  if (strong) len = wxsensor::ignoredFamily(buf[0]) ? 0 : wxsensor::checkedLength(buf, n);
  else len = wxsensor::crcLength(buf, n);
  if (len <= 0) { _wx_bad++; return; }
  // the same kind of packet: Fine Offset by family and length; else by length and the first 3 bytes
  // (an ID, most likely)
  int cmp = strong ? 1 : 3, slot = -1, oldest = 0;
  const int N = (int)(sizeof(_wx_unk) / sizeof(_wx_unk[0]));
  for (int i = 0; i < N; i++) {
    WxUnknown& u = _wx_unk[i];
    if (u.count && u.proto == _wx_rx_proto && u.len == len && memcmp(u.pkt, buf, cmp) == 0) { slot = i; break; }
    if (u.count == 0 || (int32_t)(u.at - _wx_unk[oldest].at) < 0) oldest = i;
  }
  bool fresh = slot < 0;
  if (fresh) { slot = oldest; memset(&_wx_unk[slot], 0, sizeof(WxUnknown)); }
  WxUnknown& u = _wx_unk[slot];
  if (u.count < 0xFFFF) u.count++;
  u.at = now;
  u.rssi = (int16_t) rssi;
  u.proto = _wx_rx_proto;
  u.len = (uint8_t) len;
  u.n = (uint8_t)(n < (int) sizeof(u.pkt) ? n : (int) sizeof(u.pkt));
  memcpy(u.pkt, buf, u.n);
  // only 8 bits of check: one packet in 256 of noise passes it, so it counts from the second
  if (!strong && u.count < 2) { _wx_bad++; return; }
  if ((strong ? fresh : u.count == 2) && _wx.scanningForever()) {
    char note[120];
    snprintf(note, sizeof(note), "Unknown sensor, %d dBm: %u bytes, starts %02x %02x %02x ('get wx.unknown')",
             (int) rssi, (unsigned) len, buf[0], buf[1], buf[2]);
    ChatRef to;
    memset(&to, 0, sizeof(to));
    to.kind = CHAT_CONSOLE;
    postToChat(to, note);
  }
}

int MyMesh::weatherUnknownCount() const {
  int c = 0;
  for (const WxUnknown& u : _wx_unk) {
    if (u.count >= (u.proto == wxsensor::PROTO_FINEOFFSET || u.proto == wxsensor::PROTO_FO_WIDE ? 1 : 2)) c++;
  }
  return c;
}

void MyMesh::weatherLoop() {
  if (!_wx_active) return;
  uint32_t now = millis();

  // packets heard
  uint8_t buf[WX_PKT_LEN];
  float rssi = 0;
  for (int k = 0; k < 4; k++) {
    int n = _radio->recvFsk(buf, sizeof(buf), &rssi);
    if (n <= 0) break;
    _wx_heard++;
    wxsensor::Reading r;
    if (!wxsensor::decodeAs(_wx_rx_proto, buf, n, &r)) { weatherUnknown(buf, n, rssi, now); continue; }
    if (!weatherShown(r)) continue;   // filtered out: not followed either
    if (!weatherConfirmed(r, now)) continue;
    wxsensor::Tracker::Sensor* old = _wx.find(wxsensor::sensorKey(r));
    wxsensor::Reading prev = old ? old->last : r;
    bool is_new = old == NULL;
    wxsensor::Tracker::Sensor* s = _wx.onPacket(now, r, (int16_t) rssi);
    if (!s) continue;
    if (_wx_win_open && s->key == _wx_win.key) _wx_win_got = true;
    if (is_new && _wx.scanningForever()) {   // driving around: say so the moment a new one turns up
      char note[200], label[12];
      sensorLabel(r, label, sizeof(label));
      int m = snprintf(note, sizeof(note), "New sensor, %d dBm: ", (int) rssi);
      if (m > 0 && m < (int) sizeof(note)) wxsensor::format(r, _prefs.wx.metric != 0, &note[m], sizeof(note) - m);
      ChatRef to;
      memset(&to, 0, sizeof(to));
      to.kind = CHAT_CONSOLE;
      postToChat(to, note);
    }

    // what to say, if anything: alerts at once, otherwise each sensor every wx.every minutes
    char msg[MAX_FRAME_SIZE];
    int m = -1;
    bool metric = _prefs.wx.metric != 0;
    if (r.model == wxsensor::WH57 && !is_new && r.strike_count != prev.strike_count && r.strike_state == 8) {
      if (r.strike_km) {
        unsigned d = metric ? r.strike_km : (r.strike_km * 62u + 50) / 100;
        m = snprintf(msg, sizeof(msg), "Lightning %u %s away. ", d, metric ? "km" : "mi");
      } else {
        m = snprintf(msg, sizeof(msg), "Lightning. ");
      }
    } else if ((r.have & wxsensor::HAVE_RAINING) && r.raining && !is_new && !prev.raining) {
      m = snprintf(msg, sizeof(msg), "Rain started. ");
    } else if ((r.have & wxsensor::HAVE_LEAK) && r.leak && (is_new || !prev.leak)) {
      m = snprintf(msg, sizeof(msg), "Water leak! ");
    } else if ((r.have & wxsensor::HAVE_LEAK) && !r.leak && !is_new && prev.leak) {
      m = snprintf(msg, sizeof(msg), "Leak over. ");
    } else if (!s->posted || (_prefs.wx.every && now - s->posted_at >= (uint32_t) _prefs.wx.every * 60000UL)) {
      m = 0;
    }
    if (m >= 0 && m < (int) sizeof(msg)) {
      wxsensor::format(r, metric, &msg[m], sizeof(msg) - m);
      showWeather(msg, 0);
      s->posted_at = now;
      s->posted = true;
    }
  }

  if (_wx_scan_report && !_wx.scanning(now) && !_wx_win_open) weatherScanReport();

  // the listen asked of the radio
  int st = _radio->fskListenState();
  if (_wx_win_open) {
    if (st == 0) {
      uint32_t ran = _radio->lastFskListenMillis();
      _wx_listen_ms += ran;
      _wx.windowDone(now, _wx_win, _wx_win_got, ran > 0);
      _wx_win_open = false;
    } else if (_wx_win_got && _wx_win.key != 0) {
      _radio->stopFskListen();   // heard what we came for: back to the mesh now
    }
    return;
  }
  wxsensor::Window w;
  if (_wx.nextWindow(now, &w) && (int32_t)(w.start - now) <= 0 && w.len > 0) {
    if (_radio->startFskListen(weatherListen(w.proto), w.len)) {
      _wx_rx_proto = w.proto;
      _wx_win = w;
      _wx_win_open = true;
      _wx_win_got = false;
      _wx_windows++;
    }
  }
}

// Posted to the Radio console when a scan ends: what was heard, or where to look if nothing was
void MyMesh::weatherScanReport() {
  _wx_scan_report = false;
  char msg[400];
  int n;
  if (_wx.count() == 0) {
    n = snprintf(msg, sizeof(msg), "Weather scan done: no sensors heard on %.3f MHz (%s).%s",
                 _prefs.wx.freq, (_prefs.wx.kinds & 3) == 3 ? "Ecowitt and La Crosse" : (_prefs.wx.kinds & 3) == 2 ? "La Crosse" : "Ecowitt",
                 _wx_bad ? " Some packets failed their checks: a sensor may be too far." : " 'wx scan' tries again.");
  } else {
    n = snprintf(msg, sizeof(msg), "Weather scan done: %d sensor%s.", _wx.count(), _wx.count() == 1 ? "" : "s");
    for (int i = 0; i < _wx.count() && n > 0 && n < (int) sizeof(msg); i++) {
      wxsensor::Tracker::Sensor* s = _wx.get(i);
      char label[12];
      sensorLabel(s->last, label, sizeof(label));
      n += snprintf(&msg[n], sizeof(msg) - n, "\n%s %s: %d dBm, heard %lu time%s", wxsensor::modelName(s->last.model),
                    label, s->rssi, (unsigned long) s->count, s->count == 1 ? "" : "s");
    }
    if (n > 0 && n < (int) sizeof(msg) && _wx.count() > 1 && !_prefs.wx.only[0]) {
      n += snprintf(&msg[n], sizeof(msg) - n, "\nNeighbours' too? 'set wx.only <labels>' keeps just yours.");
    }
  }
  int unk = weatherUnknownCount();
  if (unk && n > 0 && n < (int) sizeof(msg)) {
    snprintf(&msg[n], sizeof(msg) - n, "\nAlso %d kind%s of sensor this firmware can't read yet: 'get wx.unknown'.",
             unk, unk == 1 ? "" : "s");
  }
  ChatRef to;
  memset(&to, 0, sizeof(to));
  to.kind = CHAT_CONSOLE;
  postToChat(to, msg);
}

static bool wxOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}

#ifdef FISB_BENCH_TX
// Bench only: 'wx tx <kbps> <MHz> <preamble and sync hex> <packet hex>' sends one packet as a sensor
// would (no preamble of its own: the first hex holds it, up to 8 bytes). Never at 909-922 MHz,
// where real sensors and their consoles are: bench tests use 925 MHz.
static int hexBytes(const char* p, uint8_t* out, int max, const char** end) {
  int n = 0;
  while (*p == ' ') p++;
  while (p[0] && p[1] && p[0] != ' ' && n < max) {
    unsigned b;
    if (sscanf(p, "%2x", &b) != 1) break;
    out[n++] = (uint8_t) b;
    p += 2;
  }
  if (end) *end = p;
  return n;
}

bool MyMesh::weatherBenchTx(const char* command, char* reply) {
  if (strncmp(command, "wx tx ", 6) != 0) return false;
  char* e;
  float kbps = strtod(&command[6], &e);
  float mhz = strtod(e, &e);
  if (kbps < 1.0f || kbps > 100.0f) { strcpy(reply, "Error: wx tx <kbps> <MHz> <sync hex> <packet hex>"); return true; }
  if (mhz < 902.0f || mhz > 928.0f || (mhz >= 909.0f && mhz <= 922.0f)) {
    strcpy(reply, "Error: 902-909 or 922-928 MHz only");
    return true;
  }
  uint8_t sync[8], pkt[40];
  const char* p;
  int ns = hexBytes(e, sync, sizeof(sync), &p);
  int np = hexBytes(p, pkt, sizeof(pkt), NULL);
  if (ns == 0 || np == 0) { strcpy(reply, "Error: wx tx <kbps> <MHz> <sync hex> <packet hex>"); return true; }
  int16_t st = radio_driver.benchFskTx(mhz, kbps, 35.0f, sync, (uint8_t) ns, (uint8_t)(ns * 8), pkt, (uint16_t) np);
  if (st == RADIOLIB_ERR_NONE) sprintf(reply, "OK - sent %d bytes at %.2f kbps", np, kbps);
  else sprintf(reply, "Error: %d", st);
  return true;
}
#endif

bool MyMesh::handleWeatherCommand(const char* command, char* reply) {
  bool on;
#ifdef FISB_BENCH_TX
  if (weatherBenchTx(command, reply)) return true;
#endif
  const char* arg = NULL;
  if (strcmp(command, "wx") == 0 || strcmp(command, "get wx") == 0) {
    uint8_t k = _prefs.wx.kinds & 3;
    sprintf(reply, "> Weather %s: %s, %.3f MHz, %s, every %u min, sensors %s",
            _prefs.wx.en ? (_wx_active ? (_wx.scanningForever() ? "on, scanning all the time" : "on") : "on, but the radio can't") : "off",
            k == 3 ? "Ecowitt + La Crosse" : k == 2 ? "La Crosse" : "Ecowitt", _prefs.wx.freq,
            _prefs.wx.metric ? "metric" : "US units", _prefs.wx.every, _prefs.wx.only[0] ? _prefs.wx.only : "all");
    return true;
  }
  if (strcmp(command, "get wx.sensors") == 0) {   // what's been heard: label, model, interval, signal
    if (_wx.count() == 0) {
      strcpy(reply, _wx.scanning(millis()) ? "> none yet (scanning)" : "> none heard");
      return true;
    }
    int n = sprintf(reply, ">");
    uint32_t now = millis();
    for (int i = 0; i < _wx.count(); i++) {   // as many as fit in a reply
      wxsensor::Tracker::Sensor* s = _wx.get(i);
      char label[12];
      sensorLabel(s->last, label, sizeof(label));
      int room = WX_REPLY_MAX - n;
      int w = snprintf(&reply[n], room, "%s %s %s x%lu every %lus %ddBm %lus ago", i ? ";" : "",
                       wxsensor::modelName(s->last.model), label, (unsigned long)s->count, (unsigned long)(s->period / 1000),
                       s->rssi, (unsigned long)((now - s->heard_at) / 1000));
      if (w < 0 || w >= room) { reply[n] = 0; break; }
      n += w;
    }
    return true;
  }
  if (strcmp(command, "get wx.unknown") == 0 || strncmp(command, "get wx.unknown ", 15) == 0) {
    // packets that checked out but didn't decode, by kind; with a number, that one's bytes
    const int N = (int)(sizeof(_wx_unk) / sizeof(_wx_unk[0]));
    uint32_t now = millis();
    int pick = command[14] == ' ' ? atoi(&command[15]) : 0;
    int n = sprintf(reply, ">"), shown = 0;
    for (int i = 0; i < N; i++) {
      const WxUnknown& u = _wx_unk[i];
      if (u.count < (u.proto == wxsensor::PROTO_FINEOFFSET || u.proto == wxsensor::PROTO_FO_WIDE ? 1 : 2)) continue;
      shown++;
      if (pick && shown != pick) continue;
      int room = WX_REPLY_MAX - n, w;
      if (pick) {
        w = snprintf(&reply[n], room, " %s, %u bytes:", wxsensor::protocolName(u.proto), u.len);
        for (int k = 0; k < u.n && w > 0 && w + 3 < room; k++) w += snprintf(&reply[n + w], room - w, "%02x", u.pkt[k]);
      } else {
        w = snprintf(&reply[n], room, "%s %d. %s %02x%02x%02x.. %uB x%u %ddBm %lum ago", shown > 1 ? ";" : "", shown,
                     wxsensor::protocolName(u.proto), u.pkt[0], u.pkt[1], u.pkt[2], u.len,
                     u.count, u.rssi, (unsigned long)((now - u.at) / 60000));
      }
      if (w < 0 || w >= room) { reply[n] = 0; break; }
      n += w;
    }
    if (shown == 0) strcpy(reply, "> none: every packet that checked out was read");
    else if (pick && n == 1) strcpy(reply, "Error: no such entry");
    return true;
  }
  if (strcmp(command, "get wx.stats") == 0) {
    uint32_t up = millis() - _wx_since;
    unsigned pct10 = up ? (unsigned)((uint64_t)_wx_listen_ms * 1000 / up) : 0;
    sprintf(reply, "> %lu packets (%lu bad), %lu shown, %d sensors, %lu listens, away from the mesh %u.%u%%",
            (unsigned long)_wx_heard, (unsigned long)_wx_bad, (unsigned long)_wx_shown, _wx.count(),
            (unsigned long)_wx_windows, pct10 / 10, pct10 % 10);
    return true;
  }
  if (strcmp(command, "wx scan on") == 0 || strcmp(command, "wx scan off") == 0) {
    if (!_wx_active) { strcpy(reply, "Error: weather is off ('wx on')"); return true; }
    bool forever = command[8] == 'o' && command[9] == 'n';
    _wx.scanForever(millis(), forever);
    if (_wx_win_open) _radio->stopFskListen();   // the listen running now (eg. the start-up scan's) ends: the new plan starts at once
    _wx_scan_report = !forever;   // a summary of everything heard when it stops
    strcpy(reply, forever ? "OK - listening for sensors all the time; each new one shows here. The mesh can't be heard "
                            "until 'wx scan off' (sending still works)"
                          : "OK - back to normal");
    return true;
  }
  if (strcmp(command, "wx scan") == 0) {
    if (!_wx_active) { strcpy(reply, "Error: weather is off ('wx on')"); return true; }
    _wx.scanFor(millis());
    _wx_scan_report = true;
    if (_wx_win_open) _radio->stopFskListen();
    sprintf(reply, "OK - listening for sensors for %d s (the mesh can't be heard meanwhile)", (int)(_wx.scanTotal() / 1000));
    return true;
  }
  if (strncmp(command, "wx ", 3) == 0 && wxOnOff(&command[3], &on)) arg = &command[3];
  else if (strncmp(command, "set wx ", 7) == 0 && wxOnOff(&command[7], &on)) arg = &command[7];
  if (arg) {
    if (listensBusy(reply)) return true;
    char off[64] = "";
    if (on) listenOthersOff(LISTEN_WX, off, sizeof(off));
    _prefs.wx.en = on ? 1 : 0;
    applyWeather();
    if (on && !_wx_active) {
      _prefs.wx.en = 0;   // not saved as on
      strcpy(reply, "Error: this radio can't listen to weather sensors (needs an LR2021)");
    } else {
      savePrefs();
      if (on) sprintf(reply, "OK - Weather on%s, scanning for sensors for %d s. Reconnect the app to see the channel",
                      off, (int)(_wx.scanTotal() / 1000));
      else strcpy(reply, "OK - Weather off");
    }
    return true;
  }

  if (strncmp(command, "set wx.dbgmask ", 15) == 0) {
    // set wx.dbgmask <hex>: listen in only these formats (bits of 1 << Protocol), until 'set wx.kind'
    unsigned m = (unsigned) strtoul(&command[15], NULL, 16);
    _wx.setProtocols((uint8_t) m);
    _wx.scanForever(millis(), _wx.scanningForever());
    if (_wx_win_open) _radio->stopFskListen();
    sprintf(reply, "OK - formats %02x", _wx.protocols());
    return true;
  }
  if (strncmp(command, "set wx.dbg ", 11) == 0) {
    // set wx.dbg <kbps> <rxbw kHz> <dev kHz> <preamble bits, 255 = none> [sync hex]: for experiments
    char* e;
    _wx_dbg_kbps = strtod(&command[11], &e);
    _wx_dbg_rxbw = strtod(e, &e);
    _wx_dbg_dev = strtod(e, &e);
    _wx_dbg_pre = (uint8_t) strtol(e, &e, 10);
    _wx_dbg_sync_len = 0;
    while (*e == ' ') e++;
    while (e[0] && e[1] && _wx_dbg_sync_len < sizeof(_wx_dbg_sync)) {
      unsigned b;
      if (sscanf(e, "%2x", &b) != 1) break;
      _wx_dbg_sync[_wx_dbg_sync_len++] = (uint8_t) b;
      e += 2;
    }
    if (_wx_win_open) { _radio->stopFskListen(); }
    sprintf(reply, "OK - kbps %.2f, rxbw %.1f, dev %.1f, preamble %u, sync %u bytes (0 = default)", _wx_dbg_kbps,
            _wx_dbg_rxbw, _wx_dbg_dev, _wx_dbg_pre, _wx_dbg_sync_len);
    return true;
  }
  if (strncmp(command, "set wx.", 7) != 0) return false;
  const char* setting = &command[7];
  if (strncmp(setting, "freq ", 5) == 0) {
    float f = (float) atof(&setting[5]);
    if (f < 150 || f > 960) { strcpy(reply, "Error: frequency in MHz"); return true; }
    _prefs.wx.freq = f;
  } else if (strncmp(setting, "units ", 6) == 0) {
    const char* v = &setting[6];
    if (strcmp(v, "metric") == 0) _prefs.wx.metric = 1;
    else if (strcmp(v, "us") == 0 || strcmp(v, "imperial") == 0) _prefs.wx.metric = 0;
    else { strcpy(reply, "Error: units are metric or us"); return true; }
  } else if (strncmp(setting, "kind ", 5) == 0) {
    const char* v = &setting[5];
    if (strcmp(v, "ecowitt") == 0 || strcmp(v, "ambient") == 0 || strcmp(v, "fineoffset") == 0) _prefs.wx.kinds = 1;
    else if (strcmp(v, "lacrosse") == 0) _prefs.wx.kinds = 2;
    else if (strcmp(v, "both") == 0 || strcmp(v, "all") == 0) _prefs.wx.kinds = 3;
    else { strcpy(reply, "Error: kind is ecowitt, lacrosse or both"); return true; }
    _wx.setProtocols(weatherProtocols());
    if (_wx_active) {   // look for the new kind's sensors, from now
      if (!_wx.scanningForever()) _wx.scanFor(millis());
      else _wx.scanForever(millis(), true);
      _wx_scan_report = !_wx.scanningForever();
      if (_wx_win_open) _radio->stopFskListen();
    }
  } else if (strncmp(setting, "every ", 6) == 0) {
    int m = atoi(&setting[6]);
    if (m < 0 || m > 1440) { strcpy(reply, "Error: minutes, 0-1440 (0 = only alerts)"); return true; }
    _prefs.wx.every = (uint16_t) m;
  } else if (strncmp(setting, "only ", 5) == 0) {
    const char* v = &setting[5];
    if (strcmp(v, "all") == 0) v = "";
    if (strlen(v) >= sizeof(_prefs.wx.only)) {
      sprintf(reply, "Error: at most %d characters", (int) sizeof(_prefs.wx.only) - 1);
      return true;
    }
    strcpy(_prefs.wx.only, v);
  } else {
    return false;
  }
  savePrefs();
  strcpy(reply, "OK");
  return true;
}
