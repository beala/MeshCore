// Weather sensors in the MeshCore app (docs/weather_sensors.md).
//
// Ecowitt, Ambient Weather and other Fine Offset sensors send short FSK packets at a fixed interval.
// An LR2021 can step away from the mesh for a moment to hear them (CustomLR2021Wrapper's FSK
// listen). wxsensor::Tracker learns each sensor's interval and asks for a listen only around the
// moment its next packet is due, so the radio stays on the mesh nearly all the time. Readings show
// in the app as an extra, receive-only channel after the real ones (and after Meshtastic's).

#include "MyMesh.h"

#define WX_KBPS      17.24f   // 58 µs bits
#define WX_DEV_KHZ   35.0f    // only used for transmitting; the receiver bandwidth is what matters
#define WX_RXBW_KHZ  153.8f   // room for the sensors' crystal error (±20 ppm is ±18 kHz at 915 MHz)
#define WX_PKT_LEN   32       // the longest packet (WS90)
#define WX_REPLY_MAX 140      // CLI replies go into a 166 byte buffer, after an optional prefix

bool MyMesh::isWeatherChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _wx_active && idx == MAX_GROUP_CHANNELS + (_mt_active ? 1 : 0);
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

void MyMesh::applyWeather() {
  bool was = _wx_active;
  _radio->stopFskListen();
  _wx_win_open = false;
  if (!_prefs.wx.en) {
    _wx_active = false;
    return;
  }
  // probe: a radio without FSK listens says no straight away
  mesh::Radio::FskListen cfg = {};
  cfg.freq = _prefs.wx.freq; cfg.kbps = WX_KBPS; cfg.dev_khz = WX_DEV_KHZ; cfg.rxbw_khz = WX_RXBW_KHZ;
  cfg.sync[0] = 0x2D; cfg.sync[1] = 0xD4; cfg.sync_len = 2; cfg.pkt_len = WX_PKT_LEN;
  _wx_active = _radio->startFskListen(cfg, 1);
  _radio->stopFskListen();
  if (_wx_active && !was) {
    _wx.setSeed(millis() ^ 0xA5A5u);
    _wx.reset(millis());
    _wx.scanFor(millis());   // find the sensors in range: one listen without a break
    _wx_since = millis();
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
  int idx = MAX_GROUP_CHANNELS + (_mt_active ? 1 : 0);
  pushChannelText(idx, getRTCClock()->getCurrentTimeUnique(), snr_x4, 0, text, strlen(text));
  _wx_shown++;
#endif
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
    if (!wxsensor::decode(buf, n, &r)) { _wx_bad++; continue; }
    if (!weatherShown(r)) continue;   // filtered out: not followed either
    wxsensor::Tracker::Sensor* old = _wx.find(wxsensor::sensorKey(r));
    wxsensor::Reading prev = old ? old->last : r;
    bool is_new = old == NULL;
    wxsensor::Tracker::Sensor* s = _wx.onPacket(now, r, (int16_t) rssi);
    if (!s) continue;
    if (_wx_win_open && s->key == _wx_win.key) _wx_win_got = true;

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
    mesh::Radio::FskListen cfg = {};
    cfg.freq = _prefs.wx.freq; cfg.kbps = WX_KBPS; cfg.dev_khz = WX_DEV_KHZ; cfg.rxbw_khz = WX_RXBW_KHZ;
    cfg.sync[0] = 0x2D; cfg.sync[1] = 0xD4; cfg.sync_len = 2; cfg.pkt_len = WX_PKT_LEN;
    if (_radio->startFskListen(cfg, w.len)) {
      _wx_win = w;
      _wx_win_open = true;
      _wx_win_got = false;
      _wx_windows++;
    }
  }
}

static bool wxOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}

bool MyMesh::handleWeatherCommand(const char* command, char* reply) {
  bool on;
  const char* arg = NULL;
  if (strcmp(command, "wx") == 0 || strcmp(command, "get wx") == 0) {
    sprintf(reply, "> Weather %s: %.3f MHz, %s, every %u min, sensors %s",
            _prefs.wx.en ? (_wx_active ? "on" : "on, but the radio can't") : "off", _prefs.wx.freq,
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
  if (strcmp(command, "get wx.stats") == 0) {
    uint32_t up = millis() - _wx_since;
    unsigned pct10 = up ? (unsigned)((uint64_t)_wx_listen_ms * 1000 / up) : 0;
    sprintf(reply, "> %lu packets (%lu bad), %lu shown, %d sensors, %lu listens, away from the mesh %u.%u%%",
            (unsigned long)_wx_heard, (unsigned long)_wx_bad, (unsigned long)_wx_shown, _wx.count(),
            (unsigned long)_wx_windows, pct10 / 10, pct10 % 10);
    return true;
  }
  if (strcmp(command, "wx scan") == 0) {
    if (!_wx_active) { strcpy(reply, "Error: weather is off ('wx on')"); return true; }
    _wx.scanFor(millis());
    strcpy(reply, "OK - listening for sensors for 85 s (the mesh can't be heard meanwhile)");
    return true;
  }
  if (strncmp(command, "wx ", 3) == 0 && wxOnOff(&command[3], &on)) arg = &command[3];
  else if (strncmp(command, "set wx ", 7) == 0 && wxOnOff(&command[7], &on)) arg = &command[7];
  if (arg) {
    _prefs.wx.en = on ? 1 : 0;
    applyWeather();
    if (on && !_wx_active) {
      _prefs.wx.en = 0;   // not saved as on
      strcpy(reply, "Error: this radio can't listen to weather sensors (needs an LR2021)");
    } else {
      savePrefs();
      strcpy(reply, on ? "OK - Weather on, scanning for sensors for 85 s. Reconnect the app to see the channel"
                       : "OK - Weather off");
    }
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
