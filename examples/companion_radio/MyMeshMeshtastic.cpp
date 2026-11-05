// A Meshtastic channel in the MeshCore app (docs/meshtastic_channel.md).
//
// The LR2021's on-chip scanner (src/helpers/radiolib/lr2021_scan_blob.h) hops between MeshCore's
// channel and a Meshtastic one, so one radio hears both. Meshtastic packets never reach the mesh:
// the radio driver queues them, and this file decodes them and shows their texts in the app as an
// extra channel after the real ones. Receive only: nothing is ever sent on Meshtastic, and text
// typed into that channel stays on this radio.

#include "MyMesh.h"

#define MT_SYNC_WORD   0x2B
#define MT_PREAMBLE    16
#define MT_TEXT_PART   140   // a message holds about 150 bytes of text
#define MT_FRAME_TEXT  (MAX_FRAME_SIZE - 11)   // text bytes after a V3 channel message frame's header

const char* MyMesh::meshtasticChannelName() const {
  return _prefs.mt.name[0] ? _prefs.mt.name : _prefs.mt.preset;
}

bool MyMesh::isMeshtasticChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _mt_active && idx == MAX_GROUP_CHANNELS;
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::getMeshtasticChannel(ChannelDetails& ch) {
  memset(&ch, 0, sizeof(ch));
  snprintf(ch.name, sizeof(ch.name), "Meshtastic %s", meshtasticChannelName());
  // The app wants a secret for every channel. Give it one that matches no MeshCore channel.
  uint8_t h[32];
  const char* tag = "meshtastic channel";
  mesh::Utils::sha256(h, sizeof(h), (const uint8_t*) tag, strlen(tag), _prefs.mt.key, _prefs.mt.key_len);
  memcpy(ch.channel.secret, h, 16);
}

void MyMesh::applyRadioPrefs() {
  radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  radio_driver.setTxPower(_prefs.tx_power_dbm);
  radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);
}

// Starts or stops listening to the Meshtastic channel, per _prefs.mt. Loading or removing the
// scanner restarts the radio chip, so the caller applies the radio settings again.
bool MyMesh::applyMeshtastic() {
  if (!_prefs.mt.en) {
    _mt_active = false;
    if (_radio->isSideListening()) {
      _radio->stopSideListen();
      return true;
    }
    return false;
  }
  const meshtastic::Preset* p = meshtastic::findPreset(_prefs.mt.preset);
  if (p == NULL) p = meshtastic::findPreset("LongFast");
  const char* name = meshtasticChannelName();
  if (!_mt.setChannel(name, _prefs.mt.key, _prefs.mt.key_len)) {
    static const uint8_t default_key[1] = { 1 };
    _mt.setChannel(name, default_key, 1);
  }
  float freq = _prefs.mt.freq > 0 ? _prefs.mt.freq : meshtastic::usFrequency(name, p->bw_khz);
  bool was_listening = _radio->isSideListening();
  _mt_active = _radio->setSideListen(freq, p->bw_khz, p->sf, p->cr, MT_SYNC_WORD, MT_PREAMBLE);
  return !was_listening;
}

void MyMesh::meshtasticLoop() {
  if (!_mt_active) return;
  uint8_t buf[meshtastic::Receiver::MAX_PACKET];
  float rssi = 0, snr = 0;
  for (int k = 0; k < 4; k++) {
    int n = _radio->recvSide(buf, sizeof(buf), &rssi, &snr);
    if (n <= 0) break;
    _mt_last_len = n;
    memcpy(_mt_last_head, buf, sizeof(_mt_last_head));
    memcpy(_mt_last_tail, &buf[n >= 8 ? n - 8 : 0], sizeof(_mt_last_tail));
    meshtastic::Message m;
    if (_mt.handle(buf, n, &m) == meshtastic::TEXT) showMeshtasticText(m, snr);
  }
}

// "Name: text", as MeshCore channel texts are, split into several messages when long
void MyMesh::showMeshtasticText(const meshtastic::Message& m, float snr) {
#ifdef MAX_GROUP_CHANNELS
  uint8_t hops = m.hdr.hopStart() >= m.hdr.hopLimit() ? m.hdr.hopStart() - m.hdr.hopLimit() : 0;
  int8_t snr_x4 = (int8_t)(snr * 4);
  const char* text = m.text;
  int left = m.text_len;
  while (left > 0) {
    char msg[MAX_FRAME_SIZE + 1];
    int n = snprintf(msg, sizeof(msg), "%s: ", m.sender);
    if (n < 0 || n > 60) n = 0;
    int room = MT_FRAME_TEXT - n;            // what a channel message frame holds after "Name: "
    if (room > MT_TEXT_PART) room = MT_TEXT_PART;
    int cut = meshtastic::nextPart(text, left, room);
    memcpy(&msg[n], text, cut);
    n += cut;
    msg[n] = 0;
    pushChannelText(MAX_GROUP_CHANNELS, getRTCClock()->getCurrentTimeUnique(), snr_x4, hops, msg, n);
    text += cut;
    left -= cut;
    while (left > 0 && (*text == ' ' || *text == '\n')) { text++; left--; }
  }
  _mt_shown++;
#endif
}

static bool parseOnOff(const char* s, bool* on) {
  if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0) { *on = true; return true; }
  if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *on = false; return true; }
  return false;
}

bool MyMesh::handleMeshtasticCommand(const char* command, char* reply) {
  const char* arg = NULL;
  bool on;
  if (strcmp(command, "mt") == 0 || strcmp(command, "get mt") == 0) {
    const meshtastic::Preset* p = meshtastic::findPreset(_prefs.mt.preset);
    float bw = p ? p->bw_khz : 250;
    float freq = _prefs.mt.freq > 0 ? _prefs.mt.freq : meshtastic::usFrequency(meshtasticChannelName(), bw);
    const char* key = _prefs.mt.key_len == 1 && _prefs.mt.key[0] == 1 ? "default"
                    : _prefs.mt.key_len == 0 || (_prefs.mt.key_len == 1 && _prefs.mt.key[0] == 0) ? "none" : "custom";
    sprintf(reply, "> Meshtastic %s: %s, %.3f MHz%s, channel %s, key %s",
            _prefs.mt.en ? (_mt_active ? "on" : "on, but the radio can't") : "off",
            _prefs.mt.preset, freq, _prefs.mt.freq > 0 ? "" : " (auto)", meshtasticChannelName(), key);
    return true;
  }
  if (strcmp(command, "get mt.last") == 0) {   // the last packet heard, raw: length, first 20 and last 8 bytes
    int n = sprintf(reply, "> %d: ", _mt_last_len);
    for (int i = 0; i < 20; i++) n += sprintf(&reply[n], "%02x", _mt_last_head[i]);
    n += sprintf(&reply[n], " .. ");
    for (int i = 0; i < 8; i++) n += sprintf(&reply[n], "%02x", _mt_last_tail[i]);
    return true;
  }
  if (strcmp(command, "get mt.stats") == 0) {
    const meshtastic::Receiver::Stats& s = _mt.stats();
    sprintf(reply, "> heard %lu: %lu texts (%lu shown), %lu names, %lu repeats, %lu other channels, %lu DMs, %lu bad",
            (unsigned long) s.heard, (unsigned long) s.text, (unsigned long) _mt_shown, (unsigned long) s.nodeinfo,
            (unsigned long) s.duplicate, (unsigned long) s.other_channel, (unsigned long) s.not_for_us,
            (unsigned long) s.undecodable);
    return true;
  }

  if (strncmp(command, "mt ", 3) == 0 && parseOnOff(&command[3], &on)) {
    arg = &command[3];
  } else if (strncmp(command, "set mt ", 7) == 0 && parseOnOff(&command[7], &on)) {
    arg = &command[7];
  }
  if (arg) {
    _prefs.mt.en = on ? 1 : 0;
    applyMeshtastic();
    applyRadioPrefs();
    if (on && !_mt_active) {
      _prefs.mt.en = 0;   // not saved as on: there's nothing to turn on
      strcpy(reply, "Error: this radio can't listen to Meshtastic (needs an LR2021)");
    } else {
      savePrefs();
      strcpy(reply, on ? "OK - Meshtastic channel on. Reconnect the app to see it" : "OK - Meshtastic off");
    }
    return true;
  }

  if (strncmp(command, "set mt.", 7) != 0) return false;
  const char* setting = &command[7];
  if (strncmp(setting, "preset ", 7) == 0) {
    const meshtastic::Preset* p = meshtastic::findPreset(&setting[7]);
    if (p == NULL) {
      strcpy(reply, "Error: presets are ShortTurbo, ShortFast, ShortSlow, MediumFast, MediumSlow, LongFast, LongModerate, LongSlow");
      return true;
    }
    StrHelper::strncpy(_prefs.mt.preset, p->name, sizeof(_prefs.mt.preset));
  } else if (strncmp(setting, "freq ", 5) == 0) {
    const char* v = &setting[5];
    float f = strcmp(v, "auto") == 0 ? 0 : (float) atof(v);
    if (f != 0 && (f < 150 || f > 960)) {
      strcpy(reply, "Error: frequency in MHz, or auto");
      return true;
    }
    _prefs.mt.freq = f;
  } else if (strncmp(setting, "channel ", 8) == 0) {
    const char* v = &setting[8];
    if (strcmp(v, "default") == 0) v = "";
    if (strlen(v) >= sizeof(_prefs.mt.name)) {
      sprintf(reply, "Error: at most %d characters", (int) sizeof(_prefs.mt.name) - 1);
      return true;
    }
    strcpy(_prefs.mt.name, v);
  } else if (strncmp(setting, "key ", 4) == 0) {
    const char* v = &setting[4];
    uint8_t key[32];
    int len;
    if (strcmp(v, "default") == 0) {
      key[0] = 1; len = 1;
    } else if (strcmp(v, "none") == 0) {
      key[0] = 0; len = 1;
    } else {
      len = meshtastic::parseKeyBase64(v, key);
      uint8_t check[meshtastic::MAX_KEY];
      if (len < 0 || meshtastic::expandKey(key, len, check) < 0) {
        strcpy(reply, "Error: key is base64, 1, 16 or 32 bytes");
        return true;
      }
    }
    memset(_prefs.mt.key, 0, sizeof(_prefs.mt.key));
    memcpy(_prefs.mt.key, key, len);
    _prefs.mt.key_len = len;
  } else {
    return false;
  }
  savePrefs();
  if (_prefs.mt.en) applyMeshtastic();
  strcpy(reply, "OK");
  return true;
}
