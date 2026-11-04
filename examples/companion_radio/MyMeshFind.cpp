// 'find': make another companion beep, and measure the distance to it (docs/find_me.md)
//
// The finder sends a CLI command message ("find me", "find me stop", "find range") to the target,
// which handles it only if the finder is on its allow list (set find.allow), or has remote CLI
// access. Messages are encrypted and authenticated with the pair's shared secret, and the target
// remembers the newest request timestamp from each finder so an old request can't be replayed.
//
// Ranging (LR2021 on both ends): the target replies "find: ranging <addr>", waits until that reply has
// been transmitted, then answers RTToF ranging requests for RANGE_WINDOW_MILLIS. The finder starts
// sending requests as soon as it hears the reply. Both return to normal LoRa afterwards.

#include "MyMesh.h"
#include <stdarg.h>

#if defined(USE_LR2021) && defined(LR2021_IRQ_DIO)
  #include <helpers/radiolib/LR2021Ranging.h>
  #define HAS_RANGING 1
#endif

#define FIND_ALLOW_FILE       "/find_allow"
#define FIND_ALLOW_VERSION    1
#define FIND_BEEP_SECS        120
#define FIND_ANSWER_MILLIS    15000   // finder: how long to wait for an answer
#define RANGE_WINDOW_MILLIS   5000    // target: answer ranging requests for this long
#define RANGE_START_MILLIS    3000    // finder: give up if still transmitting after this long
#define RANGE_MANAGER_MILLIS  2500    // finder: stop sending requests after this long
#define RANGE_EXCHANGES       32
#define RANGE_EXCHANGE_MILLIS 100     // finder: give up on one exchange after this long
#define RANGE_ARM_MILLIS      8000    // target: give up if the reply hasn't gone out by then
#define RANGE_MIN_GAP_MILLIS  5000    // target: at most one ranging session per 5 s

void MyMesh::setFindStatus(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(_find_status, sizeof(_find_status), fmt, args);
  va_end(args);
  _find_status_at = millis();
}

ContactInfo* MyMesh::findContactByName(const char* name) {
  ContactInfo c;
  uint32_t total = getNumContacts() + MAX_ANON_CONTACTS;
  for (uint32_t i = 0; i < total; i++) {   // exact name first
    if (getContactByIdx(i, c) && c.name[0] && strcmp(c.name, name) == 0) {
      return lookupContactByPubKey(c.id.pub_key, PUB_KEY_SIZE);
    }
  }
  return searchContactsByPrefix(name);
}

int MyMesh::findAllowIndex(const uint8_t* pub_key) const {
  for (int i = 0; i < _num_find_allow; i++) {
    if (memcmp(_find_allow[i].pub_key, pub_key, PUB_KEY_SIZE) == 0) return i;
  }
  return -1;
}

// The allow list is saved in the prefs ("find" section). Older builds kept it in FIND_ALLOW_FILE:
// version, count, then count x (public key, last timestamp).
void MyMesh::loadFindAllow() {
  _num_find_allow = 0;
  static const uint8_t unused[FIND_ALLOW_REC] = { 0 };
  for (int i = 0; i < MAX_FIND_ALLOW; i++) {
    const uint8_t* rec = _prefs.find_allow[i];
    if (memcmp(rec, unused, FIND_ALLOW_REC) == 0) continue;
    memcpy(_find_allow[_num_find_allow].pub_key, rec, PUB_KEY_SIZE);
    memcpy(&_find_allow[_num_find_allow].last_ts, &rec[PUB_KEY_SIZE], 4);
    _num_find_allow++;
  }
  if (_num_find_allow > 0) return;

  uint8_t buf[2 + MAX_FIND_ALLOW * FIND_ALLOW_REC];
  int n = _store->readFile(FIND_ALLOW_FILE, buf, sizeof(buf));
  if (n < 2 || buf[0] != FIND_ALLOW_VERSION) return;
  for (int i = 0; i < buf[1] && i < MAX_FIND_ALLOW; i++) {
    int ofs = 2 + i * FIND_ALLOW_REC;
    if (ofs + FIND_ALLOW_REC > n) break;
    memcpy(_find_allow[i].pub_key, &buf[ofs], PUB_KEY_SIZE);
    memcpy(&_find_allow[i].last_ts, &buf[ofs + PUB_KEY_SIZE], 4);
    _num_find_allow++;
  }
  if (saveFindAllow()) _store->removeFile(FIND_ALLOW_FILE);
}

bool MyMesh::saveFindAllow() {
  memset(_prefs.find_allow, 0, sizeof(_prefs.find_allow));
  for (int i = 0; i < _num_find_allow; i++) {
    memcpy(_prefs.find_allow[i], _find_allow[i].pub_key, PUB_KEY_SIZE);
    memcpy(&_prefs.find_allow[i][PUB_KEY_SIZE], &_find_allow[i].last_ts, 4);
  }
  _prefs.node_lat = sensors.node_lat;
  _prefs.node_lon = sensors.node_lon;
  bool ok = _store->savePrefs(_prefs);
  if (ok) _prefs.clearDirty();
  return ok;
}

bool MyMesh::rangingAvailable(float freq) {
#ifdef HAS_RANGING
  return LR2021Ranging::bandAllowed(freq);
#else
  return false;
#endif
}

bool MyMesh::isFindRequest(const char* text) {
  return strcmp(text, "find me") == 0 || strncmp(text, "find me ", 8) == 0 || strcmp(text, "find range") == 0;
}

// target: a find request from another companion
void MyMesh::handleFindRequest(const ContactInfo& from, uint32_t sender_timestamp, const char* text, char* reply) {
  int idx = findAllowIndex(from.id.pub_key);
  if (idx < 0 && !from.isRemoteCLIAllowed()) {
    sprintf(reply, "find: not allowed. The owner can run: set find.allow %s", from.name);
    return;
  }
  if (idx >= 0) {
    if (sender_timestamp <= _find_allow[idx].last_ts) {
      strcpy(reply, "find: old request ignored (is your clock set?)");
      return;
    }
    _find_allow[idx].last_ts = sender_timestamp;
    saveFindAllow();
  }

  if (strcmp(text, "find range") == 0) {
#ifdef HAS_RANGING
    if (!rangingAvailable(_prefs.freq)) {
      strcpy(reply, "find: error: ranging needs 902-928 MHz");
    } else if (_range_armed_at || (_range_last && millis() - _range_last < RANGE_MIN_GAP_MILLIS)) {
      strcpy(reply, "find: busy, try again in a few seconds");
    } else {
      _range_armed_at = millis() | 1;
      _range_sent_mark = radio_driver.getPacketsSent();
      // A fresh random ranging address each session, sent only inside the encrypted reply, so other
      // radios don't know which address to answer (to fake the distance) or to ask (to range us).
      do { getRNG()->random((uint8_t*)&_range_addr, sizeof(_range_addr)); } while (_range_addr == 0);
      sprintf(reply, "find: ranging %08lx", (unsigned long)_range_addr);
    }
#else
    strcpy(reply, "find: error: this radio can't range (needs an LR2021)");
#endif
    return;
  }

  const char* arg = text[7] ? &text[8] : "";
  if (strcmp(arg, "stop") == 0) {
    strcpy(reply, (_listener && _listener->stopFindMe()) ? "find: stopped" : "find: wasn't beeping");
    return;
  }
  int secs = *arg ? atoi(arg) : FIND_BEEP_SECS;
  if (secs < 1 || secs > 600) {
    strcpy(reply, "find: error: seconds must be 1 to 600");
  } else if (_listener && _listener->startFindMe(secs)) {
    sprintf(reply, "find: beeping for %d s", secs);
  } else {
    strcpy(reply, "find: error: no buzzer or vibration motor");
  }
}

// finder: an answer from the target
void MyMesh::onFindReply(const ContactInfo& from, const char* text) {
  if (!_find_asked_at || memcmp(from.id.pub_key, _find_peer, PUB_KEY_SIZE) != 0) return;
  if (strncmp(text, "find: ", 6) != 0) return;
  _find_asked_at = 0;
  const char* r = &text[6];
  if (_find_asked_range && strncmp(r, "ranging", 7) == 0 && (r[7] == 0 || r[7] == ' ')) {
    if (r[7] == ' ') {
      _range_addr = strtoul(&r[8], NULL, 16);
    } else {   // older firmware: the address is the target's public key prefix
      _range_addr = (uint32_t)_find_peer[0] << 24 | (uint32_t)_find_peer[1] << 16 | (uint32_t)_find_peer[2] << 8 | _find_peer[3];
    }
    _range_go_at = millis() | 1;
    setFindStatus("%s: ranging...", from.name);
  } else {
    setFindStatus("%s: %s", from.name, &text[6]);
  }
}

// local CLI: find beep|stop|range <name>, get find, get/set find.allow, set find.deny
bool MyMesh::handleFindCommand(const char* command, char* reply) {
  if (strcmp(command, "get find") == 0) {
    if (_find_status_at == 0) {
      strcpy(reply, "> nothing yet, try: find beep <name>");
    } else {
      sprintf(reply, "> %s (%lu s ago)", _find_status, (unsigned long)((millis() - _find_status_at) / 1000));
    }
    return true;
  }

  if (strcmp(command, "get find.allow") == 0) {
    if (_num_find_allow == 0) {
      strcpy(reply, "> nobody. Allow a contact with: set find.allow <name>");
      return true;
    }
    int n = sprintf(reply, ">");
    for (int i = 0; i < _num_find_allow; i++) {
      ContactInfo* c = lookupContactByPubKey(_find_allow[i].pub_key, PUB_KEY_SIZE);
      char name[40];
      if (c) {
        snprintf(name, sizeof(name), "%s", c->name);
      } else {   // deleted contact: show its key prefix
        mesh::Utils::toHex(name, _find_allow[i].pub_key, 4);
      }
      if (n + (int)strlen(name) + 3 > 135) { strcpy(&reply[n], " ..."); break; }
      n += sprintf(&reply[n], "%s %s", i == 0 ? "" : ",", name);
    }
    return true;
  }

  if (memcmp(command, "set find.allow ", 15) == 0 || memcmp(command, "set find.deny ", 14) == 0) {
    bool allow = command[9] == 'a';
    const char* name = &command[allow ? 15 : 14];
    ContactInfo* c = findContactByName(name);
    if (c == NULL) {
      strcpy(reply, "Error: contact not found");
      return true;
    }
    int idx = findAllowIndex(c->id.pub_key);
    if (allow) {
      if (idx >= 0) {
        sprintf(reply, "> %s is already allowed", c->name);
        return true;
      }
      if (_num_find_allow >= MAX_FIND_ALLOW) {
        strcpy(reply, "Error: list is full (8). Remove one with: set find.deny <name>");
        return true;
      }
      memcpy(_find_allow[_num_find_allow].pub_key, c->id.pub_key, PUB_KEY_SIZE);
      _find_allow[_num_find_allow].last_ts = 0;
      _num_find_allow++;
      if (!saveFindAllow()) {
        _num_find_allow--;
        strcpy(reply, "Error: couldn't save");
        return true;
      }
      sprintf(reply, "OK, %s can now make this radio beep, and range to it", c->name);
    } else {
      if (idx < 0) {
        sprintf(reply, "> %s wasn't allowed", c->name);
        return true;
      }
      _find_allow[idx] = _find_allow[--_num_find_allow];
      saveFindAllow();
      sprintf(reply, "OK, %s can no longer find this radio", c->name);
    }
    return true;
  }

  const char* msg = NULL;
  const char* name = NULL;
  if (memcmp(command, "find beep ", 10) == 0) {
    msg = "find me"; name = &command[10];
  } else if (memcmp(command, "find stop ", 10) == 0) {
    msg = "find me stop"; name = &command[10];
  } else if (memcmp(command, "find range ", 11) == 0) {
    msg = "find range"; name = &command[11];
    if (!rangingAvailable(_prefs.freq)) {
#ifdef HAS_RANGING
      strcpy(reply, "Error: ranging needs 902-928 MHz");
#else
      strcpy(reply, "Error: this radio can't range (needs an LR2021)");
#endif
      return true;
    }
  } else {
    return false;
  }

  ContactInfo* c = findContactByName(name);
  if (c == NULL) {
    strcpy(reply, "Error: contact not found");
    return true;
  }
  uint32_t est_timeout;
  uint32_t ts = getRTCClock()->getCurrentTimeUnique();
  int rc = sendCommandData(*c, ts, 0, TXT_TYPE_CLI_COMMAND, msg, est_timeout);
  if (rc == MSG_SEND_FAILED) {
    strcpy(reply, "Error: couldn't send");
    return true;
  }
  memcpy(_find_peer, c->id.pub_key, PUB_KEY_SIZE);
  _find_asked_at = millis() | 1;
  _find_asked_range = msg[5] == 'r';
  setFindStatus("%s: asked, no answer yet", c->name);
  sprintf(reply, "OK, asked %s. See the answer with: get find", c->name);
  return true;
}

void MyMesh::findLoop() {
  // The *_at timestamps are millis() | 1 (0 means unset), which can be 1 ms in the future, so
  // compare the elapsed time as signed: unsigned, it wraps to ~4e9 and times out at once.
  if (_find_asked_at && (int32_t)(millis() - _find_asked_at) > FIND_ANSWER_MILLIS) {
    _find_asked_at = 0;
    ContactInfo* c = lookupContactByPubKey(_find_peer, PUB_KEY_SIZE);
    setFindStatus("%s: no answer", c ? c->name : "?");
  }

#ifdef HAS_RANGING
  // Wait only for a transmit to finish. Any other radio state is fine: ranging puts the radio in
  // standby first, and setParams() afterwards gets normal receive going again.
  if (_range_go_at) {   // finder: start as soon as we're not transmitting
    if (!isTransmitting()) {
      _range_go_at = 0;
      runRanging(true, _range_addr);
    } else if ((int32_t)(millis() - _range_go_at) > RANGE_START_MILLIS) {
      _range_go_at = 0;
      setFindStatus("ranging didn't start: this radio was busy transmitting. Try again");
    }
  }
  if (_range_armed_at) {   // target: start once the "find: ranging" reply has been sent
    if ((int32_t)(millis() - _range_armed_at) > RANGE_ARM_MILLIS) {
      _range_armed_at = 0;
    } else if (radio_driver.getPacketsSent() != _range_sent_mark && !isTransmitting()) {
      _range_armed_at = 0;
      runRanging(false, _range_addr);
      _range_last = millis();
    }
  }
#endif
}

void MyMesh::runRanging(bool manager, uint32_t addr) {
#ifdef HAS_RANGING
  LR2021Ranging rng(radio_driver);
  int16_t st = rng.begin(manager, addr);
  if (st != RADIOLIB_ERR_NONE) {
    if (manager) setFindStatus("ranging failed to start (%d)", st);
  } else if (manager) {
    int32_t raws[RANGE_EXCHANGES];
    int rssis[RANGE_EXCHANGES];
    int n = 0, tries = 0;
    unsigned long start = millis();
    while (n < RANGE_EXCHANGES && millis() - start < RANGE_MANAGER_MILLIS) {
      int32_t raw;
      int rssi;
      tries++;
      if (rng.exchange(raw, rssi, RANGE_EXCHANGE_MILLIS)) {
        raws[n] = raw;
        rssis[n] = rssi;
        n++;
      }
    }
    ContactInfo* c = lookupContactByPubKey(_find_peer, PUB_KEY_SIZE);
    const char* name = c ? c->name : "?";
    if (n == 0) {
      setFindStatus("%s: no ranging answers (%d tries). Out of direct radio range?", name, tries);
    } else {
      // median and quartiles (insertion sort, n <= 32)
      for (int i = 1; i < n; i++) {
        for (int j = i; j > 0 && raws[j] < raws[j - 1]; j--) { int32_t t = raws[j]; raws[j] = raws[j - 1]; raws[j - 1] = t; }
        for (int j = i; j > 0 && rssis[j] < rssis[j - 1]; j--) { int t = rssis[j]; rssis[j] = rssis[j - 1]; rssis[j - 1] = t; }
      }
      float med = LR2021Ranging::rawToMeters(raws[n / 2]);
      float spread = LR2021Ranging::rawToMeters(raws[(3 * n) / 4] - raws[n / 4]) / 2;
      setFindStatus("%s: %.0f m (+/- %.0f m, %d/%d answers, %d dBm)", name, med, spread, n, tries, rssis[n / 2]);
    }
  } else {
    int done = rng.respond(RANGE_WINDOW_MILLIS);
    MESH_DEBUG_PRINTLN("find: answered %d ranging requests", done);
  }

  // back to normal LoRa
  rng.end();
  radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);
  rng.restartRx();   // otherwise the radio stays deaf until it next transmits
#endif
}
