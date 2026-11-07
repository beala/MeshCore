// Damaged packets in the MeshCore app (docs/damaged_packets.md).
//
// A packet that fails the radio's CRC check is normally thrown away. With 'dmg on' the radio keeps its
// bytes, and this tries every channel key (and, for a direct message to us, the contacts whose ID byte
// matches) to read what came through: MeshCore encrypts in 16-byte pieces, each on its own, so a few
// bad bits spoil only the pieces they land in. What it reads shows in one more receive-only channel,
// "Damaged", after Aircraft's, with ▒▒▒▒ for the pieces that were lost.
//
// Nothing here is authenticated, so nothing here is acted on: no ack, no forwarding, no contact or path
// updates, and never into the channel or chat the message was for. A message whose MAC matches after a
// one-bit repair, or after joining two damaged copies, is marked "fixed", and still shows only here.

#include "MyMesh.h"

#define DMG_WAIT_MS   6000   // other copies of a flood packet (through other repeaters) come within this
#define DMG_GOOD_MS  30000   // how long an intact packet's fingerprint is kept

bool MyMesh::isDamagedChannel(int idx) const {
#ifdef MAX_GROUP_CHANNELS
  return _prefs.dmg.en && idx == MAX_GROUP_CHANNELS + VCH_DAMAGED;
#else
  (void)idx;
  return false;
#endif
}

void MyMesh::getDamagedChannel(ChannelDetails& ch) {
  memset(&ch, 0, sizeof(ch));
  strcpy(ch.name, "Damaged");
  // the app wants a secret for every channel: one that matches no MeshCore channel
  uint8_t h[32];
  const char* tag = "damaged packets channel";
  mesh::Utils::sha256(h, sizeof(h), (const uint8_t*) tag, strlen(tag));
  memcpy(ch.channel.secret, h, 16);
}

void MyMesh::applyDamaged() {
  _radio->keepDamaged(_prefs.dmg.en ? _dmg_raw : NULL, sizeof(_dmg_raw));
  if (!_prefs.dmg.en) {
    for (auto& m : _dmg_pending) m.at = 0;
  }
}

// Every intact packet: a fingerprint, so a damaged copy of it (through another repeater) isn't shown
void MyMesh::damagedNoteIntact(const uint8_t* raw, int len) {
  if (!_prefs.dmg.en) return;
  damaged::Layout l = damaged::parseHeader(raw, len);
  if (!l.ok) return;
  DamagedSeen& s = _dmg_seen[_dmg_seen_next];
  _dmg_seen_next = (_dmg_seen_next + 1) % DMG_SEEN;
  s.at = millis() | 1;
  damaged::fingerprint(raw, len, s.print);
}

bool MyMesh::damagedHadIntact(const uint8_t* raw, int len, const damaged::Result& r) const {
  uint32_t now = millis();
  for (const auto& s : _dmg_seen) {
    if (s.at == 0 || (int32_t)(now - s.at) > DMG_GOOD_MS) continue;   // signed: at may be now + 1
    if (damaged::sameMessage(s.print, raw, len, r)) return true;
  }
  return false;
}

// The best reading of a damaged packet, over every key we have. False if nothing reads right.
bool MyMesh::damagedRead(uint8_t* raw, int len, DamagedMsg& best) {
  uint32_t now = getRTCClock()->getCurrentTime();
  damaged::Layout l = damaged::parseHeader(raw, len);
  int best_score = 0;
  static damaged::Result r, r_best;   // big: not on the stack

#ifdef MAX_GROUP_CHANNELS
  int grp_ct = l.ok && l.type == damaged::TYPE_GRP_TXT ? l.payload_off + 1 + CIPHER_MAC_SIZE : -1;
  for (int i = 0; i < MAX_GROUP_CHANNELS; i++) {
    ChannelDetails ch;
    if (!getChannel(i, ch) || ch.name[0] == 0) continue;
    bool hinted = grp_ct >= 0 && raw[l.payload_off] == ch.channel.hash[0];
    int n = damaged::decode(ch.channel.secret, raw, len, damaged::KIND_CHANNEL, hinted ? grp_ct : -1, now, r);
    if (!(r.first || n >= 2 || (hinted && n >= 1))) continue;
    int score = n * 4 + (r.first ? 2 : 0) + (hinted ? 1 : 0);
    if (score <= best_score) continue;
    best_score = score;
    best.kind = damaged::KIND_CHANNEL;
    StrHelper::strncpy(best.name, ch.name, sizeof(best.name));
    memcpy(best.secret, ch.channel.secret, sizeof(best.secret));
    r_best = r;
  }
#endif

  // a direct message to us: the destination byte is ours and the source byte is a contact's. Where those
  // bytes are: from the header if it came through, or else counted back from the end of the packet
  uint8_t self = self_id.pub_key[0];
  uint8_t srcs[3];
  int n_src = 0;
  if (l.ok && l.type == damaged::TYPE_TXT_MSG) {
    if (raw[l.payload_off] == self) srcs[n_src++] = raw[l.payload_off + 1];
  } else {
    for (int k = 1; k <= damaged::MAX_PIECES && n_src < 3; k++) {
      int p = len - k * damaged::PIECE - CIPHER_MAC_SIZE - 2;
      if (p < 2) break;
      if (raw[p] != self) continue;
      bool dup = false;
      for (int j = 0; j < n_src; j++) dup |= srcs[j] == raw[p + 1];
      if (!dup) srcs[n_src++] = raw[p + 1];
    }
  }
  int tries = 0;
  for (int s = 0; s < n_src && tries < 6; s++) {
    ContactsIterator it = startContactsIterator();
    ContactInfo c;
    while (tries < 6 && it.hasNext(this, c)) {
      if (c.id.pub_key[0] != srcs[s]) continue;
      ContactInfo* stored = lookupContactByPubKey(c.id.pub_key, PUB_KEY_SIZE);   // its secret is kept there
      if (!stored) continue;
      tries++;
      const uint8_t* secret = stored->getSharedSecret(self_id);
      int dm_ct = l.ok && l.type == damaged::TYPE_TXT_MSG ? l.payload_off + 2 + CIPHER_MAC_SIZE : -1;
      int n = damaged::decode(secret, raw, len, damaged::KIND_DIRECT, dm_ct, now, r);
      if (!(r.first || n >= 1)) continue;   // the ID bytes already pointed here
      int score = n * 4 + (r.first ? 2 : 0) + 1;
      if (score <= best_score) continue;
      best_score = score;
      best.kind = damaged::KIND_DIRECT;
      StrHelper::strncpy(best.name, c.name, sizeof(best.name));
      memcpy(best.secret, secret, sizeof(best.secret));
      r_best = r;
    }
  }
  if (best_score == 0) return false;

  bool fixed = damaged::repair(best.secret, raw, len, r_best, (damaged::Kind) best.kind);
  damaged::takeCopy(raw, r_best, fixed, best.c);
  return true;
}

// Another damaged copy of a message already waiting (through another repeater): join them
bool MyMesh::damagedMerge(DamagedMsg& m, const DamagedMsg& in) {
  if (m.kind != in.kind || memcmp(m.secret, in.secret, sizeof(m.secret)) != 0) return false;
  if (!damaged::merge(m.c, in.c, m.secret)) return false;
  m.copies++;
  if (in.snr_x4 > m.snr_x4) m.snr_x4 = in.snr_x4;
  if (in.whole_heard) m.whole_heard = true;
  return true;
}

// A waiting message's time is up (or its slot is wanted): show it, unless an intact copy came since
void MyMesh::damagedFinish(DamagedMsg& m) {
  uint8_t raw[damaged::MAX_PIECES * damaged::PIECE];
  int n = m.c.r.n * damaged::PIECE;
  memcpy(raw, m.c.ct, n);
  damaged::Result r = m.c.r;
  r.ct_off = 0;
  if (!m.whole_heard && damagedHadIntact(raw, n, r)) {
    _dmg_dupes++;
    m.whole_heard = true;
  }
  if (!m.whole_heard || _prefs.dmg.all) damagedPost(m);
  m.at = 0;
}

void MyMesh::damagedPost(DamagedMsg& m) {
  // our own channel message, heard back from a repeater
  if (m.kind == damaged::KIND_CHANNEL && m.c.r.first && (m.c.r.good & 1)) {
    char own[40];
    snprintf(own, sizeof(own), "%s: ", _prefs.node_name);
    if (strncmp((const char*) &m.c.r.pt[5], own, strlen(own) < 11 ? strlen(own) : 11) == 0) {
      if (!_prefs.dmg.all) return;
      m.whole_heard = true;   // ours: the whole message is in the app already
    }
  }
  char text[MAX_FRAME_SIZE];
  int lost = m.c.r.n - damaged::countGood(m.c.r.good);
  char state[64];
  if (m.c.fixed) strcpy(state, m.copies > 1 ? "fixed from copies" : "fixed");
  else if (lost == 0) strcpy(state, m.copies > 1 ? "unchecked, from copies" : "unchecked");
  else snprintf(state, sizeof(state), m.copies > 1 ? "%d of %d lost, from copies" : "%d of %d lost", lost, m.c.r.n);
  if (m.whole_heard) strcat(state, ", also heard whole");
  int k = snprintf(text, sizeof(text), m.kind == damaged::KIND_CHANNEL ? "[#%s, %s] " : "[from %s, %s] ", m.name, state);
  if (k < 0 || k >= (int) sizeof(text)) return;
  damaged::showText(m.c.r, (damaged::Kind) m.kind, &text[k], sizeof(text) - k - 12);
  uint32_t ts = damaged::timestampOf(m.c.r);
  if (ts == 0) ts = getRTCClock()->getCurrentTimeUnique();
  pushChannelText(MAX_GROUP_CHANNELS + VCH_DAMAGED, ts, m.snr_x4, 0, text, strlen(text));
  _dmg_shown++;
  if (m.c.fixed) _dmg_fixed++;
  if (m.copies > 1) _dmg_joined++;
}

void MyMesh::damagedLoop() {
  if (!_prefs.dmg.en) return;
  float snr = 0, rssi = 0;
  int len = _radio->takeDamaged(&snr, &rssi);
  if (len > 0) {
    _dmg_heard++;
    DamagedEvent& ev = _dmg_log[_dmg_log_next];
    _dmg_log_next = (_dmg_log_next + 1) % DMG_LOG;
    ev = { millis(), (uint8_t) len, 0, 0, '-', 0 };
    static DamagedMsg in;   // big: not on the stack
    memset(&in, 0, sizeof(in));
    if (damagedRead(_dmg_raw, len, in)) {
      _dmg_read++;
      in.at = millis() | 1;
      in.copies = 1;
      in.snr_x4 = (int8_t)(snr * 4);
      ev.n = in.c.r.n;
      ev.good = in.c.r.good | (in.c.r.first ? 0x8000 : 0) | (in.c.r.start_known ? 0x4000 : 0);
      if (damagedHadIntact(_dmg_raw, len, in.c.r)) {
        _dmg_dupes++;
        ev.what = 'i';
        in.whole_heard = true;
      }
      if (!in.whole_heard || _prefs.dmg.all) {
        int merged = -1;
        for (int i = 0; i < DMG_PENDING && merged < 0; i++) {
          if (_dmg_pending[i].at && damagedMerge(_dmg_pending[i], in)) merged = i;
        }
        if (merged >= 0) {
          ev.what = 'j';
          ev.slot = (uint8_t) merged;
        } else {
          int slot = 0;   // a free one, or else the oldest
          for (int i = 0; i < DMG_PENDING; i++) {
            if (_dmg_pending[i].at == 0) { slot = i; break; }
            if ((int32_t)(_dmg_pending[i].at - _dmg_pending[slot].at) < 0) slot = i;
          }
          if (_dmg_pending[slot].at) damagedFinish(_dmg_pending[slot]);   // the oldest goes early
          _dmg_pending[slot] = in;
          ev.what = 'w';
          ev.slot = (uint8_t) slot;
        }
      }
    }
  }
  uint32_t now = millis();
  for (auto& m : _dmg_pending) {
    if (m.at == 0 || (int32_t)(now - m.at) < DMG_WAIT_MS) continue;   // signed: at may be now + 1
    damagedFinish(m);
  }
}

bool MyMesh::handleDamagedCommand(const char* command, char* reply) {
  if (strcmp(command, "dmg") == 0 || strcmp(command, "get dmg") == 0) {
    if (!_prefs.dmg.en) {
      strcpy(reply, "> Damaged off: packets that fail their CRC check are dropped ('dmg on' to read what's left of them)");
    } else {
      sprintf(reply, "> Damaged on%s: %lu heard, %lu read, %lu shown (%lu fixed, %lu joined from copies), %lu also heard intact",
              _prefs.dmg.all ? " (all)" : "", (unsigned long) _dmg_heard, (unsigned long) _dmg_read, (unsigned long) _dmg_shown,
              (unsigned long) _dmg_fixed, (unsigned long) _dmg_joined, (unsigned long) _dmg_dupes);
    }
    return true;
  }
  if (strcmp(command, "get dmg.log") == 0) {   // the last damaged packets, oldest first
    int k = sprintf(reply, ">");
    uint32_t now = millis();
    for (int i = 0; i < DMG_LOG && k < 140; i++) {
      const DamagedEvent& e = _dmg_log[(_dmg_log_next + i) % DMG_LOG];
      if (e.at == 0) continue;
      k += snprintf(&reply[k], 160 - k, " -%lus:%u %c", (unsigned long)((now - e.at) / 1000), e.len, e.what);
      if (e.what != '-' && k < 150) k += snprintf(&reply[k], 160 - k, "%u/%x", e.slot, e.good);
    }
    return true;
  }
  const char* all = strncmp(command, "set dmg.all ", 12) == 0 ? &command[12] : strncmp(command, "dmg all ", 8) == 0 ? &command[8] : NULL;
  if (all) {
    if (strcmp(all, "on") == 0) _prefs.dmg.all = 1;
    else if (strcmp(all, "off") == 0) _prefs.dmg.all = 0;
    else { strcpy(reply, "Error: set dmg.all on|off"); return true; }
    savePrefs();
    strcpy(reply, _prefs.dmg.all ? "OK - showing every damaged message, also those heard whole (and your own echoes)"
                                 : "OK - hiding damaged messages that were also heard whole");
    return true;
  }
  const char* arg = strncmp(command, "dmg ", 4) == 0 ? &command[4] : strncmp(command, "set dmg ", 8) == 0 ? &command[8] : NULL;
  if (!arg) return false;
  bool on;
  if (strcmp(arg, "on") == 0) on = true;
  else if (strcmp(arg, "off") == 0) on = false;
  else { strcpy(reply, "Error: dmg on|off"); return true; }
  _prefs.dmg.en = on ? 1 : 0;
  applyDamaged();
  savePrefs();
  strcpy(reply, on ? "OK - Damaged on. Reconnect the app to see the channel" : "OK - Damaged off");
  return true;
}
