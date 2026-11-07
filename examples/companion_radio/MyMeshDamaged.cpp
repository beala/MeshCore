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
void MyMesh::damagedCount(const uint8_t* raw, int len, bool bad, float snr) {
  damaged::RadioId who;
  damaged::senderId(raw, len, who);
  // less than 2 bytes of ID (or none): by its frequency, when that fits exactly one named radio
  int32_t err;
  if (bad ? _radio->getDamagedFreqError(&err) : _radio->getLastFreqError(&err)) freqSender(who, err, snr, bad);
  DamagedFrom* f = NULL;
  for (int i = 0; i < _dmg_from_n && !f; i++) {
    if (_dmg_from[i].who.n == who.n && memcmp(_dmg_from[i].who.b, who.b, who.n) == 0) f = &_dmg_from[i];
  }
  if (!f) {
    if (_dmg_from_n < DMG_FROM) {
      f = &_dmg_from[_dmg_from_n++];
    } else {   // full: replace the one heard least, keeping the unknown (-1) row
      for (int i = 0; i < DMG_FROM; i++) {
        if (_dmg_from[i].who.n == 0) continue;
        if (!f || _dmg_from[i].whole + _dmg_from[i].damaged < f->whole + f->damaged) f = &_dmg_from[i];
      }
    }
    memset(f, 0, sizeof(*f));
    f->who = who;
  }
  if (bad) {
    if (f->damaged < 0xFFFF) { f->damaged++; f->damaged_snr4 += (int32_t)(snr * 4); }
  } else {
    if (f->whole < 0xFFFF) { f->whole++; f->whole_snr4 += (int32_t)(snr * 4); }
  }
}

void MyMesh::damagedNoteIntact(const uint8_t* raw, int len) {
  if (!_prefs.dmg.en) return;
  damagedCount(raw, len, false, _radio->getLastSNR());
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

// Why a damaged packet that nothing could read wasn't for reading: from its header, which usually
// comes through (a channel or contact byte that was hit can make "ours" look like someone else's)
int MyMesh::damagedWhy(const uint8_t* raw, int len) {
  damaged::Layout l = damaged::parseHeader(raw, len);
  if (!damaged::sizeFits(l)) return DMG_TOO_DAMAGED;   // the header itself was hit
  uint8_t first = raw[l.payload_off];
  switch (l.type) {
    case PAYLOAD_TYPE_ADVERT: return DMG_ADVERT;
    case PAYLOAD_TYPE_ACK: return DMG_ACK;
    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA: {
#ifdef MAX_GROUP_CHANNELS
      for (int i = 0; i < MAX_GROUP_CHANNELS; i++) {
        ChannelDetails ch;
        if (getChannel(i, ch) && ch.name[0] && ch.channel.hash[0] == first) {
          return l.type == PAYLOAD_TYPE_GRP_TXT ? DMG_TOO_DAMAGED : DMG_TRAFFIC;
        }
      }
#endif
      return DMG_OTHERS;
    }
    case PAYLOAD_TYPE_TXT_MSG:
    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_PATH:
    case PAYLOAD_TYPE_ANON_REQ:
      if (first != self_id.pub_key[0]) return DMG_OTHERS;
      return l.type == PAYLOAD_TYPE_TXT_MSG ? DMG_TOO_DAMAGED : DMG_TRAFFIC;
    default:
      return DMG_TRAFFIC;
  }
}

// A radio's ID in hex, "?" if unknown. "7a3c DEN-CONI" adds the contact with that ID, but only from
// 2 bytes up: a 1-byte ID is shared by 1 in 256 radios, too many for a name to mean much.
void MyMesh::damagedRadioName(const uint8_t* id, int idn, char* out, int n) {
  if (idn <= 0) { snprintf(out, n, "?"); return; }
  int k = 0;
  for (int i = 0; i < idn && k + 3 <= n; i++) k += snprintf(&out[k], n - k, "%02x", id[i]);
  ContactInfo* c = idn >= damaged::NAME_MIN_BYTES ? lookupContactByPubKey(id, idn) : NULL;
  if (c && k + 2 < n) snprintf(&out[k], n - k, " %s", c->name);   // as much of the name as fits
}

static const char* typeName(uint8_t type) {
  static const char* names[16] = { "request", "response", "direct message", "ack", "advert", "channel message",
                                   "group data", "anonymous request", "path", "trace", "multipart", "control",
                                   "reserved type", "reserved type", "reserved type", "custom packet" };
  return names[type & 15];
}

// With 'set dmg.all on', a damaged packet nothing could read still gets a post: what it was, who sent it
void MyMesh::damagedPostUnread(const uint8_t* raw, int len, int why, float snr) {
  damaged::Layout l = damaged::parseHeader(raw, len);
  char from[24], a[24], b[24];
  damaged::RadioId who;
  damaged::senderId(raw, len, who);
  if (why == DMG_TOO_DAMAGED) who.n = 0;
  // the radio it came from by its frequency, when the packet doesn't say enough: "~88a1 Hilltop"
  int32_t err;
  bool by_freq = _radio->getDamagedFreqError(&err) && freqSender(who, err, snr, false);
  if (by_freq) from[0] = '~';
  damagedRadioName(who.b, who.n, &from[by_freq ? 1 : 0], sizeof(from) - 1);
  char detail[120];
  const uint8_t* p = &raw[l.payload_off];
  if (why == DMG_TOO_DAMAGED && !damaged::sizeFits(l)) {
    snprintf(detail, sizeof(detail), "header hit: %d bytes, can't tell what it was", len);
  } else if (l.type == PAYLOAD_TYPE_ADVERT) {
    damagedRadioName(p, l.payload_len < 4 ? l.payload_len : 4, a, sizeof(a));   // its key
    int k = snprintf(detail, sizeof(detail), "from %s", a);
    // the advert's own data isn't encrypted: its name, if that part came through
    int i = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE;
    if (i < l.payload_len) {
      uint8_t flags = p[i++];
      if (flags & ADV_LATLON_MASK) i += 8;
      if (flags & ADV_FEAT1_MASK) i += 2;
      if (flags & ADV_FEAT2_MASK) i += 2;
      if ((flags & ADV_NAME_MASK) && i < l.payload_len && k < (int) sizeof(detail) - 8) {
        k += snprintf(&detail[k], sizeof(detail) - k, ", named \"");
        for (; i < l.payload_len && p[i] && k < (int) sizeof(detail) - 3; i++) {
          detail[k++] = (p[i] >= 0x20 && p[i] < 0x7F) ? (char) p[i] : '?';   // ASCII only: a bad byte shows as ?
        }
        detail[k++] = '"';
        detail[k] = 0;
      }
    }
  } else if (l.type == PAYLOAD_TYPE_ACK) {
    snprintf(detail, sizeof(detail), "nothing to read in an ack");
  } else if (l.type == PAYLOAD_TYPE_GRP_TXT || l.type == PAYLOAD_TYPE_GRP_DATA) {
    if (why == DMG_OTHERS) snprintf(detail, sizeof(detail), "on channel %02x, not one of yours", p[0]);
    else snprintf(detail, sizeof(detail), why == DMG_TOO_DAMAGED ? "on one of your channels, but no piece came through"
                                                                  : "on one of your channels (not text)");
  } else if (l.type == PAYLOAD_TYPE_ANON_REQ) {
    damagedRadioName(p, 1, a, sizeof(a));
    snprintf(detail, sizeof(detail), "to %s", a);
  } else if (l.type == PAYLOAD_TYPE_TXT_MSG || l.type == PAYLOAD_TYPE_REQ || l.type == PAYLOAD_TYPE_RESPONSE ||
             l.type == PAYLOAD_TYPE_PATH) {
    damagedRadioName(&p[1], 1, a, sizeof(a));   // 1-byte IDs: no names
    damagedRadioName(p, 1, b, sizeof(b));
    if (why == DMG_TOO_DAMAGED) snprintf(detail, sizeof(detail), "from %s to you, but no piece came through", a);
    else snprintf(detail, sizeof(detail), "from %s to %s", a, b);
  } else {
    detail[0] = 0;
  }
  char text[MAX_FRAME_SIZE];
  int k = snprintf(text, MAX_FRAME_SIZE - 11, "%s: [%s, %+.0fdB] %s", from,
                   why == DMG_TOO_DAMAGED && !damaged::sizeFits(l) ? "unknown" : typeName(l.type), snr, detail);
  if (k < 0) return;
  pushChannelText(MAX_GROUP_CHANNELS + VCH_DAMAGED, getRTCClock()->getCurrentTimeUnique(), (int8_t)(snr * 4), 0,
                  text, strlen(text));
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
  if (m.c.fixed) strcpy(state, "fixed");
  else if (!m.c.r.start_known) {   // where the message starts wasn't found: how much is missing in front is unknown
    if (lost == 0) strcpy(state, "start lost");
    else snprintf(state, sizeof(state), "start and %d more lost", lost);
  } else if (lost == 0) strcpy(state, "unchecked");
  else snprintf(state, sizeof(state), "%d of %d lost", lost, m.c.r.n);
  if (m.copies > 1) strcat(state, m.c.fixed ? " from copies" : ", from copies");
  if (m.whole_heard) strcat(state, ", also heard whole");
  // The app takes what's before the first ": " as the sender's name, so the post starts with the name:
  // "Bob: [#Public, 1 of 3 lost] text". For a channel the name is in the message itself: found only in
  // the text before the first lost piece, else "▒▒▒▒" (it was lost)
  static char body[MAX_FRAME_SIZE];
  damaged::showText(m.c.r, (damaged::Kind) m.kind, body, sizeof(body));
  const char* sender = m.name;
  const char* rest = body;
  char lost_name[16];
  if (m.kind == damaged::KIND_CHANNEL) {
    const char* cut = strstr(body, "\xE2\x96\x92");   // the first lost piece
    const char* colon = strstr(body, ": ");
    if (colon && (!cut || colon < cut) && colon > body) {
      body[colon - body] = 0;
      sender = body;
      rest = colon + 2;
    } else {
      strcpy(lost_name, "\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92");
      sender = lost_name;
    }
  }
  // what fits in the app's frame after its 11-byte header, cut at a character boundary
  int cap = MAX_FRAME_SIZE - 11 + 1;
  int k = m.kind == damaged::KIND_CHANNEL ? snprintf(text, cap, "%s: [#%s, %s] %s", sender, m.name, state, rest)
                                          : snprintf(text, cap, "%s: [direct, %s] %s", sender, state, rest);
  if (k < 0) return;
  if (k >= cap) {   // cut short: drop a last character that lost its tail
    k = cap - 1;
    int j = k - 1;
    while (j > 0 && ((uint8_t) text[j] & 0xC0) == 0x80) j--;
    uint8_t c = (uint8_t) text[j];
    int want = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
    if (k - j < want) text[j] = 0;
  }
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
    damagedCount(_dmg_raw, len, true, snr);
    DamagedEvent& ev = _dmg_log[_dmg_log_next];
    _dmg_log_next = (_dmg_log_next + 1) % DMG_LOG;
    ev = { millis(), (uint8_t) len, 0, 0, '-', 0 };
    static DamagedMsg in;   // big: not on the stack
    memset(&in, 0, sizeof(in));
    if (!damagedRead(_dmg_raw, len, in)) {
      int why = damagedWhy(_dmg_raw, len);
      _dmg_unread[why]++;
      ev.what = "akox-"[why];
      if (_prefs.dmg.all) damagedPostUnread(_dmg_raw, len, why, snr);
    } else {
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
      snprintf(reply, 160, "> Damaged on%s: %lu heard. Read %lu: %lu shown (%lu fixed, %lu joined), %lu heard whole. "
               "Not read: %lu adverts, %lu acks, %lu for others, %lu other, %lu too damaged",
               _prefs.dmg.all ? " (all)" : "", (unsigned long) _dmg_heard, (unsigned long) _dmg_read,
               (unsigned long) _dmg_shown, (unsigned long) _dmg_fixed, (unsigned long) _dmg_joined,
               (unsigned long) _dmg_dupes, (unsigned long) _dmg_unread[DMG_ADVERT], (unsigned long) _dmg_unread[DMG_ACK],
               (unsigned long) _dmg_unread[DMG_OTHERS], (unsigned long) _dmg_unread[DMG_TRAFFIC],
               (unsigned long) _dmg_unread[DMG_TOO_DAMAGED]);
    }
    return true;
  }
  if (strcmp(command, "dmg reset") == 0) {   // start the counts again
    _dmg_heard = _dmg_read = _dmg_shown = _dmg_fixed = _dmg_joined = _dmg_dupes = 0;
    memset(_dmg_unread, 0, sizeof(_dmg_unread));
    _dmg_from_n = 0;
    memset(_dmg_log, 0, sizeof(_dmg_log));
    strcpy(reply, "OK - counts cleared");
    return true;
  }
  if (strcmp(command, "get dmg.from") == 0) {   // the radios our damaged packets came from, most first
    if (_dmg_from_n == 0) { strcpy(reply, "> nothing heard yet"); return true; }
    bool done[DMG_FROM] = {};
    int k = sprintf(reply, ">");
    for (int shown = 0; shown < _dmg_from_n && k < 150; shown++) {
      int best = -1;
      for (int i = 0; i < _dmg_from_n; i++) {
        if (done[i]) continue;
        if (best < 0 || _dmg_from[i].damaged > _dmg_from[best].damaged ||
            (_dmg_from[i].damaged == _dmg_from[best].damaged && _dmg_from[i].whole > _dmg_from[best].whole)) best = i;
      }
      done[best] = true;
      const DamagedFrom& f = _dmg_from[best];
      char name[16];
      damagedRadioName(f.who.b, f.who.n, name, 16);
      char snr[24] = "";
      if (f.damaged) {
        int n = snprintf(snr, sizeof(snr), " %+ddB", (int)(f.damaged_snr4 / 4 / (int32_t) f.damaged));
        if (f.whole) snprintf(&snr[n], sizeof(snr) - n, "/%+d", (int)(f.whole_snr4 / 4 / (int32_t) f.whole));
      }
      char item[64];
      int w = snprintf(item, sizeof(item), "%s %s: %u/%u%s", shown ? ";" : "", name, f.damaged,
                       f.damaged + f.whole, snr);
      if (k + w >= 158) break;
      memcpy(&reply[k], item, w + 1);
      k += w;
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
      if ((e.what == 'w' || e.what == 'j' || e.what == 'i') && k < 150) k += snprintf(&reply[k], 160 - k, "%u/%x", e.slot, e.good);
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
