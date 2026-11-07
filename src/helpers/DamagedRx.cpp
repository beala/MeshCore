#include "DamagedRx.h"
#include <string.h>
#include <Utils.h>
#include <MeshCore.h>
#include <Packet.h>

namespace damaged {

static const uint32_t TS_2023 = 1672531200UL;   // 2023-01-01
static const uint32_t YEAR = 366UL * 24 * 3600;

bool isTextPiece(const uint8_t* p, int n) {
  int i = 0;
  // the tail of a UTF-8 character started in the piece before
  for (int k = 0; i < n && k < 3 && (p[i] & 0xC0) == 0x80; k++) i++;
  while (i < n) {
    uint8_t c = p[i];
    if (c == 0) {                      // the end of the message: zero padding to the end of the piece
      for (int j = i + 1; j < n; j++) if (p[j]) return false;
      return true;
    }
    if (c < 0x20) {
      if (c != '\n') return false;
      i++;
      continue;
    }
    if (c < 0x7F) { i++; continue; }
    if (c < 0xC2 || c > 0xF4) return false;   // DEL, a stray continuation, an overlong or out-of-range lead
    int need = c < 0xE0 ? 1 : c < 0xF0 ? 2 : 3;
    i++;
    for (int k = 0; k < need; k++, i++) {
      if (i >= n) return true;                 // runs on into the next piece
      if ((p[i] & 0xC0) != 0x80) return false;
    }
  }
  return true;
}

static int textStart(const uint8_t* p, Kind kind) {
  uint8_t txt_type = p[4] >> 2;
  return (kind == KIND_DIRECT && txt_type == 2) ? 9 : 5;   // signed: 4 bytes of the sender's key first
}

bool isFirstPiece(const uint8_t* p, Kind kind, uint32_t now) {
  uint32_t ts = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
  if (ts < TS_2023) return false;
  if (now >= TS_2023 ? ts > now + YEAR : ts > 0x7FFFFFFFUL) return false;
  uint8_t flags = p[4];
  if (kind == KIND_CHANNEL) {
    if (flags > 3) return false;               // plain text only, a few attempt bits
  } else {
    if ((flags >> 2) > 2) return false;        // plain, CLI or signed
  }
  int s = textStart(p, kind);
  if (s >= PIECE) return true;
  if (p[s] == 0) return false;                 // an empty message
  return isTextPiece(p + s, PIECE - s) && (p[s] & 0xC0) != 0x80;
}

Layout parseHeader(const uint8_t* raw, int len) {
  Layout l = { false, 0, 0, 0 };
  if (len < 2) return l;
  uint8_t h = raw[0];
  if ((h >> PH_VER_SHIFT) & PH_VER_MASK) return l;    // only v1 payloads
  int i = 1;
  uint8_t route = h & PH_ROUTE_MASK;
  if (route == ROUTE_TYPE_TRANSPORT_FLOOD || route == ROUTE_TYPE_TRANSPORT_DIRECT) i += 4;
  if (i >= len) return l;
  uint8_t pl = raw[i++];
  int hash_size = (pl >> 6) + 1;
  if (hash_size > 3) return l;
  int path_bytes = (pl & 63) * hash_size;
  if (path_bytes > MAX_PATH_SIZE) return l;
  i += path_bytes;
  l.type = (h >> PH_TYPE_SHIFT) & PH_TYPE_MASK;
  l.payload_off = i;
  l.payload_len = len - i;
  int pre = l.type == TYPE_GRP_TXT ? 1 + CIPHER_MAC_SIZE : l.type == TYPE_TXT_MSG ? 2 + CIPHER_MAC_SIZE : -1;
  if (pre < 0) return l;
  int ct = l.payload_len - pre;
  l.ok = ct >= PIECE && ct % PIECE == 0 && l.payload_len <= MAX_PACKET_PAYLOAD;
  return l;
}

// an encrypted envelope: v1 (2-byte MAC + whole pieces) or v2 (16-byte tag + any length)
static bool envelopeFits(int n) {
  return (n >= CIPHER_MAC_SIZE + PIECE && n % PIECE == CIPHER_MAC_SIZE) || n > 16;
}

bool sizeFits(const Layout& l) {
  if (l.payload_off == 0 || l.payload_len < 1) return false;
  int n = l.payload_len;
  switch (l.type) {
    case PAYLOAD_TYPE_ACK:       return n >= 4 && n <= 8;
    case PAYLOAD_TYPE_ADVERT:    return n > PUB_KEY_SIZE + 4 + SIGNATURE_SIZE && n <= PUB_KEY_SIZE + 4 + SIGNATURE_SIZE + MAX_ADVERT_DATA_SIZE;
    case PAYLOAD_TYPE_TXT_MSG:
    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_PATH:      return envelopeFits(n - 2);
    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA:  return envelopeFits(n - 1);
    case PAYLOAD_TYPE_ANON_REQ:  return envelopeFits(n - 1 - PUB_KEY_SIZE);
    case PAYLOAD_TYPE_TRACE:     return n >= 9;
    case 0x0C: case 0x0D: case 0x0E: return false;   // reserved: no one sends these
    default:                     return true;
  }
}

void senderId(const uint8_t* raw, int len, RadioId& out) {
  out.n = 0;
  Layout l = parseHeader(raw, len);
  if (l.payload_off == 0 || l.payload_len < 1) return;
  uint8_t route = raw[0] & PH_ROUTE_MASK;
  int pl_at = (route == ROUTE_TYPE_TRANSPORT_FLOOD || route == ROUTE_TYPE_TRANSPORT_DIRECT) ? 5 : 1;
  int hops = raw[pl_at] & 63, hash_size = (raw[pl_at] >> 6) + 1;
  const uint8_t* at = NULL;
  int n = 0;
  if (hops > 0) {
    if (route == ROUTE_TYPE_DIRECT || route == ROUTE_TYPE_TRANSPORT_DIRECT) return;
    at = &raw[l.payload_off - hash_size];   // the last hop added itself at the end
    n = hash_size;
  } else if (l.type == PAYLOAD_TYPE_ADVERT) {
    at = &raw[l.payload_off];               // its public key comes first
    n = l.payload_len < 4 ? l.payload_len : 4;
  } else if (l.type == PAYLOAD_TYPE_TXT_MSG || l.type == PAYLOAD_TYPE_REQ || l.type == PAYLOAD_TYPE_RESPONSE ||
             l.type == PAYLOAD_TYPE_PATH) {
    // only a flood with no hops comes straight from its source: a direct-routed one with its path used up
    // was sent by the last repeater on the way (each takes itself off), so the source byte isn't the sender
    if (route == ROUTE_TYPE_DIRECT || route == ROUTE_TYPE_TRANSPORT_DIRECT) return;
    if (l.payload_len < 2) return;
    at = &raw[l.payload_off + 1];           // destination, then source
    n = 1;
  } else {
    return;
  }
  memcpy(out.b, at, n);
  out.n = (uint8_t) n;
}

int sender(const uint8_t* raw, int len) {
  RadioId id;
  senderId(raw, len, id);
  return id.n ? id.b[0] : -1;
}

int countGood(uint16_t mask) {
  int n = 0;
  for (; mask; mask &= mask - 1) n++;
  return n;
}

int decode(const uint8_t* secret, const uint8_t* raw, int len, Kind kind, int ct_hint, uint32_t now, Result& out) {
  memset(&out, 0, sizeof(out));
  // at least the header, path length, channel hash (or both hashes) and MAC come first
  int before = kind == KIND_CHANNEL ? 2 + 1 + CIPHER_MAC_SIZE : 2 + 2 + CIPHER_MAC_SIZE;
  int total = (len - before) / PIECE;
  if (total > MAX_PIECES) total = MAX_PIECES;
  if (total < 1) return 0;
  int start = len - total * PIECE;
  uint8_t pt[MAX_PIECES * PIECE];
  mesh::Utils::decrypt(secret, pt, raw + start, total * PIECE);

  bool text[MAX_PIECES], first[MAX_PIECES];
  for (int i = 0; i < total; i++) {
    text[i] = isTextPiece(&pt[i * PIECE], PIECE);
    first[i] = isFirstPiece(&pt[i * PIECE], kind, now);
  }
  int hint = (ct_hint >= start && ct_hint < len && (len - ct_hint) % PIECE == 0) ? (ct_hint - start) / PIECE : -1;

  // where the message starts: a piece with a timestamp (the one the header points to, if it has one),
  // else where the header says, else the first piece that reads as text
  int s = -1;
  if (hint >= 0 && first[hint]) s = hint;
  for (int i = 0; s < 0 && i < total; i++) if (first[i]) s = i;
  if (s < 0) s = hint;
  for (int i = 0; s < 0 && i < total; i++) if (text[i]) s = i;
  if (s < 0) return 0;

  out.first = first[s];
  out.start_known = first[s] || s == hint;
  out.n = total - s;
  out.ct_off = start + s * PIECE;
  for (int i = 0; i < out.n; i++) {
    // piece 0 is the message's first piece when the start is known; else just the first piece read
    bool ok = i == 0 ? (out.start_known ? first[s] : text[s]) : text[s + i];
    if (ok) out.good |= 1u << i;
  }
  memcpy(out.pt, &pt[s * PIECE], out.n * PIECE);
  return countGood(out.good);
}

static bool macOk(const uint8_t* secret, const uint8_t* mac_ct, int ct_len) {
  uint8_t tmp[MAX_PIECES * PIECE];
  return mesh::Utils::MACThenDecrypt(secret, tmp, mac_ct, CIPHER_MAC_SIZE + ct_len) > 0;
}

bool repair(const uint8_t* secret, uint8_t* raw, int len, Result& r, Kind kind) {
  if (!r.first || r.n == 0) return false;
  int mac_off = r.ct_off - CIPHER_MAC_SIZE;
  int min_mac = kind == KIND_CHANNEL ? 3 : 4;
  if (mac_off < min_mac || r.ct_off + r.n * PIECE != len) return false;
  int ct_len = r.n * PIECE;
  uint16_t all = (uint16_t)((1u << r.n) - 1);
  int bad = r.n - countGood(r.good);
  if (bad > 1) return false;
  if (macOk(secret, &raw[mac_off], ct_len)) {   // every piece came through: the damage was elsewhere
    r.good = all;
    return bad == 0;
  }
  int from, to;   // the bytes to try flipping
  if (bad == 0) {
    from = mac_off; to = r.ct_off;
  } else {
    int piece = 0;
    while (r.good & (1u << piece)) piece++;
    from = r.ct_off + piece * PIECE; to = from + PIECE;
  }
  for (int i = from; i < to; i++) {
    for (int b = 0; b < 8; b++) {
      raw[i] ^= (uint8_t)(1 << b);
      if (macOk(secret, &raw[mac_off], ct_len)) {
        // every piece must read right too: a chance MAC match (1 in 65,536) would leave noise
        uint8_t pt[MAX_PIECES * PIECE];
        mesh::Utils::decrypt(secret, pt, &raw[r.ct_off], ct_len);
        bool ok = isFirstPiece(pt, kind, 0);
        for (int p = 1; ok && p < r.n; p++) ok = isTextPiece(&pt[p * PIECE], PIECE);
        if (ok) {
          memcpy(r.pt, pt, ct_len);
          r.good = all;
          return true;
        }
      }
      raw[i] ^= (uint8_t)(1 << b);
    }
  }
  return false;
}

static const char LOST[] = "\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92\xE2\x96\x92";   // ▒▒▒▒

int showText(const Result& r, Kind kind, char* out, int cap) {
  int o = 0;
  bool ended = false;
  for (int i = 0; i < r.n && !ended; i++) {
    bool good = r.good & (1u << i);
    if (!good) {
      // one marker for a run of lost pieces
      if (i == 0 || (r.good & (1u << (i - 1)))) {
        if (o + (int)sizeof(LOST) - 1 >= cap) break;
        memcpy(&out[o], LOST, sizeof(LOST) - 1);
        o += sizeof(LOST) - 1;
      }
      continue;
    }
    const uint8_t* p = &r.pt[i * PIECE];
    int a = i == 0 && r.first ? textStart(p, kind) : 0;
    int b = PIECE;
    for (int j = a; j < b; j++) if (p[j] == 0) { b = j; ended = true; break; }
    if (i > 0 && !(r.good & (1u << (i - 1)))) {   // after a lost piece: skip the tail of a cut character
      while (a < b && (p[a] & 0xC0) == 0x80) a++;
    }
    bool next_lost = !ended && i + 1 < r.n && !(r.good & (1u << (i + 1)));
    if (next_lost) {   // before a lost piece: drop a character that runs into it
      int k = b;
      while (k > a && (p[k - 1] & 0xC0) == 0x80) k--;
      if (k > a && p[k - 1] >= 0xC0) {
        uint8_t c = p[k - 1];
        int want = c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
        if (b - (k - 1) < want) b = k - 1;
      }
    }
    int n = b - a;
    if (o + n >= cap) n = cap - 1 - o;
    if (n <= 0) break;
    memcpy(&out[o], &p[a], n);
    o += n;
  }
  out[o] = 0;
  return o;
}

uint32_t timestampOf(const Result& r) {
  if (!r.first || !(r.good & 1)) return 0;
  return (uint32_t)r.pt[0] | (uint32_t)r.pt[1] << 8 | (uint32_t)r.pt[2] << 16 | (uint32_t)r.pt[3] << 24;
}

static uint16_t fp16(const uint8_t* p) {
  uint16_t h = 0x9E37;
  for (int i = 0; i < PIECE; i++) h = (uint16_t)((h ^ p[i]) * 0x0101u + 0x3B);
  return h;
}

void fingerprint(const uint8_t* raw, int len, Fingerprint& out) {
  out.n = 0;
  for (int i = 0; i < MAX_PIECES && len - (i + 1) * PIECE >= 0; i++) {
    out.fp[i] = fp16(&raw[len - (i + 1) * PIECE]);
    out.n++;
  }
}

bool sameMessage(const Fingerprint& intact, const uint8_t* raw, int len, const Result& r) {
  if (r.ct_off + r.n * PIECE != len) return false;
  int matched = 0;
  for (int i = 0; i < r.n; i++) {
    if (!(r.good & (1u << i))) continue;
    int from_end = r.n - 1 - i;
    if (from_end >= intact.n) return false;
    if (fp16(&raw[r.ct_off + i * PIECE]) != intact.fp[from_end]) return false;
    matched++;
  }
  // the timestamp piece, or two pieces: under ECB a common ending ("lol") encrypts the same in
  // different messages
  return (r.first && (r.good & 1)) || matched >= 2;
}

void takeCopy(const uint8_t* raw, const Result& r, bool fixed, Copy& c) {
  c.r = r;
  c.fixed = fixed;
  memcpy(c.ct, &raw[r.ct_off], r.n * PIECE);
  if (r.ct_off >= CIPHER_MAC_SIZE) memcpy(c.mac, &raw[r.ct_off - CIPHER_MAC_SIZE], CIPHER_MAC_SIZE);
  else memset(c.mac, 0, sizeof(c.mac));
}

// Grows a copy to n pieces, counted from the end of the packet: the pieces added in front are lost
static void widen(Copy& c, int n) {
  int d = n - c.r.n;
  if (d <= 0) return;
  memmove(&c.r.pt[d * PIECE], c.r.pt, c.r.n * PIECE);
  memmove(&c.ct[d * PIECE], c.ct, c.r.n * PIECE);
  memset(c.r.pt, 0, d * PIECE);
  memset(c.ct, 0, d * PIECE);
  c.r.good = (uint16_t)(c.r.good << d);
  c.r.n = (uint8_t) n;
  c.r.first = c.r.start_known = false;
}

bool merge(Copy& m, const Copy& in_, const uint8_t* secret) {
  int n = m.r.n > in_.r.n ? m.r.n : in_.r.n;
  int shared = 0;
  bool shared_first = false;
  for (int j = 0; j < n; j++) {   // j: pieces from the end
    int a = m.r.n - 1 - j, b = in_.r.n - 1 - j;
    if (a < 0 || b < 0) break;
    if (!((m.r.good >> a) & 1) || !((in_.r.good >> b) & 1)) continue;
    if (memcmp(&m.r.pt[a * PIECE], &in_.r.pt[b * PIECE], PIECE) != 0) return false;
    shared++;
    if ((a == 0 && m.r.first) || (b == 0 && in_.r.first)) shared_first = true;
  }
  bool same = shared_first || shared >= 2 ||
              (m.r.start_known && in_.r.start_known && m.r.n == in_.r.n && memcmp(m.mac, in_.mac, CIPHER_MAC_SIZE) == 0);
  if (!same) return false;

  static Copy in;   // big: not on the stack
  in = in_;
  widen(m, n);
  widen(in, n);
  for (int i = 0; i < n; i++) {
    uint16_t bit = 1u << i;
    if (!(m.r.good & bit) && (in.r.good & bit)) {
      memcpy(&m.r.pt[i * PIECE], &in.r.pt[i * PIECE], PIECE);
      memcpy(&m.ct[i * PIECE], &in.ct[i * PIECE], PIECE);
      m.r.good |= bit;
    }
  }
  if (in.r.start_known && !m.r.start_known) {
    m.r.start_known = true;
    memcpy(m.mac, in.mac, CIPHER_MAC_SIZE);
  }
  if (in.r.first) m.r.first = true;
  if (in.fixed) {
    m.fixed = true;
  } else if (!m.fixed && m.r.first && m.r.good == (uint16_t)((1u << n) - 1)) {
    // whole now: check it against either copy's MAC
    uint8_t buf[CIPHER_MAC_SIZE + MAX_PIECES * PIECE];
    int ct_len = n * PIECE;
    memcpy(&buf[CIPHER_MAC_SIZE], m.ct, ct_len);
    const uint8_t* macs[2] = { m.mac, in.mac };
    for (const uint8_t* mac : macs) {
      memcpy(buf, mac, CIPHER_MAC_SIZE);
      if (macOk(secret, buf, ct_len)) { m.fixed = true; break; }
    }
  }
  return true;
}

}  // namespace damaged
