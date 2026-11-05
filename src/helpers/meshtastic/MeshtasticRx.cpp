#include "MeshtasticRx.h"

#include <string.h>
#include <stdio.h>
#include <AES.h>

namespace meshtastic {

static uint32_t le32(const uint8_t* p) {
  return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool parseHeader(const uint8_t* pkt, int len, Header* h) {
  if (pkt == NULL || len < HEADER_LEN) return false;
  h->to = le32(&pkt[0]);
  h->from = le32(&pkt[4]);
  h->id = le32(&pkt[8]);
  h->flags = pkt[12];
  h->channel = pkt[13];
  h->next_hop = pkt[14];
  h->relay = pkt[15];
  return true;
}

// The well-known default channel key ("AQ==" in the apps)
static const uint8_t DEFAULT_KEY[16] = {
  0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

int expandKey(const uint8_t* psk, int psk_len, uint8_t key[MAX_KEY]) {
  if (psk_len == 0) return 0;
  if (psk_len == 1) {
    uint8_t idx = psk[0];
    if (idx == 0) return 0;       // encryption off
    if (idx > 10) return -1;
    memcpy(key, DEFAULT_KEY, 16);
    key[15] += idx - 1;           // index 2..10: the default key with its last byte bumped
    return 16;
  }
  if (psk_len == 16 || psk_len == 32) {
    memcpy(key, psk, psk_len);
    return psk_len;
  }
  return -1;
}

static int b64value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

int parseKeyBase64(const char* text, uint8_t psk[MAX_KEY]) {
  int n = 0;
  uint32_t acc = 0;
  int bits = 0;
  const char* c = text;
  for (; *c && *c != '='; c++) {
    int v = b64value(*c);
    if (v < 0) return -1;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n >= MAX_KEY) return -1;
      psk[n++] = (uint8_t)(acc >> bits);
    }
  }
  for (; *c == '='; c++) { }
  if (*c != 0) return -1;            // something after the padding
  if (n != 1 && n != 16 && n != 32) return -1;
  return n;
}

uint8_t channelHash(const char* name, const uint8_t* key, int key_len) {
  uint8_t h = 0;
  for (const char* c = name; c && *c; c++) h ^= (uint8_t)*c;
  for (int i = 0; i < key_len; i++) h ^= key[i];
  return h;
}

void ctrCrypt(const uint8_t* key, int key_len, uint32_t from, uint32_t id, uint8_t* data, int len) {
  if (key_len != 16 && key_len != 32) return;
  AES128 aes128;
  AES256 aes256;
  BlockCipher* aes = &aes128;
  if (key_len == 32) aes = &aes256;
  aes->setKey(key, key_len);

  uint8_t block[16], stream[16];
  memset(block, 0, sizeof(block));
  for (int i = 0; i < 4; i++) block[i] = (uint8_t)(id >> (8 * i));      // id as u64 LE (upper half 0)
  for (int i = 0; i < 4; i++) block[8 + i] = (uint8_t)(from >> (8 * i));
  uint32_t counter = 0;
  for (int off = 0; off < len; off += 16) {
    block[12] = counter >> 24; block[13] = counter >> 16; block[14] = counter >> 8; block[15] = counter;
    aes->encryptBlock(stream, block);
    int n = len - off < 16 ? len - off : 16;
    for (int i = 0; i < n; i++) data[off + i] ^= stream[i];
    counter++;
  }
  memset(stream, 0, sizeof(stream));
  aes->clear();
}

float usFrequency(const char* channel_name, float bw_khz) {
  uint32_t h = 5381;
  for (const char* c = channel_name; c && *c; c++) h = h * 33 + (uint8_t)*c;
  float bw = bw_khz / 1000.0f;
  uint32_t slots = (uint32_t)(26.0f / bw + 0.5f);
  if (slots == 0) slots = 1;
  return 902.0f + bw / 2 + (h % slots) * bw;
}

static const Preset PRESETS[] = {
  { "ShortTurbo", 500, 7, 5 }, { "ShortFast", 250, 7, 5 }, { "ShortSlow", 250, 8, 5 },
  { "MediumFast", 250, 9, 5 }, { "MediumSlow", 250, 10, 5 }, { "LongFast", 250, 11, 5 },
  { "LongModerate", 125, 11, 8 }, { "LongSlow", 125, 12, 8 },
};

static bool sameIgnoreCase(const char* a, const char* b) {
  for (; *a && *b; a++, b++) {
    char x = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
    char y = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
    if (x != y) return false;
  }
  return *a == *b;
}

const Preset* findPreset(const char* name) {
  for (const Preset& p : PRESETS) {
    if (sameIgnoreCase(p.name, name)) return &p;
  }
  return NULL;
}

// ---- protobuf ----

static bool readVarint(const uint8_t* p, int len, int* i, uint64_t* v) {
  uint64_t r = 0;
  for (int shift = 0; shift < 64; shift += 7) {
    if (*i >= len) return false;
    uint8_t b = p[(*i)++];
    r |= (uint64_t)(b & 0x7F) << shift;
    if (!(b & 0x80)) { *v = r; return true; }
  }
  return false;
}

// Calls back for each field; length-delimited fields come with their bytes, others with their value
template<typename F>
static bool walkFields(const uint8_t* p, int len, F&& field) {
  int i = 0;
  while (i < len) {
    uint64_t key;
    if (!readVarint(p, len, &i, &key)) return false;
    uint32_t num = (uint32_t)(key >> 3);
    uint8_t type = key & 7;
    if (num == 0) return false;
    uint64_t v = 0;
    const uint8_t* bytes = NULL;
    int blen = 0;
    switch (type) {
      case 0:
        if (!readVarint(p, len, &i, &v)) return false;
        break;
      case 1:
        if (len - i < 8) return false;
        for (int k = 7; k >= 0; k--) v = (v << 8) | p[i + k];
        i += 8;
        break;
      case 2: {
        uint64_t l;
        if (!readVarint(p, len, &i, &l) || l > (uint64_t)(len - i)) return false;
        bytes = &p[i];
        blen = (int)l;
        i += blen;
        break;
      }
      case 5:
        if (len - i < 4) return false;
        v = le32(&p[i]);
        i += 4;
        break;
      default:
        return false;   // groups (3, 4) aren't used by Meshtastic
    }
    field(num, type, v, bytes, blen);
  }
  return true;
}

bool parseData(const uint8_t* p, int len, Data* d) {
  d->portnum = 0;
  d->payload = NULL;
  d->payload_len = 0;
  bool ok = walkFields(p, len, [d](uint32_t num, uint8_t type, uint64_t v, const uint8_t* bytes, int blen) {
    if (num == 1 && type == 0) d->portnum = (uint32_t)v;
    if (num == 2 && type == 2) { d->payload = bytes; d->payload_len = blen; }
  });
  return ok && d->portnum != 0;
}

static void copyString(char* dest, size_t size, const uint8_t* src, int len) {
  size_t n = (size_t)len < size - 1 ? (size_t)len : size - 1;
  while (n > 0 && n < (size_t)len && (src[n] & 0xC0) == 0x80) n--;   // don't cut a character in half
  memcpy(dest, src, n);
  dest[n] = 0;
  for (size_t k = 0; k < n; k++) {
    if ((uint8_t)dest[k] < 0x20) dest[k] = ' ';   // no control characters in names
  }
}

bool parseUser(const uint8_t* p, int len, User* u) {
  u->id[0] = u->long_name[0] = u->short_name[0] = 0;
  return walkFields(p, len, [u](uint32_t num, uint8_t type, uint64_t, const uint8_t* bytes, int blen) {
    if (type != 2) return;
    if (num == 1) copyString(u->id, sizeof(u->id), bytes, blen);
    if (num == 2) copyString(u->long_name, sizeof(u->long_name), bytes, blen);
    if (num == 3) copyString(u->short_name, sizeof(u->short_name), bytes, blen);
  });
}

int nextPart(const char* text, int len, int max) {
  if (len <= max) return len;
  if (max < 1) return 1;
  int cut = max;
  for (int k = max; k > max / 2; k--) {
    if (text[k] == ' ' || text[k] == '\n') { cut = k; break; }
  }
  while (cut > 0 && (((uint8_t) text[cut]) & 0xC0) == 0x80) cut--;   // text[cut] starts the next part
  return cut > 0 ? cut : max;
}

// ---- Receiver ----

void Receiver::reset() {
  memset(_key, 0, sizeof(_key));
  _key_len = 0;
  _hash = 0;
  _configured = false;
  memset(_seen, 0, sizeof(_seen));
  _seen_next = 0;
  memset(_names, 0, sizeof(_names));
  _names_next = 0;
  memset(&_stats, 0, sizeof(_stats));
}

bool Receiver::setChannel(const char* name, const uint8_t* psk, int psk_len) {
  uint8_t key[MAX_KEY];
  int n = expandKey(psk, psk_len, key);
  if (n < 0) return false;
  memcpy(_key, key, sizeof(_key));
  _key_len = n;
  _hash = channelHash(name, _key, _key_len);
  _configured = true;
  return true;
}

bool Receiver::seenBefore(uint32_t from, uint32_t id) {
  uint32_t tag = (from * 2654435761u) ^ id;   // one word per packet is enough to spot repeats
  if (tag == 0) tag = 1;
  for (uint32_t s : _seen) {
    if (s == tag) return true;
  }
  _seen[_seen_next] = tag;
  _seen_next = (_seen_next + 1) % SEEN;
  return false;
}

void Receiver::remember(uint32_t node, const char* long_name) {
  if (!long_name[0]) return;
  for (Name& n : _names) {
    if (n.node == node) { strcpy(n.long_name, long_name); return; }
  }
  _names[_names_next].node = node;
  strcpy(_names[_names_next].long_name, long_name);
  _names_next = (_names_next + 1) % NAMES;
}

const char* Receiver::nameOf(uint32_t node) {
  for (const Name& n : _names) {
    if (n.node == node && n.long_name[0]) return n.long_name;
  }
  snprintf(_fallback, sizeof(_fallback), "!%08lx", (unsigned long)node);
  return _fallback;
}

Kind Receiver::handle(const uint8_t* pkt, int len, Message* msg) {
  _stats.heard++;
  Header h;
  if (!_configured || !parseHeader(pkt, len, &h) || len > MAX_PACKET) {
    _stats.undecodable++;
    return UNDECODABLE;
  }
  if (h.channel != _hash) {
    _stats.other_channel++;
    return OTHER_CHANNEL;
  }
  if (h.to != BROADCAST) {   // direct messages need the node's own keys
    _stats.not_for_us++;
    return NOT_FOR_US;
  }
  if (seenBefore(h.from, h.id)) {   // the same packet relayed by another node
    _stats.duplicate++;
    return DUPLICATE;
  }

  int n = len - HEADER_LEN;
  memcpy(_buf, &pkt[HEADER_LEN], n);
  ctrCrypt(_key, _key_len, h.from, h.id, _buf, n);
  Data d;
  if (!parseData(_buf, n, &d)) {
    _stats.undecodable++;
    return UNDECODABLE;
  }
  if (d.portnum == PORT_NODEINFO) {
    User u;
    if (!parseUser(d.payload, d.payload_len, &u)) {
      _stats.undecodable++;
      return UNDECODABLE;
    }
    remember(h.from, u.long_name[0] ? u.long_name : u.short_name);
    _stats.nodeinfo++;
    if (msg) msg->hdr = h;
    return NODEINFO;
  }
  if (d.portnum == PORT_TEXT && d.payload_len > 0) {
    _stats.text++;
    if (msg) {
      msg->hdr = h;
      msg->text = (const char*)d.payload;
      msg->text_len = d.payload_len;
      msg->sender = nameOf(h.from);
    }
    return TEXT;
  }
  return NONE;   // position, telemetry and the rest: not shown
}

}  // namespace meshtastic
