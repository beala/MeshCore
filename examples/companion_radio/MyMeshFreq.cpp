// Frequency fingerprints of nearby radios: 'get nodes.freq' (docs/frequency_fingerprint.md)
#include "MyMesh.h"

// A direct advert's signature, checked here because its key is about to teach a row for sure
static bool advertSigned(const uint8_t* raw, int len) {
  damaged::Layout l = damaged::parseHeader(raw, len);
  if (l.payload_off == 0 || l.type != PAYLOAD_TYPE_ADVERT) return false;
  const uint8_t* p = &raw[l.payload_off];
  int n = l.payload_len;
  if (n < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE) return false;
  int app_len = n - (PUB_KEY_SIZE + 4 + SIGNATURE_SIZE);
  if (app_len > MAX_ADVERT_DATA_SIZE) app_len = MAX_ADVERT_DATA_SIZE;
  uint8_t msg[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
  memcpy(msg, p, PUB_KEY_SIZE + 4);                                           // key, timestamp
  memcpy(&msg[PUB_KEY_SIZE + 4], &p[PUB_KEY_SIZE + 4 + SIGNATURE_SIZE], app_len);
  mesh::Identity id(p);
  return id.verify(&p[PUB_KEY_SIZE + 4], msg, PUB_KEY_SIZE + 4 + app_len);
}

// Every packet that passed its CRC teaches the table (LR2021 radios: the others don't measure it)
void MyMesh::freqNote(const uint8_t* raw, int len, float snr) {
  int32_t err;
  if (!_radio->getLastFreqError(&err)) return;
  damaged::RadioId who;
  damaged::senderId(raw, len, who);
  bool strong = who.n >= damaged::NAME_MIN_BYTES;
  damaged::Layout l = damaged::parseHeader(raw, len);
  if (strong && l.type == PAYLOAD_TYPE_ADVERT && who.n == 4 && memcmp(who.b, &raw[l.payload_off], 4) == 0) {
    // a direct advert: its key says who sent it, if its signature is good (else ignore it)
    if (!advertSigned(raw, len)) return;
  }
  _freq.add(who.b, who.n, strong, err, (int)(snr * 4), millis());
}

// The sender of a packet, by its frequency, when the packet itself says less than 2 bytes of ID
// (or nothing): the named radio whose ID fits and whose frequency band holds the reading, if exactly
// one does. Replaces who and returns true then.
bool MyMesh::freqSender(damaged::RadioId& who, int32_t err, float snr, bool count) {
  if (who.n >= damaged::NAME_MIN_BYTES) return false;
  int i = _freq.whoSent(who.b, who.n, err, (int)(snr * 4), millis(), count);
  if (i < 0 || !_freq.rows[i].certain) return false;
  const freqprint::Row& r = _freq.rows[i];
  who.n = r.idn < (int) sizeof(who.b) ? r.idn : (uint8_t) sizeof(who.b);
  memcpy(who.b, r.id, who.n);
  return true;
}

static void fmtAge(uint32_t ms, char* out, int n) {
  uint32_t s = ms / 1000;
  if (s < 60) snprintf(out, n, "%lus", (unsigned long) s);
  else if (s < 3600) snprintf(out, n, "%lum", (unsigned long)(s / 60));
  else snprintf(out, n, "%luh", (unsigned long)(s / 3600));
}

// Rows in use, most heard first
static int freqOrder(const freqprint::Table& t, int* order) {
  int n = 0;
  for (int i = 0; i < freqprint::ROWS; i++) if (t.rows[i].idn) order[n++] = i;
  for (int a = 1; a < n; a++) {
    for (int b = a; b > 0; b--) {
      const freqprint::Row& x = t.rows[order[b]];
      const freqprint::Row& y = t.rows[order[b - 1]];
      if ((uint32_t) x.learned + x.matched <= (uint32_t) y.learned + y.matched) break;
      int tmp = order[b]; order[b] = order[b - 1]; order[b - 1] = tmp;
    }
  }
  return n;
}

bool MyMesh::handleFreqCommand(const char* command, char* reply) {
  if (strncmp(command, "get nodes.list", 14) == 0 && (command[14] == 0 || command[14] == ' ')) {
    // For apps (the fluxcore app's Radios tab): "> <radios> <from> rec;rec..." as many as fit, rec =
    // id hex (every byte known if named, else 1),named 0/1,name,error Hz,scatter Hz,learned,matched,age s
    int start = command[14] == ' ' ? atoi(&command[15]) : 0;
    int order[freqprint::ROWS];
    int n = freqOrder(_freq, order);
    int k = sprintf(reply, "> %d %d", n, start);
    uint32_t now = millis();
    for (int a = start; a < n; a++) {
      const freqprint::Row& r = _freq.rows[order[a]];
      char item[80];
      int w = snprintf(item, sizeof(item), "%s", a == start ? " " : ";");
      int idn = r.certain ? r.idn : 1;
      for (int b = 0; b < idn; b++) w += snprintf(&item[w], sizeof(item) - w, "%02x", r.id[b]);
      char name[16] = "";
      ContactInfo* c = r.certain && r.idn >= damaged::NAME_MIN_BYTES ? lookupContactByPubKey(r.id, r.idn) : NULL;
      if (c) {
        snprintf(name, sizeof(name), "%.15s", c->name);
        // don't end in a cut UTF-8 character (names often start with an emoji)
        int L = strlen(name), lead = L;
        while (lead > 0 && ((uint8_t) name[lead - 1] & 0xC0) == 0x80) lead--;
        if (lead > 0 && ((uint8_t) name[lead - 1] & 0x80)) {
          uint8_t b = (uint8_t) name[lead - 1];
          int need = (b & 0xE0) == 0xC0 ? 2 : (b & 0xF0) == 0xE0 ? 3 : (b & 0xF8) == 0xF0 ? 4 : 1;
          if (L - (lead - 1) < need) name[lead - 1] = 0;
        }
        for (char* q = name; *q; q++) if (*q == ',' || *q == ';') *q = ' ';
      }
      w += snprintf(&item[w], sizeof(item) - w, ",%d,%s,%ld,%u,%u,%u,%lu", r.certain ? 1 : 0, name,
                    (long)(r.mean_x16 / 16), (unsigned)((r.dev_x16 + 8) / 16), r.learned, r.matched,
                    (unsigned long)((now - r.last) / 1000));
      if (w >= (int) sizeof(item) || k + w >= 158) break;
      memcpy(&reply[k], item, w + 1);
      k += w;
    }
    return true;
  }
  if (strcmp(command, "nodes.freq reset") == 0) {
    _freq.clear();
    strcpy(reply, "OK - frequency fingerprints cleared");
    return true;
  }
  if (strncmp(command, "get nodes.freq", 14) != 0 || (command[14] != 0 && command[14] != ' ')) return false;
  int start = command[14] == ' ' ? atoi(&command[15]) : 0;
  int used = _freq.used();
  if (used == 0) {
    strcpy(reply, "> no radios heard yet (LR2021 radios measure this)");
    return true;
  }
  int order[freqprint::ROWS];
  int n = freqOrder(_freq, order);
  // which first bytes are shared by more than one radio
  int k = sprintf(reply, "> %d radio%s", used, used == 1 ? "" : "s");
  bool shared_any = false;
  for (int a = 0; a < n; a++) {
    uint8_t f = _freq.rows[order[a]].id[0];
    bool first = true;
    for (int b = 0; b < a; b++) if (_freq.rows[order[b]].id[0] == f) first = false;
    int c = _freq.radiosOn(f);
    if (first && c > 1 && k < 60) {
      k += sprintf(&reply[k], "%s %d share %02x", shared_any ? "," : ";", c, f);
      shared_any = true;
    }
  }
  if (start > 0) k += sprintf(&reply[k], " (from %d)", start);
  uint32_t now = millis();
  for (int a = start; a < n; a++) {
    const freqprint::Row& r = _freq.rows[order[a]];
    char id[20];
    // a certain row: its ID (2 or 3 bytes, as the mesh's path hashes; an advert's key shows 3) and name;
    // an unnamed one shows its 1 byte (as damaged packets do)
    damagedRadioName(r.id, r.certain ? (r.idn < 3 ? r.idn : 3) : 1, id, sizeof(id));
    char age[8];
    fmtAge(now - r.last, age, sizeof(age));
    char item[64];
    int w = snprintf(item, sizeof(item), "; %s: %+ldHz ~%u, %u, %s", id, (long)(r.mean_x16 / 16),
                     (unsigned)((r.dev_x16 + 8) / 16), (unsigned)(r.learned + r.matched), age);
    if (k + w >= 158) {
      if (k + 12 < 160) k += sprintf(&reply[k], "; +%d more", n - a);
      break;
    }
    memcpy(&reply[k], item, w + 1);
    k += w;
  }
  return true;
}
