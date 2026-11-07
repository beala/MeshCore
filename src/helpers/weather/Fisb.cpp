#include "Fisb.h"
#include "../aircraft/Uat.h"
#include <string.h>

namespace fisb {

bool correct(const uint8_t* frame, uint8_t* data, int* fixed) {
  int total = 0;
  for (int b = 0; b < BLOCKS; b++) {
    uint8_t cw[BLOCK_BYTES];
    for (int i = 0; i < BLOCK_BYTES; i++) cw[i] = frame[i * BLOCKS + b];
    int n = uat::rsDecode(cw, BLOCK_BYTES, BLOCK_BYTES - BLOCK_DATA);
    if (n < 0) return false;
    total += n;
    memcpy(&data[b * BLOCK_DATA], cw, BLOCK_DATA);
  }
  if (fixed) *fixed = total;
  return true;
}

void header(const uint8_t* d, Header* h) {
  // 23 bits of latitude and 24 of longitude, as fractions of a whole turn
  uint32_t raw_lat = ((uint32_t) d[0] << 15) | ((uint32_t) d[1] << 7) | (d[2] >> 1);
  uint32_t raw_lon = ((uint32_t)(d[2] & 1) << 23) | ((uint32_t) d[3] << 15) | ((uint32_t) d[4] << 7) | (d[5] >> 1);
  int64_t lat = (int64_t) raw_lat * 36000000 / 16777216;   // x 1e5
  int64_t lon = (int64_t) raw_lon * 36000000 / 16777216;
  if (lat > 9000000) lat -= 18000000;
  if (lon > 18000000) lon -= 36000000;
  h->lat_e5 = (int32_t) lat;
  h->lon_e5 = (int32_t) lon;
  h->pos_valid = d[5] & 1;
  h->utc_coupled = d[6] & 0x80;
  h->app_valid = d[6] & 0x20;
  h->slot = d[6] & 0x1F;
  h->tisb_site = d[7] >> 4;
}

static const char ALPHABET[] = "\x03" "ABCDEFGHIJKLMNOPQRSTUVWXYZ\x1A\t\x1E\n| !\"#$%&'()*+,-./0123456789:;<=>?";

int dlac(const uint8_t* in, int len, char* out, int n) {
  int k = 0;
  bool tab = false;
  int bits = len * 8;
  for (int at = 0; at + 6 <= bits; at += 6) {
    int byte = at >> 3, shift = at & 7;
    uint16_t w = (uint16_t)(in[byte] << 8) | (byte + 1 < len ? in[byte + 1] : 0);
    uint8_t c = (w >> (10 - shift)) & 0x3F;
    if (tab) {
      tab = false;
      for (int s = 0; s < c && k < n - 1; s++) out[k++] = ' ';
    } else if (c == 28) {
      tab = true;
    } else if (k < n - 1) {
      out[k++] = ALPHABET[c];
    }
  }
  if (n > 0) out[k < n ? k : n - 1] = 0;
  return k;
}

void Reports::start(const uint8_t* data, int len) {
  _d = data;
  _len = len;
  _pos = 8;
  _blen = _bpos = 0;
  _product = 0;
  _hours = _minutes = 0;
  if (len < 8 || !(data[6] & 0x20)) _pos = len;   // no application data
}

bool Reports::next(Text* out) {
  for (;;) {
    // the next report in the current APDU's text
    while (_bpos < _blen) {
      int s = _bpos;
      int e = s;
      while (e < _blen && _buf[e] != '\x1e' && _buf[e] != '\x03') e++;
      _bpos = e + 1;
      // skip empty ones (ETX padding, a trailing separator)
      int a = s, z = e;
      while (a < z && (_buf[a] == ' ' || _buf[a] == '\n')) a++;
      if (a == z) continue;
      out->product = _product;
      out->hours = _hours;
      out->minutes = _minutes;
      out->text = &_buf[s];
      out->len = e - s;
      return true;
    }
    // the next information frame
    if (_pos + 2 > _len) return false;
    int n = (_d[_pos] << 1) | (_d[_pos + 1] >> 7);
    int type = _d[_pos + 1] & 0x0F;
    if (n == 0 && type == 0) { _pos = _len; return false; }   // no more frames
    if (_pos + 2 + n > _len) { _pos = _len; return false; }
    const uint8_t* f = &_d[_pos + 2];
    _pos += 2 + n;
    _blen = _bpos = 0;
    if (type != 0 || n < 4) continue;   // not a FIS-B APDU
    uint16_t product = (uint16_t)(((f[0] & 0x1F) << 6) | (f[1] >> 2));
    bool segmented = f[1] & 0x02;
    int t_opt = ((f[1] & 1) << 1) | (f[2] >> 7);
    static const uint8_t HDR[4] = { 4, 5, 5, 6 };
    int h = HDR[t_opt];
    if (product != PRODUCT_TEXT || segmented || n < h) continue;   // only whole text products
    if (t_opt & 2) {   // month and day first
      _hours = (f[3] & 0x3E) >> 1;
      _minutes = (uint8_t)(((f[3] & 1) << 5) | (f[4] >> 3));
    } else {
      _hours = (f[2] & 0x7C) >> 2;
      _minutes = (uint8_t)(((f[2] & 3) << 4) | (f[3] >> 4));
    }
    _product = product;
    _blen = dlac(&f[h], n - h, _buf, sizeof(_buf));
  }
}

static int word(const char* t, int len, int* at, char* out, int n) {
  int i = *at;
  while (i < len && (t[i] == ' ' || t[i] == '\n')) i++;
  int s = i;
  while (i < len && t[i] != ' ' && t[i] != '\n') i++;
  *at = i;
  int w = i - s;
  if (n > 0) {
    int c = w < n - 1 ? w : n - 1;
    memcpy(out, &t[s], c);
    out[c] = 0;
  }
  return w;
}

bool words(const char* text, int len, char* kind, int kn, char* where, int wn, char* when, int tn) {
  int at = 0;
  if (!word(text, len, &at, kind, kn)) return false;
  if (!word(text, len, &at, where, wn)) return false;
  return word(text, len, &at, when, tn) > 0;
}

int oneLine(const char* text, int len, char* out, int n) {
  int k = 0;
  bool space = false;
  for (int i = 0; i < len && n > 0; i++) {
    char c = text[i];
    if (c == ' ' || c == '\n' || c == '\t' || c == '\x1e' || c == '\x03') { space = k > 0; continue; }
    if (space && k < n - 1) out[k++] = ' ';
    space = false;
    if (k < n - 1) out[k++] = c;
  }
  while (k > 0 && (out[k - 1] == '=' || out[k - 1] == ' ')) k--;
  if (n > 0) out[k] = 0;
  return k;
}

}  // namespace fisb
