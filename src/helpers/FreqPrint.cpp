#include "FreqPrint.h"
#include <string.h>

namespace freqprint {

void Table::clear() { memset(rows, 0, sizeof(rows)); }

int Table::used() const {
  int n = 0;
  for (const auto& r : rows) if (r.idn) n++;
  return n;
}

int Table::band(const Row& r, int snr_x4) const {
  // a radio's own scatter (3 times its average), at least MIN_BAND_HZ; wider for weak signals
  int b = 3 * r.dev_x16 / 16;
  if (b < MIN_BAND_HZ) b = MIN_BAND_HZ;
  if (snr_x4 < LEARN_MIN_SNR_X4) b += WEAK_EXTRA_HZ;
  return b;
}

// The IDs agree on the bytes both have. No ID (idn 0) fits every row.
bool Table::idFits(const Row& r, const uint8_t* id, int idn) const {
  int n = idn < r.idn ? idn : r.idn;
  return n == 0 || memcmp(r.id, id, n) == 0;
}

// The closest row whose ID fits and whose band holds the reading; in_band: how many such rows
int Table::nearest(const uint8_t* id, int idn, int32_t err_hz, int snr_x4, int* in_band) const {
  int best = -1;
  int32_t best_d = 0;
  *in_band = 0;
  for (int i = 0; i < ROWS; i++) {
    const Row& r = rows[i];
    if (!r.idn || !idFits(r, id, idn)) continue;
    int32_t d = err_hz - r.mean_x16 / 16;
    if (d < 0) d = -d;
    if (d > band(r, snr_x4)) continue;
    (*in_band)++;
    if (best < 0 || d < best_d) { best = i; best_d = d; }
  }
  return best;
}

void Table::learn(Row& r, int32_t err_hz) {
  int32_t x = err_hz * 16;
  int32_t d = x - r.mean_x16;
  int32_t ad = d < 0 ? -d : d;
  // a plain average for the first 8, then each new reading counts 1/8: follows slow drift (heat)
  int k = r.learned < 8 ? r.learned + 1 : 8;
  r.mean_x16 += d / k;
  if (r.learned > 0) r.dev_x16 = (uint16_t)((int32_t)r.dev_x16 + (ad > 0xFFFF ? 0xFFFF : ad) / k - (int32_t)r.dev_x16 / k);
  if (r.learned < 0xFFFF) r.learned++;
}

// A free row, or the one heard least lately (an unnamed one before a certain one)
int Table::newRow(uint32_t now) {
  int pick = -1;
  for (int i = 0; i < ROWS; i++) {
    if (!rows[i].idn) return i;
    uint32_t age = now - rows[i].last;
    if (pick < 0) { pick = i; continue; }
    const Row& p = rows[pick];
    uint32_t page = now - p.last;
    if (rows[i].certain != p.certain) { if (!rows[i].certain) pick = i; continue; }
    if (age > page) pick = i;
  }
  return pick;
}

int Table::add(const uint8_t* id, int idn, bool strong, int32_t err_hz, int snr_x4, uint32_t now) {
  if (idn > ID_MAX) idn = ID_MAX;
  int in_band = 0;
  int i = nearest(id, idn, err_hz, snr_x4, &in_band);
  bool good = snr_x4 >= LEARN_MIN_SNR_X4;
  if (idn == 0 || !good) {
    // no ID to go by, or a scattered reading: only put it under a radio it clearly matches
    return in_band == 1 ? whoSent(id, idn, err_hz, snr_x4, now, true) : -1;
  }
  if (i >= 0) {
    Row& r = rows[i];
    if (strong && r.idn < idn) {   // a longer ID for this radio: now it's known for sure
      memcpy(r.id, id, idn);
      r.idn = (uint8_t) idn;
      r.certain = true;
    }
    if (strong) r.certain = true;
    // a 1-byte ID that fits one radio, at its frequency: that radio (both have to agree)
    if (strong || in_band == 1) learn(r, err_hz);
    else if (r.matched < 0xFFFF) r.matched++;
    r.last = now;
    return i;
  }
  // a radio not heard before (or not at this frequency: another radio with the same ID)
  i = newRow(now);
  Row& r = rows[i];
  memset(&r, 0, sizeof(r));
  memcpy(r.id, id, idn);
  r.idn = (uint8_t) idn;
  r.certain = strong;
  r.mean_x16 = err_hz * 16;
  r.learned = 1;
  r.last = now;
  return i;
}

int Table::whoSent(const uint8_t* id, int idn, int32_t err_hz, int snr_x4, uint32_t now, bool count) {
  if (idn > ID_MAX) idn = ID_MAX;
  int in_band = 0;
  int i = nearest(id, idn, err_hz, snr_x4, &in_band);
  if (i < 0 || in_band != 1) return -1;
  if (count) {
    if (rows[i].matched < 0xFFFF) rows[i].matched++;
    rows[i].last = now;
  }
  return i;
}

int Table::radiosOn(uint8_t first) const {
  int n = 0;
  for (const auto& r : rows) if (r.idn && r.id[0] == first) n++;
  return n;
}

}  // namespace freqprint
