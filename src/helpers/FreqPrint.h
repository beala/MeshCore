#pragma once

// Frequency fingerprints of nearby radios (docs/frequency_fingerprint.md).
//
// Every radio's crystal is a little off, by its own steady amount, so the frequency error a receiver
// measures on a packet (LR2021: GetLoraPacketStatus) says roughly which radio sent it. This keeps one
// row per radio heard: its ID and its usual error, learned as packets arrive.
//
// - A row is a radio: two radios with the same ID but different frequencies get two rows.
// - A row is "certain" once a signed advert, or a packet with an ID of 2 bytes or more, taught it.
//   Only certain rows are ever named: a 1-byte ID is shared by 1 in 256 radios.
// - A packet with a 1-byte ID, or none, is put under the row whose ID and frequency both fit.
//
// The error is relative to the receiver's own crystal, which drifts too; rows follow slow drift.

#include <stdint.h>
#include <stddef.h>

namespace freqprint {

static const int ROWS = 16;
static const int ID_MAX = 4;
static const int MIN_BAND_HZ = 40;        // a radio's readings stay this close (heat moves them slowly)
static const int LEARN_MIN_SNR_X4 = -20;  // below -5 dB readings scatter (and can be a whole bin off)
static const int WEAK_EXTRA_HZ = 40;      // ...so they're only matched, with a wider band

struct Row {
  uint8_t id[ID_MAX];
  uint8_t idn;          // ID bytes known; 0 = an empty row
  bool certain;         // a signed advert or an ID of 2+ bytes taught it: the ID is the radio's
  int32_t mean_x16;     // its usual frequency error, Hz x 16
  uint16_t dev_x16;     // how far its readings stray from that, on average (Hz x 16)
  uint16_t learned;     // readings it learned from
  uint16_t matched;     // other packets put under it (1-byte or no ID, damaged, weak)
  uint32_t last;        // millis() it was last heard
};

class Table {
public:
  Row rows[ROWS];

  Table() { clear(); }
  void clear();

  // A reading from a packet that passed its CRC. id: what the packet says about its sender (1-4
  // bytes, or idn = 0 for nothing). strong: the ID is the sender's for sure (a signed advert, or 2+
  // bytes). Returns the row it went under, or -1.
  int add(const uint8_t* id, int idn, bool strong, int32_t err_hz, int snr_x4, uint32_t now);

  // The row a reading most likely came from, given whatever ID the packet gives (may be none, or
  // damaged): the one whose ID fits and whose band holds the reading, if exactly one does. -1 if none
  // or more than one. Doesn't change the table. With count, also counts it under that row.
  int whoSent(const uint8_t* id, int idn, int32_t err_hz, int snr_x4, uint32_t now, bool count);

  // How far from a row's usual error a reading may be and still be that radio
  int band(const Row& r, int snr_x4) const;

  // Rows (radios) whose ID starts with this byte
  int radiosOn(uint8_t first) const;

  int used() const;

private:
  bool idFits(const Row& r, const uint8_t* id, int idn) const;
  int nearest(const uint8_t* id, int idn, int32_t err_hz, int snr_x4, int* in_band) const;
  void learn(Row& r, int32_t err_hz);
  int newRow(uint32_t now);
};

}  // namespace freqprint
