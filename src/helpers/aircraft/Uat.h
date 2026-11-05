#pragma once
// UAT (978 MHz) ADS-B downlink messages from aircraft: Reed-Solomon error correction and decoding
// of the header, state vector (position, altitude, velocity) and mode status (callsign).
// Written from the published message format (DO-282B as documented by dump978); no code copied.
// Integer only and no allocation, so it builds for the companion and for the PC tests.

#include <stdint.h>
#include <stddef.h>

namespace uat {

// On air after the 36-bit sync word 0xEACDDA4E2: a basic message is 30 bytes (18 data + 12 RS), a
// long one 48 (34 data + 14 RS). The radio receives 48 bytes either way.
static const int SHORT_BYTES = 30, SHORT_DATA = 18;
static const int LONG_BYTES = 48, LONG_DATA = 34;
static const uint64_t SYNC_WORD = 0xEACDDA4E2ULL;

// Corrects buf (LONG_BYTES received) in place as a long message, else as a basic one. Returns the
// number of data bytes (LONG_DATA or SHORT_DATA) and the bytes corrected in *fixed, or 0 if it's
// neither.
int correct(uint8_t* buf, int len, int* fixed);

// Reed-Solomon over GF(256) (polynomial 0x187, first root 120): corrects up to nroots/2 byte errors
// in a codeword of n bytes. Returns the number corrected, or -1.
int rsDecode(uint8_t* cw, int n, int nroots);

struct Report {
  uint32_t address;       // 24-bit (ICAO address when qualifier is 0)
  uint8_t qualifier;      // 0 ADS-B ICAO, 1 ADS-B other, 2 TIS-B ICAO, 3 TIS-B track file, 4 vehicle, 5 beacon, 6 ADS-R
  uint8_t payload_type;
  bool has_pos;
  int32_t lat_e5, lon_e5; // degrees × 1e5
  bool has_alt;
  bool alt_geometric;     // else pressure altitude
  int32_t alt_ft;
  uint8_t ag_state;       // 0/1 airborne, 2 on the ground
  bool has_speed;
  uint16_t speed_kt;
  uint16_t track_deg;
  bool has_vs;
  int16_t vs_fpm;
  char callsign[9];       // "" if not in this message
  bool callsign_is_squawk;
};

// Decodes the data bytes (after correct()). Returns false for a length that isn't a message.
bool decode(const uint8_t* data, int len, Report* out);

// Distance (0.1 mile units) and bearing (degrees) from (lat1, lon1) to (lat2, lon2), × 1e5 degrees.
// Flat-earth, fine for the tens of miles UAT is heard over.
void distanceBearing(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2, uint32_t* dist_tenth_mi, uint16_t* bearing);

}  // namespace uat
