#pragma once
// 1090 MHz ADS-B (Mode S extended squitter, DF 17/18): parity, identification, position (CPR) and
// velocity. Written from the published format (ICAO Annex 10 / DO-260B as explained in "The 1090
// MHz Riddle", Junzi Sun); no code copied. Reports use the same uat::Report as the 978 MHz receiver.

#include <stdint.h>
#include <stddef.h>
#include "Uat.h"

namespace adsb {

// A frame is 14 bytes: DF/CA, 3-byte address, 7-byte message (ME), 3-byte parity. The LR2021 checks
// the parity itself and hands over the first 11.
static const int FRAME_BYTES = 14, DATA_BYTES = 11;

// CRC-24 (polynomial 0xFFF409) over n bytes
uint32_t crc24(const uint8_t* b, int n);

struct Message {
  uat::Report r;        // address, qualifier, altitude, speed/track, vertical rate, callsign
  uint8_t type_code;    // ME type code 1-31
  bool has_cpr;         // a position message: the CPR fields below are set
  bool cpr_odd;
  bool surface;         // surface position (type codes 5-8): CPR in 90° zones
  uint32_t cpr_lat, cpr_lon;   // 17 bits each
};

// Decodes 11 bytes (parity already checked) or 14 (checked here). Returns false for anything that
// isn't an extended squitter with a good parity.
bool decode(const uint8_t* b, int len, Message* m);

// Airborne position from an even and an odd message (within ~10 s of each other); the position is
// the newer one's. Returns false if they straddle a longitude zone boundary.
bool cprGlobal(uint32_t lat_even, uint32_t lon_even, uint32_t lat_odd, uint32_t lon_odd, bool odd_newer,
               int32_t* lat_e5, int32_t* lon_e5);

// Position from one message, given a reference within 180 NM (airborne) or 45 NM (surface): the
// receiver's location or the aircraft's last position. Degrees × 1e5.
bool cprLocal(uint32_t lat, uint32_t lon, bool odd, bool surface, int32_t ref_lat_e5, int32_t ref_lon_e5,
              int32_t* lat_e5, int32_t* lon_e5);

}  // namespace adsb
