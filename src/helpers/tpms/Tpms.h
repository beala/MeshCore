#pragma once
// Tire pressure sensors (TPMS) on 315 MHz, as fitted to cars sold in the US (docs/tire_pressure.md).
// Each make's sensors use their own framing; this follows rtl_433's decoders (src/devices/tpms_*.c),
// ported to work on the raw FSK chips the LR2021 hands over after a sync word. No allocation.

#include <stdint.h>
#include <stddef.h>

namespace tpms {

enum {
  P_TOYOTA = 1,   // Pacific PMV-C210 (Toyota, Lexus; newer)
  P_PMV107J,      // Pacific PMV-107J (Toyota, Lexus; older)
  P_FORD,         // Continental/VDO (Ford)
  P_JEEP,         // Continental (Jeep, Chrysler, Dodge, Ram; the same frames as Citroen/Peugeot)
  P_HYUNDAI,      // Continental/VDO (Hyundai, Kia, Mazda, Mitsubishi)
  P_KIA,          // Kia Rio, some Hyundai
  P_HONDA,        // TRW (Honda)
  P_NISSAN,       // Nissan
  P_GM,           // Schrader EG53MA4 (GM: Chevrolet, GMC, Buick, Cadillac)
  P_COUNT
};

struct Reading {
  uint8_t proto;          // P_*
  uint32_t id;            // the sensor's ID (as printed on it, in hex)
  int16_t kpa10;          // pressure, tenths of a kPa (gauge); -1 if not sent
  int16_t temp_c;         // temperature, C
  bool has_temp;
  bool battery_low;
  bool moving;            // the sensor says the car is moving (Ford)
  bool weak_check;        // its check is weak (a sum or 2 bits): take it only when heard twice
};

// One radio setting: GFSK at kbps, a sync word (its first sync_bits bits of sync[], sent MSB
// first, no preamble needed), then pkt_bytes bytes of raw chips. One setting can serve several
// protocols (Ford and Jeep share theirs).
struct Air {
  const char* name;
  float kbps;
  uint8_t sync[5];
  uint8_t sync_bits;
  uint8_t pkt_bytes;
  bool invert;            // the protocol's bits are the chips inverted (rtl_433 inverts them first)
  uint16_t protos;        // bit (1 << P_*) for each protocol read from it
  bool ook;               // on-off keyed (the radio's OOK receiver: a 1010.. detector pattern, then the sync word)
  uint8_t pre_det;        // GFSK: 1010.. preamble bits the radio waits for before the sync word (0: none; the
                          // makes that send one are heard far more reliably with it: 8 of 8 against 3-5)
  bool listen;            // in the rotation (false: read in tests, not yet heard over the air)
};
static const int AIRS = 8;
const Air& air(int i);   // 0 .. AIRS-1
static const float FREQ_MHZ = 315.0f;
static const float DEV_KHZ = 40.0f;      // the sensors' deviation is 20-50 kHz
static const float RX_BW_KHZ = 185.2f;   // that, and +-50 kHz of crystal error

// Reads one packet from air setting i: chips as the radio hands them over after the sync word.
// Tries each of the setting's protocols. False if none reads.
bool read(int i, const uint8_t* chips, int n_bytes, Reading* r);

const char* protoName(uint8_t proto);   // "Toyota", "Ford", ...

// For tests: the decoders on a bit row as rtl_433 has it (sync word included, any offset)
bool decodeRow(uint8_t proto, const uint8_t* bits, int nbits, Reading* r);
uint8_t crc8(const uint8_t* b, int n, uint8_t poly, uint8_t init);

}  // namespace tpms
