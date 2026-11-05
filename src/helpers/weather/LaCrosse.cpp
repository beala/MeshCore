// La Crosse Technology View sensors (US, 915 MHz). FSK at about 9.6 kbit/s (104-107 µs bits),
// preamble 0xAA.., sync word 0xD2AA2DD4, then a 3-byte ID, a flags/sequence byte and the readings,
// checked with CRC-8 (polynomial 0x31). The packet carries no model byte: the length the CRC
// covers, filler bytes and plausible values tell the models apart. Written from the published
// protocol descriptions (rtl_433's device notes); no code was copied.
//
//   LTV-TH2/TH2i/TH3  ID ID ID FL TT TH HH CC               CRC over 8, init 0x00, 0xAC or 0xB2
//   LTV-R1            ID ID ID FL R1 AA R0 CC               CRC over 8; rain = R1:R0 ticks of 0.25 mm
//   LTV-W1/W2         ID ID ID FL AA AA AA WW WA AA CC      CRC over 11; wind = WWW (0.1 km/h)
//   LTV-WSDTH01       ID ID ID FL TT TH HH WW WD DD CC      CRC over 11
// TTT: temperature, 0.1 °C + 40 °C. HHH: humidity %. WWW: wind, 0.1 km/h. DDD: direction, degrees.
// FL: bit 7 battery low, bits 3-1 sequence number.

#include "FineOffset.h"
#include <string.h>

namespace wxsensor {

static uint8_t crc8i(const uint8_t* b, int n, uint8_t init) {
  uint8_t c = init;
  for (int i = 0; i < n; i++) {
    c ^= b[i];
    for (int k = 0; k < 8; k++) c = (c & 0x80) ? (uint8_t)((c << 1) ^ 0x31) : (uint8_t)(c << 1);
  }
  return c;
}

static uint16_t hi12(const uint8_t* p) { return (uint16_t)p[0] << 4 | p[1] >> 4; }   // p[0], top of p[1]
static uint16_t lo12(const uint8_t* p) { return (uint16_t)(p[0] & 0x0F) << 8 | p[1]; } // bottom of p[0], p[1]

static uint16_t kmh10ToDms(uint16_t kmh10) { return (uint16_t)((kmh10 * 10u + 18) / 36); }

bool decodeLaCrosse(const uint8_t* b, int len, Reading* r) {
  if (!b || !r || len < 8) return false;
  memset(r, 0, sizeof(*r));
  r->id = (uint32_t)b[0] << 16 | (uint32_t)b[1] << 8 | b[2];
  r->battery_low = (b[3] & 0x80) != 0;
  r->have = HAVE_BATTERY;

  if (len >= 11 && crc8i(b, 11, 0) == 0) {
    if (b[4] == 0xAA && b[5] == 0xAA && b[6] == 0xAA && (b[8] & 0x0F) == 0x0A && b[9] == 0xAA) {
      r->model = LTV_W1;
      r->wind_dms = kmh10ToDms(hi12(&b[7]));
      r->have |= HAVE_WIND;
      return true;
    }
    uint16_t temp = hi12(&b[4]), hum = lo12(&b[5]), wind = hi12(&b[7]), dir = lo12(&b[8]);
    if (temp >= 400 - 400 && temp <= 400 + 700 && hum <= 100 && wind <= 2000 && dir <= 360) {
      r->model = LTV_WSDTH;
      r->temp_c10 = (int16_t)temp - 400;
      r->humidity = (uint8_t)hum;
      r->wind_dms = kmh10ToDms(wind);
      r->wind_dir = dir % 360;
      r->have |= HAVE_TEMP | HAVE_HUM | HAVE_WIND | HAVE_DIR;
      return true;
    }
    // LTV-WR1 and LTV-R3 also check over 11 bytes; their rain fields aren't understood yet
  }

  bool th = crc8i(b, 8, 0) == 0, th2 = crc8i(b, 8, 0xAC) == 0 || crc8i(b, 8, 0xB2) == 0;
  // byte 5: a TH packet has the top of the humidity in its low half, always 0 (humidity <= 100); an
  // R1 packet has the rain count's high byte XOR 0xAA there, 0xA or 0xB for any real count
  if (th && (b[5] & 0x0F) != 0 && (uint8_t)(b[5] ^ 0xAA) < 0x10) {
    r->model = LTV_R1;
    uint32_t ticks = (uint32_t)(b[5] ^ 0xAA) << 16 | (uint32_t)b[4] << 8 | b[6];
    r->rain_um = ticks * 250;
    r->have |= HAVE_RAIN;
    return true;
  }
  if (th || th2) {
    uint16_t temp = hi12(&b[4]), hum = lo12(&b[5]);
    if (temp > 400 + 700 || hum > 100) return false;   // -40..70 °C, 0..100 %
    r->model = LTV_TH;
    r->temp_c10 = (int16_t)temp - 400;
    r->humidity = (uint8_t)hum;
    r->have |= HAVE_TEMP | HAVE_HUM;
    return true;
  }
  return false;
}

}  // namespace wxsensor
