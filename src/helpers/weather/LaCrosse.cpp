// Sensors on the slower listens (US, 915 MHz): FSK at 8.6-9.6 kbit/s, a preamble, a sync word
// ending 0x2DD4, then the packet; one listen per bit rate and sync word (Protocol). Written from the published protocol descriptions (rtl_433's device
// notes); no code was copied.
//
// La Crosse Technology View (9.61, 9.36 or 9.33 kbit/s by model, sync 0xD2AA2DD4): a 3-byte ID, a flags/sequence byte
// and the readings, checked with CRC-8 (polynomial 0x31). No model byte: the length the CRC covers,
// filler bytes and plausible values tell the models apart.
//
//   LTV-TH2/TH2i/TH3  ID ID ID FL TT TH HH CC               CRC over 8, init 0x00, 0xAC or 0xB2
//   LTV-R1            ID ID ID FL R1 AA R0 CC               CRC over 8; rain = R1:R0 ticks of 0.25 mm
//   LTV-W1/W2         ID ID ID FL AA AA AA WW WA AA CC      CRC over 11; wind = WWW (0.1 km/h)
//   LTV-WR1           ID ID ID FL WW WD DD R1 RA AA CC      CRC over 11; rain R1 not understood
//   LTV-WSDTH01       ID ID ID FL TT TH HH WW WD DD CC      CRC over 11
// TTT: temperature, 0.1 °C + 40 °C. HHH: humidity %. WWW: wind, 0.1 km/h. DDD: direction, degrees.
// FL: bit 7 battery low, bits 3-1 sequence number.
//
// La Crosse IT+ (TX35DTH-IT, 9.579 kbit/s, sync 0xAAAA2DD4): see decodeItPlus.
//
// La Crosse TX22U-IT, TX31U-IT (8.62 kbit/s, sync 0xAAAA2DD4):
//   AI IF [QQ QQ] x N CC      A: 0xA; I..I: 6-bit ID; F: bit 4 no wind/rain sensor, bit 3 battery
//                             low, bits 2-0 N (1-5); CRC-8 over the rest. Each QQQQ: a type nibble,
//                             then 12 bits: 0 temperature (BCD, 0.1 °C + 40), 1 humidity (BCD),
//                             2 rain (tips of 0.518 mm), 3 direction (16ths) and wind (0.1 m/s),
//                             4 gust (0.1 m/s; bit 8 set: the sensor isn't connected)
//
// ThermoPro TX-7B (108 µs bits in rtl_433's notes: 9.26 kbit/s, sync 0xD2552DD4):
//   II BC TT TH HH AA 55 AA CC  B: bit 7 battery low, bits 5-4 channel - 1; TTT temperature, 0.1 °C
//                               + 40; HH humidity; CC an LFSR digest (generator 0x98, key 0x25)

#include "FineOffset.h"
#include <string.h>

namespace wxsensor {

static bool decodeView(const uint8_t* b, int len, Reading* r);

static uint8_t crc8i(const uint8_t* b, int n, uint8_t init) { return crc8(b, n, init); }

// ThermoPro's digest: the bytes from last to first, each bit from the top, the key shifted right
static uint8_t tpDigest(const uint8_t* b, int n) {
  uint8_t sum = 0, key = 0x25;
  for (int k = n - 1; k >= 0; k--) {
    for (int i = 7; i >= 0; i--) {
      if ((b[k] >> i) & 1) sum ^= key;
      key = (key & 1) ? (uint8_t)((key >> 1) ^ 0x98) : (uint8_t)(key >> 1);
    }
  }
  return sum;
}

static bool tx7b(const uint8_t* b, int len, Reading* r) {
  if (len < 9 || b[5] != 0xAA || b[6] != 0x55 || b[7] != 0xAA || tpDigest(b, 8) != b[8]) return false;
  uint16_t temp = (uint16_t)b[2] << 4 | b[3] >> 4;
  if (temp > 400 + 700 || b[4] > 100) return false;
  memset(r, 0, sizeof(*r));
  r->model = TP_TX7B;
  r->id = b[0];
  r->channel = (uint8_t)(((b[1] >> 4) & 0x03) + 1);
  r->battery_low = (b[1] & 0x80) != 0;
  r->temp_c10 = (int16_t)temp - 400;
  r->humidity = b[4];
  r->have = HAVE_TEMP | HAVE_HUM | HAVE_BATTERY;
  return true;
}

static int bcd3(const uint8_t* p) {   // the 12 bits after a type nibble, as 3 BCD digits; -1 if not BCD
  int a = p[0] & 0x0F, b = p[1] >> 4, c = p[1] & 0x0F;
  return a > 9 || b > 9 || c > 9 ? -1 : a * 100 + b * 10 + c;
}

static bool tx22u(const uint8_t* b, int len, Reading* r) {
  if (len < 5 || (b[0] >> 4) != 0x0A) return false;
  int n = b[1] & 0x07;
  if (n < 1 || n > 5 || len < 3 + 2 * n || crc8(b, 3 + 2 * n) != 0) return false;
  memset(r, 0, sizeof(*r));
  r->model = TX22U;
  r->weak = true;
  r->id = (uint32_t)(b[0] & 0x0F) << 2 | b[1] >> 6;
  r->battery_low = (b[1] & 0x08) != 0;
  r->have = HAVE_BATTERY;
  bool no_ext = (b[1] & 0x10) != 0;
  for (int i = 0; i < n; i++) {
    const uint8_t* q = &b[2 + 2 * i];
    int v = bcd3(q);
    switch (q[0] >> 4) {
      case 0:
        if (v < 0 || v > 400 + 700) return false;
        r->temp_c10 = (int16_t)(v - 400);
        r->have |= HAVE_TEMP;
        break;
      case 1:
        if (v < 0 || v > 100) return false;
        r->humidity = (uint8_t)v;
        r->have |= HAVE_HUM;
        break;
      case 2:
        if (!no_ext) { r->rain_um = (uint32_t)((q[0] & 0x0F) << 8 | q[1]) * 518; r->have |= HAVE_RAIN; }
        break;
      case 3:
        if (!no_ext) {
          r->wind_dir = (uint16_t)((q[0] & 0x0F) * 225 / 10);
          r->wind_dms = q[1];
          r->have |= HAVE_WIND | HAVE_DIR;
        }
        break;
      case 4:
        if (!no_ext && !(q[0] & 0x01)) { r->gust_dms = q[1]; r->have |= HAVE_GUST; }
        break;
      default:
        return false;   // types are 0-4: anything else is a coincidental CRC
    }
  }
  return true;
}

static uint16_t hi12(const uint8_t* p) { return (uint16_t)p[0] << 4 | p[1] >> 4; }   // p[0], top of p[1]
static uint16_t lo12(const uint8_t* p) { return (uint16_t)(p[0] & 0x0F) << 8 | p[1]; } // bottom of p[0], p[1]

static uint16_t kmh10ToDms(uint16_t kmh10) { return (uint16_t)((kmh10 * 10u + 18) / 36); }

bool decodeLaCrosse(const uint8_t* b, int len, Reading* r, uint8_t proto) {
  if (!b || !r || len < 5) return false;
  switch (proto) {
    case PROTO_LACROSSE: case PROTO_LTV_SLOW: case PROTO_LTV_W1: return len >= 8 && decodeView(b, len, r);
    case PROTO_ITPLUS: return decodeItPlus(b, len, TX35IT, r);
    case PROTO_TX22U: return tx22u(b, len, r);
    case PROTO_TX7B: return tx7b(b, len, r);
    default: return false;
  }
}

bool decodeView(const uint8_t* b, int len, Reading* r) {
  memset(r, 0, sizeof(*r));
  r->id = (uint32_t)b[0] << 16 | (uint32_t)b[1] << 8 | b[2];
  r->battery_low = (b[3] & 0x80) != 0;
  r->have = HAVE_BATTERY;

  // an 8-byte packet followed by zeros checks out over 11 bytes too: CRC-8 of a block that checks
  // out stays 0 with zeros after it
  bool eight_then_zeros = len >= 11 && crc8i(b, 8, 0) == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0;
  if (len >= 11 && crc8i(b, 11, 0) == 0 && !eight_then_zeros) {
    if (b[4] == 0xAA && b[5] == 0xAA && b[6] == 0xAA && (b[8] & 0x0F) == 0x0A && b[9] == 0xAA) {
      r->model = LTV_W1;
      r->wind_dms = kmh10ToDms(hi12(&b[7]));
      r->have |= HAVE_WIND;
      return true;
    }
    if ((b[8] & 0x0F) == 0x0A && b[9] == 0xAA) {   // the WR1: its second rain field is always filler
      uint16_t wind = hi12(&b[4]), dir = lo12(&b[5]);
      if (wind > 2000 || dir > 360) return false;
      r->model = LTV_WR1;
      r->wind_dms = kmh10ToDms(wind);
      r->wind_dir = dir % 360;
      r->have |= HAVE_WIND | HAVE_DIR;
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
    // LTV-R3 also checks over 11 bytes; its rain fields aren't understood yet
  }

  bool th = crc8i(b, 8, 0) == 0, th2 = crc8i(b, 8, 0xAC) == 0 || crc8i(b, 8, 0xB2) == 0;
  // byte 5: a TH packet has the top of the humidity in its low half, always 0 (humidity <= 100); an
  // R1 packet has the rain count's high byte XOR 0xAA there, 0xA or 0xB for any real count
  if (th && (b[5] & 0x0F) != 0 && (uint8_t)(b[5] ^ 0xAA) < 0x10) {
    r->model = LTV_R1;
    r->weak = true;
    uint32_t ticks = (uint32_t)(b[5] ^ 0xAA) << 16 | (uint32_t)b[4] << 8 | b[6];
    r->rain_um = ticks * 250;
    r->have |= HAVE_RAIN;
    return true;
  }
  if (th || th2) {
    uint16_t temp = hi12(&b[4]), hum = lo12(&b[5]);
    if (temp > 400 + 700 || hum > 100) return false;   // -40..70 °C, 0..100 %
    r->model = LTV_TH;
    r->weak = true;
    r->temp_c10 = (int16_t)temp - 400;
    r->humidity = (uint8_t)hum;
    r->have |= HAVE_TEMP | HAVE_HUM;
    return true;
  }
  return false;
}

}  // namespace wxsensor
