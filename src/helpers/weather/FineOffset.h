#pragma once
// Decoder for Fine Offset weather sensors (also sold as Ecowitt, Ambient Weather, Froggit, Misol and
// others). In the US they send FSK at 915 MHz, about 17.24 kbit/s, preamble 0xAA.., sync word 0x2DD4,
// then a packet whose first byte is a family code. Most families are checked the same way: CRC-8
// (polynomial 0x31, init 0) over all but the last byte comes out 0, and the last byte is the sum of
// the bytes before it; a few older ones have only a sum, or only the CRC. La Crosse's IT+ sensors
// (TX29-IT) share the radio format. Written from the published protocol descriptions (rtl_433's
// device notes); no code was copied.
//
// Integer only and no allocation, so it builds for the companion and for the PC tests.

#include <stdint.h>
#include <stddef.h>

namespace wxsensor {

enum Model : uint8_t {
  MODEL_NONE = 0,
  WH65,    // outdoor array: temperature, humidity, wind, rain, UV, light (Ambient WS-2902, Ecowitt WS69..)
  WH31,    // temperature/humidity, channels 1-8 (Ambient WH31E, Ecowitt WN31)
  WH40,    // rain gauge
  WH57,    // lightning detector
  WS80,    // ultrasonic wind + temperature/humidity/UV/light
  WS85,    // ultrasonic wind + piezo rain
  WS90,    // 7-in-1 array: WS80 plus piezo rain and pressure
  WN34,    // probe thermometer (soil/water); WN38 globe thermometer
  WH45,    // air quality: PM2.5, PM10, CO2, temperature, humidity
  WH51,    // soil moisture
  // La Crosse Technology View (915 MHz FSK, LaCrosse.cpp)
  LTV_TH,     // LTV-TH2, TH2i, TH3: temperature, humidity
  LTV_WSDTH,  // LTV-WSDTH01 Breeze Pro: temperature, humidity, wind, direction
  LTV_W1,     // LTV-W1, W2: wind
  LTV_R1,     // LTV-R1: rain
  // more Fine Offset (Ecowitt) families
  WH25,    // indoor temperature, humidity, pressure (also WN32P)
  WN32B,   // outdoor temperature, humidity (WH32B, WN32B: the WH25's packet without pressure)
  WH32,    // outdoor temperature, humidity (older)
  WH41,    // PM2.5 (WH0290, WH41, Ambient PM25)
  WH43,    // PM2.5, 24-bit ID
  WH46,    // air quality: PM1, PM2.5, PM10, CO2, temperature, humidity
  WH52,    // soil moisture, temperature, conductivity
  WH55,    // water leak, channels 1-4
  WN20,    // rain gauge
  WS68,    // anemometer: wind, light, UV
  TX29IT,  // La Crosse IT+ TX29-IT, TX29U-IT, TX25U-IT: temperature (and humidity), at 17.24 kbit/s
  // more on the 9.6 kbit/s listen (LaCrosse.cpp)
  LTV_WR1,    // LTV-WR1: wind, direction (its rain isn't understood yet)
  TX35IT,     // La Crosse IT+ at 9.58 kbit/s (TX35DTH-IT and others)
  TX22U,      // La Crosse TX22U-IT, TX31U-IT: temperature, humidity, wind, rain
  TP_TX7B,    // ThermoPro TX-7B: temperature, humidity, channels 1-3
  MODEL_COUNT
};

// Radio formats: each needs its own listen settings. The LR2021's FSK receiver takes a bit rate
// only within about 0.1-0.3% of its own, a frequency deviation within about 20% of its setting, and
// a sync word that starts where the preamble ends, so each group of senders is a format of its own
// (rates and deviations measured on rtl_433's recordings of real sensors).
enum Protocol : uint8_t {
  PROTO_FINEOFFSET = 0,   // 17.22 kbit/s, ±32 kHz, sync 0x2DD4: Fine Offset/Ecowitt (most)
  PROTO_LACROSSE = 1,     // 9.606 kbit/s, sync 0xD2AA2DD4: La Crosse View TH3, R1, WR1
  PROTO_LTV_SLOW = 2,     // 9.362 kbit/s, sync 0xD2AA2DD4: La Crosse View TH2, Breeze Pro
  PROTO_ITPLUS = 3,       // 9.577 kbit/s, ±20 kHz, sync 0x2DD4: La Crosse IT+ (TX35DTH-IT)
  PROTO_TX22U = 4,        // 8.624 kbit/s, sync 0x2DD4: La Crosse TX22U-IT, TX31U-IT
  PROTO_TX7B = 5,         // 9.26 kbit/s, sync 0xD2552DD4: ThermoPro TX-7B
  PROTO_FO_WIDE = 6,      // 17.235 kbit/s, ±60 kHz, sync 0x2DD4: Fine Offset WH25, La Crosse TX29-IT
  PROTO_LTV_W1 = 7,       // 9.329 kbit/s, sync 0xD2AA2DD4: La Crosse View W1
  PROTO_COUNT
};
// The formats of each brand setting ('set wx.kind'): bit masks of 1 << Protocol
static constexpr uint8_t PROTOS_ECOWITT = (1 << PROTO_FINEOFFSET) | (1 << PROTO_FO_WIDE);
static constexpr uint8_t PROTOS_LACROSSE = (1 << PROTO_LACROSSE) | (1 << PROTO_LTV_SLOW) | (1 << PROTO_ITPLUS) |
                                           (1 << PROTO_TX22U) | (1 << PROTO_TX7B) | (1 << PROTO_LTV_W1);
static_assert(PROTO_COUNT <= 8, "protocol masks are 8 bits");
const char* protocolName(uint8_t proto);

const char* modelName(uint8_t model);

// Fields a packet carried (Reading::have)
enum : uint32_t {
  HAVE_TEMP = 1 << 0, HAVE_HUM = 1 << 1, HAVE_WIND = 1 << 2, HAVE_GUST = 1 << 3, HAVE_DIR = 1 << 4,
  HAVE_RAIN = 1 << 5, HAVE_UV = 1 << 6, HAVE_LIGHT = 1 << 7, HAVE_PRESSURE = 1 << 8,
  HAVE_LIGHTNING = 1 << 9, HAVE_MOISTURE = 1 << 10, HAVE_PM = 1 << 11, HAVE_CO2 = 1 << 12,
  HAVE_BATTERY = 1 << 13, HAVE_RAINING = 1 << 14, HAVE_PM10 = 1 << 15, HAVE_PM1 = 1 << 16,
  HAVE_EC = 1 << 17, HAVE_LEAK = 1 << 18,
};

struct Reading {
  uint8_t model;
  uint8_t channel;          // WH31: 1-8; WH55: 1-4; TX-7B: 1-3; else 0
  uint32_t id;              // sensor ID (changes when the batteries are replaced on most models)
  uint32_t have;
  bool battery_low;
  bool weak;                // checked by 8 bits or fewer: take a new sensor only once heard twice
  uint8_t proto;            // the format it was heard in (Protocol)
  int16_t temp_c10;         // 0.1 °C
  uint8_t humidity;         // %
  uint16_t wind_dms;        // average wind, 0.1 m/s
  uint16_t gust_dms;        // gust, 0.1 m/s
  uint16_t wind_dir;        // degrees
  uint32_t rain_um;         // rain counter, micrometres (it only goes up; the console works out totals)
  bool raining;             // WS85/WS90: the piezo sensor is wet
  uint8_t uv_x10;           // UV index × 10
  uint32_t light_lux;
  uint16_t pressure_dhpa;   // 0.1 hPa
  uint8_t strike_count;     // WH57: lightning strikes counted since the sensor started (wraps at 255)
  uint8_t strike_km;        // WH57: distance to the storm front, km (0 = none yet)
  uint8_t strike_state;     // WH57: 8 = strike, 4 = noise, 1 = interference, 0 = reset
  uint8_t moisture;         // WH51: %
  uint16_t pm25_x10, pm10_x10;  // µg/m³ × 10 (HAVE_PM: PM2.5, HAVE_PM10)
  uint16_t pm1_x10;             // WH46: µg/m³ × 10 (HAVE_PM1)
  uint16_t co2_ppm;
  uint16_t ec_us;               // WH52: soil conductivity, µS/cm
  bool leak;                    // WH55: water detected
};

// Length of a family's packet (family code to sum byte), or 0 for an unknown family
int packetLength(uint8_t family);

// The common CRC-8/sum check
bool checkPacket(const uint8_t* b, int len);

// For packets that didn't decode, to spot models not known yet. A Fine Offset packet of an unknown
// family still ends with the CRC-8 and sum: the length (3-len) at which they check out, or 0.
int checkedLength(const uint8_t* b, int len);
// A 9.6 kbit/s packet: the shortest length (5-len) whose last byte is the CRC-8 of the ones
// before, or 0. Only 8 bits: count it only when the same one comes again.
int crcLength(const uint8_t* b, int len);
// Families known but not shown (the WH31E's radio clock packets)
bool ignoredFamily(uint8_t family);

// Decodes a packet that starts with the family code (the bytes after the 0x2DD4 sync word). buf may
// hold more bytes than the packet (the radio receives a fixed length). Returns false for unknown
// families, bad checks or too few bytes.
bool decode(const uint8_t* buf, int len, Reading* out);

// Decodes a packet heard in one of the slower formats (the bytes after its sync word): La Crosse
// View, IT+ and TX22U-IT, ThermoPro. proto picks which decoders apply.
bool decodeLaCrosse(const uint8_t* buf, int len, Reading* out, uint8_t proto = PROTO_LACROSSE);
// A La Crosse IT+ packet (5 bytes: model 9, ID, BCD temperature, humidity, CRC-8), as TX29IT or
// TX35IT. Used by both decoders.
bool decodeItPlus(const uint8_t* buf, int len, uint8_t model, Reading* out);
// CRC-8, polynomial 0x31, from init
uint8_t crc8(const uint8_t* b, int n, uint8_t init = 0);
// Any format; sets out->proto
inline bool decodeAs(uint8_t proto, const uint8_t* buf, int len, Reading* out) {
  bool fo = proto == PROTO_FINEOFFSET || proto == PROTO_FO_WIDE;
  bool ok = fo ? decode(buf, len, out) : decodeLaCrosse(buf, len, out, proto);
  if (ok) out->proto = proto;
  return ok;
}

// A key that identifies one sensor across packets: model, ID and channel
uint32_t sensorKey(const Reading& r);

// Writes a one-line summary, eg. "WS90 2b: 72.1°F 57% wind 5 mph gust 9 NW rain 0.42 in".
// metric: °C, m/s, mm, hPa; else °F, mph, inches, inHg. Returns the length written.
int format(const Reading& r, bool metric, char* out, size_t out_size);

// 16-point compass name for a direction in degrees
const char* compass(uint16_t deg);

}  // namespace wxsensor
