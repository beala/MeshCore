#pragma once
// Decoder for Fine Offset weather sensors (also sold as Ecowitt, Ambient Weather, Froggit, Misol and
// others). In the US they send FSK at 915 MHz, about 17.24 kbit/s, preamble 0xAA.., sync word 0x2DD4,
// then a packet whose first byte is a family code. Every family is checked the same way: CRC-8
// (polynomial 0x31, init 0) over all but the last byte comes out 0, and the last byte is the sum of
// the bytes before it. Written from the published protocol descriptions; no code was copied.
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
  MODEL_COUNT
};

const char* modelName(uint8_t model);

// Fields a packet carried (Reading::have)
enum : uint16_t {
  HAVE_TEMP = 1 << 0, HAVE_HUM = 1 << 1, HAVE_WIND = 1 << 2, HAVE_GUST = 1 << 3, HAVE_DIR = 1 << 4,
  HAVE_RAIN = 1 << 5, HAVE_UV = 1 << 6, HAVE_LIGHT = 1 << 7, HAVE_PRESSURE = 1 << 8,
  HAVE_LIGHTNING = 1 << 9, HAVE_MOISTURE = 1 << 10, HAVE_PM = 1 << 11, HAVE_CO2 = 1 << 12,
  HAVE_BATTERY = 1 << 13, HAVE_RAINING = 1 << 14,
};

struct Reading {
  uint8_t model;
  uint8_t channel;          // WH31: 1-8, else 0
  uint32_t id;              // sensor ID (changes when the batteries are replaced on most models)
  uint16_t have;
  bool battery_low;
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
  uint16_t pm25_x10, pm10_x10;  // µg/m³ × 10
  uint16_t co2_ppm;
};

// Length of a family's packet (family code to sum byte), or 0 for an unknown family
int packetLength(uint8_t family);

// The common CRC-8/sum check
bool checkPacket(const uint8_t* b, int len);

// Decodes a packet that starts with the family code (the bytes after the 0x2DD4 sync word). buf may
// hold more bytes than the packet (the radio receives a fixed length). Returns false for unknown
// families, bad checks or too few bytes.
bool decode(const uint8_t* buf, int len, Reading* out);

// A key that identifies one sensor across packets: model and ID (and channel for WH31)
uint32_t sensorKey(const Reading& r);

// Writes a one-line summary, eg. "WS90 2b: 72.1°F 57% wind 5 mph gust 9 NW rain 0.42 in".
// metric: °C, m/s, mm, hPa; else °F, mph, inches, inHg. Returns the length written.
int format(const Reading& r, bool metric, char* out, size_t out_size);

// 16-point compass name for a direction in degrees
const char* compass(uint16_t deg);

}  // namespace wxsensor
