#pragma once
// METAR (and SPECI) reports in plain words: "52°F, humidity 41%. Few clouds at 8,000 ft. Wind W
// 14 mph, gusts 23. Visibility 10+ mi. Pressure 30.02 inHg." (docs/airport_weather.md).
// Reads the main body (up to RMK) as the FAA and WMO formats write it, and the remarks' T group
// (temperature in tenths). Groups it doesn't know are skipped. No allocation.

#include <stdint.h>
#include <stddef.h>

namespace metar {

struct Layer {
  uint8_t cover;      // COVER_*
  uint16_t ft;        // height above the ground, feet
  uint8_t cloud;      // 0, CLOUD_CB (cumulonimbus: thunderstorm clouds), CLOUD_TCU (towering cumulus)
};
enum { COVER_FEW = 1, COVER_SCT, COVER_BKN, COVER_OVC, COVER_VV };
enum { CLOUD_CB = 1, CLOUD_TCU = 2 };

struct Report {
  char kind[6];         // METAR, SPECI
  char station[5];
  bool has_time;
  uint8_t day, hour, minute;   // UTC
  bool has_wind, calm, variable;
  uint16_t wind_deg;
  uint16_t wind_kt, gust_kt;   // gust 0 = none
  bool has_vis, vis_less, vis_more;
  uint16_t vis_m;               // metres (statute miles converted)
  bool vis_in_miles;            // as reported: miles (US) or metres
  bool cavok;                   // "ceiling and visibility OK"
  bool clear;                   // SKC, CLR, NSC, NCD
  uint8_t n_layers;
  Layer layers[4];
  uint8_t n_wx;
  char wx[3][10];               // weather groups as sent, eg. "-RA", "+TSRA", "BR"
  bool has_temp, has_dew;
  int16_t temp_c10, dew_c10;    // tenths of a degree C
  bool has_pressure;
  uint16_t pressure_hpa10;      // tenths of a hPa (inHg converted)
  bool pressure_in_inhg;        // as reported: inches (A) or hPa (Q)
};

// Parses a report's text (eg. "METAR KLMO 052153Z 31012KT 10SM FEW080 12/M01 A3002 RMK ..."). Returns
// false if it isn't a METAR or SPECI, or nothing in it could be read.
bool parse(const char* text, int len, Report* r);

// The report in words, without the station or time. us: °F, mph, miles, inHg (else °C, km/h, km,
// hPa). Returns the length; out is always 0-terminated.
int describe(const Report& r, bool us, char* out, int n);

// One weather group in words: "-RA" "light rain", "+TSRA" "thunderstorm with heavy rain", "VCSH"
// "showers nearby", "BR" "mist". Returns false for a group that isn't weather.
bool weatherWords(const char* group, char* out, int n);

}  // namespace metar
