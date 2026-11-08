#include "FineOffset.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace wxsensor {

static const char* const NAMES[MODEL_COUNT] = {
  "?", "WH65", "WH31", "WH40", "WH57", "WS80", "WS85", "WS90", "WN34", "WH45", "WH51",
  "LTV-TH", "LTV-WSDTH", "LTV-W1", "LTV-R1",
  "WH25", "WN32B", "WH32", "WH41", "WH43", "WH46", "WH52", "WH55", "WN20", "WS68", "TX29-IT",
  "LTV-WR1", "TX35-IT", "TX22U", "TX-7B",
};

const char* protocolName(uint8_t proto) {
  static const char* const P[PROTO_COUNT] = { "Ecowitt 17.22k", "La Crosse View 9.61k", "La Crosse View 9.36k",
                                              "La Crosse IT+ 9.58k", "La Crosse TX22U 8.62k", "ThermoPro 9.26k",
                                              "Ecowitt 17.24k wide", "La Crosse View 9.33k" };
  return proto < PROTO_COUNT ? P[proto] : "?";
}

const char* modelName(uint8_t model) {
  return model < MODEL_COUNT ? NAMES[model] : "?";
}

// How each family is checked
enum Check : uint8_t {
  CHK_CRC_SUM,   // CRC-8 over all but the last byte comes out 0, the last byte is the sum
  CHK_CRC,       // CRC-8 over all comes out 0 (WH55, IT+)
  CHK_SUM_XOR,   // WH25: byte 6 the sum of 0-5, byte 7 their XOR with its halves swapped
  CHK_SUM,       // WH32, WN32B: byte 6 the sum of 0-5 (byte 7 not checked)
};

struct Layout { uint8_t len; uint8_t check; };

static Layout layoutOf(uint8_t family) {
  switch (family) {
    case 0x24: return { 17, CHK_CRC_SUM };   // WH65 (WH24, WS69, HP1000)
    case 0x30: case 0x37: return { 7, CHK_CRC_SUM };   // WH31 (E), WH31B (Ecowitt WN31)
    case 0x40: return { 9, CHK_CRC_SUM };    // WH40
    case 0x57: return { 9, CHK_CRC_SUM };    // WH57
    case 0x80: return { 18, CHK_CRC_SUM };   // WS80
    case 0x85: return { 28, CHK_CRC_SUM };   // WS85
    case 0x90: return { 32, CHK_CRC_SUM };   // WS90
    case 0x34: case 0x38: return { 9, CHK_CRC_SUM };   // WN34, WN38
    case 0x45: return { 15, CHK_CRC_SUM };   // WH45
    case 0x51: return { 14, CHK_CRC_SUM };   // WH51
    case 0x20: return { 10, CHK_CRC_SUM };   // WN20
    case 0x41: case 0x42: return { 8, CHK_CRC_SUM };   // WH0290, WH41
    case 0x43: return { 10, CHK_CRC_SUM };   // WH43
    case 0x46: return { 21, CHK_CRC_SUM };   // WH46
    case 0x52: return { 11, CHK_CRC_SUM };   // WH31E radio clock time
    case 0x55: return { 9, CHK_CRC };        // WH55
    case 0x68: return { 16, CHK_CRC_SUM };   // WS68
    case 0xA2: return { 24, CHK_CRC_SUM };   // WH52
  }
  if ((family & 0xF0) == 0xE0) return { 8, CHK_SUM };   // WH25 (and its XOR), WN32B
  if ((family & 0xF0) == 0xD0) return { 8, CHK_SUM };   // WH32
  return { 0, CHK_CRC_SUM };
}

int packetLength(uint8_t family) {
  return layoutOf(family).len;
}

bool ignoredFamily(uint8_t family) {
  return family == 0x52;
}

uint8_t crc8(const uint8_t* b, int n, uint8_t init) {
  uint8_t c = init;
  for (int i = 0; i < n; i++) {
    c ^= b[i];
    for (int k = 0; k < 8; k++) c = (c & 0x80) ? (uint8_t)((c << 1) ^ 0x31) : (uint8_t)(c << 1);
  }
  return c;
}

static uint8_t sum8(const uint8_t* b, int n) {
  uint8_t s = 0;
  for (int i = 0; i < n; i++) s += b[i];
  return s;
}

bool checkPacket(const uint8_t* b, int len) {
  if (len < 3) return false;
  return crc8(b, len - 1) == 0 && sum8(b, len - 1) == b[len - 1];
}

// WH25: the XOR of bytes 0-5, its halves swapped
static bool wh25Xor(const uint8_t* b) {
  uint8_t x = 0;
  for (int i = 0; i < 6; i++) x ^= b[i];
  return (uint8_t)(x << 4 | x >> 4) == b[7];
}

static bool checkAs(const uint8_t* b, Layout l) {
  switch (l.check) {
    case CHK_CRC: return crc8(b, l.len) == 0;
    case CHK_SUM_XOR: return sum8(b, 6) == b[6] && wh25Xor(b);
    case CHK_SUM: return sum8(b, 6) == b[6];
    default: return checkPacket(b, l.len);
  }
}

int checkedLength(const uint8_t* b, int len) {
  for (int n = 3; n <= len; n++) if (checkPacket(b, n)) return n;
  return 0;
}

int crcLength(const uint8_t* b, int len) {
  for (int n = 5; n <= len; n++) if (crc8(b, n) == 0) return n;
  return 0;
}

static bool bcdOk(uint8_t v) { return (v >> 4) <= 9 && (v & 0x0F) <= 9; }

bool decodeItPlus(const uint8_t* b, int len, uint8_t model, Reading* r) {
  if (len < 5 || (b[0] >> 4) != 9 || crc8(b, 5) != 0) return false;
  if ((b[1] & 0x0F) > 9 || !bcdOk(b[2])) return false;
  memset(r, 0, sizeof(*r));
  r->model = model;
  r->weak = true;
  r->id = (uint32_t)(b[0] & 0x0F) << 2 | b[1] >> 6;
  r->temp_c10 = (int16_t)((b[1] & 0x0F) * 100 + (b[2] >> 4) * 10 + (b[2] & 0x0F) - 400);
  r->battery_low = (b[3] & 0x80) != 0;
  r->have = HAVE_TEMP | HAVE_BATTERY;
  uint8_t hum = b[3] & 0x7F;
  if (hum == 0x7D) r->id += 0x40;            // TX25U: its second probe's temperature
  else if (hum == 0x6A) {}                    // no humidity sensor
  else if (hum <= 100) { r->humidity = hum; r->have |= HAVE_HUM; }
  else return false;
  return true;
}

static uint32_t u24(const uint8_t* p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }

// WS80/WS85/WS90: bit 7 of a 9-bit value lives in the flags byte
static uint16_t nine(uint8_t flags, uint8_t mask, uint8_t low) { return (uint16_t)((flags & mask) ? 0x100 : 0) | low; }

static void wh65(const uint8_t* b, Reading* r) {
  r->model = WH65;
  r->id = b[1];
  r->battery_low = (b[3] & 0x08) != 0;
  r->have |= HAVE_BATTERY;
  uint16_t dir = b[2] | (uint16_t)(b[3] & 0x80) << 1;
  uint16_t temp = (uint16_t)(b[3] & 0x07) << 8 | b[4];
  uint16_t wind = b[6] | (uint16_t)(b[3] & 0x10) << 4;
  if (temp != 0x7FF) { r->temp_c10 = (int16_t)temp - 400; r->have |= HAVE_TEMP; }
  if (b[5] != 0xFF) { r->humidity = b[5]; r->have |= HAVE_HUM; }
  if (dir != 0x1FF) { r->wind_dir = dir; r->have |= HAVE_DIR; }
  // WH65 units: wind is 1/8 of 0.51 m/s per count, gust 0.51 m/s per count, rain 0.254 mm per tip
  if (wind != 0x1FF) { r->wind_dms = (uint16_t)((wind * 51u + 40) / 80); r->have |= HAVE_WIND; }
  if (b[7] != 0xFF) { r->gust_dms = (uint16_t)((b[7] * 51u + 5) / 10); r->have |= HAVE_GUST; }
  r->rain_um = ((uint32_t)b[8] << 8 | b[9]) * 254;
  r->have |= HAVE_RAIN;
  uint16_t uv = (uint16_t)b[10] << 8 | b[11];
  if (uv != 0xFFFF) {
    // raw UV reading to UV index: the start of each index step
    static const uint16_t steps[] = { 433, 852, 1211, 1571, 2018, 2451, 2762, 3101, 3513, 3919, 4278, 4651 };
    uint8_t uvi = 0;
    for (uint16_t s : steps) if (uv >= s) uvi++;
    r->uv_x10 = uvi * 10;
    r->have |= HAVE_UV;
  }
  uint32_t light = u24(&b[12]);
  if (light != 0xFFFFFF) { r->light_lux = light / 10; r->have |= HAVE_LIGHT; }
}

static void wsCommonWind(uint8_t flags, uint8_t avg, uint8_t dir, uint8_t gust, Reading* r) {
  uint16_t a = nine(flags, 0x10, avg), d = nine(flags, 0x20, dir), g = nine(flags, 0x40, gust);
  if (a != 0x1FF) { r->wind_dms = a; r->have |= HAVE_WIND; }
  if (d != 0x1FF) { r->wind_dir = d; r->have |= HAVE_DIR; }
  if (g != 0x1FF) { r->gust_dms = g; r->have |= HAVE_GUST; }
}

static void ws80(const uint8_t* b, Reading* r) {   // also the first 14 bytes of WS90
  r->id = u24(&b[1]);
  uint16_t light = (uint16_t)b[4] << 8 | b[5];
  if (light != 0xFFFF) { r->light_lux = light * 10u; r->have |= HAVE_LIGHT; }
  r->battery_low = b[6] * 20 < 2400;   // 2 × AA, 1.2 V each
  r->have |= HAVE_BATTERY;
  uint16_t temp = (uint16_t)(b[7] & 0x03) << 8 | b[8];
  if (temp != 0x3FF) { r->temp_c10 = (int16_t)temp - 400; r->have |= HAVE_TEMP; }
  if (b[9] != 0xFF) { r->humidity = b[9]; r->have |= HAVE_HUM; }
  wsCommonWind(b[7], b[10], b[11], b[12], r);
  if (b[13] != 0xFF) { r->uv_x10 = b[13]; r->have |= HAVE_UV; }
}

uint32_t sensorKey(const Reading& r) {
  return (uint32_t)r.model << 24 ^ r.id ^ (uint32_t)r.channel << 21;
}

// battery bars out of 5 (6: on USB power), split over two bytes' top bits: low at 1 or 0
static bool barsLow(uint8_t hi, uint8_t lo) { return ((hi & 0x40) >> 4 | (lo & 0xC0) >> 6) <= 1; }

bool decode(const uint8_t* b, int len, Reading* r) {
  if (len < 1 || !r) return false;
  Layout l = layoutOf(b[0]);
  if (l.len == 0 || len < l.len || !checkAs(b, l) || ignoredFamily(b[0])) {
    // a La Crosse IT+ sensor (model 9, then its ID): 0x90 is also the WS90's family
    return (b[0] >> 4) == 9 && decodeItPlus(b, len, TX29IT, r);
  }
  memset(r, 0, sizeof(*r));
  if ((b[0] & 0xF0) == 0xD0 || (b[0] & 0xF0) == 0xE0) {   // 0xD_, 0xE_: WH32, WH25, WN32B
    bool wh25 = (b[0] & 0xF0) == 0xE0 && wh25Xor(b);
    r->model = (b[0] & 0xF0) == 0xD0 ? WH32 : wh25 ? WH25 : WN32B;
    r->weak = !wh25;   // a sum only
    r->id = (uint32_t)(b[0] & 0x0F) << 4 | b[1] >> 4;
    r->battery_low = (b[1] & 0x08) != 0;
    uint16_t temp = (uint16_t)(b[1] & 0x03) << 8 | b[2];
    if (temp > 400 + 700 || b[3] > 100) return false;   // -40..70 °C, 0..100 %
    r->temp_c10 = (int16_t)temp - 400;
    r->humidity = b[3];
    r->have = HAVE_TEMP | HAVE_HUM | HAVE_BATTERY;
    uint16_t p = (uint16_t)b[4] << 8 | b[5];
    if (r->model != WH32 && p != 0xFFFF && p != 0) { r->pressure_dhpa = p; r->have |= HAVE_PRESSURE; }
    return true;
  }
  switch (b[0]) {
    case 0x24:
      wh65(b, r);
      // a WS69 adds 8 bytes, with their own check: pressure, 0.01 hPa (0x1FFFF: no sensor)
      if (len >= 25 && checkPacket(b, 25)) {
        uint32_t p = (uint32_t)(b[17] & 0x01) << 16 | (uint32_t)b[18] << 8 | b[19];
        if (p < 0x1FFFF && p > 0) { r->pressure_dhpa = (uint16_t)((p + 5) / 10); r->have |= HAVE_PRESSURE; }
      }
      break;
    case 0x30:
    case 0x37: {   // WH31B / WN31: the same layout (rtl_433 ambientweather_wh31e.c)
      r->model = WH31;
      r->id = b[1];
      r->channel = ((b[2] >> 4) & 0x07) + 1;
      r->battery_low = (b[2] & 0x04) != 0;
      uint16_t temp = (uint16_t)(b[2] & 0x03) << 8 | b[3];
      r->temp_c10 = (int16_t)temp - 400;
      r->humidity = b[4];
      r->have = HAVE_TEMP | HAVE_HUM | HAVE_BATTERY;
      break;
    }
    case 0x40:
      r->model = WH40;
      r->id = (uint32_t)(b[1] & 0x0F) << 16 | (uint32_t)b[2] << 8 | b[3];
      r->battery_low = (b[4] & 0x1F) < 11;   // 0.1 V units, one AA
      r->rain_um = ((uint32_t)b[5] << 8 | b[6]) * 100;
      r->have = HAVE_RAIN | HAVE_BATTERY;
      break;
    case 0x57:
      r->model = WH57;
      r->id = (uint32_t)(b[1] & 0x0F) << 16 | (uint32_t)b[2] << 8 | b[3];
      r->strike_state = b[1] >> 4;
      r->battery_low = ((b[4] >> 1) & 0x03) == 0;
      r->strike_km = (b[5] & 0x3F) == 0x3F ? 0 : (b[5] & 0x3F);
      r->strike_count = b[6];
      r->have = HAVE_LIGHTNING | HAVE_BATTERY;
      break;
    case 0x80:
      r->model = WS80;
      ws80(b, r);
      break;
    case 0x85:
      r->model = WS85;
      r->id = u24(&b[1]);
      r->battery_low = b[4] * 20 < 2400;
      wsCommonWind(b[5], b[7], b[8], b[9], r);
      r->raining = (b[12] & 0x10) != 0;
      r->rain_um = ((uint32_t)b[15] << 8 | b[16]) * 100;
      r->have |= HAVE_RAIN | HAVE_RAINING | HAVE_BATTERY;
      break;
    case 0x90: {
      r->model = WS90;
      ws80(b, r);
      uint16_t p = (uint16_t)b[14] << 8 | b[15];
      if (p != 0x3FFF) { r->pressure_dhpa = p; r->have |= HAVE_PRESSURE; }
      r->raining = (b[16] & 0x10) != 0;
      r->rain_um = ((uint32_t)b[19] << 8 | b[20]) * 100;
      r->have |= HAVE_RAIN | HAVE_RAINING;
      break;
    }
    case 0x34: case 0x38: {
      r->model = WN34;
      r->id = u24(&b[1]);
      int16_t raw = (int16_t)((uint16_t)(b[4] & 0x0F) << 12 | (uint16_t)b[5] << 4) >> 4;   // 12-bit signed
      r->temp_c10 = (b[4] >> 4) == 4 ? raw : (int16_t)(raw - 400);   // sub type 4 (WN34D, WN38): no offset
      r->battery_low = (b[6] & 0x7F) * 20 < 1200;
      r->have = HAVE_TEMP | HAVE_BATTERY;
      break;
    }
    case 0x45: {
      r->model = WH45;
      r->id = u24(&b[1]);
      uint16_t temp = (uint16_t)(b[4] & 0x07) << 8 | b[5];
      r->temp_c10 = (int16_t)temp - 400;
      r->humidity = b[6];
      r->pm25_x10 = (uint16_t)(b[7] & 0x3F) << 8 | b[8];
      r->pm10_x10 = (uint16_t)(b[9] & 0x3F) << 8 | b[10];
      r->co2_ppm = (uint16_t)b[11] << 8 | b[12];
      r->have = HAVE_TEMP | HAVE_HUM | HAVE_PM | HAVE_PM10 | HAVE_CO2;
      break;
    }
    case 0x51:
      r->model = WH51;
      r->id = u24(&b[1]);
      r->battery_low = (b[4] & 0x1F) < 11;
      r->moisture = b[6];
      r->have = HAVE_MOISTURE | HAVE_BATTERY;
      break;
    case 0x20:
      r->model = WN20;
      r->id = (uint32_t)b[2] << 8 | b[3];
      r->battery_low = b[4] <= 90;   // 0.02 V units, 2 × AAA: 1.8 V
      r->rain_um = ((uint32_t)b[5] << 8 | b[6]) * 100;
      r->have = HAVE_RAIN | HAVE_BATTERY;
      break;
    case 0x41: case 0x42:
      r->model = WH41;
      r->id = b[1];
      r->battery_low = barsLow(b[2], b[4]);
      r->pm25_x10 = (uint16_t)(b[2] & 0x3F) << 8 | b[3];
      r->have = HAVE_PM | HAVE_BATTERY;   // its PM10 is an estimate from the PM2.5: not shown
      break;
    case 0x43:
      r->model = WH43;
      r->id = u24(&b[1]);
      r->battery_low = barsLow(b[4], b[6]);
      r->pm25_x10 = (uint16_t)(b[4] & 0x3F) << 8 | b[5];
      r->have = HAVE_PM | HAVE_BATTERY;
      break;
    case 0x46: {
      r->model = WH46;
      r->id = u24(&b[1]);
      uint16_t temp = (uint16_t)(b[4] & 0x07) << 8 | b[5];
      r->temp_c10 = (int16_t)temp - 400;
      r->humidity = b[6];
      r->battery_low = barsLow(b[7], b[9]);
      r->pm25_x10 = (uint16_t)(b[7] & 0x3F) << 8 | b[8];
      r->pm10_x10 = (uint16_t)(b[9] & 0x3F) << 8 | b[10];
      r->co2_ppm = (uint16_t)b[11] << 8 | b[12];
      r->pm1_x10 = (uint16_t)b[13] << 8 | b[14];
      r->have = HAVE_TEMP | HAVE_HUM | HAVE_PM | HAVE_PM10 | HAVE_PM1 | HAVE_CO2 | HAVE_BATTERY;
      break;
    }
    case 0x55:
      r->model = WH55;
      r->weak = true;   // CRC only
      r->channel = (uint8_t)((b[1] >> 4) + 1);
      r->id = (uint32_t)(b[1] & 0x0F) << 16 | (uint32_t)b[2] << 8 | b[3];
      r->battery_low = b[4] <= 1;   // fifths
      r->leak = (b[7] & 0x40) != 0;
      r->have = HAVE_LEAK | HAVE_BATTERY;
      break;
    case 0x68:
      r->model = WS68;
      r->id = (uint32_t)b[2] << 8 | b[3];
      if (((uint16_t)b[4] << 8 | b[5]) != 0xFFFF) { r->light_lux = ((uint32_t)b[4] << 8 | b[5]) * 10; r->have |= HAVE_LIGHT; }
      wsCommonWind(b[7], b[10], b[11], b[12], r);
      if (b[13] != 0xFF) { r->uv_x10 = b[13]; r->have |= HAVE_UV; }
      break;
    case 0xA2: {
      r->model = WH52;
      r->id = u24(&b[1]);
      uint16_t temp = (uint16_t)(b[4] & 0x1F) << 8 | b[5];
      r->temp_c10 = (int16_t)temp - 400;
      r->moisture = b[6];
      uint32_t ec = (uint32_t)(b[8] & 0x0F) << 16 | (uint32_t)b[9] << 8 | b[10];
      r->ec_us = (uint16_t)((ec * 10 + 128) / 256);   // ÷ 25.6
      r->battery_low = b[20] * 20 < 1300;   // 0.02 V units, one AA
      r->have = HAVE_TEMP | HAVE_MOISTURE | HAVE_EC | HAVE_BATTERY;
      break;
    }
  }
  return true;
}

const char* compass(uint16_t deg) {
  static const char* const P[16] = { "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
                                     "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW" };
  return P[((deg % 360) * 16 + 180) / 360 % 16];
}

// appends with snprintf, never past the end
struct Out {
  char* p; size_t size; size_t n;
  void add(const char* fmt, ...) __attribute__((format(printf, 2, 3)));
};

void Out::add(const char* fmt, ...) {
  if (n + 1 >= size) return;
  va_list ap;
  va_start(ap, fmt);
  int w = vsnprintf(p + n, size - n, fmt, ap);
  va_end(ap);
  if (w > 0) n = (n + (size_t)w < size) ? n + (size_t)w : size - 1;
}

// tenths as "12.3" (handles negatives)
static void tenths(Out& o, long v) {
  if (v < 0) { o.add("-"); v = -v; }
  o.add("%ld.%ld", v / 10, v % 10);
}

static void speed(Out& o, uint16_t dms, bool metric) {
  if (metric) tenths(o, dms);
  else o.add("%u", (unsigned)((dms * 2237u + 5000) / 10000));   // 0.1 m/s to mph
}

int format(const Reading& r, bool metric, char* buf, size_t size) {
  if (!buf || size == 0) return 0;
  buf[0] = 0;
  Out o = { buf, size, 0 };
  o.add("%s", modelName(r.model));
  if (r.model == WH31) o.add(" ch%u", r.channel);
  else o.add(" %lx", (unsigned long)r.id);
  if (r.model != WH31 && r.channel) o.add(" ch%u", r.channel);
  o.add(":");
  if (r.have & HAVE_TEMP) {
    o.add(" ");
    if (metric) { tenths(o, r.temp_c10); o.add("C"); }
    else { tenths(o, ((long)r.temp_c10 * 9 + (r.temp_c10 >= 0 ? 2 : -2)) / 5 + 320); o.add("F"); }
  }
  if (r.have & HAVE_HUM) o.add(" %u%%", r.humidity);
  if (r.have & HAVE_WIND) {
    o.add(" wind ");
    speed(o, r.wind_dms, metric);
    if (r.have & HAVE_DIR) o.add(" %s", compass(r.wind_dir));
  }
  if (r.have & HAVE_GUST) { o.add(" gust "); speed(o, r.gust_dms, metric); }
  if ((r.have & (HAVE_WIND | HAVE_GUST)) && !metric) o.add(" mph");
  else if (r.have & (HAVE_WIND | HAVE_GUST)) o.add(" m/s");
  if (r.have & HAVE_RAIN) {
    if (metric) { o.add(" rain "); tenths(o, (long)((r.rain_um + 50) / 100)); o.add("mm"); }
    else o.add(" rain %lu.%02lu in", (unsigned long)(r.rain_um / 25400), (unsigned long)((r.rain_um % 25400) * 100 / 25400));
  }
  if ((r.have & HAVE_RAINING) && r.raining) o.add(" raining");
  if (r.have & HAVE_UV) { o.add(" UV "); tenths(o, r.uv_x10); }
  if (r.have & HAVE_LIGHT) o.add(" %lu lux", (unsigned long)r.light_lux);
  if (r.have & HAVE_PRESSURE) {
    if (metric) { o.add(" "); tenths(o, r.pressure_dhpa); o.add(" hPa"); }
    else { unsigned long inhg = ((unsigned long)r.pressure_dhpa * 2953u + 5000) / 10000; o.add(" %lu.%02lu inHg", inhg / 100, inhg % 100); }
  }
  if (r.have & HAVE_LIGHTNING) {
    o.add(" %u strikes", r.strike_count);
    if (r.strike_km) {
      if (metric) o.add(", storm %u km", r.strike_km);
      else o.add(", storm %u mi", (unsigned)((r.strike_km * 62u + 50) / 100));
    }
  }
  if (r.have & HAVE_MOISTURE) o.add(" soil %u%%", r.moisture);
  if (r.have & HAVE_EC) o.add(" EC %u uS/cm", r.ec_us);
  if (r.have & HAVE_PM1) { o.add(" PM1 "); tenths(o, r.pm1_x10); }
  if (r.have & HAVE_PM) { o.add(" PM2.5 "); tenths(o, r.pm25_x10); }
  if (r.have & HAVE_PM10) { o.add(" PM10 "); tenths(o, r.pm10_x10); }
  if (r.have & HAVE_CO2) o.add(" CO2 %u ppm", r.co2_ppm);
  if (r.have & HAVE_LEAK) o.add(r.leak ? " LEAK" : " dry");
  if ((r.have & HAVE_BATTERY) && r.battery_low) o.add(" (battery low)");
  return (int)o.n;
}

}  // namespace wxsensor
