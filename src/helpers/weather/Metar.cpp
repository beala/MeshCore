#include "Metar.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

namespace metar {

static bool isDigits(const char* s, int n) {
  for (int i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return false;
  return true;
}

static int num(const char* s, int n) {
  int v = 0;
  for (int i = 0; i < n; i++) v = v * 10 + (s[i] - '0');
  return v;
}

// ---- weather groups ----

struct Code { char c[3]; const char* words; };
static const Code DESCRIPTORS[] = {
  { "MI", "shallow " }, { "PR", "partial " }, { "BC", "patches of " }, { "DR", "drifting " },
  { "BL", "blowing " }, { "SH", "" }, { "TS", "" }, { "FZ", "freezing " },
};
static const Code PHENOMENA[] = {
  { "DZ", "drizzle" }, { "RA", "rain" }, { "SN", "snow" }, { "SG", "snow grains" }, { "IC", "ice crystals" },
  { "PL", "ice pellets" }, { "GR", "hail" }, { "GS", "small hail" }, { "UP", "precipitation" },
  { "BR", "mist" }, { "FG", "fog" }, { "FU", "smoke" }, { "VA", "volcanic ash" }, { "DU", "dust" },
  { "SA", "sand" }, { "HZ", "haze" }, { "PY", "spray" }, { "PO", "dust whirls" }, { "SQ", "squalls" },
  { "FC", "funnel cloud" }, { "SS", "sandstorm" }, { "DS", "dust storm" },
};

static const Code* find(const Code* t, int n, const char* p) {
  for (int i = 0; i < n; i++) if (p[0] == t[i].c[0] && p[1] == t[i].c[1]) return &t[i];
  return NULL;
}

// appends to out (k: its length so far), never past n
static void add(char* out, int n, int* k, const char* fmt, ...) {
  if (*k >= n - 1) return;
  va_list ap;
  va_start(ap, fmt);
  int w = vsnprintf(&out[*k], n - *k, fmt, ap);
  va_end(ap);
  if (w > 0) *k += w;
  if (*k > n - 1) *k = n - 1;
}

bool weatherWords(const char* g, char* out, int n) {
  if (n > 0) out[0] = 0;
  const char* p = g;
  const char* intensity = "";
  bool nearby = false;
  if (*p == '-') { intensity = "light "; p++; }
  else if (*p == '+') { intensity = "heavy "; p++; }
  else if (p[0] == 'V' && p[1] == 'C') { nearby = true; p += 2; }
  const Code* desc = NULL;
  if (p[0] && p[1]) desc = find(DESCRIPTORS, sizeof(DESCRIPTORS) / sizeof(DESCRIPTORS[0]), p);
  if (desc) p += 2;
  const Code* ph[4];
  int nph = 0;
  while (p[0] && p[1] && nph < 4) {
    const Code* c = find(PHENOMENA, sizeof(PHENOMENA) / sizeof(PHENOMENA[0]), p);
    if (!c) return false;
    ph[nph++] = c;
    p += 2;
  }
  if (*p || (!desc && !nph)) return false;   // something left over: not weather
  char what[48] = "";
  int w = 0;
  for (int i = 0; i < nph; i++) add(what, sizeof(what), &w, "%s%s", i ? " and " : "", ph[i]->words);
  if (nph == 1 && ph[0]->c[0] == 'F' && ph[0]->c[1] == 'C' && g[0] == '+') { w = 0; add(what, sizeof(what), &w, "tornado or waterspout"); intensity = ""; }
  int k = 0;
  if (desc && desc->c[0] == 'T') {          // TS: thunderstorm, with what falls
    if (nph) add(out, n, &k, "thunderstorm with %s%s", intensity, what);
    else add(out, n, &k, "%sthunderstorm", intensity);
  } else if (desc && desc->c[0] == 'S') {   // SH: showers of it
    add(out, n, &k, "%s%s%sshowers", intensity, what, nph ? " " : "");
  } else {
    add(out, n, &k, "%s%s%s", intensity, desc ? desc->words : "", what);
  }
  if (nearby) add(out, n, &k, " nearby");
  return true;
}

// ---- the report ----

static bool wind(const char* t, int n, Report* r) {
  int unit = 0;   // 1 knots, 2 m/s
  if (n > 2 && t[n - 2] == 'K' && t[n - 1] == 'T') { unit = 1; n -= 2; }
  else if (n > 3 && t[n - 3] == 'M' && t[n - 2] == 'P' && t[n - 1] == 'S') { unit = 2; n -= 3; }
  if (!unit || n < 5) return false;
  bool vrb = memcmp(t, "VRB", 3) == 0;
  if (!vrb && !isDigits(t, 3)) return false;
  int i = 3, s = i;
  while (i < n && t[i] >= '0' && t[i] <= '9') i++;
  if (i - s < 2 || i - s > 3) return false;
  int speed = num(&t[s], i - s), gust = 0;
  if (i < n) {
    if (t[i] != 'G') return false;
    int g = ++i;
    while (i < n && t[i] >= '0' && t[i] <= '9') i++;
    if (i != n || i - g < 2 || i - g > 3) return false;
    gust = num(&t[g], i - g);
  }
  if (unit == 2) { speed = (speed * 1944 + 500) / 1000; gust = (gust * 1944 + 500) / 1000; }   // m/s to knots
  r->has_wind = true;
  r->variable = vrb;
  r->wind_deg = vrb ? 0 : (uint16_t) num(t, 3);
  r->wind_kt = (uint16_t) speed;
  r->gust_kt = (uint16_t) gust;
  r->calm = speed == 0 && !vrb;
  return true;
}

static void setVisMiles(Report* r, int sixteenths, bool less, bool more) {
  r->has_vis = true;
  r->vis_in_miles = true;
  r->vis_less = less;
  r->vis_more = more || sixteenths == 160;   // 10SM: 10 miles or more (US reports stop there)
  long m = (long) sixteenths * 160934 / 1600;
  r->vis_m = (uint16_t)(m > 65535 ? 65535 : m);
}

// "10SM", "3/4SM", "M1/4SM", "P6SM"; whole: a number in the token before ("1 3/4SM"), else -1
static bool visMiles(const char* t, int n, int whole, Report* r) {
  if (n < 3 || t[n - 2] != 'S' || t[n - 1] != 'M') return false;
  n -= 2;
  bool less = false, more = false;
  if (t[0] == 'M') { less = true; t++; n--; }
  else if (t[0] == 'P') { more = true; t++; n--; }
  const char* slash = (const char*) memchr(t, '/', n);
  int sixteenths;
  if (slash) {
    int a = slash - t, b = n - a - 1;
    if (a < 1 || a > 2 || b < 1 || b > 2 || !isDigits(t, a) || !isDigits(slash + 1, b)) return false;
    int den = num(slash + 1, b);
    if (den == 0 || 16 % den) return false;
    sixteenths = num(t, a) * (16 / den) + (whole > 0 ? whole * 16 : 0);
  } else {
    if (n < 1 || n > 2 || !isDigits(t, n)) return false;
    sixteenths = num(t, n) * 16;
  }
  setVisMiles(r, sixteenths, less, more);
  return true;
}

static bool layer(const char* t, int n, Report* r) {
  static const char* COVERS[] = { "FEW", "SCT", "BKN", "OVC" };
  int cover = 0, at = 3;
  for (int i = 0; i < 4; i++) if (n >= 6 && memcmp(t, COVERS[i], 3) == 0) cover = COVER_FEW + i;
  if (!cover && n >= 5 && t[0] == 'V' && t[1] == 'V') { cover = COVER_VV; at = 2; }
  if (!cover || n < at + 3 || !isDigits(&t[at], 3)) return false;
  uint8_t cloud = 0;
  if (n == at + 5 && memcmp(&t[at + 3], "CB", 2) == 0) cloud = CLOUD_CB;
  else if (n == at + 6 && memcmp(&t[at + 3], "TCU", 3) == 0) cloud = CLOUD_TCU;
  else if (n != at + 3) return false;
  if (r->n_layers < 4) {
    Layer& l = r->layers[r->n_layers++];
    l.cover = (uint8_t) cover;
    l.ft = (uint16_t)(num(&t[at], 3) * 100);
    l.cloud = cloud;
  }
  return true;
}

// "12/M01", "M05/M08", "10/" (no dew point), "10/-01" (a minus some stations use)
static bool temps(const char* t, int n, Report* r) {
  const char* slash = (const char*) memchr(t, '/', n);
  if (!slash) return false;
  int a = slash - t, b = n - a - 1;
  auto one = [](const char* s, int len, int16_t* c10) {
    bool neg = false;
    if (len == 3 && (s[0] == 'M' || s[0] == '-')) { neg = true; s++; len--; }
    if (len != 2 || !isDigits(s, 2)) return false;
    *c10 = (int16_t)(num(s, 2) * 10 * (neg ? -1 : 1));
    return true;
  };
  int16_t tc = 0, dc = 0;
  if (!one(t, a, &tc)) return false;
  bool dew = b > 0 && one(slash + 1, b, &dc);
  if (b > 0 && !dew) return false;
  r->has_temp = true;
  r->temp_c10 = tc;
  r->has_dew = dew;
  r->dew_c10 = dc;
  return true;
}

bool parse(const char* text, int len, Report* r) {
  memset(r, 0, sizeof(*r));
  int at = 0, idx = 0, pending_whole = -1;
  bool remarks = false, found = false;
  char tok[24];
  while (at < len) {
    while (at < len && (text[at] == ' ' || text[at] == '\n')) at++;
    int s = at;
    while (at < len && text[at] != ' ' && text[at] != '\n') at++;
    int n = at - s;
    if (n == 0) break;
    if (n >= (int) sizeof(tok)) { idx++; continue; }
    memcpy(tok, &text[s], n);
    tok[n] = 0;
    while (n > 0 && tok[n - 1] == '=') tok[--n] = 0;   // the report's end mark
    int whole = pending_whole;
    pending_whole = -1;
    if (idx == 0) {
      if (strcmp(tok, "METAR") && strcmp(tok, "SPECI")) return false;
      strcpy(r->kind, tok);
    } else if (idx == 1) {
      if (n < 3 || n > 4) return false;
      memcpy(r->station, tok, n + 1);
    } else if (remarks) {
      // T01171006: temperature and dew point in tenths (1 = below zero)
      if (n == 9 && tok[0] == 'T' && isDigits(&tok[1], 8) && (tok[1] == '0' || tok[1] == '1') && (tok[5] == '0' || tok[5] == '1')) {
        r->has_temp = r->has_dew = true;
        r->temp_c10 = (int16_t)(num(&tok[2], 3) * (tok[1] == '1' ? -1 : 1));
        r->dew_c10 = (int16_t)(num(&tok[6], 3) * (tok[5] == '1' ? -1 : 1));
      }
    } else if (strcmp(tok, "RMK") == 0) {
      remarks = true;
    } else if (n == 7 && tok[6] == 'Z' && isDigits(tok, 6)) {
      r->has_time = true;
      r->day = (uint8_t) num(tok, 2);
      r->hour = (uint8_t) num(&tok[2], 2);
      r->minute = (uint8_t) num(&tok[4], 2);
    } else if (wind(tok, n, r)) {
      found = true;
    } else if (strcmp(tok, "CAVOK") == 0) {
      r->cavok = r->has_vis = r->vis_more = found = true;   // 10 km or more, no clouds below 5,000 ft
      r->vis_m = 10000;
    } else if (visMiles(tok, n, whole, r)) {
      found = true;
    } else if ((n == 1 || n == 2) && isDigits(tok, n)) {
      pending_whole = num(tok, n);   // "1" of "1 3/4SM"
    } else if (n == 4 && isDigits(tok, 4) && !r->has_vis && r->has_wind) {   // metres, 9999 = 10 km or more
      int m = num(tok, 4);
      r->has_vis = found = true;
      r->vis_in_miles = false;
      r->vis_more = m == 9999;
      r->vis_m = (uint16_t)(m == 9999 ? 10000 : m);
    } else if (!strcmp(tok, "SKC") || !strcmp(tok, "CLR") || !strcmp(tok, "NSC") || !strcmp(tok, "NCD")) {
      r->clear = found = true;
    } else if (layer(tok, n, r)) {
      found = true;
    } else if (n == 5 && (tok[0] == 'A' || tok[0] == 'Q') && isDigits(&tok[1], 4)) {
      int v = num(&tok[1], 4);
      r->has_pressure = found = true;
      r->pressure_in_inhg = tok[0] == 'A';
      long h10 = tok[0] == 'A' ? ((long) v * 338639 + 50000) / 100000 : (long) v * 10;   // inHg x100 to hPa x10
      r->pressure_hpa10 = (uint16_t)(h10 > 65535 ? 65535 : h10);
    } else if (tok[0] != 'R' && temps(tok, n, r)) {   // (R..: runway visual range, skipped)
      found = true;
    } else if (r->n_wx < 3 && n < (int) sizeof(r->wx[0])) {
      char words[2];
      if (weatherWords(tok, words, sizeof(words))) {
        memcpy(r->wx[r->n_wx++], tok, n + 1);
        found = true;
      }
    }
    idx++;
  }
  return found;
}

static const char* compass(uint16_t deg) {
  static const char* P[] = { "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW" };
  return P[((deg % 360) * 16 + 180) / 360 % 16];
}

static void thousands(char* out, int n, long v) {
  if (v >= 1000) snprintf(out, n, "%ld,%03ld", v / 1000, v % 1000);
  else snprintf(out, n, "%ld", v);
}

static long roundDiv(long a, long b) { return a >= 0 ? (a + b / 2) / b : -((-a + b / 2) / b); }

int describe(const Report& r, bool us, char* out, int n) {
  int k = 0;
  if (n > 0) out[0] = 0;
  const char* sep = "";
  // temperature, and humidity from the dew point
  if (r.has_temp) {
    long t = us ? roundDiv((long) r.temp_c10 * 9 + 1600, 50) : roundDiv(r.temp_c10, 10);
    add(out, n, &k, "%ld°%s", t, us ? "F" : "C");
    if (r.has_dew) {
      float tc = r.temp_c10 / 10.0f, dc = r.dew_c10 / 10.0f;
      float rh = 100.0f * expf(17.625f * dc / (243.04f + dc)) / expf(17.625f * tc / (243.04f + tc));
      if (rh > 100.0f) rh = 100.0f;
      add(out, n, &k, ", humidity %d%%", (int)(rh + 0.5f));
    }
    sep = ". ";
  }
  // weather, then the sky
  for (int i = 0; i < r.n_wx; i++) {
    char w[48];
    if (!weatherWords(r.wx[i], w, sizeof(w))) continue;
    if (i == 0 && w[0] >= 'a' && w[0] <= 'z') w[0] -= 32;
    add(out, n, &k, "%s%s", i ? ", " : sep, w);
    sep = ". ";
  }
  if (r.cavok) {
    add(out, n, &k, "%sNo low clouds, good visibility", sep);
    sep = ". ";
  } else if (r.clear) {
    add(out, n, &k, "%sClear sky", sep);
    sep = ". ";
  }
  static const char* COVER[] = { "", "few clouds", "scattered clouds", "mostly cloudy", "overcast", "sky hidden, can see up" };
  for (int i = 0; i < r.n_layers; i++) {
    const Layer& l = r.layers[i];
    char h[16];
    thousands(h, sizeof(h), us ? (long) l.ft : roundDiv((long) l.ft * 3048, 100000) * 10);
    char what[24];
    snprintf(what, sizeof(what), "%s", COVER[l.cover]);
    if (i == 0) what[0] -= 32;   // a new sentence
    add(out, n, &k, "%s%s %s %s %s%s", i ? ", " : sep, what, l.cover == COVER_VV ? "to" : "at", h, us ? "ft" : "m",
        l.cloud == CLOUD_CB ? " (thunderstorm clouds)" : l.cloud == CLOUD_TCU ? " (building clouds)" : "");
    sep = ". ";
  }
  // wind
  if (r.has_wind) {
    long s = us ? roundDiv((long) r.wind_kt * 115078, 100000) : roundDiv((long) r.wind_kt * 1852, 1000);
    const char* unit = us ? "mph" : "km/h";
    if (r.calm) add(out, n, &k, "%sCalm wind", sep);
    else if (r.variable) add(out, n, &k, "%sWind variable %ld %s", sep, s, unit);
    else add(out, n, &k, "%sWind %s %ld %s", sep, compass(r.wind_deg), s, unit);
    if (r.gust_kt) {
      long g = us ? roundDiv((long) r.gust_kt * 115078, 100000) : roundDiv((long) r.gust_kt * 1852, 1000);
      add(out, n, &k, ", gusts %ld", g);
    }
    sep = ". ";
  }
  // visibility
  if (r.has_vis && !r.cavok) {
    char v[48];
    if (us) {
      // in sixteenths of a mile, as reported (or from metres)
      long x = r.vis_in_miles ? roundDiv((long) r.vis_m * 1600, 160934) : roundDiv((long) r.vis_m * 16, 1609);
      if (x > 16 * 999) x = 16 * 999;
      int whole = (int)(x / 16), f = (int)(x % 16), den = 16;
      while (f && f % 2 == 0) { f /= 2; den /= 2; }
      if (whole >= 3 || !f) snprintf(v, sizeof(v), "%d", whole + (whole >= 3 && f >= den / 2 ? 1 : 0));
      else if (whole) snprintf(v, sizeof(v), "%d %d/%d", whole, f, den);
      else snprintf(v, sizeof(v), "%d/%d", f, den);
      add(out, n, &k, "%sVisibility %s%s%s mi", sep, r.vis_less ? "under " : "", v, r.vis_more ? "+" : "");
    } else {
      const char* unit = "km";
      if (r.vis_m >= 5000) snprintf(v, sizeof(v), "%ld", roundDiv(r.vis_m, 1000));
      else if (r.vis_m >= 1000) snprintf(v, sizeof(v), "%ld.%ld", (long) r.vis_m / 1000, (long)(r.vis_m % 1000) / 100);
      else { snprintf(v, sizeof(v), "%u", r.vis_m); unit = "m"; }
      add(out, n, &k, "%sVisibility %s%s%s %s", sep, r.vis_less ? "under " : "", v, r.vis_more ? "+" : "", unit);
    }
    sep = ". ";
  }
  // pressure
  if (r.has_pressure) {
    if (us) {
      long x = roundDiv((long) r.pressure_hpa10 * 100000, 338639);   // inHg x 100
      add(out, n, &k, "%sPressure %ld.%02ld inHg", sep, x / 100, x % 100);
    } else {
      add(out, n, &k, "%sPressure %ld hPa", sep, roundDiv(r.pressure_hpa10, 10));
    }
    sep = ". ";
  }
  if (k > 0) add(out, n, &k, ".");
  return k;
}

}  // namespace metar
