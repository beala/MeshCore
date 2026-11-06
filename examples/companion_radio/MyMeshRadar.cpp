// Radar sweep detector (docs/radar.md): 'radar' listens on 1030 MHz, where ground radars
// interrogate aircraft transponders, and works out how fast the radars around turn from the
// bursts of pulses heard each time a beam points this way (src/helpers/aircraft/RadarSweep.*).
// Receive only. The radio does nothing else meanwhile, like 'air scan on'.

#include "MyMesh.h"
#include <helpers/aircraft/RadarSweep.h>

#define RADAR_MAX_S   90
static uint8_t radar_bins[RADAR_MAX_S * 1000 / radar::BIN_MS];   // pulses per 10 ms

// thresh: dB over the noise (> 0), or a fixed level in dBm (< 0); 0 = the radio's default
static mesh::Radio::FskListen pulseListen(float freq, int thresh) {
  mesh::Radio::FskListen cfg = {};
  cfg.modem = mesh::Radio::MODEM_PULSE;
  cfg.freq = freq;
  cfg.rxbw_khz = 3076.0f;   // 0.8 µs pulses
  cfg.pkt_len = 1;
  if (thresh > 0) cfg.thresh_db = (uint8_t) thresh;
  else if (thresh < 0) cfg.thresh_dbm = (int8_t) thresh;
  return cfg;
}

void MyMesh::radarReport() {
  int nbins = (int)(_radar_secs * 1000 / radar::BIN_MS);
  radar::Burst b[radar::MAX_BURSTS];
  int nb = radar::findBursts(radar_bins, nbins, b);
  radar::Period p[3];
  int np = radar::findPeriods(b, nb, (float)_radar_secs, p, 3);
  int m = snprintf(_radar_result, sizeof(_radar_result), "Radar, %.0f MHz, %u s: %lu pulses, %d bursts. ",
                   _radar_freq, _radar_secs, (unsigned long)_radar_pulses, nb);
  if (np == 0) {
    snprintf(&_radar_result[m], sizeof(_radar_result) - m, "No sweep found; a window or outdoors helps.");
  } else {
    for (int i = 0; i < np && m < (int) sizeof(_radar_result); i++) {
      int slots = (int)(_radar_secs / p[i].seconds);
      m += snprintf(&_radar_result[m], sizeof(_radar_result) - m, "%sone turning every %.2f s (heard %d of %d turns)",
                    i ? "; " : "", p[i].seconds, (int)(p[i].hits * slots + 0.5f), slots);
    }
    if (m < (int) sizeof(_radar_result)) snprintf(&_radar_result[m], sizeof(_radar_result) - m, ".");
  }
  consoleNote(_radar_result);
}

void MyMesh::radarLoop() {
  if (!_radar_active) return;
  uint32_t now = millis();
  uint8_t buf[8];
  float rssi = 0;
  int nbins = (int)(_radar_secs * 1000 / radar::BIN_MS);
  for (int k = 0; k < 16; k++) {
    int len = _radio->recvFsk(buf, sizeof(buf), &rssi);
    if (len <= 0) break;
    if (len != 4) continue;
    uint32_t t;
    memcpy(&t, buf, 4);
    uint32_t i = (t - _radar_start) / radar::BIN_MS;
    if (i < (uint32_t) nbins && radar_bins[i] < 255) radar_bins[i]++;
    _radar_pulses++;
  }
  int st = _radio->fskListenState();
  if ((int32_t)(now - _radar_end) >= 0) {
    _radio->stopFskListen();
    _radar_active = false;
    drainFsk();
    resumeListens();
    radarReport();
    return;
  }
  if (_radar_listening && st == 0) _radar_listening = false;   // cut short (a transmit)
  if (!_radar_listening && st == 0) {
    if (_radio->startFskListen(pulseListen(_radar_freq, _radar_thresh), _radar_end - now)) {
      _radar_listening = true;
    }
  }
}

bool MyMesh::handleRadarCommand(const char* command, char* reply) {
  if (strcmp(command, "get radar") == 0) {
    if (_radar_active) sprintf(reply, "> listening: %lu pulses so far, %lu s to go", (unsigned long)_radar_pulses,
                               (unsigned long)((_radar_end - millis()) / 1000));
    else if (_radar_result[0]) sprintf(reply, "> %s", _radar_result);   // 150 at most: fits
    else strcpy(reply, "> no result yet: 'radar' listens for a minute");
    return true;
  }
  if (strcmp(command, "get radar.bursts") == 0) {   // the last listen's bursts, seconds from its start
    int nbins = (int)(_radar_secs * 1000 / radar::BIN_MS);
    radar::Burst b[radar::MAX_BURSTS];
    int nb = _radar_secs ? radar::findBursts(radar_bins, nbins, b) : 0;
    int m = sprintf(reply, "> %d:", nb);
    for (int i = 0; i < nb && m < 150; i++) m += snprintf(&reply[m], 160 - m, " %.1f", b[i].t);
    return true;
  }
  if (strcmp(command, "radar stop") == 0) {
    if (_radar_active) { _radar_end = millis(); strcpy(reply, "OK - stopping; the result shows here"); }
    else strcpy(reply, "OK - not listening");
    return true;
  }
  if (strcmp(command, "radar") != 0 && strncmp(command, "radar ", 6) != 0) return false;
  // radar [seconds] [threshold: dB over the noise, or -dBm] [MHz]
  // default threshold: 1 dB over the noise. From a basement 30 km from the nearest radar, its pulses
  // are only a dB or two over the noise; the bursts still stand out over the noise's own triggers
  long secs = 60, th = 1, mhz = 1030;
  if (command[5]) sscanf(&command[6], "%ld %ld %ld", &secs, &th, &mhz);
  if (secs < 20 || secs > RADAR_MAX_S || th < -127 || th > 40 || th == 0 || mhz < 150 || mhz > 1100) {
    sprintf(reply, "Error: radar [20-%d s] [threshold: 1-40 dB over the noise, or -dBm] [MHz]", RADAR_MAX_S);
    return true;
  }
  if (_radar_active) { strcpy(reply, "Error: already listening ('get radar', 'radar stop')"); return true; }
  if (listensBusy(reply)) return true;
  // probe: only radios that can listen away from the mesh
  if (!_radio->startFskListen(pulseListen((float) mhz, 0), 1)) {
    strcpy(reply, "Error: this radio can't listen for radar (needs an LR2021)");
    return true;
  }
  _radio->stopFskListen();
  const char* paused = _prefs.mt.en ? " Meshtastic" : _prefs.wx.en ? " Weather" : _prefs.air.en ? " Aircraft" : "";
  pauseListens();
  memset(radar_bins, 0, sizeof(radar_bins));
  _radar_secs = (uint16_t) secs;
  _radar_thresh = (int8_t) th;
  _radar_freq = (float) mhz;
  _radar_pulses = 0;
  _radar_start = millis();
  _radar_end = _radar_start + (uint32_t) secs * 1000;
  _radar_active = true;
  _radar_listening = false;
  _radar_result[0] = 0;
  sprintf(reply, "OK - listening on %ld MHz for %ld s; the mesh%s%s can't be heard meanwhile. The result shows here", mhz, secs,
          paused[0] ? " and" : "", paused);
  return true;
}
