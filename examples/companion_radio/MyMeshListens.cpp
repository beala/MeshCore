// One listen at a time. Meshtastic (the on-chip scanner), weather, aircraft and airport weather (short FSK/OOK
// listens away from the mesh) each cost the mesh some of its receive time; together they cost too
// much, and they got in each other's way. So turning one on turns the others off, and 'radar' and
// copying a radio, which need the radio to themselves, pause whichever is on until they finish.

#include "MyMesh.h"

static void addName(char* out, size_t n, const char* name) {
  size_t m = strlen(out);
  if (m < n) snprintf(&out[m], n - m, "%s%s", m ? " and " : "", name);
}

void MyMesh::listenOthersOff(uint8_t keep, char* off, size_t n) {
  off[0] = 0;   // first the names, eg. "Meshtastic and Weather"
  if (!(keep & LISTEN_MT) && _prefs.mt.en) {
    _prefs.mt.en = 0;
    applyMeshtastic();
    applyRadioPrefs();   // removing the scanner restarts the radio
    addName(off, n, "Meshtastic");
  }
  if (!(keep & LISTEN_WX) && _prefs.wx.en) {
    _prefs.wx.en = 0;
    applyWeather();
    addName(off, n, "Weather");
  }
  if (!(keep & LISTEN_AIR) && _prefs.air.en) {
    _prefs.air.en = 0;
    applyAircraft();
    addName(off, n, "Aircraft");
  }
  if (!(keep & LISTEN_METAR) && _prefs.metar.en) {
    _prefs.metar.en = 0;
    applyMetar();
    addName(off, n, "Airport weather");
  }
  if (!(keep & LISTEN_METERS) && _prefs.meter.en) {
    _prefs.meter.en = 0;
    applyMeters();
    addName(off, n, "Meters");
  }
  drainFsk();   // packets the last listen left queued belong to the one turned off
  if (off[0]) {   // as a note for the reply: " (Weather off: one at a time)"
    char names[40];
    StrHelper::strncpy(names, off, sizeof(names));
    snprintf(off, n, " (%s off: one at a time)", names);
  }
}

void MyMesh::drainFsk() {
  uint8_t buf[64];
  while (_radio->recvFsk(buf, sizeof(buf), NULL) > 0) { }
}

bool MyMesh::listensBusy(char* reply) const {
  if (!_listens_paused) return false;
  strcpy(reply, _xfer_on ? "Error: busy copying this radio; try again when it's done"
                         : "Error: busy listening for radar; try again when it's done ('radar stop')");
  return true;
}

void MyMesh::pauseListens() {
  if (_listens_paused) return;
  _listens_paused = true;
  _radio->stopFskListen();
  _wx_win_open = false;   // the window is lost, not missed: don't count it against the sensor
  _air_listening = false;
  _metar_listening = false;
  _meter_listening = false;
  drainFsk();
  if (_mt_active && _radio->isSideListening()) {
    _radio->stopSideListen();   // Semtech's patch back in the chip while the radio is busy elsewhere
    applyRadioPrefs();
  }
}

void MyMesh::resumeListens() {
  if (!_listens_paused) return;
  _listens_paused = false;
  if (_mt_active) {
    applyMeshtastic();
    applyRadioPrefs();
  }
}
