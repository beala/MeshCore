// Copying this radio to another one next to it (docs/clone_takeover.md): its key, contacts,
// channels, encryption policies and settings, over a fast link away from the mesh
// (src/helpers/CloneTransfer, CPace): GFSK, which the LR2021 and SX1262 share, moving to FLRC when
// both radios are LR2021s. The copy restarts as a backup of this radio (CloneCoordinator).
//
//   on the new radio:   clone receive        -> shows a 6-digit code, waits 5 minutes
//   on this radio:      clone send <code>
//   either can add 'gfsk' to keep to GFSK (eg. to test it between two LR2021s)
//
// Both radios are off the mesh while it runs (a few seconds once they've found each other).

#include "MyMesh.h"
#include <helpers/CloneTransfer.h>
#include <helpers/EntropyPool.h>
#include <new>

#define CLONE_WAIT_MS      (5UL * 60 * 1000)   // receiver: how long to wait for the sender
#ifndef CLONE_TX_DBM
  #define CLONE_TX_DBM     0                   // the radios are side by side
#endif
#ifndef CLONE_MIN_RSSI
  #define CLONE_MIN_RSSI   clonelink::MIN_RSSI // dBm: closer than this (bench builds on dummy loads: lower)
#endif
#define CLONE_GAP_US       600                 // after each frame sent: time for the receiver to re-arm (FLRC)
#define CLONE_GAP_GFSK_US  2000                // ...in GFSK, where an SX1262 on an ESP32 re-arms slower
#define CLONE_TURN_GFSK_US 10000               // GFSK: before answering a frame, time for its sender to
                                               // get back to receive (an SX1262 on an ESP32 took > 4 ms)
#define CLONE_MAX_FILE     (256UL * 1024)
#define CLONE_COMMIT_MS    1500                // receiver: answer repeats of DONE this long, then commit

// bundle file ids
enum { CF_IDENTITY = 1, CF_PREFS, CF_CONTACTS, CF_CHANNELS, CF_CRYPTO_A, CF_CRYPTO_B };
static const uint8_t CLONE_IDS[] = { CF_IDENTITY, CF_PREFS, CF_CONTACTS, CF_CHANNELS, CF_CRYPTO_A, CF_CRYPTO_B };

static clonelink::Session xfer;
static clonelink::BundleSource xfer_src;
static clonelink::BundleSink xfer_sink;
static char xfer_code[clonelink::CODE_LEN + 1];
static uint8_t xfer_identity[96];    // the identity, sent or received (kept in RAM, never in a temp file)
static int xfer_identity_len = 0;
static bool xfer_absent[8];          // receiver: the sender has none of this file
static uint32_t xfer_rx = 0, xfer_tx = 0, xfer_tx_fail = 0;   // frames, for 'clone' while it runs
static uint8_t xfer_modes = 0xFF;    // the link modes this copy may use ('gfsk': GFSK only)
static uint32_t xfer_rx_us = 0;      // when the last frame came in
#ifdef CLONE_TEST_DROP_ACK
static uint8_t xfer_test_acks = 0;
#endif

static_assert((int)clonelink::M_GFSK == (int)mesh::Radio::LINK_GFSK && (int)clonelink::M_FLRC == (int)mesh::Radio::LINK_FLRC,
              "link mode numbers");

static const char* modeName(uint8_t m) { return m == clonelink::M_FLRC ? "FLRC" : "GFSK"; }

struct CloneIo : clonelink::Io {
  MyMesh* mesh;
  bool send(const uint8_t* f, int len) override {
    if (xfer.mode() != clonelink::M_FLRC) {
      while (micros() - xfer_rx_us < CLONE_TURN_GFSK_US) { }
    }
    bool ok = mesh->_radio->linkSend(f, len);
    if (ok) xfer_tx++; else xfer_tx_fail++;
    delayMicroseconds(xfer.mode() == clonelink::M_FLRC ? CLONE_GAP_US : CLONE_GAP_GFSK_US);
    return ok;
  }
  void random(uint8_t* buf, int len) override { EntropyPool::generate(buf, len); }
  uint8_t modes() override { return (mesh->_radio->linkModes() & xfer_modes) | (1 << clonelink::M_GFSK); }
  bool setMode(uint8_t m) override { return mesh->_radio->linkSetMode(m); }
  void stalled() override { mesh->_radio->linkStalled(); }
};

// where each file lives: the identity in RAM, prefs on the main filesystem, the rest with the contacts
struct CloneFiles : clonelink::Files {
  MyMesh* mesh;
  uint8_t cur_id = 0;    // the file open for reading (sender) or writing (receiver)
  File* cur = NULL;      // in file_mem (nRF52's File has no empty constructor)
  alignas(File) uint8_t file_mem[sizeof(File)];

  static const char* name(uint8_t id) {
    switch (id) {
      case CF_PREFS: return "/prefs.json";
      case CF_CONTACTS: return "/contacts3";
      case CF_CHANNELS: return "/channels2";
      case CF_CRYPTO_A: return "/crypto_pa";
      case CF_CRYPTO_B: return "/crypto_pb";
    }
    return NULL;
  }
  static const char* tempName(uint8_t id) {
    switch (id) {
      case CF_PREFS: return "/clone_prefs";
      case CF_CONTACTS: return "/clone_contacts";
      case CF_CHANNELS: return "/clone_channels";
      case CF_CRYPTO_A: return "/clone_cpa";
      case CF_CRYPTO_B: return "/clone_cpb";
    }
    return NULL;
  }
  FILESYSTEM* fsFor(uint8_t id) const {
    return id == CF_PREFS ? mesh->_store->getPrimaryFS() : mesh->_store->getContactsFS();
  }
  void close() {
    if (cur) { cur->close(); cur->~File(); cur = NULL; }
    cur_id = 0;
  }
  bool openWith(uint8_t id, File f) {
    if (!f) return false;
    cur = new (file_mem) File(f);
    cur_id = id;
    return true;
  }

  int32_t fileSize(uint8_t id) override {
    if (id == CF_IDENTITY) return xfer_identity_len;
    const char* n = name(id);
    if (!n || !fsFor(id)->exists(n)) return -1;
    File f = mesh->_store->openRead(fsFor(id), n);
    if (!f) return -1;
    int32_t sz = (int32_t)f.size();
    f.close();
    return sz;
  }
  int fileRead(uint8_t id, uint32_t off, uint8_t* buf, int len) override {
    if (id == CF_IDENTITY) {
      if (off + len > (uint32_t)xfer_identity_len) return -1;
      memcpy(buf, &xfer_identity[off], len);
      return len;
    }
    if (cur_id != id) {
      close();
      const char* n = name(id);
      if (!n) return -1;
      if (!openWith(id, mesh->_store->openRead(fsFor(id), n))) return -1;
    }
    if (!cur->seek(off)) return -1;
    return cur->read(buf, len);
  }
  bool fileBegin(uint8_t id, int32_t size) override {
    close();
    if (id >= sizeof(xfer_absent)) return false;
    xfer_absent[id] = size < 0;
    if (id == CF_IDENTITY) {
      xfer_identity_len = 0;
      return size == 96 || size == 64;
    }
    const char* t = tempName(id);
    if (!t) return false;
    if (size < 0) return true;
    return openWith(id, mesh->_store->openWriteFile(fsFor(id), t));
  }
  bool fileWrite(uint8_t id, const uint8_t* buf, int len) override {
    if (id == CF_IDENTITY) {
      if (xfer_identity_len + len > (int)sizeof(xfer_identity)) return false;
      memcpy(&xfer_identity[xfer_identity_len], buf, len);
      xfer_identity_len += len;
      return true;
    }
    if (cur_id != id || !cur) return false;
    return cur->write(buf, len) == (size_t)len;
  }
  bool fileEnd(uint8_t id) override {
    if (cur_id == id) close();
    return true;
  }
  void removeTemps() {
    close();
    for (uint8_t id : CLONE_IDS) {
      const char* t = tempName(id);
      if (t && fsFor(id)->exists(t)) fsFor(id)->remove(t);
    }
  }
};

static CloneIo xfer_io;
static CloneFiles xfer_files;

static float linkFreq(float mesh_mhz) {
  // US band: 920 MHz, clear of the mesh (910.525), Meshtastic (906.875), the weather sensors (915) and
  // LoRaWAN (uplinks to 914.9, downlinks from 923.3). Elsewhere, the mesh's own frequency.
  if (mesh_mhz >= 902.0f && mesh_mhz <= 928.0f) return 920.0f;
  return mesh_mhz;
}

bool MyMesh::handleCloneTransferCommand(const char* command, char* reply) {
  bool recv = strncmp(command, "clone receive", 13) == 0 && (command[13] == 0 || command[13] == ' ');
  bool send = strncmp(command, "clone send", 10) == 0 && (command[10] == 0 || command[10] == ' ');
  if (_xfer_on && (strcmp(command, "clone") == 0 || strcmp(command, "get clone") == 0)) {
    static const char* st[] = { "idle", "waiting", "copying", "finishing", "done", "failed" };
    uint32_t ok = 0, bad = 0, restarts = 0;
    _radio->linkStats(&ok, &bad, &restarts);
    // reply holds 160 (MyMesh's reply_buf is 166)
    snprintf(reply, 160, "Copy %s (%s, code %s, %.1f MHz %s): %lu bytes, %lu resent, frames %lu/%lu, failed %lu, CRC %lu, restarts %lu, weakest %.0f, peer %.0f dBm",
             st[xfer.state()], _xfer_sender ? "sending" : "receiving", xfer_code, _xfer_freq, modeName(xfer.mode()),
             (unsigned long)xfer.done(), (unsigned long)xfer.resent(), (unsigned long)xfer_rx, (unsigned long)xfer_tx,
             (unsigned long)xfer_tx_fail, (unsigned long)bad, (unsigned long)restarts, xfer.weakest(), xfer.peerRssi());
    return true;
  }
  if (strcmp(command, "clone stop") == 0) {
    if (!_xfer_on) { strcpy(reply, "No copy running."); return true; }
    xfer.abort(millis());
    cloneFinish();
    strcpy(reply, "Stopped. This radio is unchanged and back on the mesh.");
    return true;
  }
  if (!recv && !send) return false;
  if (_xfer_on) { strcpy(reply, "A copy is already running ('clone stop' ends it)."); return true; }
  if (_radar_active) { strcpy(reply, "Error: the radar listen is running ('radar stop')."); return true; }
  if (_radio->linkModes() == 0) { strcpy(reply, "Error: this radio can't copy (it needs an LR2021 or SX1262)"); return true; }
  // the CPace scalars and the code come from the DRBG; nothing is collected at boot when the key is
  // just loaded, so add the hardware RNG now (as 'get entropy' does)
  if (EntropyPool::hardwareStatus() == 0) EntropyPool::addHardware();
  if (!EntropyPool::readyForKeys()) { strcpy(reply, "Error: not enough trusted randomness on this radio ('get entropy')."); return true; }

  const char* args = command + (recv ? 13 : 10);
  while (*args == ' ') args++;
  char code[16] = "";
  float mhz = 0;
  if (send) {
    int i = 0;
    while (args[i] >= '0' && args[i] <= '9' && i < 15) { code[i] = args[i]; i++; }
    code[i] = 0;
    if (i != clonelink::CODE_LEN || (args[i] != 0 && args[i] != ' ')) {
      strcpy(reply, "Usage: clone send <the 6-digit code shown by 'clone receive' on the other radio> [MHz] [gfsk]");
      return true;
    }
    args += i;
    while (*args == ' ') args++;
  }
  xfer_modes = 0xFF;
  if (strstr(args, "gfsk")) xfer_modes = 1 << clonelink::M_GFSK;
  if (*args) mhz = (float)atof(args);
  if (mhz == 0) mhz = linkFreq(_prefs.freq);
  if (mhz < 150.0f || mhz > 960.0f) { strcpy(reply, "Error: frequency out of range"); return true; }
  if ((mhz >= 162.39f && mhz <= 162.56f) || (mhz >= 977.0f && mhz <= 979.0f)) {
    strcpy(reply, "Error: that frequency isn't allowed");
    return true;
  }

  xfer_io.mesh = this;
  xfer_files.mesh = this;
  xfer_files.close();
  memset(xfer_absent, 0, sizeof(xfer_absent));

  if (send) {
    // this radio becomes the main one: the copy starts as its backup, with the same epoch
    _clone.takeover(getRTCClock()->getCurrentTime());
    saveCloneState();
    saveContacts();
    saveChannels();
    if (_crypto_save_pending && !_crypto_lost) { _crypto_save_pending = false; saveCryptoPolicies(); }
    xfer_identity_len = (int)self_id.writeTo(xfer_identity, sizeof(xfer_identity));
    if (!xfer_src.init(&xfer_files, CLONE_IDS, sizeof(CLONE_IDS))) { strcpy(reply, "Error: couldn't read this radio's files"); return true; }
  } else {
    // 6 digits, all equally likely
    const uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % 1000000u);
    uint32_t r;
    do { EntropyPool::generate((uint8_t*)&r, sizeof(r)); } while (r >= limit);
    snprintf(code, sizeof(code), "%06lu", (unsigned long)(r % 1000000u));
    xfer_files.removeTemps();
    xfer_sink.init(&xfer_files, CLONE_MAX_FILE);
  }
  strcpy(xfer_code, code);

  pauseListens();   // the link has the radio to itself: no Meshtastic scanner, no other listens
  if (!_radio->linkStart(mhz, CLONE_TX_DBM)) {
    resumeListens();
    strcpy(reply, "Error: couldn't start the radio link");
    return true;
  }
  _xfer_on = true;
  xfer_rx = xfer_tx = xfer_tx_fail = 0;
#ifdef CLONE_TEST_DROP_ACK
  xfer_test_acks = 0;
#endif
  _xfer_sender = send;
  _xfer_freq = mhz;
  _xfer_ok_at = 0;
  if (send) {
    xfer.startSend(&xfer_io, &xfer_src, xfer_code, millis());
    xfer.setMinRssi(CLONE_MIN_RSSI);
    snprintf(reply, 160, "Copying this radio (%lu KB) to the one showing %s, on %.1f MHz. The mesh pauses until it's done.",
             (unsigned long)((xfer_src.size() + 1023) / 1024), xfer_code, mhz);
  } else {
    xfer.startReceive(&xfer_io, &xfer_sink, xfer_code, millis(), CLONE_WAIT_MS);
    xfer.setMinRssi(CLONE_MIN_RSSI);
    snprintf(reply, 160, "Waiting 5 min to become a copy: its key, contacts, channels and settings replace this radio's. "
             "On the radio to copy, send: clone send %s", xfer_code);
  }
  return true;
}

void MyMesh::cloneLoop() {
  uint8_t buf[256];
  float rssi = 0;
  // while frames keep coming (a burst), stay here: the radio holds one at a time. The receiver waits
  // out the gaps between a burst's frames (~1 ms apart in FLRC, ~9-15 ms in GFSK) by time, not by count:
  // a fast loop's polls would give up long before the next frame. At most 1 s, for the rest of the loop.
  uint32_t start = millis(), last = start;
  for (;;) {
    int n = _radio->linkRecv(buf, sizeof(buf), &rssi);
    if (n > 0) {
      xfer_rx++;
      xfer_rx_us = micros();
#ifdef CLONE_TEST_DROP_ACK
      // test builds: the sender acts as if its 2nd ACK was lost on air, once
      if (_xfer_sender && buf[2] == clonelink::T_ACK && ++xfer_test_acks == 2) continue;
#endif
      xfer.onFrame(buf, n, rssi, millis());
      last = millis();
      if (millis() - start >= 1000) break;
      continue;
    }
    if (_xfer_sender || xfer.state() != clonelink::TRANSFER) break;
    // the gap between frames; and right after our ACK, the time until the next burst starts
    uint32_t gap = xfer.mode() == clonelink::M_FLRC ? 6 : 60;
    if (millis() - last >= gap || millis() - start >= 1000) break;
  }
  xfer.tick(millis());

  if (xfer.state() == clonelink::DONE_OK && !_xfer_sender) {
    if (_xfer_ok_at == 0) _xfer_ok_at = millis();
    if (millis() - _xfer_ok_at < CLONE_COMMIT_MS) return;   // answer repeats of DONE meanwhile
  }
  if (!xfer.active()) cloneFinish();
}

void MyMesh::cloneFinish() {
  if (!_xfer_on) return;
  xfer_files.close();
  _radio->linkStop();
  radio_driver.setTxPower(_prefs.tx_power_dbm);
  _xfer_on = false;
  resumeListens();
  char msg[200];
  uint32_t kb = (xfer.total() + 1023) / 1024;
  uint32_t ms = xfer.finishedAt() - xfer.startedAt();
  if (xfer.state() == clonelink::DONE_OK && _xfer_sender) {
    snprintf(msg, sizeof(msg), "Copied to the other radio: %lu KB in %lu.%lu s over %s (%lu chunks resent). It restarts as a "
             "backup of this one, which is now the main radio.", (unsigned long)kb, (unsigned long)(ms / 1000),
             (unsigned long)(ms % 1000 / 100), modeName(xfer.dataMode()), (unsigned long)xfer.resent());
    consoleNote(msg);
    sendClaim();   // in case another radio with this key is about: this one is main
  } else if (xfer.state() == clonelink::DONE_OK) {
    if (cloneCommit()) {
      delay(200);
      board.reboot();   // doesn't return
    }
    consoleNote("The copy arrived, but couldn't be saved. This radio may be partly changed: check it, or copy again.");
  } else {
    snprintf(msg, sizeof(msg), "Copy failed: %s.%s", clonelink::failText(xfer.fail()),
             _xfer_sender ? "" : " This radio is unchanged.");
    if (!_xfer_sender) xfer_files.removeTemps();
    consoleNote(msg);
  }
  memset(xfer_identity, 0, sizeof(xfer_identity));
  xfer_identity_len = 0;
  xfer.reset();
}

// receiver: the copy checked out. Replace this radio's files with it, keeping what belongs to this
// board (transmit power, receiver gains, BLE PIN, GPS) and its own clone tag; it becomes a backup.
bool MyMesh::cloneCommit() {
  if (!xfer_sink.complete() || xfer_identity_len == 0 || xfer_absent[CF_PREFS] || xfer_absent[CF_IDENTITY]) return false;
  mesh::LocalIdentity id;
  id.readFrom(xfer_identity, xfer_identity_len);

  int8_t tx = _prefs.tx_power_dbm;
  uint32_t pin = _prefs.ble_pin;
  uint8_t rxgain = _prefs.rx_boosted_gain, fem_rx = _prefs.radio_fem_rxgain, fem_tx = _prefs.radio_fem_txgain;
  uint8_t gps = _prefs.gps_enabled;
  uint32_t gps_int = _prefs.gps_interval;
  uint32_t tag = _prefs.clone.tag;

  bool ok = true;
  for (uint8_t fid : CLONE_IDS) {
    if (fid == CF_IDENTITY) continue;
    FILESYSTEM* fs = xfer_files.fsFor(fid);
    if (xfer_absent[fid]) {
      if (fs->exists(CloneFiles::name(fid))) fs->remove(CloneFiles::name(fid));
    } else {
      ok = _store->renameFile(fs, CloneFiles::tempName(fid), CloneFiles::name(fid)) && ok;
    }
  }
  if (_store->getPrimaryFS()->exists("/new_prefs")) _store->getPrimaryFS()->remove("/new_prefs");   // old format
  _store->loadPrefs(_prefs);
  _prefs.tx_power_dbm = tx;
  _prefs.ble_pin = pin;
  _prefs.rx_boosted_gain = rxgain;
  _prefs.radio_fem_rxgain = fem_rx;
  _prefs.radio_fem_txgain = fem_tx;
  _prefs.gps_enabled = gps;
  _prefs.gps_interval = gps_int;
  _prefs.clone.tag = tag;
  _prefs.clone.role = CLONE_ROLE_BACKUP;   // the sender's epoch came with its prefs
  ok = _store->savePrefs(_prefs) && ok;
  ok = _store->saveMainIdentity(id) && ok;
  return ok;
}
