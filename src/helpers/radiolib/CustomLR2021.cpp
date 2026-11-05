#ifdef USE_LR2021

#include "CustomLR2021.h"
#include "lr20xx_pram_lr2021.h"
#include "lr2021_scan_blob.h"

// PRAM write window, from Semtech's LR20xx driver (LR20XX_PRAM_BASE_ADDRESS).
// RadioLib has the same value in LR2021_registers.h, which LR2021.h doesn't include.
#define PRAM_BASE_ADDR    0x801000
// WriteRegMem32 takes at most 32 words per call, as in Semtech's lr20xx_patch_load_pram()
#define PRAM_BLOCK_WORDS  32

// Uploads Semtech's patch image to PRAM and activates it, following
// lr20xx_pram_load_pram_lr2021() from Semtech's LR20xx driver, then checks
// that the chip reports it as loaded.
int16_t CustomLR2021::loadPram() {
  for (uint32_t i = 0; i < pram_lr2021_size; i += PRAM_BLOCK_WORDS) {
    size_t len = pram_lr2021_size - i;
    if (len > PRAM_BLOCK_WORDS) len = PRAM_BLOCK_WORDS;
    int16_t state = writeRegMem32(PRAM_BASE_ADDR + i * 4, &pram_lr2021[i], len);
    if (state != RADIOLIB_ERR_NONE) return state;
  }

  int16_t state = activatePram();
  if (state != RADIOLIB_ERR_NONE) return state;

  bool loaded = false;
  state = checkPramLoaded(&loaded);
  if (state != RADIOLIB_ERR_NONE) return state;
  if (!loaded) return RADIOLIB_ERR_UNKNOWN;

  return getPramVersion(&_pram_version);
}

// ---- On-chip scanner (tools/lr2021_scan/scan.c) ----

#define SCAN_TABLE_ADDR  0x807800   // channel table in the chip's RAM, 3 words per channel
#define SCAN_ENTRY       1          // ActivatePram entry of the scanner
#define SCAN_HELLO       2          // entry that answers "MCS1"
#define SCAN_CAD_SYMBOLS 2
#define SCAN_WAIT_SYMS   8          // after a CAD detection, how long to wait for a preamble
#define SCAN_CAD_FLAGS   0x18       // preamble-only detection, fast CAD (docs/pram-scanner.md in lr2021-re-public)

// CAD detect peaks for a 2-symbol CAD, SF5..SF12 (Semtech datasheet table, as used by the scanner bench)
static const uint8_t SCAN_PEAK_2SYM[8] = { 56, 56, 56, 58, 58, 60, 64, 68 };

int16_t CustomLR2021::loadScanBlob() {
  for (uint32_t i = 0; i < lr2021_scan_blob_words; i += PRAM_BLOCK_WORDS) {
    size_t len = lr2021_scan_blob_words - i;
    if (len > PRAM_BLOCK_WORDS) len = PRAM_BLOCK_WORDS;
    int16_t state = writeRegMem32(PRAM_BASE_ADDR + i * 4, &lr2021_scan_blob[i], len);
    if (state != RADIOLIB_ERR_NONE) return state;
  }
  int16_t state = activatePram();
  if (state != RADIOLIB_ERR_NONE) return state;

  uint8_t req[1] = { SCAN_HELLO };
  uint8_t rsp[4] = { 0 };
  state = SPIcommand(RADIOLIB_LR2021_CMD_ACTIVATE_PRAM, false, rsp, sizeof(rsp), req, sizeof(req));
  if (state != RADIOLIB_ERR_NONE) return state;
  if (memcmp(rsp, "MCS1", 4) != 0) return RADIOLIB_ERR_UNKNOWN;
  _pram_version = 0;
  return RADIOLIB_ERR_NONE;
}

bool CustomLR2021::bwCode(float bw, uint8_t* code) {
  static const struct { float khz; uint8_t code; } table[] = {
    { 31.25f, RADIOLIB_LR2021_LORA_BW_31 }, { 41.67f, RADIOLIB_LR2021_LORA_BW_41 },
    { 62.5f, RADIOLIB_LR2021_LORA_BW_62 }, { 83.34f, RADIOLIB_LR2021_LORA_BW_83 },
    { 101.56f, RADIOLIB_LR2021_LORA_BW_101 }, { 125.0f, RADIOLIB_LR2021_LORA_BW_125 },
    { 203.13f, RADIOLIB_LR2021_LORA_BW_203 }, { 250.0f, RADIOLIB_LR2021_LORA_BW_250 },
    { 500.0f, RADIOLIB_LR2021_LORA_BW_500 },
  };
  for (auto& t : table) {
    if (fabsf(bw - t.khz) < 0.1f) { *code = t.code; return true; }
  }
  return false;
}

static void scanTableEntry(uint32_t* w, float freqMHz, uint8_t sf, uint8_t bw_code, uint8_t cr_code, bool ldro,
                           uint16_t preamble, uint8_t sync) {
  w[0] = (uint32_t)(freqMHz * 1000000.0f + 0.5f);
  uint8_t mod0 = (uint8_t)((sf << 4) | (bw_code & 0x0F));
  uint8_t mod1 = (uint8_t)((cr_code << 4) | (ldro ? 1 : 0));
  uint8_t peak = SCAN_PEAK_2SYM[(sf >= 5 && sf <= 12) ? sf - 5 : 2];
  uint8_t pre = preamble > 255 ? 255 : (uint8_t)preamble;
  w[1] = mod0 | (mod1 << 8) | ((uint32_t)peak << 16) | ((uint32_t)pre << 24);
  // raw sync symbols: each nibble doubled, as SetLoraSyncword does (0x12 -> 2, 4)
  uint8_t s1 = (uint8_t)((sync >> 4) * 2), s2 = (uint8_t)((sync & 0x0F) * 2);
  w[2] = s1 | (s2 << 8);
}

int16_t CustomLR2021::scanCmd(const uint8_t* req, size_t req_len, ScanStatus* st) {
  uint8_t rsp[40] = { 0 };
  int16_t state = SPIcommand(RADIOLIB_LR2021_CMD_ACTIVATE_PRAM, false, rsp, sizeof(rsp), req, req_len);
  if (state != RADIOLIB_ERR_NONE || !st) return state;
  uint32_t v[10];
  for (int i = 0; i < 10; i++) {
    v[i] = rsp[4 * i] | (rsp[4 * i + 1] << 8) | (rsp[4 * i + 2] << 16) | ((uint32_t)rsp[4 * i + 3] << 24);
  }
  st->state = v[0] & 0xFF;
  st->last_hit = (v[0] >> 8) & 0xFF;
  st->channel = (v[0] >> 16) & 0xFF;
  st->hooked = (v[0] >> 24) != 0;
  st->cads = v[1]; st->falses = v[2]; st->lost = v[3]; st->packets = v[4]; st->rounds = v[5];
  st->events = v[6]; st->packets_main = v[7]; st->packets_other = v[8]; st->irq = v[9];
  return state;
}

int16_t CustomLR2021::scanStart() {
  if (_scan_running) scanStop();
  int16_t state = LR2021::standby();
  if (state != RADIOLIB_ERR_NONE) return state;
  this->mod->setRfSwitchState(Module::MODE_RX);

  // channel 0 is MeshCore, from RadioLib's cached settings; then the extra channels
  uint32_t words[3 * (1 + SCAN_MAX_EXTRA)];
  scanTableEntry(&words[0], freqMHz, spreadingFactor, bandwidth, codingRate, ldrOptimize, preambleLengthLoRa, _sync_word);
  for (uint8_t i = 0; i < _scan_extra_n; i++) {
    const ScanChannel& c = _scan_extra[i];
    uint8_t code = RADIOLIB_LR2021_LORA_BW_125;
    bwCode(c.bwKHz, &code);
    bool ldro = (float)(1UL << c.sf) / c.bwKHz >= 16.0f;
    scanTableEntry(&words[3 * (i + 1)], c.freqMHz, c.sf, code, c.cr - 4, ldro, c.preamble, c.sync);
  }
  uint8_t n = 1 + _scan_extra_n;
  state = writeRegMem32(SCAN_TABLE_ADDR, words, 3 * n);
  if (state != RADIOLIB_ERR_NONE) return state;

  // the synthesizer keeps running between hops; a detected preamble stops the RX timeout
  state = setRxTxFallbackMode(RADIOLIB_LR2021_FALLBACK_MODE_FS);
  if (state != RADIOLIB_ERR_NONE) return state;
  uint8_t on = 1;
  state = SPIcommand(RADIOLIB_LR2021_CMD_STOP_TIMEOUT_ON_PREAMBLE, true, &on, 1);
  if (state != RADIOLIB_ERR_NONE) return state;
  state = setDioIrqConfig(irqDioNum, RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_CRC_ERROR);
  if (state != RADIOLIB_ERR_NONE) return state;
  state = clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
  if (state != RADIOLIB_ERR_NONE) return state;

  uint8_t req[] = { SCAN_ENTRY, 1, n, SCAN_CAD_SYMBOLS, SCAN_WAIT_SYMS, SCAN_CAD_FLAGS };
  ScanStatus st;
  state = scanCmd(req, sizeof(req), &st);
  if (state == RADIOLIB_ERR_NONE) _scan_running = true;
  return state;
}

int16_t CustomLR2021::scanResume(uint8_t* hit) {
  uint8_t req[] = { SCAN_ENTRY, 3 };
  ScanStatus st;
  int16_t state = scanCmd(req, sizeof(req), &st);
  if (hit) *hit = st.last_hit;
  return state;
}

void CustomLR2021::addScanTotals(const ScanStatus& st) {
  _scan_totals.cads += st.cads; _scan_totals.falses += st.falses; _scan_totals.lost += st.lost;
  _scan_totals.packets += st.packets; _scan_totals.rounds += st.rounds; _scan_totals.events += st.events;
  _scan_totals.packets_main += st.packets_main; _scan_totals.packets_other += st.packets_other;
}

int16_t CustomLR2021::scanStop() {
  uint8_t req[] = { SCAN_ENTRY, 0 };
  ScanStatus st;
  int16_t state = scanCmd(req, sizeof(req), &st);
  if (state == RADIOLIB_ERR_NONE) addScanTotals(st);
  _scan_running = false;
  setRxTxFallbackMode(RADIOLIB_LR2021_FALLBACK_MODE_STBY_RC);   // RadioLib's setting
  uint8_t off = 0;
  SPIcommand(RADIOLIB_LR2021_CMD_STOP_TIMEOUT_ON_PREAMBLE, true, &off, 1);
  return state;
}

int16_t CustomLR2021::scanGetStatus(ScanStatus* st) {
  int16_t state = RADIOLIB_ERR_NONE;
  ScanStatus now = {};
  if (_scan_running) {
    uint8_t req[] = { SCAN_ENTRY, 2 };
    state = scanCmd(req, sizeof(req), &now);
    if (state != RADIOLIB_ERR_NONE) return state;
  }
  *st = now;
  st->cads += _scan_totals.cads; st->falses += _scan_totals.falses; st->lost += _scan_totals.lost;
  st->packets += _scan_totals.packets; st->rounds += _scan_totals.rounds; st->events += _scan_totals.events;
  st->packets_main += _scan_totals.packets_main; st->packets_other += _scan_totals.packets_other;
  return state;
}

// ---- FSK listen ----

static uint8_t gfskRxBwCode(float khz) {
  static const struct { float khz; uint8_t code; } table[] = {
    { 38.5f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_38_5 }, { 59.5f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_59_5 },
    { 76.9f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_76_9 }, { 92.6f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_92_6 },
    { 119.0f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_119_0 }, { 153.8f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_153_8 },
    { 185.2f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_185_2 }, { 238.1f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_238_1 },
    { 307.7f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_307_7 }, { 476.2f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_476_2 },
    { 769.2f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_769_2 }, { 1111.0f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_1111 },
    { 2222.0f, RADIOLIB_LR2021_GFSK_OOK_RX_BW_2222 },
  };
  for (auto& t : table) {
    if (khz <= t.khz + 0.05f) return t.code;   // the narrowest setting that is wide enough
  }
  return RADIOLIB_LR2021_GFSK_OOK_RX_BW_2222;
}

static uint16_t feCode(float mhz) {
  uint16_t fe = (uint16_t)((mhz / 4.0f) + 0.5f);
  return fe | ((mhz > RADIOLIB_LR2021_LF_CUTOFF_FREQ) ? RADIOLIB_LR2021_CALIBRATE_FE_HF_PATH : RADIOLIB_LR2021_CALIBRATE_FE_LF_PATH);
}

// Calibrates the front end for the mesh frequency, the FSK listen frequency and the scanner's first
// extra channel (Meshtastic), once per change of any of them. Runs in standby, in LoRa packet type.
int16_t CustomLR2021::calibrateFor(float fskMHz) {
  if (fskMHz == _cal_fsk_mhz && freqMHz == _cal_mesh_mhz) return RADIOLIB_ERR_NONE;
  uint16_t f[3] = { feCode(freqMHz), feCode(fskMHz), feCode(_scan_extra_n ? _scan_extra[0].freqMHz : freqMHz) };
  uint8_t buff[6] = { (uint8_t)(f[0] >> 8), (uint8_t)f[0], (uint8_t)(f[1] >> 8), (uint8_t)f[1], (uint8_t)(f[2] >> 8), (uint8_t)f[2] };
  int16_t state = SPIcommand(RADIOLIB_LR2021_CMD_CALIB_FRONT_END, true, buff, sizeof(buff));
  if (state == RADIOLIB_ERR_NONE) { _cal_fsk_mhz = fskMHz; _cal_mesh_mhz = freqMHz; }
  return state;
}

int16_t CustomLR2021::fskStart(float fMHz, float kbps, float devKHz, float rxbwKHz,
                               const uint8_t* sync, uint8_t syncLen, uint8_t pktLen, uint8_t syncBits, bool noPreamble,
                               uint8_t preDetBits) {
  if (syncLen == 0 || syncLen > RADIOLIB_LR2021_GFSK_SYNC_WORD_LEN || pktLen == 0) return RADIOLIB_ERR_INVALID_SYNC_WORD;
  int16_t state = standby();   // stops a scan or an earlier listen
  if (state != RADIOLIB_ERR_NONE) return state;
  state = calibrateFor(fMHz);  // in LoRa packet type: calibrating in other types can miscalibrate
  if (state != RADIOLIB_ERR_NONE) return state;
  _fsk_active = true;          // from here on, standby()/transmit/sleep put LoRa back
  state = setPacketType(RADIOLIB_LR2021_PACKET_TYPE_GFSK);
  if (state == RADIOLIB_ERR_NONE) {
    state = setGfskModulationParams((uint32_t)(kbps * 1000.0f + 0.5f), RADIOLIB_LR2021_GFSK_BPSK_FLRC_OOK_SHAPING_NONE,
                                    gfskRxBwCode(rxbwKHz), (uint32_t)(devKHz * 1000.0f + 0.5f));
  }
  // after the modulation params: RadioLib's DC-DC workaround in setPacketType() and
  // setGfskModulationParams() retunes to its cached (mesh) frequency
  if (state == RADIOLIB_ERR_NONE) state = setRfFrequency((uint32_t)(fMHz * 1000000.0f + 0.5f));
  if (state == RADIOLIB_ERR_NONE) {
    state = setGfskPacketParams(32, preDetBits ? preDetBits : (noPreamble ? 0 : 16), false, false, RADIOLIB_LR2021_GFSK_OOK_ADDR_FILT_DISABLED,
                                RADIOLIB_LR2021_GFSK_OOK_PACKET_FORMAT_FIXED, pktLen, RADIOLIB_LR2021_GFSK_OOK_CRC_OFF, 0);
  }
  if (state == RADIOLIB_ERR_NONE) {
    // SetGfskSyncword: 8 bytes, the sync word right-aligned (its last bit in the last byte), then
    // MSB-first flag and the length in bits
    uint8_t buff[9] = { 0 };
    memcpy(&buff[RADIOLIB_LR2021_GFSK_SYNC_WORD_LEN - syncLen], sync, syncLen);
    uint8_t bits = syncBits ? syncBits : (uint8_t)(syncLen * 8);
    buff[8] = 0x80 | (bits & 0x7F);
    state = SPIcommand(RADIOLIB_LR2021_CMD_SET_GFSK_SYNCWORD, true, buff, sizeof(buff));
  }
  if (state == RADIOLIB_ERR_NONE) state = setDioIrqConfig(irqDioNum, RADIOLIB_LR2021_IRQ_RX_DONE);
  if (state == RADIOLIB_ERR_NONE) {
    this->mod->setRfSwitchState(Module::MODE_RX);
    state = fskRearm();
  }
  if (state != RADIOLIB_ERR_NONE) fskStopInternal();
  return state;
}

int16_t CustomLR2021::fskRearm() {
  int16_t state = clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
  if (state == RADIOLIB_ERR_NONE) state = clearRxFifo();
  if (state == RADIOLIB_ERR_NONE) state = setRx(RADIOLIB_LR2021_RX_TIMEOUT_INF);
  return state;
}

int16_t CustomLR2021::fskRead(uint8_t* buf, uint8_t len, float* rssi) {
  if (!_fsk_active) return RADIOLIB_ERR_WRONG_MODEM;
  uint32_t irq = getIrqStatus();
  if (!(irq & RADIOLIB_LR2021_IRQ_RX_DONE)) return RADIOLIB_ERR_RX_TIMEOUT;
  float rssiSync = 0;
  getGfskPacketStatus(NULL, NULL, &rssiSync, NULL, NULL, NULL);
  if (rssi) *rssi = rssiSync;
  return readRadioRxFifo(buf, len);
}

int16_t CustomLR2021::fskStopInternal() {
  _fsk_active = false;
  uint16_t rx = 0, crc = 0, len = 0, pre = 0, sok = 0, sfail = 0, to = 0;
  if (getGfskRxStats(&rx, &crc, &len, &pre, &sok, &sfail, &to) == RADIOLIB_ERR_NONE) {
    _fsk_stats_raw.packets += rx; _fsk_stats_raw.len_err += len; _fsk_stats_raw.preambles += pre;
    _fsk_stats_raw.sync_ok += sok; _fsk_stats_raw.sync_fail += sfail;
  }
  int16_t state = LR2021::standby();
  // LoRa again, with RadioLib's cached MeshCore settings
  if (state == RADIOLIB_ERR_NONE) state = setPacketType(RADIOLIB_LR2021_PACKET_TYPE_LORA);
  if (state == RADIOLIB_ERR_NONE) state = setRfFrequency((uint32_t)(freqMHz * 1000000.0f + 0.5f));
  if (state == RADIOLIB_ERR_NONE) state = setSpreadingFactor(spreadingFactor);   // all modulation params
  if (state == RADIOLIB_ERR_NONE) state = setPreambleLength(preambleLengthLoRa);  // all packet params
  if (state == RADIOLIB_ERR_NONE) state = LR2021::setSyncWord(_sync_word);
  clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
  return state;
}

#endif
