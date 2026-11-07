#pragma once

#include <RadioLib.h>
#include "MeshCore.h"

class CustomLR2021 : public LR2021 {
  friend class LR2021Ranging;   // raw RTToF commands, see LR2021Ranging.h
  uint32_t _preambleMillis = 66;
  uint32_t _maxPayloadMillis = 3934;
  uint32_t _activityAt = 0;
  bool _headerSeen = false;
  bool _rx_boosted = false;
  bool _pram_pending = false;   // load the firmware patch on the next standby() (set before begin())
  int16_t _pram_status = RADIOLIB_ERR_UNKNOWN;
  uint16_t _pram_version = 0;   // patch type (high byte) and version (low byte) read back from the chip

  int16_t loadPram();

public:
  // One extra channel the on-chip scanner listens to besides MeshCore's own (see lr2021_scan_blob.h
  // and tools/lr2021_scan/scan.c). sync is the one-byte LoRa sync word (MeshCore 0x12, Meshtastic 0x2B).
  struct ScanChannel {
    float freqMHz;
    float bwKHz;
    uint8_t sf, cr, preamble, sync;
  };
  struct ScanStatus {
    uint8_t state, last_hit, channel;
    bool hooked;
    uint32_t cads, falses, lost, packets, rounds, events, packets_main, packets_other, irq;
  };
  static const int SCAN_MAX_EXTRA = 3;
  enum { SCAN_OFF, SCAN_CAD, SCAN_WAIT, SCAN_RX, SCAN_PARK };

private:
  bool _scan_blob = false;      // load the scanner into PRAM instead of Semtech's patch
  bool _scan_loaded = false;    // the scanner answered after the last load
  bool _scan_running = false;   // started on the chip and not stopped since
  uint8_t _scan_extra_n = 0;
  ScanChannel _scan_extra[SCAN_MAX_EXTRA];
  uint8_t _sync_word = RADIOLIB_LR2021_LORA_SYNC_WORD_PRIVATE;
  ScanStatus _scan_totals = {};   // counts from scans that have ended (the chip's restart at each start)
  void addScanTotals(const ScanStatus& st);
  SPIClass* _spi = NULL;

  int16_t loadScanBlob();

  bool _fsk_active = false;     // in GFSK for an FSK listen; LoRa comes back with fskStop()
  bool _fsk_link = false;       // ...or in GFSK / FLRC for a link (linkStart)
  uint8_t _link_mode = 0;       // mesh::Radio::LINK_GFSK / LINK_FLRC
  float _link_mhz = 0;
  uint32_t _link_check_at = 0, _link_rearms = 0;
  int16_t linkConfig(uint8_t mode);
  int16_t linkPacketParams(uint8_t len);
  int16_t linkRx();
  void linkCollectStats();
  bool _fsk_ook = false;        // the listen is the OOK ADS-B receiver (adsbStart), not GFSK
  float _ook_noise = 0;         // noise level measured at the last ADS-B listen start, dBm
  // Front-end calibration covering an FSK listen frequency. The chip keeps calibrations for up to 3
  // frequencies; RadioLib only ever calibrates the mesh's. Without one, a listen a few MHz away hears nothing.
  float _cal_fsk_mhz = 0, _cal_mesh_mhz = 0;
  int16_t calibrateFor(float fskMHz);
  struct { uint32_t packets, len_err, preambles, sync_ok, sync_fail; } _fsk_stats_raw = {};
  struct { uint32_t packets, crc_err, len_err; } _ook_stats_raw = {};
  struct { uint32_t packets, crc_err, len_err; } _link_stats = {};   // the link, all time
  int16_t fskStopInternal();
  bool _fifo_big = false;             // the receive FIFO is in its 1 KB region (a long FSK listen)
  uint32_t _fifo_rx_base = 0, _fifo_rx_size = 0;   // its usual place, to put it back
  int16_t rxFifoBig(bool on);
  int16_t resetRxStats();
  int16_t ookStart(float fMHz, uint32_t bps, float rxbwKHz, uint16_t pattern, uint8_t patBits, uint8_t pktLen,
                   uint8_t crcLen, uint8_t manchester, uint8_t threshDb, uint8_t gain, int8_t threshDbm,
                   const uint8_t* sync = NULL, uint8_t syncLen = 0, uint8_t patRepeats = 0);
  int16_t scanCmd(const uint8_t* req, size_t req_len, ScanStatus* st);
  static bool bwCode(float bw, uint8_t* code);

  // Sub-GHz PA table, one entry per dBm from -9 to +22 (RADIOLIB_LR2021_PA_TABLE_LEN entries).
  // paVal is TX_POWER in 0.5 dB units.
  // +10..+22 dBm come from the Semtech LR2021/22/12 datasheet Rev 2.2 (2026-08-08), Table 7-19
  // (915 MHz reference design). Earlier revisions (1.1, 2.1: Table 7-16) list different values.
  // RadioLib's default table tops out at TX_POWER = 17.5 dBm, so output stops rising above ~14 dBm
  // (see https://github.com/jgromes/RadioLib/pull/1909).
  // -9..+9 dBm are RadioLib's defaults, because the datasheet table doesn't cover them.
  static LR2021PaTableEntry_t* semtechPaTableLf() {
    static LR2021PaTableEntry_t table[RADIOLIB_LR2021_PA_TABLE_LEN] = {
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 8 },   // -9
      { .paDutyCycle = 2, .paSlices = 2, .paVal = 1 },   // -8
      { .paDutyCycle = 2, .paSlices = 2, .paVal = 3 },   // -7
      { .paDutyCycle = 2, .paSlices = 2, .paVal = 5 },   // -6
      { .paDutyCycle = 1, .paSlices = 2, .paVal = 13 },  // -5
      { .paDutyCycle = 2, .paSlices = 1, .paVal = 13 },  // -4
      { .paDutyCycle = 2, .paSlices = 2, .paVal = 11 },  // -3
      { .paDutyCycle = 2, .paSlices = 2, .paVal = 13 },  // -2
      { .paDutyCycle = 3, .paSlices = 1, .paVal = 12 },  // -1
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 18 },  //  0
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 20 },  //  1
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 23 },  //  2
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 27 },  //  3
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 33 },  //  4
      { .paDutyCycle = 1, .paSlices = 2, .paVal = 26 },  //  5
      { .paDutyCycle = 1, .paSlices = 2, .paVal = 31 },  //  6
      { .paDutyCycle = 1, .paSlices = 3, .paVal = 27 },  //  7
      { .paDutyCycle = 1, .paSlices = 1, .paVal = 37 },  //  8
      { .paDutyCycle = 1, .paSlices = 2, .paVal = 40 },  //  9
      { .paDutyCycle = 1, .paSlices = 2, .paVal = 32 },  // 10  (TX_POWER 16)
      { .paDutyCycle = 2, .paSlices = 4, .paVal = 30 },  // 11  (TX_POWER 15)
      { .paDutyCycle = 4, .paSlices = 2, .paVal = 30 },  // 12  (TX_POWER 15)
      { .paDutyCycle = 4, .paSlices = 2, .paVal = 32 },  // 13  (TX_POWER 16)
      { .paDutyCycle = 4, .paSlices = 2, .paVal = 34 },  // 14  (TX_POWER 17)
      { .paDutyCycle = 4, .paSlices = 5, .paVal = 34 },  // 15  (TX_POWER 17)
      { .paDutyCycle = 7, .paSlices = 3, .paVal = 34 },  // 16  (TX_POWER 17)
      { .paDutyCycle = 7, .paSlices = 3, .paVal = 36 },  // 17  (TX_POWER 18)
      { .paDutyCycle = 5, .paSlices = 7, .paVal = 38 },  // 18  (TX_POWER 19)
      { .paDutyCycle = 5, .paSlices = 7, .paVal = 40 },  // 19  (TX_POWER 20)
      { .paDutyCycle = 5, .paSlices = 6, .paVal = 42 },  // 20  (TX_POWER 21)
      { .paDutyCycle = 5, .paSlices = 6, .paVal = 44 },  // 21  (TX_POWER 22)
      { .paDutyCycle = 7, .paSlices = 7, .paVal = 44 },  // 22  (TX_POWER 22)
    };
    return table;
  }

  // 2.4 GHz PA table, one entry per dBm from -19 to +12 (RADIOLIB_LR2021_PA_TABLE_LEN entries).
  // paDutyCycle is PA_HF_DUTY_CYCLE - 16 (RadioLib adds 16 back; only 16..31 are allowed).
  // paVal is TX_POWER in 0.5 dB units.
  // 0..+12 dBm come from datasheet Rev 2.2 Table 7-21 (2445 MHz reference design).
  // -19..-1 dBm are RadioLib's defaults, because the datasheet table doesn't cover them.
  static LR2021PaTableEntry_t* semtechPaTableHf() {
    #define HF_ENTRY(duty, half_dbm) { .paDutyCycle = (duty) - 16, .paSlices = RADIOLIB_LR2021_PA_LF_SLICES_UNUSED, .paVal = (half_dbm) }
    static LR2021PaTableEntry_t table[RADIOLIB_LR2021_PA_TABLE_LEN] = {
      HF_ENTRY(16, -38), HF_ENTRY(16, -36), HF_ENTRY(16, -34), HF_ENTRY(16, -32),  // -19..-16
      HF_ENTRY(16, -30), HF_ENTRY(16, -28), HF_ENTRY(16, -26), HF_ENTRY(16, -24),  // -15..-12
      HF_ENTRY(16, -22), HF_ENTRY(16, -20), HF_ENTRY(16, -18), HF_ENTRY(16, -16),  // -11..-8
      HF_ENTRY(16, -14), HF_ENTRY(16, -12), HF_ENTRY(16, -10), HF_ENTRY(16, -8),   //  -7..-4
      HF_ENTRY(16, -6),  HF_ENTRY(16, -4),  HF_ENTRY(16, -2),                      //  -3..-1
      HF_ENTRY(28, 2),   //  0  (TX_POWER 1)
      HF_ENTRY(28, 4),   //  1  (TX_POWER 2)
      HF_ENTRY(27, 6),   //  2  (TX_POWER 3)
      HF_ENTRY(27, 8),   //  3  (TX_POWER 4)
      HF_ENTRY(27, 10),  //  4  (TX_POWER 5)
      HF_ENTRY(27, 12),  //  5  (TX_POWER 6)
      HF_ENTRY(27, 14),  //  6  (TX_POWER 7)
      HF_ENTRY(27, 16),  //  7  (TX_POWER 8)
      HF_ENTRY(30, 20),  //  8  (TX_POWER 10)
      HF_ENTRY(30, 22),  //  9  (TX_POWER 11)
      HF_ENTRY(30, 24),  // 10  (TX_POWER 12)
      HF_ENTRY(27, 24),  // 11  (TX_POWER 12)
      HF_ENTRY(16, 24),  // 12  (TX_POWER 12)
    };
    #undef HF_ENTRY
    return table;
  }

  public:
    CustomLR2021(Module *mod) : LR2021(mod) {
      irqDioNum = LR2021_IRQ_DIO;
      // set before begin(), which applies the initial TX power
      setPaTable(semtechPaTableLf(), false);
      setPaTable(semtechPaTableHf(), true);
    }

    bool std_init(SPIClass* spi = NULL)
    {
      if (spi) _spi = spi;
      _scan_running = false;
      _scan_loaded = false;
      _fsk_active = false;
      _cal_fsk_mhz = 0;
      
  #ifdef LR2021_TCXO_VOLTAGE
      float tcxo = LR2021_TCXO_VOLTAGE;
  #else
      float tcxo = 1.6f;
  #endif

  #ifdef LORA_CR
      uint8_t cr = LORA_CR;
  #else
      uint8_t cr = 5;
  #endif

  #if defined(P_LORA_SCLK)
    #ifdef NRF52_PLATFORM
      if (spi) { spi->setPins(P_LORA_MISO, P_LORA_SCLK, P_LORA_MOSI); spi->begin(); }
    #elif defined(RP2040_PLATFORM)
      if (spi) {
        spi->setMISO(P_LORA_MISO);
        //spi->setCS(P_LORA_NSS); // Setting CS results in freeze
        spi->setSCK(P_LORA_SCLK);
        spi->setMOSI(P_LORA_MOSI);
        spi->begin();
      }
    #else
      if (spi) spi->begin(P_LORA_SCLK, P_LORA_MISO, P_LORA_MOSI);
    #endif
  #endif
      _pram_pending = true; _pram_status = RADIOLIB_ERR_UNKNOWN;
      int status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_LR2021_LORA_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo);
      // if radio init fails with -707/-706, try again with tcxo voltage set to 0.0f
      if (status == RADIOLIB_ERR_SPI_CMD_FAILED || status == RADIOLIB_ERR_SPI_CMD_INVALID) {
        tcxo = 0.0f;
        _pram_pending = true; _pram_status = RADIOLIB_ERR_UNKNOWN;
        status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_LR2021_LORA_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo);
      }
      _pram_pending = false;
      if (status != RADIOLIB_ERR_NONE) {
        Serial.print("ERROR: radio init failed: ");
        Serial.println(status);
        return false;  // fail
      }
    
    #ifdef LR2021_USE_SIMO
      // Power VDCC/VPAX from the SIMO DC-DC converter instead of the LDOs (chip default).
      // Needs the SIMO inductor on LXA/LXB. SetRegMode is only accepted in Standby RC.
      int16_t simoState = standby(RADIOLIB_LR2021_STANDBY_RC);
      if (simoState == RADIOLIB_ERR_NONE) simoState = setRegulatorDCDC();
      if (simoState != RADIOLIB_ERR_NONE) {
        MESH_DEBUG_PRINTLN("LR2021: switching to SIMO DC-DC failed (%d), staying on LDO", simoState);
      }
    #endif

      setCRC(2);
      explicitHeader();

      if (_scan_blob) {
        if (_scan_loaded) {
          Serial.println("LR2021 scanner loaded in place of Semtech's patch");
        } else {
          Serial.print("WARNING: LR2021 scanner not loaded: ");
          Serial.println(_pram_status);
        }
      } else if (_pram_status == RADIOLIB_ERR_NONE) {
        Serial.print("LR2021 PRAM patch loaded: type ");
        Serial.print(_pram_version >> 8);
        Serial.print(", version 0x");
        Serial.println(_pram_version & 0xFF, HEX);
      } else {
        Serial.print("WARNING: LR2021 PRAM patch not loaded: ");
        Serial.println(_pram_status);
      }

      
    #ifdef LR2021_RX_BOOSTED_GAIN
      setRxBoostedGainMode(LR2021_RX_BOOSTED_GAIN);
    #endif

    #ifdef LR2021_OCP_LF
      static_assert(LR2021_OCP_LF >= 0 && LR2021_OCP_LF <= 63, "LR2021_OCP_LF must be 0..63");
      int16_t ocpState = setOcpLf(LR2021_OCP_LF);
      if (ocpState != RADIOLIB_ERR_NONE) {
        MESH_DEBUG_PRINTLN("LR2021: setting OCP LF threshold failed (%d)", ocpState);
      }
    #endif

      return true;  // success
    }
    
    // begin() resets the chip, which clears PRAM. RadioLib calls standby() right
    // after that reset and before TCXO setup and calibration, which is where
    // Semtech's own driver loads the patch, so the load is hooked in here.
    using LR2021::standby;
    int16_t standby() override {
      if (_fsk_active) fskStopInternal();
      if (_scan_running) scanStop();
      int16_t state = LR2021::standby();
      if (_pram_pending && state == RADIOLIB_ERR_NONE) {
        _pram_pending = false;
        if (_scan_blob) {
          _pram_status = loadScanBlob();
          _scan_loaded = _pram_status == RADIOLIB_ERR_NONE;
        } else {
          _pram_status = loadPram();
        }
      }
      return state;
    }

    // RadioLib starts a transmit (and other modes) without going to standby first. While scanning,
    // the chip may be tuned to the other network or in the middle of a CAD: stop the scan, which
    // puts MeshCore's settings back, before anything is staged.
    int16_t stageMode(RadioModeType_t mode, RadioModeConfig_t* cfg) override {
      resetActivity();                      // staging clears the IRQ flags isReceiving() follows
      if (_fsk_active) fskStopInternal();   // a transmit ends an FSK listen
      if (_scan_running) {
        scanStop();
        LR2021::standby();
      }
      return LR2021::stageMode(mode, cfg);
    }

    using LR2021::sleep;
    int16_t sleep() override {
      if (_fsk_active) fskStopInternal();
      if (_scan_running) scanStop();
      return LR2021::sleep();
    }

    // ---- On-chip scanner ----
    // Choose the PRAM image for the next std_init(): the scanner, or Semtech's patch.
    void setScanBlob(bool en) { _scan_blob = en; }
    bool wantsScanBlob() const { return _scan_blob; }
    bool isScanLoaded() const { return _scan_loaded; }
    bool isScanning() const { return _scan_running; }
    SPIClass* getSPI() const { return _spi; }

    // Channels scanned after MeshCore's own (channel 0, always the current radio settings).
    // Takes effect at the next startReceive().
    bool setScanChannels(const ScanChannel* chans, uint8_t n) {
      if (n > SCAN_MAX_EXTRA) return false;
      for (uint8_t i = 0; i < n; i++) {
        uint8_t code;
        if (!bwCode(chans[i].bwKHz, &code) || chans[i].sf < 5 || chans[i].sf > 12 || chans[i].cr < 5 || chans[i].cr > 8) return false;
        _scan_extra[i] = chans[i];
      }
      _scan_extra_n = n;
      return true;
    }
    uint8_t getScanChannelCount() const { return _scan_extra_n; }

    // Starts the scan over channel 0 (MeshCore) and the extra channels. Only RxDone and CRC errors
    // reach the IRQ pin; the chip hops on its own between packets.
    int16_t scanStart();
    // After a packet has been read: carry on scanning. *hit is the channel it came in on.
    int16_t scanResume(uint8_t* hit);
    // Leaves the scan with the radio tuned to MeshCore's settings again.
    int16_t scanStop();
    // Counts since boot (all scans so far plus the running one)
    int16_t scanGetStatus(ScanStatus* st);

    float getFreqMHz() const { return freqMHz; }

    // RadioLib calibrates the front end for the new frequency only, replacing the FSK listen's
    using LR2021::setFrequency;
    int16_t setFrequency(float freq) override {
      _cal_fsk_mhz = 0;
      return LR2021::setFrequency(freq);
    }

    // ---- FSK listen (weather sensors) ----
    static const uint16_t FSK_PKT_MAX = 1000;   // the longest packet: the receive FIFO's 1 KB region
    // Leaves LoRa (and the scan) for GFSK receive with these settings, continuous, RxDone on the IRQ
    // pin. Packets are fixed length, with no CRC or whitening: the caller checks them.
    // syncBits: 0 = syncLen * 8, else the sync word is the last syncBits bits of sync[]
    // pktLen over 256 (FIS-B's 552-byte frames): the receive FIFO moves to its 1 KB region for the
    // listen (datasheet 5.3.3), so the whole frame is read after RxDone; fskStop puts it back.
    int16_t fskStart(float freqMHz, float kbps, float devKHz, float rxbwKHz,
                     const uint8_t* sync, uint8_t syncLen, uint16_t pktLen, uint8_t syncBits = 0, bool noPreamble = false,
                     uint8_t preDetBits = 0);
    // receiver counts over all FSK listens (GetGfskRxStats, read as each listen ends)
    struct FskStats { uint32_t packets, len_err, preambles, sync_ok, sync_fail; };
    FskStats fskStats() const {
      FskStats f = { _fsk_stats_raw.packets, _fsk_stats_raw.len_err, _fsk_stats_raw.preambles,
                     _fsk_stats_raw.sync_ok, _fsk_stats_raw.sync_fail };
      return f;
    }
    // ---- ADS-B listen (1090 MHz) ----
    // Same idea as fskStart, with the chip's OOK receiver set up for Mode S extended squitters as in
    // the datasheet (SetOokDetector, pattern 0x0285) and RadioLib's ADS-B example: 2 Mchip/s,
    // inverted Manchester, 11 data bytes, the 24-bit parity checked by the chip (bad ones dropped).
    // threshDb: detection threshold above the noise measured at the start (0 = 10 dB).
    // gain: fixed receiver gain step 1-13 (0 = automatic). fskRead/fskStop/fskRearm work the same.
    int16_t adsbStart(float freqMHz, float rxbwKHz, uint8_t threshDb = 0, uint8_t gain = 0, int8_t threshDbm = 0);
    // Pulses (eg. radar interrogations at 1030 MHz): every pulse above the threshold ends a 1-byte
    // packet, so each RxDone marks one; the caller just counts them. fskRearm/fskStop as above.
    int16_t pulseStart(float freqMHz, float rxbwKHz, uint8_t threshDb = 0, uint8_t gain = 0, int8_t threshDbm = 0);
    // Raw on-off keyed chips (eg. utility meters at 32768 chip/s): the detector pattern (first chip in
    // the LSB, 2-16 chips), then the sync word (1-4 bytes, sent MSB first), then pktLen bytes of chips
    // as they came (no Manchester, CRC or whitening: the caller reads them). fskRead/fskStop as above.
    int16_t ookRawStart(float freqMHz, uint32_t bps, float rxbwKHz, uint16_t pattern, uint8_t patBits,
                        const uint8_t* sync, uint8_t syncLen, uint8_t pktLen, uint8_t threshDb = 0, uint8_t gain = 0,
                        int8_t threshDbm = 0, uint8_t patRepeats = 31);
    float adsbNoise() const { return _ook_noise; }
    struct OokStats { uint32_t packets, crc_err, len_err; };
    OokStats ookStats() const {
      OokStats o = { _ook_stats_raw.packets, _ook_stats_raw.crc_err, _ook_stats_raw.len_err };
      return o;
    }
#ifdef FISB_BENCH_TX
    // Bench only (never in release builds): sends one fixed-length GFSK packet up to 1000 bytes, no
    // preamble, no CRC or whitening, as FIS-B ground stations frame theirs, then back to LoRa in
    // standby. 902-928 MHz only: never 978 MHz (an aviation band).
    int16_t benchFskTx(float freqMHz, float kbps, float devKHz, const uint8_t* sync, uint8_t syncLen, uint8_t syncBits,
                       const uint8_t* data, uint16_t len);
#endif
#ifdef FISB_BENCH_TX
    // Bench only: sends len bytes of raw on-off keyed chips (first chip in each byte's top bit), as
    // they are: no preamble, sync word or coding added. 902-928 MHz only.
    int16_t benchOokTx(float freqMHz, uint32_t bps, const uint8_t* chips, uint16_t len);
#endif
    int16_t fskRearm();                                    // receive again after a packet
    int16_t fskRead(uint8_t* buf, uint16_t len, float* rssi);
    // Back to LoRa with MeshCore's settings, in standby. The caller starts receive again.
    int16_t fskStop() { return _fsk_active ? fskStopInternal() : RADIOLIB_ERR_NONE; }
    // Point-to-point link (copying a radio). It starts in GFSK, framed as on the SX126x so either
    // chip hears the other: 250 kbps, 62.5 kHz deviation, Gaussian BT 0.5, 64-bit preamble, the
    // 32-bit sync word "MCCL", an 8-bit length, CRC-16 (CCITT, init 0x1D0F, inverted) and SX126x
    // whitening (datasheet 11.3). linkSetMode(LINK_FLRC) moves it to FLRC: 1.3 Mbps, coding rate 3/4
    // (975 kbps of data), Gaussian BT 0.5, 32-bit sync word and CRC, variable length 6..255 bytes
    // (datasheet 18). Receives until linkSend(), which transmits and receives again. fskStop() ends it.
    int16_t linkStart(float fMHz, int8_t dbm);
    int16_t linkSetMode(uint8_t mode);
    uint8_t linkMode() const { return _link_mode; }
    uint32_t linkRearms() const { return _link_rearms; }
    int16_t linkSend(const uint8_t* buf, uint8_t len, uint32_t timeoutMs);
    // > 0: a packet's length; 0: none yet; < 0: one failed its CRC
    int linkRead(uint8_t* buf, uint8_t max, float* rssi);
    bool isLinkActive() const { return _fsk_active && _fsk_link; }
    void linkStats(uint32_t* packets, uint32_t* crc_err) const { *packets = _link_stats.packets; *crc_err = _link_stats.crc_err + _link_stats.len_err; }
    bool isFskActive() const { return _fsk_active; }

    // MeshCore only sends LoRa, and asks for airtimes at any moment, including during an FSK/OOK
    // listen or the FLRC link. RadioLib answers for the chip's current packet type: 0 for OOK (the
    // Dispatcher's send timeout then cut every transmit short) and a huge number for GFSK set up
    // outside RadioLib (its send budget then held every transmit for hours). Always LoRa, from the
    // cached settings.
    RadioLibTime_t getTimeOnAir(size_t len) override {
      return LRxxxx::getToA(len, ModemType_t::RADIOLIB_MODEM_LORA);
    }
    // The chip's status word and IRQ flags, read without a command (datasheet 6.1, table 6-38), and
    // the packet type; mode: 0 sleep, 1 standby RC, 2 standby XOSC, 3 FS, 4 Rx, 5 Tx
    uint32_t chipStatus(uint8_t* mode, uint8_t* pkt) {
      uint8_t buff[6] = { 0 };
      Module::BitWidth_t w = mod->spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS];
      mod->spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_0;
      mod->SPItransferStream(NULL, 0, false, NULL, buff, sizeof(buff), true);
      mod->spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = w;
      if (mode) *mode = buff[1] & 0x07;
      if (pkt) getPacketType(pkt);
      return ((uint32_t)buff[2] << 24) | ((uint32_t)buff[3] << 16) | ((uint32_t)buff[4] << 8) | buff[5];
    }

    int16_t setRxBoostedGainMode(uint8_t level) {
      int16_t state = LR2021::setRxBoostedGainMode(level);
      if (state == RADIOLIB_ERR_NONE) _rx_boosted = level > 0;
      return state;
    }

    bool getRxBoostedGainMode() const { return _rx_boosted; }

    int16_t startReceive() override {
      if (_scan_loaded && _scan_extra_n > 0) return scanStart();
      // include the PREAMBLE_DETECTED irq bit in reported flags
      return LR2021::startReceive(RADIOLIB_LR2021_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED), RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
    }

    // isReceiving() follows one packet through the IRQ flags; when the flags are cleared (a new
    // receive or transmit, a packet read, the end of a listen), that packet is over. Without this, a
    // header seen long ago made the next packet's header look stuck, and clearing it then made
    // RadioLib reject that packet as damaged.
    void resetActivity() { _activityAt = 0; _headerSeen = false; }

    bool isReceiving() {
      uint32_t irq = getIrqStatus();
      bool preamble = irq & RADIOLIB_LR2021_IRQ_PREAMBLE_DETECTED;  // bit 5
      bool header   = irq & RADIOLIB_LR2021_IRQ_LORA_HEADER_VALID;  // bit 6
      bool hdrErr   = irq & RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR; // bit 9
      uint32_t now  = millis();
      if (hdrErr) {
        clearIrqFlags(RADIOLIB_LR2021_IRQ_PREAMBLE_DETECTED | RADIOLIB_LR2021_IRQ_LORA_HEADER_VALID | RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR);
        _activityAt = 0;
        _headerSeen = false;
        return false;
      }
      if (!header && _headerSeen) {
        // something cleared the header flag, reset our state.
        _activityAt = 0; _headerSeen = false;
        return false;
      }

      if (header) {
        if (!_headerSeen) { _headerSeen = true; _activityAt = now; };
        if (now - _activityAt > _maxPayloadMillis) {
          MESH_DEBUG_PRINTLN("Clearing header IRQ after %ums", _maxPayloadMillis);
          clearIrqFlags(RADIOLIB_LR2021_IRQ_PREAMBLE_DETECTED | RADIOLIB_LR2021_IRQ_LORA_HEADER_VALID | RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR);
          _activityAt = 0; _headerSeen = false;
          return false;
        }
        return true;
      }
      if (preamble) {
        if (_activityAt == 0) _activityAt = now;
        if (now - _activityAt > _preambleMillis) {
          clearIrqFlags(RADIOLIB_LR2021_IRQ_PREAMBLE_DETECTED);
          _activityAt = 0;
          MESH_DEBUG_PRINTLN("Clearing preamble IRQ after %ums", _preambleMillis);
          return false;
        }
        return true;
      }
      _activityAt = 0; _headerSeen = false;
      return false;
    }
    
    void setPreambleMillis(uint32_t preambleMillis) {
      _preambleMillis = preambleMillis;
      MESH_DEBUG_PRINTLN("Set _preambleMillis=%u", _preambleMillis);
    }
    void setMaxPayloadMillis(uint32_t payloadMillis) {
      _maxPayloadMillis = payloadMillis;
      MESH_DEBUG_PRINTLN("Set _maxPayloadMillis=%u", _maxPayloadMillis);
    }


    uint8_t getSpreadingFactor() const { return spreadingFactor; }

    // Full receiver reset: warm sleep to power down the analog front end, wake, recalibrate,
    // then restore what sleep loses. Warm sleep keeps RAM (command settings) but not
    // registers (datasheet 23.6), so register-based settings must be written again.
    int16_t resetAGC() {
      _cal_fsk_mhz = 0;   // the calibration below covers the mesh frequency only
      if (_fsk_active) fskStopInternal();
      if (_scan_running) scanStop();
      sleep(true, 0);
      int16_t state = standby(RADIOLIB_LR2021_STANDBY_RC, true);  // NOP pulls NSS low to wake
      if (state != RADIOLIB_ERR_NONE) return state;

      uint8_t blocks = RADIOLIB_LR2021_CALIBRATE_ALL;
      state = SPIcommand(RADIOLIB_LR2021_CMD_CALIBRATE, true, &blocks, 1);
      if (state != RADIOLIB_ERR_NONE) return state;

      // Calibrate resets image calibration to its default band, so redo the front end
      // for the operating frequency (same encoding as RadioLib's setFrequency()).
      uint16_t fe = (uint16_t)((freqMHz / 4.0f) + 0.5f);
      fe |= (freqMHz > RADIOLIB_LR2021_LF_CUTOFF_FREQ) ? RADIOLIB_LR2021_CALIBRATE_FE_HF_PATH : RADIOLIB_LR2021_CALIBRATE_FE_LF_PATH;
      uint8_t feBuff[6] = { (uint8_t)(fe >> 8), (uint8_t)fe, 0, 0, 0, 0 };
      state = SPIcommand(RADIOLIB_LR2021_CMD_CALIB_FRONT_END, true, feBuff, sizeof(feBuff));
      if (state != RADIOLIB_ERR_NONE) return state;

      // register-based settings
      state = setSpreadingFactor(spreadingFactor);  // also rewrites the SF6 legacy-mode register bit
    #ifdef LR2021_OCP_LF
      if (state == RADIOLIB_ERR_NONE) state = setOcpLf(LR2021_OCP_LF);
    #endif
      return state;
    }

    int16_t writeRegMask32(uint32_t addr, uint32_t mask, uint32_t data) {
      uint8_t buff[11] = {
        (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr,
        (uint8_t)(mask >> 24), (uint8_t)(mask >> 16), (uint8_t)(mask >> 8), (uint8_t)mask,
        (uint8_t)(data >> 24), (uint8_t)(data >> 16), (uint8_t)(data >> 8), (uint8_t)data,
      };
      return SPIcommand(RADIOLIB_LR2021_CMD_WRITE_REG_MEM_MASK_32, true, buff, sizeof(buff));
    }

    // Set the sub-GHz PA over-current protection threshold (datasheet 23.7):
    // unlock with 0xC0DE at 0xF40338, then write bits [24:19] of 0xF40300.
    // level is 0..63; the power-on default is 41 (OCPLF typ. 164 mA, Table 3-22).
    int16_t setOcpLf(uint8_t level) {
      int16_t state = writeRegMask32(0x00F40338, 0x0000FFFF, 0xC0DE);
      if (state != RADIOLIB_ERR_NONE) return state;
      return writeRegMask32(0x00F40300, 0x3FUL << 19, ((uint32_t)(level & 0x3F)) << 19);
    }

    // Reads the AGC gain step (1..13, 13 = most gain) the chip used for the last received LoRa packet.
    // GetLoraPacketStatus returns 10 bytes but the datasheet documents only the first 9; RadioLib
    // reads 6. Byte 9 holds the gain step, which the ROM latches from the AGC when the packet arrives.
    // Undocumented; found by disassembling the LR2021 ROM and confirmed with SetAgcGainManual (0x021A).
    int16_t readLastGainStep(uint8_t* step) { return readLastStatus(step, NULL, NULL); }

    // The same status, also with the packet's frequency error: how far the transmitter's carrier was
    // from ours, in Hz (bytes 6-8, signed 24-bit, datasheet 9.9.9), and the length the header gave.
    // The error comes from the sender's crystal, so it stays about the same for each radio.
    int16_t readLastStatus(uint8_t* step, int32_t* freq_err, uint8_t* len) {
      uint8_t buff[10] = { 0 };
      int16_t state = SPIcommand(RADIOLIB_LR2021_CMD_GET_LORA_PACKET_STATUS, false, buff, sizeof(buff));
      if (state != RADIOLIB_ERR_NONE) return state;
      if (step) *step = buff[9];
      if (len) *len = buff[1];
      if (freq_err) {
        int32_t v = ((int32_t)buff[6] << 16) | ((int32_t)buff[7] << 8) | buff[8];
        if (v & 0x800000) v -= 0x1000000;
        *freq_err = v;
      }
      return state;
    }
};