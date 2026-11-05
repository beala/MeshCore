#pragma once

#include "CustomLR2021.h"
#include "RadioLibWrappers.h"
#include "../RecentHistory.h"

#ifndef USE_LR2021
#define USE_LR2021
#endif

#ifndef LR2021_RX_BOOST_LEVEL
#define LR2021_RX_BOOST_LEVEL 7
#endif

class CustomLR2021Wrapper : public RadioLibWrapper {
  friend class LR2021Ranging;
public:
  struct TxFault {
    uint32_t at_millis;
    uint32_t irq;          // IRQ status after the transmit
    uint16_t chip_errors;  // error register, when the ERROR IRQ was set
  };
  static const int TX_FAULT_HISTORY = 8;

  struct RxGain {
    uint32_t at_millis;
    uint8_t gain_step;  // AGC gain step G1..G13 (13 = most gain)
    int16_t rssi;       // dBm
    int8_t snr_x4;      // dB * 4
  };
  static const int RX_GAIN_HISTORY = 8;

private:
  // IRQ bits that mean a transmit went wrong (a missing TX_DONE is also a fault)
  static constexpr uint32_t TX_FAULT_IRQS = RADIOLIB_LR2021_IRQ_EOL | RADIOLIB_LR2021_IRQ_PA_OCP_OVP |
      RADIOLIB_LR2021_IRQ_ERROR | RADIOLIB_LR2021_IRQ_CMD_ERROR | RADIOLIB_LR2021_IRQ_TIMEOUT;

  // Checks how the last transmit ended. Returns true on a fault, with the IRQ status and, when the
  // ERROR bit is set, the chip error register (which is then cleared). Must run before
  // finishTransmit(), which clears all IRQ flags.
  bool checkTxFault(uint32_t* irq_out, uint16_t* err_out) {
    CustomLR2021* radio = (CustomLR2021 *)_radio;
    uint32_t irq = radio->getIrqStatus();
    uint16_t err = 0;
    bool fault = !(irq & RADIOLIB_LR2021_IRQ_TX_DONE) || (irq & TX_FAULT_IRQS);
    if (fault && (irq & RADIOLIB_LR2021_IRQ_ERROR)) {
      // ERROR is a summary bit; the cause is in the chip's error register
      int16_t state = radio->getErrors(&err);
      if (state == RADIOLIB_ERR_NONE) {
        radio->clearErrors();
      } else {
        MESH_DEBUG_PRINTLN("LR2021:   getErrors failed (%d)", state);
      }
    }
    *irq_out = irq;
    *err_out = err;
    return fault;
  }

#ifdef MESH_DEBUG
  // Logs a TX fault: the fault IRQs, a missing TX_DONE, and the decoded chip errors.
  static void logTxFault(uint32_t irq, uint16_t err) {
    static const struct { uint32_t bit; const char* name; } irqFaults[] = {
      { RADIOLIB_LR2021_IRQ_EOL,        "EOL" },
      { RADIOLIB_LR2021_IRQ_PA_OCP_OVP, "PA_OCP_OVP" },
      { RADIOLIB_LR2021_IRQ_ERROR,      "ERROR" },
      { RADIOLIB_LR2021_IRQ_CMD_ERROR,  "CMD_ERROR" },
      { RADIOLIB_LR2021_IRQ_TIMEOUT,    "TIMEOUT" },
    };
    static const char* const errNames[16] = {
      "HF_XOSC_START", "LF_XOSC_START", "PLL_LOCK", "LF_RC_CALIB",
      "HF_RC_CALIB", "PLL_CALIB", "AAF_CALIB", "IMG_CALIB",
      "CHIP_BUSY", "RXFREQ_NO_FE_CAL", "MEAS_UNIT_ADC_CALIB", "PA_OFFSET_CALIB",
      "PPF_CALIB", "SRC_CALIB", "SRC_SATURATION_CALIB", "SRC_TOLERANCE_CALIB",
    };
    MESH_DEBUG_PRINTLN("LR2021: TX fault, irq=0x%08lX", (unsigned long)irq);
    if (!(irq & RADIOLIB_LR2021_IRQ_TX_DONE)) MESH_DEBUG_PRINTLN("LR2021:   TX_DONE not set");
    for (auto& f : irqFaults) {
      if (irq & f.bit) MESH_DEBUG_PRINTLN("LR2021:   %s", f.name);
    }
    if (err) {
      MESH_DEBUG_PRINTLN("LR2021:   chip errors=0x%04X", err);
      for (int i = 0; i < 16; i++) {
        if (err & (1u << i)) MESH_DEBUG_PRINTLN("LR2021:     %s", errNames[i]);
      }
    }
  }
#endif

  static const int REPLY_MAX = 140;  // CLI replies go into a 166 byte buffer, after an optional prefix

  // eg. "> 3 since boot: 12s OCP; 95s ERR=0004; 300s NODONE,TIMEOUT"
  void formatTxFaults(char* reply) const {
    if (_tx_faults.total() == 0) {
      strcpy(reply, "> no TX faults since boot");
      return;
    }
    int n = sprintf(reply, "> %lu since boot:", (unsigned long)_tx_faults.total());
    uint32_t now = millis();
    for (int i = 0; i < _tx_faults.count(); i++) {
      const TxFault& f = _tx_faults.get(i);
      char entry[64];
      int e = sprintf(entry, "%s %lus ", i == 0 ? "" : ";", (unsigned long)((now - f.at_millis) / 1000));
      const char* sep = "";
      if (!(f.irq & RADIOLIB_LR2021_IRQ_TX_DONE)) { e += sprintf(&entry[e], "%sNODONE", sep); sep = ","; }
      if (f.irq & RADIOLIB_LR2021_IRQ_PA_OCP_OVP) { e += sprintf(&entry[e], "%sOCP", sep); sep = ","; }
      if (f.irq & RADIOLIB_LR2021_IRQ_ERROR)      { e += sprintf(&entry[e], "%sERR=%04X", sep, f.chip_errors); sep = ","; }
      if (f.irq & RADIOLIB_LR2021_IRQ_CMD_ERROR)  { e += sprintf(&entry[e], "%sCMD", sep); sep = ","; }
      if (f.irq & RADIOLIB_LR2021_IRQ_TIMEOUT)    { e += sprintf(&entry[e], "%sTIMEOUT", sep); sep = ","; }
      if (f.irq & RADIOLIB_LR2021_IRQ_EOL)        { e += sprintf(&entry[e], "%sEOL", sep); sep = ","; }
      if (n + e > REPLY_MAX) break;
      strcpy(&reply[n], entry);
      n += e;
    }
  }

  // eg. "> G13 -112dBm -6.5dB 4s; G9 -71dBm 9.2dB 31s"
  void formatRxGains(char* reply) const {
    if (_rx_gains.count() == 0) {
      strcpy(reply, "> no packets received yet");
      return;
    }
    strcpy(reply, ">");
    int n = 1;
    uint32_t now = millis();
    for (int i = 0; i < _rx_gains.count(); i++) {
      const RxGain& g = _rx_gains.get(i);
      char entry[64];
      int e = sprintf(entry, "%s G%u %ddBm %.1fdB %lus", i == 0 ? "" : ";", g.gain_step, g.rssi,
                      g.snr_x4 / 4.0f, (unsigned long)((now - g.at_millis) / 1000));
      if (n + e > REPLY_MAX) break;
      strcpy(&reply[n], entry);
      n += e;
    }
  }

public:
  CustomLR2021Wrapper(CustomLR2021& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) override {
    auto r = (CustomLR2021 *)_radio;
    // LR2021 only accepts RF/modulation config commands while in STANDBY mode.
    // Re-configuring while in continuous RX gets silently rejected (-706),
    // which broke hot frequency changes over BLE.
    int16_t status = r->standby();
    if (status != RADIOLIB_ERR_NONE) { MESH_DEBUG_PRINTLN("CustomLR2021Wrapper: standby() -> %d", status); }
    if ((status = r->setFrequency(freq)) != RADIOLIB_ERR_NONE) { MESH_DEBUG_PRINTLN("CustomLR2021Wrapper: setFrequency() -> %d", status); }
    if ((status = r->setSpreadingFactor(sf)) != RADIOLIB_ERR_NONE) { MESH_DEBUG_PRINTLN("CustomLR2021Wrapper: setSpreadingFactor() -> %d", status); }
    if ((status = r->setBandwidth(bw)) != RADIOLIB_ERR_NONE) { MESH_DEBUG_PRINTLN("CustomLR2021Wrapper: setBandwidth() -> %d", status); }
    if ((status = r->setCodingRate(cr)) != RADIOLIB_ERR_NONE) { MESH_DEBUG_PRINTLN("CustomLR2021Wrapper: setCodingRate() -> %d", status); }
    updatePreamble(sf);
    // internal idle() sets STATE_IDLE, which triggers a startReceive() on the next loop
    status = applySideDetectorConfig();
    if (status != RADIOLIB_ERR_NONE) { MESH_DEBUG_PRINTLN("CustomLR2021Wrapper: applySideDetectorConfig() -> %d", status); }
    PacketMillis pm = calcMaxPacketMillis(sf, bw, cr, preambleLengthForSF(sf));
    r->setPreambleMillis(pm.preambleMillis);      // pure in-memory setters, no standby needed
    r->setMaxPayloadMillis(pm.payloadMillis);

  }

  bool configSideDetectors(const uint8_t* sideDetSFs, uint8_t num, float bw) override {
    LR2021LoRaSideDetector_t tmp[3] = {};
    uint8_t sf = getSpreadingFactor();

    if (sf >= 10 && num > 1) { return false; }  // only 1 side detector allowed when primary SF >= 10
    for (int i = 0; i < num; i++) {
      if (sideDetSFs[i] > 12 || sideDetSFs[i] < 5) { return false; }  // must be valid SF
      if (sideDetSFs[i] <= sf) { return false; }  // must be < primary SF
      if (sideDetSFs[i] > sf + 4) { return false; }  // span must not be > 4

      tmp[i].sf = sideDetSFs[i];
      float tSym = calcTsym(tmp[i].sf, bw);
      if (tSym >= 16.0f) {
        tmp[i].ldro = true;
      } else {
        tmp[i].ldro = false; 
      }
      tmp[i].invertIQ = false;
      tmp[i].syncWord = 0x12;
    }
    int16_t status = ((CustomLR2021 *)_radio)->setSideDetector(tmp, num);
    RadioLibWrapper::idle(); // trigger startReceive()
    MESH_DEBUG_PRINTLN("setSideDetector() returned %d", status);

    if (status == RADIOLIB_ERR_NONE) {
      for (int i = 0; i < num; i++) { _sideDet[i] = tmp[i]; }
      _numSideDet = num;
    } else {
      return false;
    }
    
    return true;
  }

  int16_t applySideDetectorConfig() {
    int16_t status = ((CustomLR2021 *)_radio)->setSideDetector(_sideDet, _numSideDet);
    RadioLibWrapper::idle(); // trigger startReceive()
    return status;
  }

  float calcTsym(uint8_t sf, float bw) {
    float tSym = (float)(uint32_t(1) << sf) / (float)bw;
    return tSym;
  }

  bool lastRxHadCRC() override {
    bool crc = true;
    ((CustomLR2021 *)_radio)->getLoRaRxHeaderInfo(NULL, &crc);
    return crc;
  }
  bool isReceivingPacket() override {
    return ((CustomLR2021 *)_radio)->isReceiving();
  }

  float getCurrentRSSI() override {
    float rssi = -110;
    ((CustomLR2021 *)_radio)->getRssiInst(&rssi);
    return rssi;
  }

  void onSendFinished() override {
    uint32_t irq;
    uint16_t err;
    if (checkTxFault(&irq, &err)) {  // must run before finishTransmit() clears all IRQ flags
      _tx_faults.add({ (uint32_t)millis(), irq, err });
    #ifdef MESH_DEBUG
      logTxFault(irq, err);
    #endif
    }
    RadioLibWrapper::onSendFinished();
    _radio->setPreambleLength(preambleLengthForSF(getSpreadingFactor())); // overcomes weird issues with small and big pkts
  }

  int recvRaw(uint8_t* bytes, int sz) override {
    CustomLR2021* r = (CustomLR2021 *)_radio;
    bool scan_pkt = r->isScanning() && isIrqPending();
    int len = RadioLibWrapper::recvRaw(bytes, sz);
    _scan_cached = false;
    if (len > 0 || scan_pkt) {
      uint8_t step = 0;
      if (len > 0 && r->readLastGainStep(&step) == RADIOLIB_ERR_NONE && step >= 1 && step <= 13) {
        _last_gain_step = step;
      } else {
        _last_gain_step = -1;
      }
      if (scan_pkt) {
        // The scan parks after RxDone; read what belongs to this packet, then let it carry on.
        _scan_rssi = r->getRSSI();
        _scan_snr = r->getSNR();
        _scan_cached = true;
        uint8_t hit = 0;
        if (r->scanResume(&hit) != RADIOLIB_ERR_NONE) {
          _scan_restarts++;
          _scan_resume_fail++;
          idle();     // the next recvRaw() starts the scan again
        }
        if (hit != 0 && hit != 0xFF) {   // another network's packet: never give it to the mesh
          if (len > 0) {
            n_recv--;
            pushSide(bytes, len, _scan_rssi, _scan_snr);
          }
          _scan_cached = false;
          return 0;
        }
      }
      if (len > 0 && _last_gain_step > 0) {
        _rx_gains.add({ (uint32_t)millis(), (uint8_t)_last_gain_step, (int16_t)getLastRSSI(), (int8_t)(getLastSNR() * 4) });
        MESH_DEBUG_PRINTLN("LR2021: RX gain step G%u", _last_gain_step);
      }
    }
    return len;
  }

  // ---- Second network (on-chip scanner) ----
  bool setSideListen(float freq, float bw, uint8_t sf, uint8_t cr, uint8_t sync, uint8_t preamble) override {
    CustomLR2021* r = (CustomLR2021 *)_radio;
    CustomLR2021::ScanChannel ch = { freq, bw, sf, cr, preamble, sync };
    if (!r->setScanChannels(&ch, 1)) return false;
    if (!r->isScanLoaded()) {
      // the scanner replaces Semtech's patch in PRAM, which only a chip reset clears
      r->setScanBlob(true);
      reinitRadio();
      if (!r->isScanLoaded()) {
        r->setScanChannels(NULL, 0);
        r->setScanBlob(false);
        reinitRadio();
        return false;
      }
    }
    idle();   // restart receive as a scan
    return true;
  }

  void stopSideListen() override {
    CustomLR2021* r = (CustomLR2021 *)_radio;
    r->setScanChannels(NULL, 0);
    if (r->wantsScanBlob()) {
      r->setScanBlob(false);   // put Semtech's patch back
      reinitRadio();
    }
    _side_head = _side_count = 0;
  }

  bool isSideListening() const override {
    CustomLR2021* r = (CustomLR2021 *)_radio;
    return r->isScanLoaded() && r->getScanChannelCount() > 0;
  }

  int recvSide(uint8_t* bytes, int sz, float* rssi, float* snr) override {
    if (_side_count == 0) return 0;
    const SidePacket& p = _side[_side_head];
    int len = p.len < sz ? p.len : sz;
    memcpy(bytes, p.data, len);
    if (rssi) *rssi = p.rssi;
    if (snr) *snr = p.snr_x4 / 4.0f;
    _side_head = (_side_head + 1) % SIDE_QUEUE;
    _side_count--;
    return len;
  }

  void loop() override {
    if (isSideListening()) {
      // no noise floor sampling while the radio hops between networks
      if (millis() - _scan_check_at >= 1000) {
        _scan_check_at = millis();
        checkScan();
      }
      return;
    }
    RadioLibWrapper::loop();
  }

  int getLastGainStep() const override { return _last_gain_step; }

  // Companion/remote CLI: recent TX faults and AGC gain steps. Replies list the newest entries
  // first, as many as fit in REPLY_MAX characters.
  bool handleCommand(const char* command, uint32_t sender_timestamp, char* reply) override {
    if (strcmp(command, "get radio.faults") == 0) {
      formatTxFaults(reply);
      return true;
    }
    if (strcmp(command, "get radio.agc") == 0) {
      formatRxGains(reply);
      return true;
    }
    if (strcmp(command, "get radio.counts") == 0) {
      sprintf(reply, "> rx %lu ok %lu errors, tx %lu, other network %lu",
              (unsigned long)getPacketsRecv(), (unsigned long)getPacketsRecvErrors(), (unsigned long)getPacketsSent(),
              (unsigned long)_side_heard);
      return true;
    }
    if (strcmp(command, "get radio.scan.restarts") == 0) {
      sprintf(reply, "> %lu restarts: %lu lost hook, %lu parked without IRQ, %lu stuck in RX, %lu resume failed",
              (unsigned long)_scan_restarts, (unsigned long)_scan_unhooked, (unsigned long)_scan_unparked,
              (unsigned long)_scan_stuck, (unsigned long)_scan_resume_fail);
      return true;
    }
    if (strcmp(command, "get radio.scan") == 0) {
      formatScan(reply);
      return true;
    }
    return false;
  }

  // the most recent TX faults since boot (newest first via get(0))
  const RecentHistory<TxFault, TX_FAULT_HISTORY>& getTxFaults() const { return _tx_faults; }

  // gain step, RSSI and SNR of the most recent received packets (newest first via get(0))
  const RecentHistory<RxGain, RX_GAIN_HISTORY>& getRxGains() const { return _rx_gains; }

  float getLastRSSI() const override { return _scan_cached ? _scan_rssi : ((CustomLR2021 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return _scan_cached ? _scan_snr : ((CustomLR2021 *)_radio)->getSNR(); }

  uint8_t getSpreadingFactor() const override { return ((CustomLR2021 *)_radio)->getSpreadingFactor(); }
  
  bool setRxBoostedGainMode(bool en) override {
    ((CustomLR2021 *)_radio)->standby(); // LR2021 must be in standby to accept setRxBoostedGainMode
    int16_t status = ((CustomLR2021 *)_radio)->setRxBoostedGainMode(en ? LR2021_RX_BOOST_LEVEL: 0);
    RadioLibWrapper::idle(); // trigger startReceive()
    return status == RADIOLIB_ERR_NONE;
  }

  // The generic doResetAGC() only calls sleep(), and nothing wakes the LR2021 again,
  // so every later command times out (-705) until reboot.
  void doResetAGC() override {
    int16_t state = ((CustomLR2021 *)_radio)->resetAGC();
    if (state != RADIOLIB_ERR_NONE) {
      MESH_DEBUG_PRINTLN("LR2021: AGC reset failed (%d)", state);
    }
  }

  bool getRxBoostedGainMode() const override {
    return ((CustomLR2021 *)_radio)->getRxBoostedGainMode();
  }

  protected:
    struct SidePacket {
      uint8_t len;
      int8_t snr_x4;
      int16_t rssi;
      uint8_t data[255];
    };
    static const int SIDE_QUEUE = 4;
    SidePacket _side[SIDE_QUEUE];
    uint8_t _side_head = 0, _side_count = 0;
    uint32_t _side_dropped = 0, _side_heard = 0;
    bool _scan_cached = false;
    float _scan_rssi = 0, _scan_snr = 0;
    uint32_t _scan_check_at = 0;
    uint32_t _scan_restarts = 0;
    uint32_t _scan_unhooked = 0, _scan_unparked = 0, _scan_stuck = 0, _scan_resume_fail = 0;   // why
    uint8_t _scan_parked_checks = 0, _scan_busy_checks = 0;

    void pushSide(const uint8_t* bytes, int len, float rssi, float snr) {
      _side_heard++;
      if (len > (int)sizeof(_side[0].data)) len = sizeof(_side[0].data);
      if (_side_count == SIDE_QUEUE) {          // full: drop the oldest
        _side_head = (_side_head + 1) % SIDE_QUEUE;
        _side_count--;
        _side_dropped++;
      }
      SidePacket& p = _side[(_side_head + _side_count) % SIDE_QUEUE];
      p.len = len;
      p.rssi = (int16_t)rssi;
      p.snr_x4 = (int8_t)(snr * 4);
      memcpy(p.data, bytes, len);
      _side_count++;
    }

    // Resets and configures the chip again (std_init), eg. to swap what's in PRAM. The caller
    // applies the MeshCore radio settings again afterwards.
    void reinitRadio() {
      CustomLR2021* r = (CustomLR2021 *)_radio;
      r->std_init(NULL);
      updatePreamble(getSpreadingFactor());
      idle();
    }

    // Once a second while scanning: restart the scan if a host command took it over, and
    // resume it if a packet's IRQ was missed.
    void checkScan() {
      CustomLR2021* r = (CustomLR2021 *)_radio;
      if (!r->isScanning() || !isInRecvMode() || isIrqPending()) {
        _scan_parked_checks = _scan_busy_checks = 0;
        return;
      }
      CustomLR2021::ScanStatus st;
      if (r->scanGetStatus(&st) != RADIOLIB_ERR_NONE || !st.hooked || st.state == CustomLR2021::SCAN_OFF) {
        _scan_restarts++;
        _scan_unhooked++;
        idle();
        return;
      }
      _scan_parked_checks = st.state == CustomLR2021::SCAN_PARK ? _scan_parked_checks + 1 : 0;
      _scan_busy_checks = (st.state == CustomLR2021::SCAN_WAIT || st.state == CustomLR2021::SCAN_RX) ? _scan_busy_checks + 1 : 0;
      if (_scan_parked_checks >= 2 || _scan_busy_checks >= 8) {   // no IRQ for a parked packet, or stuck in RX
        _scan_restarts++;
        if (_scan_parked_checks >= 2) _scan_unparked++; else _scan_stuck++;
        _scan_parked_checks = _scan_busy_checks = 0;
        idle();
      }
    }

    // eg. "> scan: 1203 CADs 0 false 1 lost, 12 mesh 5 side (5 queued 0 dropped), 0 restarts"
    void formatScan(char* reply) {
      CustomLR2021* r = (CustomLR2021 *)_radio;
      if (!isSideListening()) {
        strcpy(reply, r->isScanLoaded() ? "> scan: loaded, no channels" : "> scan: off");
        return;
      }
      CustomLR2021::ScanStatus st;
      memset(&st, 0, sizeof(st));
      r->scanGetStatus(&st);
      snprintf(reply, REPLY_MAX, "> scan %s: %lu CADs %lu false %lu lost, %lu mesh %lu side (%lu heard, %lu dropped), %lu restarts",
               r->isScanning() ? "on" : "paused", (unsigned long)st.cads, (unsigned long)st.falses,
               (unsigned long)st.lost, (unsigned long)st.packets_main, (unsigned long)st.packets_other,
               (unsigned long)_side_heard, (unsigned long)_side_dropped, (unsigned long)_scan_restarts);
    }

    int _last_gain_step = -1;
    RecentHistory<TxFault, TX_FAULT_HISTORY> _tx_faults;
    RecentHistory<RxGain, RX_GAIN_HISTORY> _rx_gains;
    LR2021LoRaSideDetector_t _sideDet[3];
    size_t _numSideDet = 0;

};
