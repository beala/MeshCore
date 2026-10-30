#pragma once

#include "CustomLR2021.h"
#include "RadioLibWrappers.h"

#ifndef USE_LR2021
#define USE_LR2021
#endif

#ifndef LR2021_RX_BOOST_LEVEL
#define LR2021_RX_BOOST_LEVEL 7
#endif

class CustomLR2021Wrapper : public RadioLibWrapper {
#ifdef MESH_DEBUG
  // Logs fault IRQs, decoded chip errors, and a missing TX_DONE after a transmit.
  void logTxFaults() {
    CustomLR2021* radio = (CustomLR2021 *)_radio;
    uint32_t irq = radio->getIrqStatus();

    static const struct { uint32_t bit; const char* name; } irqFaults[] = {
      { RADIOLIB_LR2021_IRQ_EOL,        "EOL" },
      { RADIOLIB_LR2021_IRQ_PA_OCP_OVP, "PA_OCP_OVP" },
      { RADIOLIB_LR2021_IRQ_ERROR,      "ERROR" },
      { RADIOLIB_LR2021_IRQ_CMD_ERROR,  "CMD_ERROR" },
      { RADIOLIB_LR2021_IRQ_TIMEOUT,    "TIMEOUT" },
    };
    bool fault = !(irq & RADIOLIB_LR2021_IRQ_TX_DONE);
    for (auto& f : irqFaults) {
      if (irq & f.bit) fault = true;
    }
    if (!fault) return;

    MESH_DEBUG_PRINTLN("LR2021: TX fault, irq=0x%08lX", (unsigned long)irq);
    if (!(irq & RADIOLIB_LR2021_IRQ_TX_DONE)) MESH_DEBUG_PRINTLN("LR2021:   TX_DONE not set");
    for (auto& f : irqFaults) {
      if (irq & f.bit) MESH_DEBUG_PRINTLN("LR2021:   %s", f.name);
    }

    // ERROR is a summary bit; the cause is in the chip's error register
    if (irq & RADIOLIB_LR2021_IRQ_ERROR) {
      static const char* const errNames[16] = {
        "HF_XOSC_START", "LF_XOSC_START", "PLL_LOCK", "LF_RC_CALIB",
        "HF_RC_CALIB", "PLL_CALIB", "AAF_CALIB", "IMG_CALIB",
        "CHIP_BUSY", "RXFREQ_NO_FE_CAL", "MEAS_UNIT_ADC_CALIB", "PA_OFFSET_CALIB",
        "PPF_CALIB", "SRC_CALIB", "SRC_SATURATION_CALIB", "SRC_TOLERANCE_CALIB",
      };
      uint16_t err = 0;
      int16_t state = radio->getErrors(&err);
      if (state != RADIOLIB_ERR_NONE) {
        MESH_DEBUG_PRINTLN("LR2021:   getErrors failed (%d)", state);
        return;
      }
      MESH_DEBUG_PRINTLN("LR2021:   chip errors=0x%04X", err);
      for (int i = 0; i < 16; i++) {
        if (err & (1u << i)) MESH_DEBUG_PRINTLN("LR2021:     %s", errNames[i]);
      }
      radio->clearErrors();
    }
  }
#endif

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
    LR2021LoRaSideDetector_t tmp[3];
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

  bool isReceivingPacket() override {
    return ((CustomLR2021 *)_radio)->isReceiving();
  }

  float getCurrentRSSI() override {
    float rssi = -110;
    ((CustomLR2021 *)_radio)->getRssiInst(&rssi);
    return rssi;
  }

  void onSendFinished() override {
  #ifdef MESH_DEBUG
    logTxFaults();  // must run before finishTransmit() clears all IRQ flags
  #endif
    RadioLibWrapper::onSendFinished();
    _radio->setPreambleLength(preambleLengthForSF(getSpreadingFactor())); // overcomes weird issues with small and big pkts
  }

  float getLastRSSI() const override { return ((CustomLR2021 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomLR2021 *)_radio)->getSNR(); }

  uint8_t getSpreadingFactor() const override { return ((CustomLR2021 *)_radio)->getSpreadingFactor(); }
  
  bool setRxBoostedGainMode(bool en) override {
    ((CustomLR2021 *)_radio)->standby(); // LR2021 must be in standby to accept setRxBoostedGainMode
    int16_t status = ((CustomLR2021 *)_radio)->setRxBoostedGainMode(en ? LR2021_RX_BOOST_LEVEL: 0);
    RadioLibWrapper::idle(); // trigger startReceive()
    return status == RADIOLIB_ERR_NONE;
  }

  bool getRxBoostedGainMode() const override {
    return ((CustomLR2021 *)_radio)->getRxBoostedGainMode();
  }

  protected:
    LR2021LoRaSideDetector_t _sideDet[3];
    size_t _numSideDet = 0;

};
