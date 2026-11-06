#pragma once

#include <RadioLib.h>
#include "MeshCore.h"
#include "LinkGfsk.h"

class CustomSX1262 : public SX1262 {
  uint32_t _preambleMillis = 66;
  uint32_t _maxPayloadMillis = 3934;
  uint32_t _activityAt = 0;
  bool _headerSeen = false;

  // the link (linkStart): registers the GFSK set-up's calibration may change, put back after
  // (receive gain, the Heltec V4's 0x8B5 patch, the over-current limit)
  static const int LINK_KEEP_REGS = 3;
  static uint16_t linkKeepReg(int i) {
    static const uint16_t regs[LINK_KEEP_REGS] = { RADIOLIB_SX126X_REG_RX_GAIN, 0x08B5, RADIOLIB_SX126X_REG_OCP_CONFIGURATION };
    return regs[i];
  }
  uint8_t _link_regs[LINK_KEEP_REGS] = {};
  float _link_mesh_mhz = 0;
  bool _link = false;
  uint32_t _link_packets = 0, _link_bad = 0;
  uint32_t _link_irq = 0;
  uint32_t _link_rearms = 0, _link_restarts = 0;
  float _link_mhz = 0, _link_stall_rssi = 0;
  int8_t _link_dbm = 0;
  uint8_t _link_stall_status = 0;
  uint16_t _link_stall_irq = 0, _link_stall_errors = 0;

  // single Rx, no timeout: one packet, kept until it's read and receive is started again. In
  // continuous Rx a packet that came while the host was busy was overwritten by the next one (and
  // each is written after the last in the buffer, SX1261/2 datasheet 7.2).
  int16_t linkRx() {
    return SX1262::startReceive(RADIOLIB_SX126X_RX_TIMEOUT_NONE, RADIOLIB_IRQ_RX_DEFAULT_FLAGS, RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
  }
  // GFSK with the link's settings (LinkGfsk.h), from standby
  int16_t linkConfigure() {
    int16_t state;
    // as beginFSK() does, without its reset (that would lose the board's TCXO, regulator and
    // register settings): GFSK packet type, then each setting
    this->bitRate = 21333;
    this->frequencyDev = 52428;
    this->rxBandwidth = RADIOLIB_SX126X_GFSK_RX_BW_467_0;
    this->rxBandwidthKhz = LINK_GFSK_RXBW_KHZ;
    this->pulseShape = RADIOLIB_SX126X_GFSK_FILTER_GAUSS_0_5;
    this->crcTypeFSK = RADIOLIB_SX126X_GFSK_CRC_2_BYTE_INV;
    this->preambleLengthFSK = LINK_GFSK_PBL_BITS;
    this->packetType = RADIOLIB_SX126X_GFSK_PACKET_VARIABLE;
    state = config(RADIOLIB_SX126X_PACKET_TYPE_GFSK);   // (calibrates)
    // the receive gain, the Heltec V4's 0x8B5 patch and the current limit, as on the mesh
    for (int i = 0; state == RADIOLIB_ERR_NONE && i < LINK_KEEP_REGS; i++) writeRegister(linkKeepReg(i), &_link_regs[i], 1);
    if (state == RADIOLIB_ERR_NONE) state = setBitRate(LINK_GFSK_KBPS);
    if (state == RADIOLIB_ERR_NONE) state = setFrequencyDeviation(LINK_GFSK_DEV_KHZ);
    if (state == RADIOLIB_ERR_NONE) state = setRxBandwidth(LINK_GFSK_RXBW_KHZ);
    if (state == RADIOLIB_ERR_NONE) state = setDataShaping(RADIOLIB_SHAPING_0_5);
    if (state == RADIOLIB_ERR_NONE) {
      uint8_t sync[4];
      memcpy(sync, LINK_SYNC_BYTES, 4);
      state = setSyncWord(sync, 4);
    }
    if (state == RADIOLIB_ERR_NONE) state = setPreambleLength(LINK_GFSK_PBL_BITS);
    // the preamble detector must be shorter than the sync word, 8 or 16 bits recommended (SX1261/2
    // datasheet 6.2.2.1); RadioLib picks min(sync word, preamble) = 32 bits, and then the chip
    // locks onto only some packets. Receive (stageMode) applies the cached value.
    this->preambleDetLength = RADIOLIB_SX126X_GFSK_PREAMBLE_DETECT_16;
    if (state == RADIOLIB_ERR_NONE) state = variablePacketLengthMode(RADIOLIB_SX126X_MAX_PACKET_LENGTH);
    if (state == RADIOLIB_ERR_NONE) state = setCRC(2, LINK_GFSK_CRC_INIT, LINK_GFSK_CRC_POLY, true);
    if (state == RADIOLIB_ERR_NONE) state = setWhitening(true, LINK_GFSK_WHITEN);
    if (state == RADIOLIB_ERR_NONE) state = setFrequency(_link_mhz);
    if (state == RADIOLIB_ERR_NONE) state = SX1262::setOutputPower(_link_dbm);
    if (state == RADIOLIB_ERR_NONE) {
      // after each packet in or out, keep the synthesizer running: quicker turnarounds
      uint8_t fs = RADIOLIB_SX126X_RX_TX_FALLBACK_MODE_FS;
      state = this->mod->SPIwriteStream(RADIOLIB_SX126X_CMD_SET_RX_TX_FALLBACK_MODE, &fs, 1);
    }
    return state;
  }


  public:
    CustomSX1262(Module *mod) : SX1262(mod) { }

  #ifdef RP2040_PLATFORM
    bool std_init(SPIClassRP2040* spi = NULL)
  #else
    bool std_init(SPIClass* spi = NULL)
  #endif
    {
  #ifdef SX126X_DIO3_TCXO_VOLTAGE
      float tcxo = SX126X_DIO3_TCXO_VOLTAGE;
  #else
      float tcxo = 1.6f;
  #endif

  #ifdef LORA_CR
      uint8_t cr = LORA_CR;
  #else
      uint8_t cr = 5;
  #endif

  #ifdef SX126X_USE_REGULATOR_LDO
      constexpr bool useRegulatorLDO = SX126X_USE_REGULATOR_LDO;
  #else
      constexpr bool useRegulatorLDO = false;
  #endif

      MESH_DEBUG_PRINTLN("SX1262 regulator requested: %s", useRegulatorLDO ? "LDO" : "DC-DC");

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
      int status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo, useRegulatorLDO);
      // if radio init fails with -707/-706, try again with tcxo voltage set to 0.0f
      if (status == RADIOLIB_ERR_SPI_CMD_FAILED || status == RADIOLIB_ERR_SPI_CMD_INVALID) {
        MESH_DEBUG_PRINTLN("SX1262 init failed with error %d, retrying with TCXO at 0.0V", status);
        tcxo = 0.0f;
        status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo, useRegulatorLDO);
      }
      if (status != RADIOLIB_ERR_NONE) {
        Serial.print("ERROR: radio init failed: ");
        Serial.println(status);
        return false;  // fail
      }
    
      setCRC(1);
  
  #ifdef SX126X_CURRENT_LIMIT
      setCurrentLimit(SX126X_CURRENT_LIMIT);
  #endif
  #ifdef SX126X_DIO2_AS_RF_SWITCH
      setDio2AsRfSwitch(SX126X_DIO2_AS_RF_SWITCH);
  #endif
  #ifdef SX126X_RX_BOOSTED_GAIN
      setRxBoostedGainMode(SX126X_RX_BOOSTED_GAIN);
  #endif
  #if defined(SX126X_RXEN) || defined(SX126X_TXEN)
    #ifndef SX126X_RXEN
      #define SX126X_RXEN RADIOLIB_NC
    #endif
    #ifndef SX126X_TXEN
      #define SX126X_TXEN RADIOLIB_NC
    #endif
      setRfSwitchPins(SX126X_RXEN, SX126X_TXEN);
  #endif 

  // for improved RX with Heltec v4
  #ifdef SX126X_REGISTER_PATCH
    uint8_t r_data = 0;
    readRegister(0x8B5, &r_data, 1);
    r_data |= 0x01;
    writeRegister(0x8B5, &r_data, 1);
  #endif

      MESH_DEBUG_PRINTLN("SX1262 status=0x%02X device_errors=0x%04X", getStatus(), getDeviceErrors());

      return true;  // success
    }

    int16_t startReceive() override {
      // include the PREAMBLE_DETECTED irq bit in reported flags
      return SX1262::startReceive(RADIOLIB_SX126X_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED), RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
    }

    bool isReceiving() {
      uint32_t irq = getIrqFlags();
      bool preamble = irq & RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED; // bit 2
      bool header   = irq & RADIOLIB_SX126X_IRQ_HEADER_VALID;      // bit 4
      bool hdrErr   = irq & RADIOLIB_SX126X_IRQ_HEADER_ERR;        // bit 5
      uint32_t now  = millis();
      if (hdrErr) {
        clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID | RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID);
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
          clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID | RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID);
          _activityAt = 0; _headerSeen = false;
          return false;
        }
        return true;
      }
      if (preamble) {
        if (_activityAt == 0) _activityAt = now;
        if (now - _activityAt > _preambleMillis) {
          clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED);
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

    // ---- point-to-point link (copying a radio): GFSK, framed as the LR2021's (LinkGfsk.h) ----
    // Receives between sends, one packet at a time (linkRx); linkStop() puts LoRa back with
    // MeshCore's settings, in standby.

    int16_t linkStart(float fMHz, int8_t dbm) {
      int16_t state = standby();
      if (state != RADIOLIB_ERR_NONE) return state;
      for (int i = 0; i < LINK_KEEP_REGS; i++) readRegister(linkKeepReg(i), &_link_regs[i], 1);
      _link_mesh_mhz = freqMHz;
      _link = true;
      _link_mhz = fMHz;
      _link_dbm = dbm;
      state = linkConfigure();
      if (state == RADIOLIB_ERR_NONE) state = linkRx();
      if (state != RADIOLIB_ERR_NONE) linkStop();
      return state;
    }

    // Sets the link up again from scratch, receiving: for a receiver that heard nothing when an
    // answer was due. Notes the chip's state first ('get radio.link').
    int16_t linkRestart() {
      if (!_link) return RADIOLIB_ERR_WRONG_MODEM;
      _link_restarts++;
      _link_stall_status = getStatus();
      _link_stall_irq = getIrqFlags();
      _link_stall_errors = getDeviceErrors();
      _link_stall_rssi = getRSSI(false);
      clearDeviceErrors();
      int16_t state = standby();
      if (state == RADIOLIB_ERR_NONE) state = linkConfigure();
      if (state == RADIOLIB_ERR_NONE) state = linkRx();
      return state;
    }
    uint32_t linkRestarts() const { return _link_restarts; }
    void linkStall(uint8_t* status, uint16_t* irq, uint16_t* errors, float* rssi) const {
      *status = _link_stall_status; *irq = _link_stall_irq; *errors = _link_stall_errors; *rssi = _link_stall_rssi;
    }


    int16_t linkSend(const uint8_t* buf, uint8_t len) {
      if (!_link) return RADIOLIB_ERR_WRONG_MODEM;
      int16_t state = SX1262::transmit(buf, len);   // standby, send, wait for TxDone, standby
      int16_t rx = linkRx();
      return state != RADIOLIB_ERR_NONE ? state : rx;
    }

    // > 0: a packet's length; 0: none yet; < 0: one failed its CRC
    int linkRead(uint8_t* buf, uint8_t max, float* rssi) {
      if (!_link) return 0;
      uint32_t irq = getIrqFlags();
      _link_irq = irq;
      if (!(irq & (RADIOLIB_SX126X_IRQ_RX_DONE | RADIOLIB_SX126X_IRQ_CRC_ERR))) {
        // single Rx also ends without a packet when a preamble isn't followed by one (SX1261/2
        // datasheet 6.2.2.1): the chip then waits in FS, deaf. Start receive again.
        if ((getStatus() & 0x70) != RADIOLIB_SX126X_STATUS_MODE_RX &&
            !(getIrqFlags() & (RADIOLIB_SX126X_IRQ_RX_DONE | RADIOLIB_SX126X_IRQ_CRC_ERR))) {   // (not one just in)
          _link_rearms++;
          clearIrqStatus();
          setRx(RADIOLIB_SX126X_RX_TIMEOUT_NONE);
        }
        return 0;
      }
      if (irq & RADIOLIB_SX126X_IRQ_CRC_ERR) {
        _link_bad++;
        clearIrqStatus();
        setRx(RADIOLIB_SX126X_RX_TIMEOUT_NONE);
        return -1;
      }
      uint8_t offset = 0;
      size_t len = getPacketLength(true, &offset);
      int n = len > max ? max : (int)len;
      if (rssi) *rssi = getRSSI(true);
      if (n > 0 && readBuffer(buf, n, offset) != RADIOLIB_ERR_NONE) n = 0;
      _link_packets++;
      // receive the next packet: just clear and SetRx (the chip waits in FS, and the rest is as it
      // was), so short frames close behind aren't missed; a full startReceive() took ~1 ms here
      clearIrqStatus();
      setRx(RADIOLIB_SX126X_RX_TIMEOUT_NONE);
      return n;
    }

    int16_t linkStop() {
      if (!_link) return RADIOLIB_ERR_NONE;
      _link = false;
      int16_t state = standby();
      // LoRa again, from RadioLib's cached MeshCore settings
      if (state == RADIOLIB_ERR_NONE) state = config(RADIOLIB_SX126X_PACKET_TYPE_LORA);
      if (state == RADIOLIB_ERR_NONE) state = setModulationParams(spreadingFactor, bandwidth, codingRate, ldrOptimize);
      if (state == RADIOLIB_ERR_NONE) state = setPacketParams(preambleLengthLoRa, crcTypeLoRa, implicitLen, headerType, invertIQEnabled);
      if (state == RADIOLIB_ERR_NONE) state = SX1262::setSyncWord(RADIOLIB_SX126X_SYNC_WORD_PRIVATE);
      if (state == RADIOLIB_ERR_NONE) state = setFrequency(_link_mesh_mhz);
      for (int i = 0; i < LINK_KEEP_REGS; i++) writeRegister(linkKeepReg(i), &_link_regs[i], 1);
      return state;
    }
    bool isLinkActive() const { return _link; }
    uint32_t linkLastIrq() const { return _link_irq; }
    uint32_t linkRearms() const { return _link_rearms; }
    // the chip's own GFSK counts since the link started (GetStats): received, CRC errors, length errors
    void linkChipStats(uint16_t* rx, uint16_t* crc, uint16_t* len) {
      uint8_t d[6] = { 0 };
      this->mod->SPIreadStream(RADIOLIB_SX126X_CMD_GET_STATS, d, 6);
      *rx = (d[0] << 8) | d[1]; *crc = (d[2] << 8) | d[3]; *len = (d[4] << 8) | d[5];
    }
    void linkStats(uint32_t* packets, uint32_t* bad) const { *packets = _link_packets; *bad = _link_bad; }

    bool getRxBoostedGainMode() {
      uint8_t rxGain = 0;
      readRegister(RADIOLIB_SX126X_REG_RX_GAIN, &rxGain, 1);
      return (rxGain == RADIOLIB_SX126X_RX_GAIN_BOOSTED);
    }
};