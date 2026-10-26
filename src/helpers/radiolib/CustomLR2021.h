#pragma once

#include <RadioLib.h>
#include "MeshCore.h"

class CustomLR2021 : public LR2021 {
  uint32_t _preambleMillis = 66;
  uint32_t _maxPayloadMillis = 3934;
  uint32_t _activityAt = 0;
  bool _headerSeen = false;
  bool _rx_boosted = false;

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
      int status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_LR2021_LORA_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo);
      // if radio init fails with -707/-706, try again with tcxo voltage set to 0.0f
      if (status == RADIOLIB_ERR_SPI_CMD_FAILED || status == RADIOLIB_ERR_SPI_CMD_INVALID) {
        tcxo = 0.0f;
        status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_LR2021_LORA_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo);
      }
      if (status != RADIOLIB_ERR_NONE) {
        Serial.print("ERROR: radio init failed: ");
        Serial.println(status);
        return false;  // fail
      }
    
    #ifdef LR2021_USE_SIMO
      int16_t simoState = setRegModeSimo();
      if (simoState != RADIOLIB_ERR_NONE) {
        MESH_DEBUG_PRINTLN("LR2021: SetRegMode(SIMO_NORMAL) failed (%d), staying on LDO", simoState);
      }
    #endif

    #ifdef LR2021_OCP_LF
      static_assert(LR2021_OCP_LF >= 0 && LR2021_OCP_LF <= 63, "LR2021_OCP_LF must be 0..63");
      int16_t ocpState = setOcpLf(LR2021_OCP_LF);
      if (ocpState != RADIOLIB_ERR_NONE) {
        MESH_DEBUG_PRINTLN("LR2021: setting OCP LF threshold failed (%d)", ocpState);
      }
    #endif

      setCRC(2);
      explicitHeader();

      
    #ifdef LR2021_RX_BOOSTED_GAIN
      setRxBoostedGainMode(LR2021_RX_BOOSTED_GAIN);
    #endif

      return true;  // success
    }
    
    float getFreqMHz() const { return freqMHz; }

    bool getRxBoostedGainMode() const { return _rx_boosted; }

    int16_t startReceive() override {
      // include the PREAMBLE_DETECTED irq bit in reported flags
      return LR2021::startReceive(RADIOLIB_LR2021_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED), RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
    }

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

    // RadioLib's getErrors()/clearErrors() are private, so issue the commands directly.
    int16_t getChipErrors(uint16_t* err) {
      uint8_t buff[2] = { 0 };
      int16_t state = SPIcommand(RADIOLIB_LR2021_CMD_GET_ERRORS, false, buff, sizeof(buff));
      if (err) *err = ((uint16_t)buff[0] << 8) | buff[1];
      return state;
    }
    int16_t clearChipErrors() {
      return SPIcommand(RADIOLIB_LR2021_CMD_CLEAR_ERRORS, true, NULL, 0);
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

    // Full receiver reset: warm sleep to power down the analog front end, wake, recalibrate,
    // then restore what sleep loses. Warm sleep keeps RAM (command settings) but not
    // registers (datasheet 23.6), so register-based settings must be written again.
    int16_t resetAGC() {
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

    // Switch VDCC/VPAX from the LDOs (chip default) to the SIMO DC-DC converter.
    // Datasheet 6.3.18: one byte, 0x02 = SIMO_NORMAL; only valid in Standby RC.
    // Requires the SIMO inductor on LXA/LXB.
    int16_t setRegModeSimo() {
      int16_t state = standby(RADIOLIB_LR2021_STANDBY_RC);
      if (state != RADIOLIB_ERR_NONE) return state;
      uint8_t simo = RADIOLIB_LR2021_REG_MODE_SIMO_NORMAL;
      return SPIcommand(RADIOLIB_LR2021_CMD_SET_REG_MODE, true, &simo, 1);
    }
};
