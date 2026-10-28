#pragma once

#include <RadioLib.h>
#include "MeshCore.h"

class CustomLR2021 : public LR2021 {
  bool _rx_boosted = false;
  bool _pram_pending = false;   // load the firmware patch on the next standby() (set before begin())
  int16_t _pram_status = RADIOLIB_ERR_UNKNOWN;
  uint32_t _pram_info = 0;      // patch type/version word read back from the chip

  int16_t readWord(uint32_t addr, uint32_t* out);
  int16_t loadPram();

  public:
    CustomLR2021(Module *mod) : LR2021(mod) { irqDioNum = LR2021_IRQ_DIO; }

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
    
      setCRC(2);
      explicitHeader();

      if (_pram_status == RADIOLIB_ERR_NONE) {
        Serial.print("LR2021 PRAM patch loaded: type ");
        Serial.print((_pram_info >> 16) & 0xFF);
        Serial.print(", version 0x");
        Serial.println((_pram_info >> 8) & 0xFF, HEX);
      } else {
        Serial.print("WARNING: LR2021 PRAM patch not loaded: ");
        Serial.println(_pram_status);
      }

      
    #ifdef LR2021_RX_BOOSTED_GAIN
      setRxBoostedGainMode(LR2021_RX_BOOSTED_GAIN);
    #endif

      return true;  // success
    }
    
    // begin() resets the chip, which clears PRAM. RadioLib calls standby() right
    // after that reset and before TCXO setup and calibration, which is where
    // Semtech's own driver loads the patch, so the load is hooked in here.
    using LR2021::standby;
    int16_t standby() override {
      int16_t state = LR2021::standby();
      if (_pram_pending && state == RADIOLIB_ERR_NONE) {
        _pram_pending = false;
        _pram_status = loadPram();
      }
      return state;
    }

    float getFreqMHz() const { return freqMHz; }

    bool getRxBoostedGainMode() const { return _rx_boosted; }

    bool isReceiving() {
      uint32_t irq = getIrqStatus();
      bool detected = ((irq & RADIOLIB_LR2021_IRQ_SYNCWORD_VALID) || (irq & RADIOLIB_LR2021_IRQ_PREAMBLE_DETECTED));
      return detected;
    }

    uint8_t getSpreadingFactor() const { return spreadingFactor; }
};