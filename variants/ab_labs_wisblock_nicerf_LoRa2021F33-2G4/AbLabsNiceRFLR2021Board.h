#pragma once

#include <MeshCore.h>
#include <Arduino.h>
#include <helpers/NRF52Board.h>

// built-ins
#define  PIN_VBAT_READ    5
#define  ADC_MULTIPLIER   (3 * 1.73 * 1.187 * 1000)

class AbLabsNiceRFLR2021Board : public NRF52BoardDCDC {
protected:
#ifdef NRF52_POWER_MANAGEMENT
  void initiateShutdown(uint8_t reason) override;
#endif
  void powerDownRadioModule();

public:
  AbLabsNiceRFLR2021Board() : NRF52Board("ABLABS_LR2021_OTA") {}
  void begin();
  void shutdownPeripherals() override;

  #define BATTERY_SAMPLES 8

  uint16_t getBattMilliVolts() override {
    analogReadResolution(12);

    uint32_t raw = 0;
    for (int i = 0; i < BATTERY_SAMPLES; i++) {
      raw += analogRead(PIN_VBAT_READ);
    }
    raw = raw / BATTERY_SAMPLES;

    return (ADC_MULTIPLIER * raw) / 4096;
  }

  const char* getManufacturerName() const override {
    return "AB Labs WisBlock NiceRF LoRa2021F33-2G4";
  }

  // PA / LNA / antenna switching is done by the LR2021's own DIO5..DIO8 in
  // RF-switch mode (see target.cpp), so no onBeforeTransmit/onAfterTransmit needed.
};
