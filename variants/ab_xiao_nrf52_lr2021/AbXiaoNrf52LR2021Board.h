#pragma once

#include <MeshCore.h>
#include <Arduino.h>
#include <helpers/NRF52Board.h>

#ifndef USER_BTN_PRESSED
#define USER_BTN_PRESSED LOW
#endif

#ifdef AB_XIAO_NRF52_LR2021

class AbXiaoNrf52LR2021Board : public NRF52BoardDCDC {
protected:
#if NRF52_POWER_MANAGEMENT
  void initiateShutdown(uint8_t reason) override;
#endif

public:
  AbXiaoNrf52LR2021Board() : NRF52Board("XIAO_NRF52_LR2021_OTA") {}
  void begin();

#if defined(P_LORA_TX_LED)
  void onBeforeTransmit() override {
    digitalWrite(P_LORA_TX_LED, LOW);   // turn TX LED on
  }
  void onAfterTransmit() override {
    digitalWrite(P_LORA_TX_LED, HIGH);   // turn TX LED off
  }
#endif

  uint16_t getBattMilliVolts() override;

  const char* getManufacturerName() const override {
    return "AB Labs LLC Xiao-nrf52 LR2021";
  }

  void powerOff() override {
    // set led on and wait for button release before poweroff
    digitalWrite(PIN_LED, LOW);
#ifdef PIN_USER_BTN
    while(digitalRead(PIN_USER_BTN) == USER_BTN_PRESSED);
#endif
    digitalWrite(LED_GREEN, HIGH);
    digitalWrite(LED_BLUE, HIGH);
    digitalWrite(PIN_LED, HIGH);

#ifdef PIN_USER_BTN
    // configure button press to wake up when in powered off state
    nrf_gpio_cfg_sense_input(digitalPinToInterrupt(g_ADigitalPinMap[PIN_USER_BTN]), NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
#endif

    NRF52Board::powerOff();
  }
};

#endif
