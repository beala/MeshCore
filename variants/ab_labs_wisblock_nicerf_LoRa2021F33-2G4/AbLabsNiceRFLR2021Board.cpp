#include <Arduino.h>
#include <Wire.h>

#include "AbLabsNiceRFLR2021Board.h"

#ifdef NRF52_POWER_MANAGEMENT
// Static configuration for power management
// Values set in variant.h defines
const PowerMgtConfig power_config = {
  .lpcomp_ain_channel = PWRMGT_LPCOMP_AIN,
  .lpcomp_refsel = PWRMGT_LPCOMP_REFSEL,
  .voltage_bootlock = PWRMGT_VOLTAGE_BOOTLOCK
};

void AbLabsNiceRFLR2021Board::initiateShutdown(uint8_t reason) {
  powerDownRadioModule();

  if (reason == SHUTDOWN_REASON_LOW_VOLTAGE ||
      reason == SHUTDOWN_REASON_BOOT_PROTECT) {
    configureVoltageWake(power_config.lpcomp_ain_channel, power_config.lpcomp_refsel);
  }

  enterSystemOff(reason);
}
#endif

void AbLabsNiceRFLR2021Board::begin() {
  NRF52BoardDCDC::begin();
  pinMode(PIN_VBAT_READ, INPUT);
#ifdef PIN_USER_BTN
  pinMode(PIN_USER_BTN, INPUT_PULLUP);
#endif

#ifdef PIN_USER_BTN_ANA
  pinMode(PIN_USER_BTN_ANA, INPUT_PULLUP);
#endif

#if defined(PIN_BOARD_SDA) && defined(PIN_BOARD_SCL)
  Wire.setPins(PIN_BOARD_SDA, PIN_BOARD_SCL);
#endif

  Wire.begin();

  // WB_IO2 is both the base board's 3V3_S enable and the carrier's BOOST_EN
  // (TPS61023, VBAT -> ~5V for the module's VCC / PAs). Keep it on.
  pinMode(PIN_3V3_EN, OUTPUT);
  digitalWrite(PIN_3V3_EN, HIGH);

  // CE enables the module's internal 3.3V LDO, which powers the LR2021.
  // It has an internal pull-up, but drive it so we control the power sequence.
  pinMode(P_LORA_CE, OUTPUT);
#ifdef NRF52_POWER_MANAGEMENT
  // Boot voltage protection check (may not return if voltage too low).
  // Done before powering the module so a flat battery doesn't brown out on the 5V boost.
  checkBootVoltage(&power_config);
#endif
  digitalWrite(P_LORA_CE, HIGH);
  delay(10);  // let the boost, LDO and LR2021 start up before RadioLib resets it
}

// Datasheet: to sleep, pull CE low and drive every MCU pin connected to the
// module (incl. NSS and RESET) low to avoid back-powering it (< 20 uA).
void AbLabsNiceRFLR2021Board::powerDownRadioModule() {
  digitalWrite(P_LORA_CE, LOW);
  pinMode(P_LORA_NSS, OUTPUT);
  digitalWrite(P_LORA_NSS, LOW);
  pinMode(P_LORA_RESET, OUTPUT);
  digitalWrite(P_LORA_RESET, LOW);
  pinMode(P_LORA_SCLK, OUTPUT);
  digitalWrite(P_LORA_SCLK, LOW);
  pinMode(P_LORA_MOSI, OUTPUT);
  digitalWrite(P_LORA_MOSI, LOW);

  digitalWrite(PIN_3V3_EN, LOW);  // 3V3_S + boost off
}

void AbLabsNiceRFLR2021Board::shutdownPeripherals() {
  NRF52Board::shutdownPeripherals();  // puts the LR2021 to sleep over SPI first
  powerDownRadioModule();
}
