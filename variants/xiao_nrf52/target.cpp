#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>

#ifdef DISPLAY_CLASS
  DISPLAY_CLASS display;
  MomentaryButton user_btn(PIN_USER_BTN, 1000, true, true);
#endif

XiaoNrf52Board board;

RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);

WRAPPER_CLASS radio_driver(radio, board);

VolatileRTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);

EnvironmentSensorManager sensors;

bool radio_init() {
#if !defined(KISS_UART_RX) && !defined(KISS_UART_TX)
  // Wire is left uninitialized when native UART is used for the KISS modem
  // (its pins are shared with I2C on this board) -- see XiaoNrf52Board.cpp.
  rtc_clock.begin(Wire);
#endif

  return radio.std_init(&SPI);
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng); // create new random identity
}