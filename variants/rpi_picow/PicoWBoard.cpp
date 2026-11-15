#include <Arduino.h>
#include "PicoWBoard.h"

//#include <bluefruit.h>
#include <Wire.h>

//static BLEDfu bledfu;

void PicoWBoard::begin() {
  // for future use, sub-classes SHOULD call this from their begin()
  startup_reason = BD_STARTUP_NORMAL;
  pinMode(PIN_VBAT_READ, INPUT);
#ifdef PIN_USER_BTN
  pinMode(PIN_USER_BTN, INPUT_PULLUP);
#endif

#if defined(PIN_BOARD_SDA) && defined(PIN_BOARD_SCL)
  Wire.setPins(PIN_BOARD_SDA, PIN_BOARD_SCL);
#endif

  Wire.begin();

  //pinMode(SX126X_POWER_EN, OUTPUT);
  //digitalWrite(SX126X_POWER_EN, HIGH);
  delay(10);   // give sx1262 some time to power up
}

bool PicoWBoard::startOTAUpdate(const char* id, char reply[]) {
  return false;
}
