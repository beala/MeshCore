#pragma once
// The radio driver the radio settings code talks to

#include <cstdint>

struct MockRadioDriver {
  bool setRxBoostedGainMode(bool) { return true; }
  void setTxPower(int8_t) { }
};
inline MockRadioDriver radio_driver;
