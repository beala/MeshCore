#pragma once

// QST QMA6100P accelerometer, used here only as a motion wake source: the any-motion engine
// raises INT1 when the change between two samples exceeds a threshold. Written from the
// QMA6100P Preliminary Datasheet Rev A1 (document 13-52-20); section and register names below
// are the datasheet's. The bandwidth (0x10) and clock (0x11 MCLK_SEL) settings, and so the
// sample rate and current, are left at their reset values: the datasheet does not give their tables.

#include <Arduino.h>
#include <Wire.h>

class QMA6100P {
public:
  static const uint8_t ADDR_AD0_LOW = 0x12;   // Table 8: AD0 to GND
  static const uint8_t ADDR_AD0_HIGH = 0x13;  // AD0 to VDD
  static const uint8_t CHIP_ID = 0x90;

private:
  enum : uint8_t {
    REG_CHIP_ID = 0x00,
    REG_INT_ST0 = 0x09,   // NO_MOT, STEP_FLAG, -, -, ANY_MOT_SIGN, FIRST_Z, FIRST_Y, FIRST_X
    REG_FSR = 0x0F,       // RANGE<3:0>
    REG_PM = 0x11,        // MODE_BIT<7>
    REG_INT_EN2 = 0x18,   // ANY_MOT_EN_Z<2>, _Y<1>, _X<0>
    REG_INT_MAP1 = 0x1A,  // INT1_ANY_MOT<0>
    REG_INT_PIN_CFG = 0x20,  // INT1_OD<1>, INT1_LVL<0>
    REG_INT_CFG = 0x21,   // INT_RD_CLR<7>, LATCH_INT<0>
    REG_MOT_CONF0 = 0x2C, // ANY_MOT_DUR<1:0>: (n + 1) samples above the threshold
    REG_MOT_CONF2 = 0x2E, // ANY_MOT_TH<7:0>: threshold = n * 16 LSB (slope input)
    REG_MOT_CONF3 = 0x2F, // ANY_MOT_IN_SEL<6>: 0 = slope
    REG_S_RESET = 0x36,   // 0xB6 = soft reset
  };

  TwoWire* _wire = &Wire;
  uint8_t _addr = ADDR_AD0_LOW;
  bool _ok = false;
  char _probe[48] = "not probed";

  bool write(uint8_t reg, uint8_t value) {
    _wire->beginTransmission(_addr);
    _wire->write(reg);
    _wire->write(value);
    return _wire->endTransmission() == 0;
  }

  bool read(uint8_t reg, uint8_t& value) {
    _wire->beginTransmission(_addr);
    _wire->write(reg);
    if (_wire->endTransmission(false) != 0) return false;
    if (_wire->requestFrom(_addr, (uint8_t)1) != 1) return false;
    value = _wire->read();
    return true;
  }

  bool update(uint8_t reg, uint8_t mask, uint8_t bits) {
    uint8_t v;
    return read(reg, v) && write(reg, (v & ~mask) | (bits & mask));
  }

public:
  // Finds the chip at either address and checks CHIP_ID. The caller powers it and starts Wire.
  bool probe(TwoWire& wire = Wire) {
    _wire = &wire;
    const uint8_t addrs[] = { ADDR_AD0_LOW, ADDR_AD0_HIGH };
    int len = 0;
    for (uint8_t a : addrs) {
      _addr = a;
      uint8_t id;
      const bool acked = read(REG_CHIP_ID, id);
      len += snprintf(_probe + len, sizeof(_probe) - len, "%s%02X:%s", len ? " " : "", a, acked ? "" : "nak");
      if (acked) len += snprintf(_probe + len, sizeof(_probe) - len, "id%02X", id);
      if (acked && id == CHIP_ID) return true;
    }
    return false;
  }

  // What the last probe saw, e.g. "12:nak 13:nak" (no answer) or "12:id90" (found)
  const char* probeInfo() const { return _probe; }

  // Any-motion on all three axes to INT1: push-pull, active high, latched until INT_ST0 is
  // read. threshold: ANY_MOT_TH (1..255, x 16 LSB of slope); samples: 1..4 samples above it.
  bool beginMotionWake(uint8_t threshold, uint8_t samples, TwoWire& wire = Wire) {
    _ok = false;
    if (!probe(wire)) return false;
    if (!write(REG_S_RESET, 0xB6)) return false;   // all registers to defaults, standby (6.2.2)
    delay(5);
    if (!write(REG_S_RESET, 0x00)) return false;
    delay(5);
    uint8_t id = 0;
    if (!read(REG_CHIP_ID, id) || id != CHIP_ID) {
      snprintf(_probe, sizeof(_probe), "%02X: id%02X after reset", _addr, id);
      return false;
    }
    if (samples < 1) samples = 1;
    if (samples > 4) samples = 4;
    _ok = update(REG_FSR, 0x0F, 0x01) &&                  // RANGE 2 g (244 ug/LSB)
          update(REG_MOT_CONF3, 0x40, 0x00) &&             // ANY_MOT_IN_SEL = slope
          write(REG_MOT_CONF2, threshold ? threshold : 1) &&
          update(REG_MOT_CONF0, 0x03, samples - 1) &&
          update(REG_INT_PIN_CFG, 0x03, 0x01) &&           // INT1 push-pull, active high
          update(REG_INT_CFG, 0x81, 0x01) &&               // latched; cleared by reading INT_ST0 (INT_RD_CLR = 0)
          update(REG_INT_MAP1, 0x01, 0x01) &&              // any-motion to INT1
          update(REG_INT_EN2, 0x07, 0x07) &&               // any-motion on X, Y, Z
          update(REG_PM, 0x80, 0x80);                      // active mode
    return _ok;
  }

  bool isOk() const { return _ok; }
  uint8_t address() const { return _addr; }

  bool setThreshold(uint8_t threshold) { return _ok && write(REG_MOT_CONF2, threshold ? threshold : 1); }
  bool setSamples(uint8_t samples) {
    if (samples < 1) samples = 1;
    if (samples > 4) samples = 4;
    return _ok && update(REG_MOT_CONF0, 0x03, samples - 1);
  }

  // Reads (and so clears, in latched mode) INT_ST0. Bits 0-2: axis that triggered, 3: sign.
  bool readAndClear(uint8_t& int_st0) { return read(REG_INT_ST0, int_st0); }

  // Standby: most blocks off, about 0.5 uA (datasheet Table "Standby current"); no motion wake.
  bool standby() { return update(REG_PM, 0x80, 0x00); }
  bool active() { return update(REG_PM, 0x80, 0x80); }
};
