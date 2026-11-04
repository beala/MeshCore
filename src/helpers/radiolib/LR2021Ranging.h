#pragma once

// RTToF ranging between two LR2021 radios: the manager sends a ranging request, the subordinate
// answers automatically after a fixed turnaround, and the manager reads the round-trip time.
// Command sequence from Semtech's usp v1.2.1 radio layer, as tested between two boards in
// https://github.com/beala/lr2021-re (docs/ranging.md, tools/ranging.py).
//
// Ranging uses LoRa SF9 at 500 kHz bandwidth on the current frequency, so it is only allowed where
// a 500 kHz channel fits the band (902-928 MHz). The caller restores the normal LoRa settings
// afterwards with end(), the wrapper's setParams(), then restartRx().

#include "CustomLR2021Wrapper.h"

class LR2021Ranging {
public:
  static const uint8_t SF = 9;
  static const uint32_t TX_RX_DELAY = 20305;      // Semtech's value for BW 500 kHz, SF9 (uncalibrated here)
  static const uint8_t RESPONSE_SYMBOLS = 15;

  // a 500 kHz channel centred on freq must fit in 902-928 MHz
  static bool bandAllowed(float mhz) { return mhz >= 902.25f && mhz <= 927.75f; }

  // one raw unit is 150 / (4096 * 0.5 MHz) = 7.3 cm
  static float rawToMeters(int32_t raw) { return raw * 150.0f / (4096.0f * 0.5f); }

  explicit LR2021Ranging(CustomLR2021Wrapper& w) : _w(&w), _r((CustomLR2021 *)w._radio) { }

  // Switch to RTToF. addr: the subordinate answers only requests for this address (all 4 bytes checked).
  int16_t begin(bool manager, uint32_t addr) {
    int16_t st;
    uint8_t b[5];
    if ((st = standbyRC()) != RADIOLIB_ERR_NONE) return st;
    if ((st = packetType(RADIOLIB_LR2021_PACKET_TYPE_RTTOF)) != RADIOLIB_ERR_NONE) return st;
    b[0] = (SF << 4) | 0x06; b[1] = 1 << 4;                       // SF9, BW 500 kHz, CR 4/5
    if ((st = cmd(0x0220, b, 2)) != RADIOLIB_ERR_NONE) return st;   // SetLoraModulationParams
    b[0] = 0; b[1] = 12; b[2] = 0; b[3] = 0x02;                    // preamble 12, explicit header, CRC
    if ((st = cmd(0x0221, b, 4)) != RADIOLIB_ERR_NONE) return st;   // SetLoraPacketParams
    b[0] = 0x12;
    if ((st = cmd(0x0223, b, 1)) != RADIOLIB_ERR_NONE) return st;   // SetLoraSyncword
    b[0] = LR2021_IRQ_DIO; be32(&b[1], RNG_IRQS);
    if ((st = cmd(0x0115, b, 5)) != RADIOLIB_ERR_NONE) return st;   // SetDioIrqConfig
    be32(b, TX_RX_DELAY);
    if ((st = cmd(0x027B, b, 4)) != RADIOLIB_ERR_NONE) return st;   // SetRangingTxRxDelay
    b[0] = RESPONSE_SYMBOLS;
    if ((st = cmd(0x027C, b, 1)) != RADIOLIB_ERR_NONE) return st;   // SetRangingParams, normal mode
    be32(b, addr);
    if (manager) {
      st = cmd(0x0279, b, 4);                                        // SetRangingReqAddr
    } else {
      b[4] = 4;
      st = cmd(0x0278, b, 5);                                        // SetRangingAddr
    }
    if (st != RADIOLIB_ERR_NONE) return st;
    if ((st = cmd(0x020A, NULL, 0)) != RADIOLIB_ERR_NONE) return st; // ResetRxStats
    irqs();
    return RADIOLIB_ERR_NONE;
  }

  // Manager: one exchange. Returns true with the raw result and RSSI if the subordinate answered.
  bool exchange(int32_t& raw, int& rssi_dbm, uint32_t timeout_ms) {
    uint8_t t[3] = { 0, 0, 0 };
    if (cmd(0x020D, t, 3) != RADIOLIB_ERR_NONE) return false;      // SetTx
    uint32_t start = millis(), f = 0;
    while (millis() - start < timeout_ms) {
      f = irqs();
      if (f & (IRQ_EXCH_VALID | IRQ_RNG_TIMEOUT | IRQ_TIMEOUT)) break;
    }
    if (!(f & IRQ_EXCH_VALID)) {
      standbyRC();
      return false;
    }
    uint8_t type = 0, d[4] = { 0 };
    if (read(0x027A, &type, 1, d, 4) != RADIOLIB_ERR_NONE) return false;   // GetRangingResult, raw
    raw = (int32_t)((uint32_t)d[0] << 16 | (uint32_t)d[1] << 8 | d[2]);
    if (raw & 0x800000) raw -= 0x1000000;
    rssi_dbm = -(d[3] >> 1);
    return true;
  }

  // Subordinate: answer ranging requests for window_ms. Returns how many responses were sent.
  int respond(uint32_t window_ms) {
    uint8_t t[3] = { 0xFF, 0xFF, 0xFF };
    if (cmd(0x020C, t, 3) != RADIOLIB_ERR_NONE) return -1;         // SetRx, continuous
    int done = 0;
    uint32_t start = millis();
    while (millis() - start < window_ms) {
      if (irqs() & IRQ_RESP_DONE) done++;
      delay(1);
    }
    standbyRC();
    return done;
  }

  // Back to standby and the LoRa packet type. Then call the wrapper's setParams() to restore the rest.
  int16_t end() {
    standbyRC();
    int16_t st = packetType(RADIOLIB_LR2021_PACKET_TYPE_LORA);
    if (st == RADIOLIB_ERR_NONE) st = _r->setSyncWord(RADIOLIB_LR2021_LORA_SYNC_WORD_PRIVATE);
    irqs();
    return st;
  }

  // After the wrapper's setParams(): the radio is in standby, but the wrapper still thinks it's
  // receiving and would never restart Rx. Mark it idle so the next loop calls startReceive().
  void restartRx() { _w->idle(); }

private:
  static const uint32_t IRQ_REQ_VALID = 1UL << 2, IRQ_TIMEOUT = 1UL << 21, IRQ_RESP_DONE = 1UL << 28,
                        IRQ_REQ_DIS = 1UL << 29, IRQ_EXCH_VALID = 1UL << 30, IRQ_RNG_TIMEOUT = 1UL << 31;
  static const uint32_t RNG_IRQS = IRQ_REQ_VALID | IRQ_RESP_DONE | IRQ_REQ_DIS | IRQ_EXCH_VALID |
                                   IRQ_RNG_TIMEOUT | IRQ_TIMEOUT;

  CustomLR2021Wrapper* _w;
  CustomLR2021* _r;

  static void be32(uint8_t* b, uint32_t v) {
    b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v;
  }
  int16_t cmd(uint16_t op, const uint8_t* p, size_t n) { return _r->SPIcommand(op, true, (uint8_t *)p, n); }
  int16_t read(uint16_t op, const uint8_t* p, size_t n, uint8_t* out, size_t olen) {
    return _r->SPIcommand(op, false, out, olen, p, n);
  }
  int16_t standbyRC() { uint8_t m = 0; return cmd(0x0128, &m, 1); }
  uint32_t irqs() {   // GetAndClearIrqStatus
    uint8_t d[4] = { 0 };
    if (read(0x0117, NULL, 0, d, 4) != RADIOLIB_ERR_NONE) return 0;
    return (uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3];
  }
  int16_t writeMask(uint32_t addr, uint32_t mask, uint32_t data) {   // WriteRegMemMask32
    uint8_t b[11] = { (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr };
    be32(&b[3], mask); be32(&b[7], data);
    return cmd(0x0105, b, sizeof(b));
  }
  // SetPacketType, plus the DC-DC workaround RadioLib applies after every packet type change
  int16_t packetType(uint8_t type) {
    int16_t st = cmd(0x0207, &type, 1);
    if (st != RADIOLIB_ERR_NONE) return st;
    if ((st = writeMask(0xF20024, 0x0FUL << 20, 15UL << 20)) != RADIOLIB_ERR_NONE) return st;
    if ((st = writeMask(0xF20024, 0x0FUL << 16, 15UL << 16)) != RADIOLIB_ERR_NONE) return st;
    uint8_t b[7] = { 0x80, 0x00, 0x4C };   // WriteRegMem32 DCDC_FREQ_LF = 2800000 * 1.048576
    be32(&b[3], 2936012);
    if ((st = cmd(0x0104, b, sizeof(b))) != RADIOLIB_ERR_NONE) return st;
    return _r->setFrequency(_r->freqMHz, true);
  }
};
