#pragma once

#include "CustomSX1262.h"
#include "RadioLibWrappers.h"
#include "SX126xReset.h"

#ifndef USE_SX1262
#define USE_SX1262
#endif

class CustomSX1262Wrapper : public RadioLibWrapper {
public:
  CustomSX1262Wrapper(CustomSX1262& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) override {
    ((CustomSX1262 *)_radio)->setFrequency(freq);
    ((CustomSX1262 *)_radio)->setSpreadingFactor(sf);
    ((CustomSX1262 *)_radio)->setBandwidth(bw);
    ((CustomSX1262 *)_radio)->setCodingRate(cr);
    updatePreamble(sf);
    PacketMillis pm = calcMaxPacketMillis(sf, bw, cr, preambleLengthForSF(sf));
    ((CustomSX1262 *)_radio)->setPreambleMillis(pm.preambleMillis);
    ((CustomSX1262 *)_radio)->setMaxPayloadMillis(pm.payloadMillis);
  }

  bool lastRxHadCRC() override {
    bool crc = true;
    ((CustomSX1262 *)_radio)->getLoRaRxHeaderInfo(NULL, &crc);
    return crc;
  }
  bool isReceivingPacket() override { 
    return ((CustomSX1262 *)_radio)->isReceiving();
  }
  float getCurrentRSSI() override {
    return ((CustomSX1262 *)_radio)->getRSSI(false);
  }
  float getLastRSSI() const override { return ((CustomSX1262 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomSX1262 *)_radio)->getSNR(); }

  float packetScore(float snr, int packet_len) override {
    int sf = ((CustomSX1262 *)_radio)->spreadingFactor;
    return packetScoreInt(snr, sf, packet_len);
  }
  uint8_t getSpreadingFactor() const override { return ((CustomSX1262 *)_radio)->spreadingFactor; }
  virtual void powerOff() override {
    ((CustomSX1262 *)_radio)->sleep(false);
  }

  bool setRxBoostedGainMode(bool en) override {
    return ((CustomSX1262 *)_radio)->setRxBoostedGainMode(en) == RADIOLIB_ERR_NONE;
  }
  bool getRxBoostedGainMode() const override {
    return ((CustomSX1262 *)_radio)->getRxBoostedGainMode();
  }

  void doResetAGC() override { sx126xResetAGC((SX126x *)_radio, getRxBoostedGainMode()); }

  // ---- link (copying a radio): GFSK only ----
  uint8_t linkModes() const override { return 1 << LINK_GFSK; }
  bool linkStart(float freq, int8_t dbm) override {
    idle();
    if (((CustomSX1262 *)_radio)->linkStart(freq, dbm) != RADIOLIB_ERR_NONE) {
      idle();   // linkStart put LoRa back
      return false;
    }
    clearIrqPending();
    _link_up = true;
    return true;
  }
  bool linkSetMode(uint8_t mode) override { return _link_up && mode == LINK_GFSK; }
  void linkStalled() override {
    if (!_link_up) return;
    ((CustomSX1262 *)_radio)->linkRestart();
    clearIrqPending();
    uint8_t st; uint16_t irq, err; float rssi;
    ((CustomSX1262 *)_radio)->linkStall(&st, &irq, &err, &rssi);
    logLink('Z', irq, st, (int)rssi);   // what the chip looked like: IRQ flags, status, RSSI now
    if (err) logLink('D', err, 0, 0);   // device errors
  }
  bool linkSend(const uint8_t* bytes, int len) override {
    if (!_link_up || len < 6 || len > 255) return false;
    _board->onBeforeTransmit();   // eg. the Heltec V4's front end to transmit
    bool ok = ((CustomSX1262 *)_radio)->linkSend(bytes, (uint8_t)len) == RADIOLIB_ERR_NONE;
    logLink(ok ? 'T' : 'F', 0, bytes[2], len);
    clearIrqPending();            // that was TxDone; receive is armed again
    _board->onAfterTransmit();
    return ok;
  }
  int linkRecv(uint8_t* bytes, int sz, float* rssi) override {
    if (!_link_up) return 0;
    // read the chip only when DIO1 (RxDone) has risen, with a slow poll in case an edge was missed:
    // polling its IRQ status over SPI in a tight loop made it miss most packets
    if (!isIrqPending() && millis() - _link_poll_at < 50) return 0;
    _link_poll_at = millis();
    bool pin = isIrqPending();
    clearIrqPending();
    int n = ((CustomSX1262 *)_radio)->linkRead(bytes, (uint8_t)(sz > 255 ? 255 : sz), rssi);
    uint32_t irq = ((CustomSX1262 *)_radio)->linkLastIrq();
    if (n != 0 || pin || irq) logLink(n > 0 ? 'R' : (n < 0 ? 'E' : (pin ? 'P' : 'I')), irq, n > 0 ? bytes[2] : 0, n);
    return n > 0 ? n : 0;
  }
  void linkStats(uint32_t* ok, uint32_t* bad, uint32_t* restarts) const override {
    ((CustomSX1262 *)_radio)->linkStats(ok, bad);
    *restarts = ((CustomSX1262 *)_radio)->linkRearms() + ((CustomSX1262 *)_radio)->linkRestarts();
  }
  void linkStop() override {
    if (!_link_up) return;
    _link_up = false;
    ((CustomSX1262 *)_radio)->linkStop();   // LoRa with MeshCore's settings again
    clearIrqPending();
    idle();                                 // the mesh starts receive again
  }

  bool handleCommand(const char* command, uint32_t sender_timestamp, char* reply) override {
    if (strcmp(command, "get radio.link") == 0) {   // the link's last events, oldest first
      uint16_t rx = 0, crc = 0, len = 0;
      if (_link_up) ((CustomSX1262 *)_radio)->linkChipStats(&rx, &crc, &len);
      int n = sprintf(reply, "> chip %u/%u/%u rearm %lu", rx, crc, len, (unsigned long)((CustomSX1262 *)_radio)->linkRearms());
      while (_link_log_n > 0 && n < 130) {   // takes what it shows off the log
        const LinkEvent& e = _link_log[(_link_log_at + LINK_LOG - _link_log_n) % LINK_LOG];
        n += snprintf(&reply[n], 160 - n, " %c%lu:%x/%d/%d", e.what, (unsigned long)e.at % 100000, (unsigned)e.irq, e.type, e.len);
        _link_log_n--;
      }
      return true;
    }
    return RadioLibWrapper::handleCommand(command, sender_timestamp, reply);
  }

private:
  bool _link_up = false;
  uint32_t _link_poll_at = 0;
  struct LinkEvent { uint32_t at; uint16_t irq; uint8_t type; int16_t len; char what; };
  static const int LINK_LOG = 48;
  LinkEvent _link_log[LINK_LOG];
  int _link_log_at = 0, _link_log_n = 0;
  void logLink(char what, uint32_t irq, uint8_t type, int len) {
    _link_log[_link_log_at] = { (uint32_t)millis(), (uint16_t)irq, type, (int16_t)len, what };
    _link_log_at = (_link_log_at + 1) % LINK_LOG;
    if (_link_log_n < LINK_LOG) _link_log_n++;
  }
};
