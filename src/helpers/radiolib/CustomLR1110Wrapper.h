#pragma once

#include "CustomLR1110.h"
#include "RadioLibWrappers.h"
#include "LR11x0Reset.h"

class CustomLR1110Wrapper : public RadioLibWrapper {
public:
  CustomLR1110Wrapper(CustomLR1110& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) override {
    ((CustomLR1110 *)_radio)->setFrequency(freq);
    ((CustomLR1110 *)_radio)->setSpreadingFactor(sf);
    ((CustomLR1110 *)_radio)->setBandwidth(bw);
    ((CustomLR1110 *)_radio)->setCodingRate(cr);
    updatePreamble(sf);
    PacketMillis pm = calcMaxPacketMillis(sf, bw, cr, preambleLengthForSF(sf));
    ((CustomLR1110 *)_radio)->setPreambleMillis(pm.preambleMillis);
    ((CustomLR1110 *)_radio)->setMaxPayloadMillis(pm.payloadMillis);
  }

  bool lastRxHadCRC() override {
    bool crc = true;
    ((CustomLR1110 *)_radio)->getLoRaRxHeaderInfo(NULL, &crc);
    return crc;
  }
  bool isReceivingPacket() override {
    return ((CustomLR1110 *)_radio)->isReceiving();
  }
  float getCurrentRSSI() override {
    float rssi = -110;
    ((CustomLR1110 *)_radio)->getRssiInst(&rssi);
    return rssi;
  }

  uint32_t getEstAirtimeFor(int len_bytes) override {
    auto airtime = RadioLibWrapper::getEstAirtimeFor(len_bytes);
    return airtime < 200 ? 200 : airtime;   // at least 200 millis
  }

  void onSendFinished() override {
    RadioLibWrapper::onSendFinished();
    _radio->setPreambleLength(preambleLengthForSF(getSpreadingFactor())); // overcomes weird issues with small and big pkts
  }

  float getLastRSSI() const override { return ((CustomLR1110 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomLR1110 *)_radio)->getSNR(); }

  uint8_t getSpreadingFactor() const override { return ((CustomLR1110 *)_radio)->getSpreadingFactor(); }
  
  bool supportsRxBoostedGain() const override { return true; }
  bool setRxBoostedGainMode(bool en) override {
    return ((CustomLR1110 *)_radio)->setRxBoostedGainMode(en) == RADIOLIB_ERR_NONE;
  }
  bool getRxBoostedGainMode() const override {
    return ((CustomLR1110 *)_radio)->getRxBoostedGainMode();
  }

  void doResetAGC() override { lr11x0ResetAGC((LR11x0 *)_radio, ((CustomLR1110 *)_radio)->getFreqMHz(), getRxBoostedGainMode()); }

  static const int WIFI_SCAN_BUSY = -1000;

  // Passive 2.4 GHz Wi-Fi beacon scan. LoRa receive stops for the scan (it blocks, up to
  // channels x scans_per_chan x timeout_ms) and restarts on the next loop. Returns the
  // number of results, or a RadioLib error, or WIFI_SCAN_BUSY if a packet is being sent or received.
  // Read the results with getWifiResult() before the next scan.
  // type: 'b', 'g' (= 'n': both scan g and n), or '*' (a b pass, then a g/n pass). mode: 1 beacon,
  // 2 beacon and packet, 4 full beacon (802.11b only), 5 until SSID (Semtech lr11xx_wifi_types.h).
  // Each pass listens ms_per_channel on every channel in chan_mask. The results of all passes go
  // to out (at most max). Returns the number of results, a RadioLib error, or WIFI_SCAN_BUSY.
  // Two passes rather than the chip's own b+g/n type: one blocking call over ~2.3 s lost the USB
  // output that followed it (bench, 2026-11-23).
  int wifiScan(char type, uint8_t mode, uint16_t chan_mask, uint16_t ms_per_channel,
               CustomLR1110::WifiResult* out, int max) {
    // free: asleep, idle (e.g. just after a scan), or listening with no packet coming in
    const bool free = _asleep || isIdleState() || (isInRecvMode() && !isIrqPending() && !isReceivingPacket());
    if (!free) return WIFI_SCAN_BUSY;
    _asleep = false;   // the scan's first command (standby) wakes it: the caller restores LoRa, then may sleep it again
    CustomLR1110* radio = (CustomLR1110 *)_radio;
    const uint8_t passes[2] = { (uint8_t)(type == 'b' || type == '*' ? 1 : 2), 2 };
    const int num_passes = type == '*' ? 2 : 1;
    int total = 0;
    int16_t err = RADIOLIB_ERR_NONE;
    for (int p = 0; p < num_passes && err == RADIOLIB_ERR_NONE; p++) {
      uint8_t count = 0;
      err = radio->wifiScanTimed(passes[p], mode, chan_mask, ms_per_channel, &count);
      for (uint8_t i = 0; err == RADIOLIB_ERR_NONE && i < count && total < max; i++) {
        if (radio->readWifiResult(i, mode, out[total])) total++;
      }
    }
    idle();   // standby; the main loop restarts LoRa receive, which maps the RX interrupts again
    _wifi_restore_err = 0;
    _wifi_pkt_type = radio->restoreLoRaAfterWifi(_wifi_restore_err);
    return err == RADIOLIB_ERR_NONE ? total : err;
  }

  // Geofence: radio off (sleep, configuration kept, ~1 uA) until wakeRadio(). Don't call
  // recvRaw()/startSendRaw() meanwhile: the caller stops the mesh loop. Not during a send.
  void sleepRadio() {
    idle();
    ((CustomLR1110 *)_radio)->sleep(true, 0);
    _asleep = true;
  }
  // Standby (a NOP wakes it); the caller then re-applies the LoRa settings and the next
  // recvRaw() starts receiving.
  void wakeRadio() {
    idle();
    _asleep = false;
  }
  bool isAsleep() const { return _asleep; }

  // After wifiScan(): the packet type the scan left (2 = LoRa) and the error from restoring LoRa
  bool _asleep = false;
  uint8_t _wifi_pkt_type = 0;
  int16_t _wifi_restore_err = 0;

  // LR1110 Wi-Fi firmware version (major.minor); false if the radio did not answer
  bool getWifiFirmware(uint8_t& major, uint8_t& minor) {
    LR11x0VersionInfo_t info;
    if (((CustomLR1110 *)_radio)->getVersionInfo(&info) != RADIOLIB_ERR_NONE) return false;
    major = info.fwMajorWiFi;
    minor = info.fwMinorWiFi;
    return true;
  }

};
