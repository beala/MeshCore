#pragma once

#include <RadioLib.h>
#include "MeshCore.h"

class CustomLR1110 : public LR1110 {
  uint32_t _preambleMillis = 66;
  uint32_t _maxPayloadMillis = 3934;
  uint32_t _activityAt = 0;
  bool _headerSeen = false;
  bool _rx_boosted = false;

  public:
    CustomLR1110(Module *mod) : LR1110(mod) { }

    int16_t begin(float freq = 434.0, float bw = 125.0, uint8_t sf = 9, uint8_t cr = 7,
                  uint8_t syncWord = RADIOLIB_LR11X0_LORA_SYNC_WORD_PRIVATE, int8_t power = 10,
                  uint16_t preambleLength = 8, float tcxoVoltage = 1.6) {
      int16_t state = LR1110::begin(freq, bw, sf, cr, syncWord, power, preambleLength,
                                    tcxoVoltage);
      // RadioLib begin() defaults to LDO; use the LR1110 DC/DC regulator.
      if (state == RADIOLIB_ERR_NONE) state = setRegulatorDCDC();
      return state;
    }

    size_t getPacketLength(bool update) override {
      size_t len = LR1110::getPacketLength(update);
      if (len == 0 && getIrqStatus() & RADIOLIB_LR11X0_IRQ_HEADER_ERR) {
        // we've just received a corrupted packet
        // this may have triggered a bug causing subsequent packets to be shifted
        // call standby() to return radio to known-good state
        // recvRaw will call startReceive() to restart rx
        MESH_DEBUG_PRINTLN("LR1110: got header err, calling standby()");
        standby();
      }
      return len;
    }
    
    float getFreqMHz() const { return freqMHz; }

    // Passive Wi-Fi scan with WifiScanTimeLimit (Semtech lr11xx_wifi_scan_time_limit): listens
    // ms_per_channel on every channel in chan_mask, with no per-search timeout, so a beacon
    // (every ~102 ms) is not missed the way WifiScan's abort-on-timeout can. type: 1 = b,
    // 2 = g/n, 4 = b then g/n. Blocks until done, bounded by our own deadline (RadioLib's
    // wifiScan() waits up to 30 s, the loop watchdog). The chip is left in standby.
    int16_t wifiScanTimed(uint8_t type, uint8_t mode, uint16_t chan_mask, uint16_t ms_per_channel, uint8_t* count) {
      *count = 0;
      int16_t err = standby();
      if (err == RADIOLIB_ERR_NONE) err = clearIrqState(RADIOLIB_LR11X0_IRQ_ALL);
      if (err == RADIOLIB_ERR_NONE) err = setDioIrqParams(RADIOLIB_LR11X0_IRQ_WIFI_DONE);
      if (err != RADIOLIB_ERR_NONE) return err;
      const uint8_t buff[9] = {
        type, (uint8_t)(chan_mask >> 8), (uint8_t)chan_mask, mode, RADIOLIB_LR11X0_WIFI_MAX_NUM_RESULTS,
        (uint8_t)(ms_per_channel >> 8), (uint8_t)ms_per_channel,
        0, 0   // timeout per preamble search: 0 = listen for the whole channel time
      };
      // BUSY goes high as the scan starts: don't wait on it (as RadioLib's wifiScan() does)
      err = this->mod->SPIwriteStream(RADIOLIB_LR11X0_CMD_WIFI_SCAN_TIME_LIMIT, buff, sizeof(buff), false, false);
      if (err != RADIOLIB_ERR_NONE) return err;
      uint32_t channels = 0;
      for (uint16_t m = chan_mask; m; m >>= 1) channels += m & 1;
      const uint32_t limit_ms = (type == 4 ? 2 : 1) * channels * ms_per_channel + 1000;
      const uint32_t start = millis();
      while (!this->mod->hal->digitalRead(this->mod->getIrq())) {
        if ((uint32_t)(millis() - start) > limit_ms) {
          standby();
          return RADIOLIB_ERR_RX_TIMEOUT;
        }
        delay(1);   // a real task sleep: yield() starved USB, and output after a 2 s+ scan was lost
      }
      return getWifiScanResultsCount(count);   // also clears the IRQ
    }

    // One Wi-Fi scan result, decoded as Semtech's LR11xx driver (SWDR001 lr11xx_wifi.c) does:
    // result format code 0x01 is "basic complete" after scan modes 1-2 and "extended full"
    // (with the SSID) after modes 4-5. RadioLib only decodes the extended layout after mode 4
    // and turns the RSSI byte into byte / -2; Semtech reads it as a signed dBm value.
    struct WifiResult {
      uint8_t mac[6];
      int8_t rssi;        // dBm
      bool rssi_valid;    // channel info bit 6 clear
      uint8_t channel;    // 1-14
      char type;          // 'b', 'g' or 'n'
      char ssid[33];      // empty after modes 1-2
    };
    bool readWifiResult(uint8_t index, uint8_t scan_mode, WifiResult& out) {
      uint8_t raw[RADIOLIB_LR11X0_WIFI_RESULT_MAX_LEN] = { 0 };
      if (wifiReadResults(index, 1, 0x01, raw) != RADIOLIB_ERR_NONE) return false;
      const bool extended = scan_mode == 4 || scan_mode == 5;
      static const char types[] = { '?', 'b', 'g', 'n' };
      out.type = types[raw[0] & 0x03];
      out.channel = raw[1] & 0x0F;
      out.rssi_valid = (raw[1] & 0x40) == 0;
      out.rssi = (int8_t)raw[2];
      memcpy(out.mac, &raw[extended ? 16 : 4], 6);   // extended: address 2, the sender (the AP) of a beacon
      out.ssid[0] = 0;
      if (extended) {
        int k = 0;
        for (; k < 32 && raw[40 + k]; k++) out.ssid[k] = (raw[40 + k] >= 32 && raw[40 + k] < 127) ? (char)raw[40 + k] : '?';
        out.ssid[k] = 0;
      }
      return true;
    }

    // A Wi-Fi scan leaves the chip in another packet type, and RadioLib then refuses to start LoRa
    // receive (RADIOLIB_ERR_WRONG_MODEM). Back to LoRa with the packet settings radio_init() made;
    // the caller sets frequency, SF, BW, CR, preamble and power again. Returns the packet type found.
    uint8_t restoreLoRaAfterWifi(int16_t& err) {
      uint8_t found = 0xFF;
      getPacketType(&found);
      err = setPacketType(RADIOLIB_LR11X0_PACKET_TYPE_LORA);
      if (err == RADIOLIB_ERR_NONE) err = setSyncWord((uint8_t)RADIOLIB_LR11X0_LORA_SYNC_WORD_PRIVATE);
      if (err == RADIOLIB_ERR_NONE) err = setCRC(2);
      if (err == RADIOLIB_ERR_NONE) err = explicitHeader();
      return found;
    }

    int16_t setRxBoostedGainMode(bool en) {
      int16_t status = LR1110::setRxBoostedGainMode(en);
      if (status == RADIOLIB_ERR_NONE) _rx_boosted = en;
      return status;
    }

    bool getRxBoostedGainMode() const { return _rx_boosted; }

    int16_t startReceive() override {
      // include the PREAMBLE_DETECTED irq bit in reported flags.
      return LR1110::startReceive(RADIOLIB_LR11X0_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED), RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
    }

    bool isReceiving() {
      uint32_t irq = getIrqStatus();
      bool preamble = irq & RADIOLIB_LR11X0_IRQ_PREAMBLE_DETECTED;      // bit 4
      bool header   = irq & RADIOLIB_LR11X0_IRQ_SYNC_WORD_HEADER_VALID; // bit 5
      bool hdrErr   = irq & RADIOLIB_LR11X0_IRQ_HEADER_ERR;             // bit 6
      uint32_t now  = millis();
      if (hdrErr) {
        clearIrqState(RADIOLIB_LR11X0_IRQ_PREAMBLE_DETECTED | RADIOLIB_LR11X0_IRQ_SYNC_WORD_HEADER_VALID | RADIOLIB_LR11X0_IRQ_HEADER_ERR);
        _activityAt = 0;
        _headerSeen = false;
        return false;
      }
      if (!header && _headerSeen) {
        // something cleared the header flag, reset our state.
        _activityAt = 0; _headerSeen = false;
        return false;
      }
      if (header) {
        if (!_headerSeen) { _headerSeen = true; _activityAt = now; };
        if (now - _activityAt > _maxPayloadMillis) {
          MESH_DEBUG_PRINTLN("Clearing header IRQ after %ums", _maxPayloadMillis);
          clearIrqState(RADIOLIB_LR11X0_IRQ_PREAMBLE_DETECTED | RADIOLIB_LR11X0_IRQ_SYNC_WORD_HEADER_VALID | RADIOLIB_LR11X0_IRQ_HEADER_ERR);
          _activityAt = 0; _headerSeen = false;
          return false;
        }
        return true;
      }
      if (preamble) {
        if (_activityAt == 0) _activityAt = now;
        if (now - _activityAt > _preambleMillis) {
          clearIrqState(RADIOLIB_LR11X0_IRQ_PREAMBLE_DETECTED);
          _activityAt = 0;
          MESH_DEBUG_PRINTLN("Clearing preamble IRQ after %ums", _preambleMillis);

          return false;
        }
        return true;
      }
      _activityAt = 0; _headerSeen = false;
      return false;
    }
    
    void setPreambleMillis(uint32_t preambleMillis) {
      _preambleMillis = preambleMillis;
      MESH_DEBUG_PRINTLN("Set _preambleMillis=%u", _preambleMillis);
    }
    void setMaxPayloadMillis(uint32_t payloadMillis) {
      _maxPayloadMillis = payloadMillis;
      MESH_DEBUG_PRINTLN("Set _maxPayloadMillis=%u", _maxPayloadMillis);
    }

    uint8_t getSpreadingFactor() const { return spreadingFactor; }
};
