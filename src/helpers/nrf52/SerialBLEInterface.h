#pragma once

#include "../BaseSerialInterface.h"
#include <bluefruit.h>

#ifndef BLE_TX_POWER
#define BLE_TX_POWER 4
#endif

class SerialBLEInterface : public BaseSerialInterface {
  BLEDfu bledfu;
  BLEUart bleuart;
  bool _isEnabled;
  bool _isDeviceConnected;
  uint16_t _conn_handle;
  unsigned long _last_health_check;
  unsigned long _last_retry_attempt;
  volatile unsigned long _last_rx_ms = 0;   // set in the Bluetooth task when a frame comes in
  // fast while busy (SerialBLEInterface.cpp, BLE_FAST_MODE)
  volatile unsigned long _last_activity = 0;   // the app's last write
  volatile bool _fast_wanted = false;
  uint8_t _params_sent = 2;                    // 0 idle, 1 fast, 2 neither yet (this connection)
  unsigned long _params_retry_at = 0;
  bool requestParams(bool fast);
  bool _led_enabled;     // 'set led on/off' (BLE_LED_PAIRING_BLINK boards only)
  bool _led_lit;
  unsigned long _last_led_toggle;

  // The pairing window (docs/ble_pairing.md). Closed: no passkey is set, so the SoftDevice makes up a
  // random one per attempt and shows it nowhere, and a pairing request is answered with a disconnect.
  // Written in the main loop, read in the Bluetooth task.
  volatile bool _pw_open = false;
  unsigned long _pw_until = 0;
  volatile bool _pw_bonded = false;     // a pairing succeeded while open: close it (main loop)
  uint32_t _passkey_set_err = 0;        // the last sd_ble_opt_set(BLE_GAP_OPT_PASSKEY) result
  bool setPasskey(bool on);

  // What happened to pairing, for the Radio console and serial. Set from the Bluetooth task
  volatile bool _pr_pending = false;
  bool _pr_peer_seen = false;
  uint8_t _pr_status = 0, _pr_lesc = 0, _pr_bonded = 0, _pr_lv = 0;
  uint8_t _pr_peer_lesc = 0, _pr_peer_mitm = 0, _pr_peer_io = 0;
  volatile uint16_t _pr_refused = 0;    // pairing requests refused with the window closed
  uint16_t _pr_refused_told = 0;
  volatile uint8_t _pr_window = 0;      // 1 opened, 2 closed (timeout or press), 3 closed after a bond

  struct Frame {
    uint8_t len;
    uint8_t buf[MAX_FRAME_SIZE];
  };

  #define FRAME_QUEUE_SIZE  12
  
  uint8_t send_queue_len;
  Frame send_queue[FRAME_QUEUE_SIZE];
  
  uint8_t recv_queue_len;
  Frame recv_queue[FRAME_QUEUE_SIZE];

  // the fluxcore service (BaseSerialInterface: checkRecvSideFrame/writeSideFrame). Frames in come
  // from the Bluetooth task: a ring with one writer (head) and one reader (tail)
  #define SIDE_QUEUE_SIZE  4
  BLEService fluxsvc;
  BLECharacteristic fluxrx, fluxtx;
  Frame side_recv[SIDE_QUEUE_SIZE];
  volatile uint8_t side_recv_head, side_recv_tail;
  uint8_t side_send_len;
  Frame side_send[SIDE_QUEUE_SIZE];

  void clearBuffers();
  void shiftSendQueueLeft();
  void shiftRecvQueueLeft();
  bool isValidConnection(uint16_t handle, bool requireWaitingForSecurity = false) const;
  bool isAdvertising() const;
  void setLedLit(bool lit);
  void updateLed();
  static void onConnect(uint16_t connection_handle);
  static void onDisconnect(uint16_t connection_handle, uint8_t reason);
  static void onSecured(uint16_t connection_handle);
  static bool onPairingPasskey(uint16_t connection_handle, uint8_t const passkey[6], bool match_request);
  static void onPairingComplete(uint16_t connection_handle, uint8_t auth_status);
  static void onBLEEvent(ble_evt_t* evt);
  static void onBleUartRX(uint16_t conn_handle);
  static void onSideRX(uint16_t conn_hdl, BLECharacteristic* chr, uint8_t* data, uint16_t len);

public:
  SerialBLEInterface() : fluxsvc(FLUX_SERVICE_UUID), fluxrx(FLUX_RX_UUID), fluxtx(FLUX_TX_UUID) {
    side_recv_head = side_recv_tail = 0;
    side_send_len = 0;
    _isEnabled = false;
    _isDeviceConnected = false;
    _conn_handle = BLE_CONN_HANDLE_INVALID;
    _last_health_check = 0;
    _last_retry_attempt = 0;
    _led_enabled = true;
    _led_lit = false;
    _last_led_toggle = 0;
    send_queue_len = 0;
    recv_queue_len = 0;
  }

  /**
   * init the BLE interface.
   * @param prefix   a prefix for the device name
   * @param name  IN/OUT - a name for the device (combined with prefix). If "@@MAC", is modified and returned
   * @param pin_code   the BLE security pin
   */
  void begin(const char* prefix, char* name, uint32_t pin_code);

  void disconnect();
  // bench test: a line about the last pairing, once each, or false if none since the last call
  // isConsole: set when the line is for the Radio console; false means serial only
  bool takePairingReport(char* out, size_t len, bool* isConsole);

  void loop() override;
  bool hasPairingWindow() const override { return true; }
  void openPairingWindow(uint32_t ms) override;
  void closePairingWindow() override;
  bool isPairingWindowOpen() const override { return _pw_open; }
  void enable() override;
  void disable() override;
  bool isEnabled() const override { return _isEnabled; }
  void setLedEnabled(bool enabled) override;
  bool isConnected() const override;
  bool isWriteBusy() const override;
  bool hasPendingWrite() const override;
  unsigned long lastRecvMillis() const override { return _last_rx_ms; }
  void describeLink(char* out, size_t len) const override;
  size_t writeFrame(const uint8_t src[], size_t len) override;
  size_t checkRecvFrame(uint8_t dest[]) override;
  size_t checkRecvSideFrame(uint8_t dest[]) override;
  size_t writeSideFrame(const uint8_t src[], size_t len) override;
};

#if BLE_DEBUG_LOGGING && ARDUINO
  #include <Arduino.h>
  // each line starts with millis(), for timing a message sync (request in, reply out)
  #define BLE_DEBUG_PRINT(F, ...) Serial.printf("BLE %lu: " F, (unsigned long)millis(), ##__VA_ARGS__)
  #define BLE_DEBUG_PRINTLN(F, ...) Serial.printf("BLE %lu: " F "\n", (unsigned long)millis(), ##__VA_ARGS__)
#else
  #define BLE_DEBUG_PRINT(...) {}
  #define BLE_DEBUG_PRINTLN(...) {}
#endif
