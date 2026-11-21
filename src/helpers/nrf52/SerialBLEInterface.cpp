#include "SerialBLEInterface.h"
#include <stdio.h>
#include <string.h>
#include "ble_gap.h"
#include "ble_hci.h"

// Magic numbers came from actual testing
#define BLE_HEALTH_CHECK_INTERVAL  10000  // Advertising watchdog check every 10 seconds
#define BLE_RETRY_THROTTLE_MS      250    // Throttle retries to 250ms when queue buildup detected

// Connection parameters (units: interval=1.25ms, timeout=10ms)
#define BLE_MIN_CONN_INTERVAL      12     // 15ms
#define BLE_MAX_CONN_INTERVAL      24     // 30ms
// Slave latency lets the radio skip connection events it has nothing to send in, which saves a
// little power but holds each write from the app until the radio next listens: up to (latency + 1)
// intervals, ~150 ms at 4. A message sync is one write and one reply per message, so that wait
// comes once per message. 0: the radio listens every interval. -D BLE_SLAVE_LATENCY=4 for the old
#ifndef BLE_SLAVE_LATENCY
#define BLE_SLAVE_LATENCY          0
#endif
#define BLE_CONN_SUP_TIMEOUT       200    // 2000ms

// Advertising parameters
#define BLE_ADV_INTERVAL_MIN       32     // 20ms (units: 0.625ms)
#define BLE_ADV_INTERVAL_MAX       244    // 152.5ms (units: 0.625ms)
#define BLE_ADV_FAST_TIMEOUT       30     // seconds

// RX drain buffer size for overflow protection
#define BLE_RX_DRAIN_BUF_SIZE      32

static SerialBLEInterface* instance = nullptr;

// the PIN, while the pairing window is open. The SoftDevice keeps the pointer, so it lives here
static char ble_passkey[BLE_GAP_PASSKEY_LEN + 1];

void SerialBLEInterface::onConnect(uint16_t connection_handle) {
  BLE_DEBUG_PRINTLN("SerialBLEInterface: connected handle=0x%04X", connection_handle);
  if (instance) {
    if (instance->_conn_handle != BLE_CONN_HANDLE_INVALID && instance->_conn_handle != connection_handle) {
      // a second phone or computer: one at a time. (Apps on the same phone share its one link and
      // never get here.) Advertising starts again when it's gone.
      sd_ble_gap_disconnect(connection_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
      return;
    }
    instance->_conn_handle = connection_handle;
    instance->_isDeviceConnected = false;
    instance->clearBuffers();
    // Keep advertising while connected, so a second app on the same phone (the fluxcore app in a
    // browser, next to the MeshCore app) can find the radio and share the link: a phone only lists
    // radios that advertise
    Bluefruit.Advertising.start(0);
  }
}

void SerialBLEInterface::onDisconnect(uint16_t connection_handle, uint8_t reason) {
  BLE_DEBUG_PRINTLN("SerialBLEInterface: disconnected handle=0x%04X reason=%u", connection_handle, reason);
  if (instance) {
    if (instance->_conn_handle == connection_handle) {
      instance->_conn_handle = BLE_CONN_HANDLE_INVALID;
      instance->_isDeviceConnected = false;
      instance->clearBuffers();
    }
  }
}

void SerialBLEInterface::onSecured(uint16_t connection_handle) {
  BLE_DEBUG_PRINTLN("SerialBLEInterface: onSecured handle=0x%04X", connection_handle);
  if (instance) {
    if (instance->isValidConnection(connection_handle, true)) {
      instance->_isDeviceConnected = true;
      
      // Connection interval units: 1.25ms, supervision timeout units: 10ms
      // Apple: "The product will not read or use the parameters in the Peripheral Preferred Connection Parameters characteristic."
      // So we explicitly set it here to make Android & Apple match
      ble_gap_conn_params_t conn_params;
      conn_params.min_conn_interval = BLE_MIN_CONN_INTERVAL;
      conn_params.max_conn_interval = BLE_MAX_CONN_INTERVAL;
      conn_params.slave_latency = BLE_SLAVE_LATENCY;
      conn_params.conn_sup_timeout = BLE_CONN_SUP_TIMEOUT;
      
      uint32_t err_code = sd_ble_gap_conn_param_update(connection_handle, &conn_params);
      if (err_code == NRF_SUCCESS) {
        BLE_DEBUG_PRINTLN("Connection parameter update requested: %u-%ums interval, latency=%u, %ums timeout",
                         conn_params.min_conn_interval * 5 / 4,  // convert to ms (1.25ms units)
                         conn_params.max_conn_interval * 5 / 4,
                         conn_params.slave_latency,
                         conn_params.conn_sup_timeout * 10);  // convert to ms (10ms units)
      } else {
        BLE_DEBUG_PRINTLN("Failed to request connection parameter update: %lu", err_code);
      }
    } else {
      BLE_DEBUG_PRINTLN("onSecured: ignoring stale/duplicate callback");
    }
  }
}

bool SerialBLEInterface::onPairingPasskey(uint16_t connection_handle, uint8_t const passkey[6], bool match_request) {
  (void)connection_handle;
  (void)passkey;
  BLE_DEBUG_PRINTLN("SerialBLEInterface: pairing passkey request match=%d", match_request);
  return true;
}

void SerialBLEInterface::onPairingComplete(uint16_t connection_handle, uint8_t auth_status) {
  BLE_DEBUG_PRINTLN("SerialBLEInterface: pairing complete handle=0x%04X status=%u", connection_handle, auth_status);
  if (instance) {
    if (instance->isValidConnection(connection_handle)) {
      if (auth_status == BLE_GAP_SEC_STATUS_SUCCESS) {
        BLE_DEBUG_PRINTLN("SerialBLEInterface: pairing successful");
      } else {
        BLE_DEBUG_PRINTLN("SerialBLEInterface: pairing failed, disconnecting");
        instance->disconnect();
      }
    } else {
      BLE_DEBUG_PRINTLN("onPairingComplete: ignoring stale callback");
    }
  }
}

void SerialBLEInterface::onBLEEvent(ble_evt_t* evt) {
  if (!instance) return;

  if (evt->header.evt_id == BLE_GAP_EVT_SEC_PARAMS_REQUEST) {
    // A new pairing (a bonded phone reconnecting asks for its keys instead: SEC_INFO_REQUEST). With
    // the window closed, drop the link. The second guard: no passkey is set then, but a central that
    // says it has no input or output would get Just Works, which needs none. Bluefruit has already
    // replied by now, but the disconnect lands before the pairing round trips that are left
    if (!instance->_pw_open) {
      sd_ble_gap_disconnect(evt->evt.gap_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
      instance->_pr_refused++;
      return;
    }
    const ble_gap_sec_params_t* p = &evt->evt.gap_evt.params.sec_params_request.peer_params;
    instance->_pr_peer_lesc = p->lesc;
    instance->_pr_peer_mitm = p->mitm;
    instance->_pr_peer_io = p->io_caps;
    instance->_pr_peer_seen = true;
  } else if (evt->header.evt_id == BLE_GAP_EVT_AUTH_STATUS) {
    const ble_gap_evt_auth_status_t* a = &evt->evt.gap_evt.params.auth_status;
    instance->_pr_status = a->auth_status;
    instance->_pr_lesc = a->lesc;
    instance->_pr_bonded = a->bonded;
    instance->_pr_lv = a->sm1_levels.lv4 ? 4 : a->sm1_levels.lv3 ? 3 : a->sm1_levels.lv2 ? 2 : 1;
    instance->_pr_pending = true;
    if (a->auth_status == BLE_GAP_SEC_STATUS_SUCCESS && instance->_pw_open) instance->_pw_bonded = true;   // one bond per window
  }
  
  if (evt->header.evt_id == BLE_GAP_EVT_CONN_PARAM_UPDATE) {   // what the phone actually agreed to
    const ble_gap_conn_params_t* cp = &evt->evt.gap_evt.params.conn_param_update.conn_params;
    (void)cp;   // only read by the debug line
    BLE_DEBUG_PRINTLN("conn params now: interval %u-%u (x1.25ms), latency=%u, timeout=%ums",
                     cp->min_conn_interval, cp->max_conn_interval, cp->slave_latency, cp->conn_sup_timeout * 10);
  }

  if (evt->header.evt_id == BLE_GAP_EVT_CONN_PARAM_UPDATE_REQUEST) {
    uint16_t conn_handle = evt->evt.gap_evt.conn_handle;
    if (instance->isValidConnection(conn_handle)) {
      BLE_DEBUG_PRINTLN("CONN_PARAM_UPDATE_REQUEST: handle=0x%04X, min_interval=%u, max_interval=%u, latency=%u, timeout=%u",
                       conn_handle,
                       evt->evt.gap_evt.params.conn_param_update_request.conn_params.min_conn_interval,
                       evt->evt.gap_evt.params.conn_param_update_request.conn_params.max_conn_interval,
                       evt->evt.gap_evt.params.conn_param_update_request.conn_params.slave_latency,
                       evt->evt.gap_evt.params.conn_param_update_request.conn_params.conn_sup_timeout);
      
      uint32_t err_code = sd_ble_gap_conn_param_update(conn_handle, NULL);
      if (err_code == NRF_SUCCESS) {
        BLE_DEBUG_PRINTLN("Accepted CONN_PARAM_UPDATE_REQUEST (using PPCP)");
      } else {
        BLE_DEBUG_PRINTLN("ERROR: Failed to accept CONN_PARAM_UPDATE_REQUEST: 0x%08X", err_code);
      }
    } else {
      BLE_DEBUG_PRINTLN("CONN_PARAM_UPDATE_REQUEST: ignoring stale callback for handle=0x%04X", conn_handle);
    }
  }
}

void SerialBLEInterface::begin(const char* prefix, char* name, uint32_t pin_code) {
  instance = this;

  char charpin[20];
  snprintf(charpin, sizeof(charpin), "%lu", (unsigned long)pin_code);
  
  #ifdef DISABLE_BLE_LED  // use variant platformio.ini build_flags macro: -D DISABLE_BLE_LED
    Bluefruit.autoConnLed(false);  // false removes the automatic control of the LED by the Bluefruit library
  #else
    Bluefruit.autoConnLed(true);  // true leaves the default automatic control of the LED by the Bluefruit library
  #endif
  
  Bluefruit.configPrphBandwidth(BANDWIDTH_MAX);
  Bluefruit.begin(2, 0);   // 2 links: advertising (connectable) needs a free one while the app is connected
 
  char dev_name[32+16];
  if (strcmp(name, "@@MAC") == 0) {
    ble_gap_addr_t addr;
    if (sd_ble_gap_addr_get(&addr) == NRF_SUCCESS) {
      sprintf(name, "%02X%02X%02X%02X%02X%02X",    // modify (IN-OUT param)
          addr.addr[5], addr.addr[4], addr.addr[3], addr.addr[2], addr.addr[1], addr.addr[0]);
    }
  }
  sprintf(dev_name, "%s%s", prefix, name);

  // Connection interval units: 1.25ms, supervision timeout units: 10ms
  ble_gap_conn_params_t ppcp_params;
  ppcp_params.min_conn_interval = BLE_MIN_CONN_INTERVAL;
  ppcp_params.max_conn_interval = BLE_MAX_CONN_INTERVAL;
  ppcp_params.slave_latency = BLE_SLAVE_LATENCY;
  ppcp_params.conn_sup_timeout = BLE_CONN_SUP_TIMEOUT;
  
  uint32_t err_code = sd_ble_gap_ppcp_set(&ppcp_params);
  if (err_code == NRF_SUCCESS) {
    BLE_DEBUG_PRINTLN("PPCP set: %u-%ums interval, latency=%u, %ums timeout",
                     ppcp_params.min_conn_interval * 5 / 4,  // convert to ms (1.25ms units)
                     ppcp_params.max_conn_interval * 5 / 4,
                     ppcp_params.slave_latency,
                     ppcp_params.conn_sup_timeout * 10);  // convert to ms (10ms units)
  } else {
    BLE_DEBUG_PRINTLN("Failed to set PPCP: %lu", err_code);
  }
  
  Bluefruit.setTxPower(BLE_TX_POWER);
  Bluefruit.setName(dev_name);

  // Not Security.setPIN(): it turns Secure Connections off (lesc = 0), and Legacy pairing derives its
  // keys from the 6-digit passkey, so one recorded pairing gives away the key. The passkey goes
  // straight to the SoftDevice instead (setPasskey), only while the pairing window is open, and lesc
  // stays at Bluefruit's default (1 on the nRF52840, which has the CryptoCell for it)
  memset(ble_passkey, 0, sizeof(ble_passkey));
  if (strlen(charpin) == BLE_GAP_PASSKEY_LEN) memcpy(ble_passkey, charpin, BLE_GAP_PASSKEY_LEN);
  setPasskey(false);   // the window starts closed
  Bluefruit.Security.setMITM(true);
  Bluefruit.Security.setIOCaps(true, false, false);   // display only: the phone types the passkey
  Bluefruit.Security.setPairPasskeyCallback(onPairingPasskey);
  Bluefruit.Security.setPairCompleteCallback(onPairingComplete);

  Bluefruit.Periph.setConnectCallback(onConnect);
  Bluefruit.Periph.setDisconnectCallback(onDisconnect);
  Bluefruit.Security.setSecuredCallback(onSecured);

  Bluefruit.setEventCallback(onBLEEvent);

  bleuart.setPermission(SECMODE_ENC_WITH_MITM, SECMODE_ENC_WITH_MITM);
  bleuart.begin();
  bleuart.setRxCallback(onBleUartRX);

  // The fluxcore service, for the fluxcore app next to the MeshCore app on the same connection.
  // Same security as the UART service: only a paired (PIN) connection can write or subscribe
  fluxsvc.begin();
  fluxtx.setProperties(CHR_PROPS_NOTIFY);
  fluxtx.setPermission(SECMODE_ENC_WITH_MITM, SECMODE_NO_ACCESS);   // the subscription (CCCD) needs it too
  fluxtx.setMaxLen(MAX_FRAME_SIZE);
  fluxtx.begin();
  fluxrx.setProperties(CHR_PROPS_WRITE | CHR_PROPS_WRITE_WO_RESP);
  fluxrx.setPermission(SECMODE_NO_ACCESS, SECMODE_ENC_WITH_MITM);
  fluxrx.setMaxLen(MAX_FRAME_SIZE);
  fluxrx.setWriteCallback(onSideRX, true);
  fluxrx.begin();



  // Register DFU on the main BLE stack so paired clients can discover it
  // without switching the device into a separate OTA-only BLE mode first.
  bledfu.setPermission(SECMODE_ENC_WITH_MITM, SECMODE_ENC_WITH_MITM);
  bledfu.begin();

  Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
  Bluefruit.Advertising.addTxPower();
  Bluefruit.Advertising.addService(bleuart);

  Bluefruit.ScanResponse.addName();

  Bluefruit.Advertising.setInterval(BLE_ADV_INTERVAL_MIN, BLE_ADV_INTERVAL_MAX);
  Bluefruit.Advertising.setFastTimeout(BLE_ADV_FAST_TIMEOUT);

  Bluefruit.Advertising.restartOnDisconnect(true);

}

bool SerialBLEInterface::setPasskey(bool on) {
  ble_opt_t opt;
  memset(&opt, 0, sizeof(opt));
  // NULL: the SoftDevice picks a random passkey for each attempt, which nobody is shown
  opt.gap_opt.passkey.p_passkey = (on && ble_passkey[0]) ? (const uint8_t*)ble_passkey : NULL;
  _passkey_set_err = sd_ble_opt_set(BLE_GAP_OPT_PASSKEY, &opt);
  return _passkey_set_err == NRF_SUCCESS;
}

void SerialBLEInterface::openPairingWindow(uint32_t ms) {
  _pw_bonded = false;
  _pw_until = millis() + ms;
  if (!_pw_open) _pr_window = 1;
  setPasskey(true);
  _pw_open = true;
}

void SerialBLEInterface::closePairingWindow() {
  if (!_pw_open) return;
  _pw_open = false;
  setPasskey(false);
  _pr_window = 2;
}

void SerialBLEInterface::loop() {
  if (_pw_open && _pw_bonded) {
    closePairingWindow();
    _pr_window = 3;
  } else if (_pw_open && (long)(millis() - _pw_until) >= 0) {
    closePairingWindow();
  }
}

bool SerialBLEInterface::takePairingReport(char* out, size_t len, bool* isConsole) {
  *isConsole = false;
  if (_pr_pending) {
    _pr_pending = false;
    *isConsole = true;
    if (_pr_status == BLE_GAP_SEC_STATUS_SUCCESS) {
      static const char* const io_names[] = { "display", "display+yes/no", "keyboard", "no I/O", "keyboard+display" };
      const char* io = _pr_peer_seen && _pr_peer_io < 5 ? io_names[_pr_peer_io] : "?";
      snprintf(out, len, "Bluetooth: a new device paired (%s, %s, level %u%s). Its side: lesc=%u mitm=%u io=%s",
               _pr_lesc ? "Secure Connections" : "Legacy",
               _pr_lv >= 3 ? "PIN" : "no PIN",
               _pr_lv, _pr_bonded ? ", bonded" : ", not bonded",
               _pr_peer_lesc, _pr_peer_mitm, io);
    } else {
      bool wrong_pin = _pr_status == BLE_GAP_SEC_STATUS_PASSKEY_ENTRY_FAILED || _pr_status == BLE_GAP_SEC_STATUS_CONFIRM_VALUE;
      snprintf(out, len, "Bluetooth: a pairing attempt failed (%s, status 0x%02X)",
               wrong_pin ? "wrong PIN" : "not completed", _pr_status);
    }
    _pr_peer_seen = false;
    return true;
  }
  if (_pr_window) {
    uint8_t w = _pr_window;
    _pr_window = 0;
    if (w == 1) {
      snprintf(out, len, "Bluetooth pairing open for %lu s (passkey set: %s)", (unsigned long)(PAIRING_WINDOW_MS / 1000),
               _passkey_set_err == NRF_SUCCESS ? "ok" : "FAILED");
    } else {
      snprintf(out, len, "Bluetooth pairing closed%s (passkey cleared: %s)", w == 3 ? " after a new bond" : "",
               _passkey_set_err == NRF_SUCCESS ? "ok" : "FAILED");
    }
    return true;   // serial only: the console says what matters (a bond, a failure)
  }
  uint16_t refused = _pr_refused;
  if (refused != _pr_refused_told) {
    snprintf(out, len, "Bluetooth: pairing refused, the window is closed (%u so far)", (unsigned)refused);
    _pr_refused_told = refused;
    return true;   // serial only: anyone nearby can cause these
  }
  return false;
}

void SerialBLEInterface::clearBuffers() {
  send_queue_len = 0;
  recv_queue_len = 0;
  side_recv_tail = side_recv_head;
  side_send_len = 0;
  _last_retry_attempt = 0;
  bleuart.flush();
}

void SerialBLEInterface::shiftSendQueueLeft() {
  if (send_queue_len > 0) {
    send_queue_len--;
    for (uint8_t i = 0; i < send_queue_len; i++) {
      send_queue[i] = send_queue[i + 1];
    }
  }
}

void SerialBLEInterface::shiftRecvQueueLeft() {
  if (recv_queue_len > 0) {
    recv_queue_len--;
    for (uint8_t i = 0; i < recv_queue_len; i++) {
      recv_queue[i] = recv_queue[i + 1];
    }
  }
}

bool SerialBLEInterface::isValidConnection(uint16_t handle, bool requireWaitingForSecurity) const {
  if (_conn_handle != handle) {
    return false;
  }
  BLEConnection* conn = Bluefruit.Connection(handle);
  if (conn == nullptr || !conn->connected()) {
    return false;
  }
  if (requireWaitingForSecurity && _isDeviceConnected) {
    return false;
  }
  return true;
}

bool SerialBLEInterface::isAdvertising() const {
  ble_gap_addr_t adv_addr;
  uint32_t err_code = sd_ble_gap_adv_addr_get(0, &adv_addr);
  return (err_code == NRF_SUCCESS);
}

void SerialBLEInterface::enable() {
  if (_isEnabled) return;

  _isEnabled = true;
  clearBuffers();
  _last_health_check = millis();

  Bluefruit.Advertising.restartOnDisconnect(true);
  Bluefruit.Advertising.start(0);
}

void SerialBLEInterface::disconnect() {
  if (_conn_handle != BLE_CONN_HANDLE_INVALID) {
    sd_ble_gap_disconnect(_conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
  }
}

void SerialBLEInterface::disable() {
  _isEnabled = false;
  BLE_DEBUG_PRINTLN("SerialBLEInterface: disable");

  Bluefruit.Advertising.restartOnDisconnect(false);
  Bluefruit.Advertising.stop();
  disconnect();
  _last_health_check = 0;
}

size_t SerialBLEInterface::writeFrame(const uint8_t src[], size_t len) {
  if (len > MAX_FRAME_SIZE) {
    BLE_DEBUG_PRINTLN("writeFrame(), frame too big, len=%u", (unsigned)len);
    return 0;
  }

  bool connected = isConnected();
  if (connected && len > 0) {
    // Nothing ahead of it: send it now rather than on the next pass of the main loop, which may
    // first sleep until something else wakes it (a sync reply would wait out the loop for nothing)
    if (send_queue_len == 0 &&
        !(_last_retry_attempt > 0 && (millis() - _last_retry_attempt) < BLE_RETRY_THROTTLE_MS)) {
      size_t written = bleuart.write(src, len);
      if (written == len) {
        BLE_DEBUG_PRINTLN("writeBytes: sz=%u, hdr=%u (direct)", (unsigned)len, (unsigned)src[0]);
        _last_retry_attempt = 0;
        return len;
      } else if (written > 0) {
        BLE_DEBUG_PRINTLN("writeBytes: partial write, sent=%u of %u, dropping corrupted frame", (unsigned)written, (unsigned)len);
        _last_retry_attempt = 0;
        return 0;
      }
      _last_retry_attempt = millis();   // the stack's buffers are full: queue it, retry after the throttle
    }

    if (send_queue_len >= FRAME_QUEUE_SIZE) {
      BLE_DEBUG_PRINTLN("writeFrame(), send_queue is full!");
      return 0;
    }

    send_queue[send_queue_len].len = len;
    memcpy(send_queue[send_queue_len].buf, src, len);
    send_queue_len++;
    
    return len;
  }
  return 0;
}

size_t SerialBLEInterface::checkRecvFrame(uint8_t dest[]) {
  if (send_queue_len > 0) {
    if (!isConnected()) {
      BLE_DEBUG_PRINTLN("writeBytes: connection invalid, clearing send queue");
      send_queue_len = 0;
    } else {
      unsigned long now = millis();
      bool throttle_active = (_last_retry_attempt > 0 && (now - _last_retry_attempt) < BLE_RETRY_THROTTLE_MS);

      if (!throttle_active) {
        Frame frame_to_send = send_queue[0];

        size_t written = bleuart.write(frame_to_send.buf, frame_to_send.len);
        if (written == frame_to_send.len) {
          BLE_DEBUG_PRINTLN("writeBytes: sz=%u, hdr=%u", (unsigned)frame_to_send.len, (unsigned)frame_to_send.buf[0]);
          _last_retry_attempt = 0;
          shiftSendQueueLeft();
        } else if (written > 0) {
          BLE_DEBUG_PRINTLN("writeBytes: partial write, sent=%u of %u, dropping corrupted frame", (unsigned)written, (unsigned)frame_to_send.len);
          _last_retry_attempt = 0;
          shiftSendQueueLeft();
        } else {
          if (!isConnected()) {
            BLE_DEBUG_PRINTLN("writeBytes failed: connection lost, dropping frame");
            _last_retry_attempt = 0;
            shiftSendQueueLeft();
          } else {
            BLE_DEBUG_PRINTLN("writeBytes failed (buffer full), keeping frame for retry");
            _last_retry_attempt = now;
          }
        }
      }
    }
  }
  
  if (recv_queue_len > 0) {
    size_t len = recv_queue[0].len;
    memcpy(dest, recv_queue[0].buf, len);
    
    BLE_DEBUG_PRINTLN("readBytes: sz=%u, hdr=%u", (unsigned)len, (unsigned)dest[0]);
    
    shiftRecvQueueLeft();
    return len;
  }
  
  // Advertising watchdog: periodically check if advertising is running, restart if not.
  // Disconnected, or connected and paired (it advertises then too), not while a connection is set up
  unsigned long now = millis();
  if (_isEnabled && (_conn_handle == BLE_CONN_HANDLE_INVALID || isConnected())) {
    if (now - _last_health_check >= BLE_HEALTH_CHECK_INTERVAL) {
      _last_health_check = now;
      
      if (!isAdvertising()) {
        BLE_DEBUG_PRINTLN("SerialBLEInterface: advertising watchdog - advertising stopped, restarting");
        Bluefruit.Advertising.start(0);
      }
    }
  }
  
  return 0;
}

void SerialBLEInterface::onBleUartRX(uint16_t conn_handle) {
  if (!instance) {
    return;
  }
  
  if (instance->_conn_handle != conn_handle || !instance->isConnected()) {
    while (instance->bleuart.available() > 0) {
      instance->bleuart.read();
    }
    return;
  }
  
  while (instance->bleuart.available() > 0) {
    if (instance->recv_queue_len >= FRAME_QUEUE_SIZE) {
      while (instance->bleuart.available() > 0) {
        instance->bleuart.read();
      }
      BLE_DEBUG_PRINTLN("onBleUartRX: recv queue full, dropping data");
      break;
    }
    
    int avail = instance->bleuart.available();
    
    if (avail > MAX_FRAME_SIZE) {
      BLE_DEBUG_PRINTLN("onBleUartRX: WARN: BLE RX overflow, avail=%d, draining all", avail);
      uint8_t drain_buf[BLE_RX_DRAIN_BUF_SIZE];
      while (instance->bleuart.available() > 0) {
        int chunk = instance->bleuart.available() > BLE_RX_DRAIN_BUF_SIZE ? BLE_RX_DRAIN_BUF_SIZE : instance->bleuart.available();
        instance->bleuart.readBytes(drain_buf, chunk);
      }
      continue;
    }
    
    int read_len = avail;
    instance->recv_queue[instance->recv_queue_len].len = read_len;
    instance->bleuart.readBytes(instance->recv_queue[instance->recv_queue_len].buf, read_len);
    BLE_DEBUG_PRINTLN("rx: sz=%u, hdr=%u", (unsigned)read_len, (unsigned)instance->recv_queue[instance->recv_queue_len].buf[0]);
    instance->recv_queue_len++;
  }
}

bool SerialBLEInterface::isConnected() const {
  return _isDeviceConnected && Bluefruit.connected() > 0;
}

bool SerialBLEInterface::isWriteBusy() const {
  return send_queue_len >= (FRAME_QUEUE_SIZE * 2 / 3);
}

bool SerialBLEInterface::hasPendingWrite() const {
  if (!isConnected()) return false;
  if (side_send_len > 0) return true;
  if (send_queue_len == 0) return false;
  // waiting out the retry throttle: nothing to do until it ends, so sleeping is fine
  return !(_last_retry_attempt > 0 && (millis() - _last_retry_attempt) < BLE_RETRY_THROTTLE_MS);
}

// ---------- the fluxcore service

void SerialBLEInterface::onSideRX(uint16_t conn_hdl, BLECharacteristic* chr, uint8_t* data, uint16_t len) {
  (void)chr;
  if (!instance || instance->_conn_handle != conn_hdl || !instance->isConnected()) return;
  if (len == 0 || len > MAX_FRAME_SIZE) return;
  uint8_t head = instance->side_recv_head;
  uint8_t next = (head + 1) % SIDE_QUEUE_SIZE;
  if (next == instance->side_recv_tail) {
    BLE_DEBUG_PRINTLN("onSideRX: queue full, dropping frame");
    return;
  }
  instance->side_recv[head].len = len;
  memcpy(instance->side_recv[head].buf, data, len);
  instance->side_recv_head = next;
}

size_t SerialBLEInterface::writeSideFrame(const uint8_t src[], size_t len) {
  if (len == 0 || len > MAX_FRAME_SIZE || !isConnected() || side_send_len >= SIDE_QUEUE_SIZE) return 0;
  side_send[side_send_len].len = len;
  memcpy(side_send[side_send_len].buf, src, len);
  side_send_len++;
  return len;
}

size_t SerialBLEInterface::checkRecvSideFrame(uint8_t dest[]) {
  if (side_send_len > 0) {
    if (!isConnected() || !fluxtx.notifyEnabled(_conn_handle)) {
      side_send_len = 0;   // nobody to tell
    } else if (fluxtx.notify(_conn_handle, side_send[0].buf, side_send[0].len)) {
      side_send_len--;
      for (uint8_t i = 0; i < side_send_len; i++) side_send[i] = side_send[i + 1];
    }   // else: the stack's buffers are full, try again next time
  }
  uint8_t tail = side_recv_tail;
  if (tail == side_recv_head) return 0;
  size_t len = side_recv[tail].len;
  memcpy(dest, side_recv[tail].buf, len);
  side_recv_tail = (tail + 1) % SIDE_QUEUE_SIZE;
  return len;
}
