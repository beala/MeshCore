#pragma once

#include <Arduino.h>

#define MAX_FRAME_SIZE  176   // +4 for transport codes (region scoping)
#define PAIRING_WINDOW_MS  60000UL   // how long the Bluetooth pairing window stays open

class BaseSerialInterface {
protected:
  BaseSerialInterface() { }

public:
  virtual void enable() = 0;
  virtual void disable() = 0;
  virtual bool isEnabled() const = 0;

  virtual bool isConnected() const = 0;
  virtual void loop() {};

  virtual bool isWriteBusy() const = 0;
  virtual size_t writeFrame(const uint8_t src[], size_t len) = 0;
  virtual size_t checkRecvFrame(uint8_t dest[]) = 0;
  // frames written but not yet handed to the transport: the main loop shouldn't sleep on them
  virtual bool hasPendingWrite() const { return false; }

  // A second channel on the same connection, for an app next to the MeshCore app (the fluxcore app):
  // its own frames in and out, so neither app sees the other's. Bluetooth only; others have none.
  virtual size_t checkRecvSideFrame(uint8_t dest[]) { (void)dest; return 0; }
  virtual size_t writeSideFrame(const uint8_t src[], size_t len) { (void)src; (void)len; return 0; }

  // The pairing window (docs/ble_pairing.md): a new Bluetooth bond only while it's open, opened at the
  // radio. Only nRF52 gates pairing so far; elsewhere these do nothing and pairing works as before.
  virtual bool hasPairingWindow() const { return false; }
  virtual void openPairingWindow(uint32_t ms) { (void)ms; }
  virtual void closePairingWindow() { }
  virtual bool isPairingWindowOpen() const { return false; }
};

// The fluxcore service: frames in (written to RX) and out (notified on TX), as on the UART service
#define FLUX_SERVICE_UUID  "f1c00001-8a5d-4c75-b0c2-666c7578636f"
#define FLUX_RX_UUID       "f1c00002-8a5d-4c75-b0c2-666c7578636f"
#define FLUX_TX_UUID       "f1c00003-8a5d-4c75-b0c2-666c7578636f"
