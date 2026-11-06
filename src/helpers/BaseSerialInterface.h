#pragma once

#include <Arduino.h>

#define MAX_FRAME_SIZE  176   // +4 for transport codes (region scoping)

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

  // A second channel on the same connection, for an app next to the MeshCore app (the fluxcore app):
  // its own frames in and out, so neither app sees the other's. Bluetooth only; others have none.
  virtual size_t checkRecvSideFrame(uint8_t dest[]) { (void)dest; return 0; }
  virtual size_t writeSideFrame(const uint8_t src[], size_t len) { (void)src; (void)len; return 0; }
};

// The fluxcore service: frames in (written to RX) and out (notified on TX), as on the UART service
#define FLUX_SERVICE_UUID  "f1c00001-8a5d-4c75-b0c2-666c7578636f"
#define FLUX_RX_UUID       "f1c00002-8a5d-4c75-b0c2-666c7578636f"
#define FLUX_TX_UUID       "f1c00003-8a5d-4c75-b0c2-666c7578636f"
