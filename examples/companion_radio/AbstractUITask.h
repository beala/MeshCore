#pragma once

#include <MeshCore.h>
#include <helpers/ui/DisplayDriver.h>
#include <helpers/ui/UIScreen.h>
#include <helpers/SensorManager.h>
#include <helpers/MultiSerialInterface.h>
#include <Arduino.h>

#ifdef PIN_BUZZER
  #include <helpers/ui/buzzer.h>
#endif

#include "NodePrefs.h"
#include "MyMesh.h"

enum class UIEventType {
    none,
    contactMessage,
    channelMessage,
    roomMessage,
    newContactMessage,
    ack
};

#if defined(PIN_BUZZER) || defined(HAS_DRV2605) || defined(PIN_VIBRATION)
  #define HAS_FIND_ME 1
#endif

// 'find me': three short high beeps, then a pause, repeated
#define FIND_ME_TUNE  "FindMe:d=8,o=7,b=200:e,p,e,p,e,2p"

class AbstractUITask : public MyMesh::Listener {
protected:
  mesh::MainBoard* _board;
  MultiSerialInterface* _interfaceManager;
  unsigned long _find_start = 0, _find_ms = 0;

  // true while 'find me' is running: beep and vibrate, even if they're turned off
  bool isFindingMe() {
    if (_find_ms != 0 && millis() - _find_start >= _find_ms) _find_ms = 0;
    return _find_ms != 0;
  }

  AbstractUITask(mesh::MainBoard* board, MultiSerialInterface* interfaceManager) : _board(board), _interfaceManager(interfaceManager) {
  }

public:
  bool hasConnection() const { return _interfaceManager->isConnected(); }
  uint16_t getBattMilliVolts() const { return _board->getBattMilliVolts(); }
  bool isBluetoothEnabled() const { return _interfaceManager->isBluetoothEnabled(); }
  void enableBluetooth() { _interfaceManager->enableBluetooth(); }
  void disableBluetooth() { _interfaceManager->disableBluetooth(); }

  bool startFindMe(uint32_t secs) override {
#ifdef HAS_FIND_ME
    _find_start = millis();
    _find_ms = secs * 1000UL;
    return true;
#else
    return false;
#endif
  }
  bool stopFindMe() override {
    bool was = isFindingMe();
    _find_ms = 0;
    return was;
  }

  virtual void notify(UIEventType t = UIEventType::none) = 0;
  virtual void loop() = 0;
};
