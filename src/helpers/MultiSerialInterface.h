#pragma once

#include "BaseSerialInterface.h"

#ifndef MAX_INTERFACES
  // ble, usb, wifi, ethernet
  #define MAX_INTERFACES 4
#endif

enum class InterfaceType : uint8_t {
  NONE,
  Bluetooth,
  USB,
  WiFi,
  Ethernet,
  HardwareSerial
};

class MultiSerialInterface : public BaseSerialInterface {
private:

  struct RegisteredInterface {
    InterfaceType type = InterfaceType::NONE;
    BaseSerialInterface* instance = nullptr;
  };

  bool _enabled = false;
  RegisteredInterface _interfaces[MAX_INTERFACES] = {};

public:
  bool addInterface(InterfaceType type, BaseSerialInterface* iface) {
    // make sure an interface was provided
    if(iface == nullptr){
      return false;
    }

    // put it in the first free slot
    for(int i = 0; i < MAX_INTERFACES; i++){
      if(_interfaces[i].instance == nullptr){
        _interfaces[i].instance = iface;
        _interfaces[i].type = type;
        return true;
      }
    }

    // no free slots available
    return false;
  }

  bool removeInterface(BaseSerialInterface* iface) {
    // make sure an interface was provided
    if(iface == nullptr){
      return false;
    }

    // find and remove interface
    for(int i = 0; i < MAX_INTERFACES; i++){
      if(_interfaces[i].instance == iface){
        _interfaces[i] = {};
        return true;
      }
    }

    // interface not found
    return false;
  }

  void enableBluetooth() {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth){
        iface.instance->enable();
      }
    }
  }

  void disableBluetooth() {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth){
        iface.instance->disable();
      }
    }
  }

  bool hasPairingWindow() const override {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth && iface.instance->hasPairingWindow()) return true;
    }
    return false;
  }
  void openPairingWindow(uint32_t ms) override {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth) iface.instance->openPairingWindow(ms);
    }
  }
  void closePairingWindow() override {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth) iface.instance->closePairingWindow();
    }
  }
  bool isPairingWindowOpen() const override {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth && iface.instance->isPairingWindowOpen()) return true;
    }
    return false;
  }

  bool isBluetoothEnabled() {
    for(auto iface : _interfaces){
      if(iface.instance && iface.type == InterfaceType::Bluetooth){
        return iface.instance->isEnabled();
      }
    }
    return false; 
  }

  // enable all interfaces
  void enable() override {
    _enabled = true;
    for(auto iface : _interfaces){
      if(iface.instance){
        iface.instance->enable();
      }
    }
  }

  // disable all interfaces
  void disable() override {
    _enabled = false;
    for(auto iface : _interfaces){
      if(iface.instance){
        iface.instance->disable();
      }
    }
  }

  bool isEnabled() const override { 
    return _enabled; 
  }

  bool isConnected() const override {
    // not connected when disabled
    if(!_enabled){
      return false;
    }
    
    // check if any interface is connected
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isConnected()) {
        return true;
      }
    }

    // nothing connected
    return false;
  }

  // loop all interfaces
  void loop() override {
    for(auto iface : _interfaces){
      if(iface.instance){
        iface.instance->loop();
      }
    }
  }

  void setLedEnabled(bool enabled) override {
    for(auto iface : _interfaces){
      if(iface.instance){
        iface.instance->setLedEnabled(enabled);
      }
    }
  }

  bool isWriteBusy() const override {
    // not busy when disabled
    if(!_enabled){
      return false;
    }

    // check if any interface is busy
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled() && iface.instance->isWriteBusy()){
        return true;
      }
    }

    // nothing busy
    return false;
  }

  size_t writeFrame(const uint8_t src[], size_t len) override {
    // don't write when disabled or nothing provided
    if(!_enabled || len == 0){
      return 0;
    }

    // write frame to all enabled interfaces
    bool allSuccessful = true;
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled()){
        if(iface.instance->writeFrame(src, len) != len){
          allSuccessful = false;
        }
      }
    }

    // report success if all writes completed successfully
    return allSuccessful ? len : 0; 
  }

  size_t checkRecvFrame(uint8_t dest[]) override {
    // don't read when disabled
    if(!_enabled){
      return 0;
    }

    // try to read a frame from any enabled interface
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled()){
        size_t frameSize = iface.instance->checkRecvFrame(dest);
        if(frameSize > 0){
          return frameSize; 
        }
      }
    }

    // no frame received
    return 0;
  }

  bool hasPendingWrite() const override {
    if(!_enabled){
      return false;
    }
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled() && iface.instance->hasPendingWrite()) return true;
    }
    return false;
  }

  // the latest frame in from any of them
  unsigned long lastRecvMillis() const override {
    unsigned long latest = 0;
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled()){
        unsigned long t = iface.instance->lastRecvMillis();
        if(t != 0 && (latest == 0 || (long)(t - latest) > 0)) latest = t;
      }
    }
    return latest;
  }

  // the connected one's link (Bluetooth is the only one that describes it)
  void describeLink(char* out, size_t len) const override {
    if(len) out[0] = 0;
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled() && iface.instance->isConnected()){
        iface.instance->describeLink(out, len);
        if(len && out[0]) return;
      }
    }
  }

  // the second channel (BaseSerialInterface::checkRecvSideFrame): only Bluetooth has one, and
  // the others' do nothing, so ask and answer them all
  size_t checkRecvSideFrame(uint8_t dest[]) override {
    if(!_enabled){
      return 0;
    }
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled()){
        size_t frameSize = iface.instance->checkRecvSideFrame(dest);
        if(frameSize > 0){
          return frameSize;
        }
      }
    }
    return 0;
  }

  size_t writeSideFrame(const uint8_t src[], size_t len) override {
    if(!_enabled || len == 0){
      return 0;
    }
    size_t written = 0;
    for(auto iface : _interfaces){
      if(iface.instance && iface.instance->isEnabled() && iface.instance->writeSideFrame(src, len) == len){
        written = len;
      }
    }
    return written;
  }

};
