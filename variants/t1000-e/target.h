#pragma once

#define RADIOLIB_STATIC_ONLY 1
#include <RadioLib.h>
#include <helpers/radiolib/RadioLibWrappers.h>
#include "T1000eBoard.h"
#include <helpers/radiolib/CustomLR1110Wrapper.h>
#include <helpers/ArduinoHelpers.h>
#include <helpers/SensorManager.h>
#include <helpers/sensors/LocationProvider.h>
#ifdef DISPLAY_CLASS
  #include "NullDisplayDriver.h"
  #include <UITask.h>
#endif

class AirohaGpsDriver;

class T1000SensorManager: public SensorManager {
  LocationProvider * _nmea;
  AirohaGpsDriver* _gps_driver;

  void start_gps();
  void sleep_gps();
  void stop_gps();
public:
  T1000SensorManager(LocationProvider &nmea, AirohaGpsDriver& gps_driver)
    : _nmea(&nmea), _gps_driver(&gps_driver) { }
  bool begin() override;
  bool querySensors(uint8_t requester_permissions, CayenneLPP& telemetry) override;
  void loop() override;
  int getNumSettings() const override;
  const char* getSettingName(int i) const override;
  const char* getSettingValue(int i) const override;
  bool setSettingValue(const char* name, const char* value) override;
  LocationProvider* getLocationProvider() { return _nmea; }
};

#ifdef DISPLAY_CLASS
  extern NullDisplayDriver display;
  extern UITask ui_task;
#endif

#ifdef MOTION_WAKE_QMA6100P
#include <helpers/sensors/QMA6100P.h>
// Accelerometer motion wake (QMA6100P on INT1 = QMA_6100P_INT_PIN)
struct MotionState {
  bool ok = false;
  uint8_t threshold = 4;        // ANY_MOT_TH, x 16 LSB of slope
  uint8_t samples = 2;          // samples above the threshold
  volatile uint32_t irqs = 0;   // INT1 rising edges
  uint32_t events = 0;          // latched any-motion events read back
  uint32_t last_ms = 0;
  uint8_t last_st0 = 0;
};
extern QMA6100P motion;
extern MotionState motion_state;
bool motion_begin();       // powers the accelerometer and arms the any-motion interrupt
void motion_end();         // powers it off
uint32_t motion_events();  // count of motion events so far
void button_begin();
uint32_t button_presses(); // count of user button presses so far
void gps_serial_end();     // close the GPS UART (GPS already off): starting the GPS reopens it
#endif

extern T1000eBoard board;
extern WRAPPER_CLASS radio_driver;
extern VolatileRTCClock rtc_clock;
extern T1000SensorManager sensors;

bool radio_init();
mesh::LocalIdentity radio_new_identity();
