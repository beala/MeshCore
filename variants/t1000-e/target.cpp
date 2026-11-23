#include <Arduino.h>
#include "t1000e_sensors.h"
#include "target.h"
#include <helpers/sensors/AirohaGpsDriver.h>
#include <helpers/sensors/MicroNMEALocationProvider.h>

T1000eBoard board;

RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);

WRAPPER_CLASS radio_driver(radio, board);

VolatileRTCClock rtc_clock;
AirohaGpsDriver gps_driver(Serial1);
MicroNMEALocationProvider nmea(gps_driver, &rtc_clock);
T1000SensorManager sensors(nmea, gps_driver);

#ifdef MOTION_WAKE_QMA6100P
QMA6100P motion;
MotionState motion_state;

static void onMotionIrq() { motion_state.irqs++; }

bool motion_begin() {
  digitalWrite(PIN_3V3_ACC_EN, HIGH);   // accelerometer power
  delay(10);
  motion_state.ok = motion.beginMotionWake(motion_state.threshold, motion_state.samples);
  if (motion_state.ok) {
    pinMode(QMA_6100P_INT_PIN, INPUT);  // INT1 is push-pull
    attachInterrupt(digitalPinToInterrupt(QMA_6100P_INT_PIN), onMotionIrq, RISING);
  }
  return motion_state.ok;
}

// Accelerometer unpowered (geofence off): no motion events
void motion_end() {
  detachInterrupt(digitalPinToInterrupt(QMA_6100P_INT_PIN));
  pinMode(QMA_6100P_INT_PIN, INPUT_PULLDOWN);   // don't float while the chip has no power
  digitalWrite(PIN_3V3_ACC_EN, LOW);
  motion_state.ok = false;
}

uint32_t motion_events() { return motion_state.events; }

// User button (active high, pulled down by the board): counted in the interrupt so a short
// press is not missed while the loop sleeps between passes. Presses closer than 300 ms are one.
static volatile uint32_t button_count = 0;
static volatile uint32_t button_last_ms = 0;
static void onButtonIrq() {
  const uint32_t now = millis();
  if (button_count == 0 || now - button_last_ms >= 300) button_count++;
  button_last_ms = now;
}
void button_begin() {
  attachInterrupt(digitalPinToInterrupt(PIN_USER_BTN), onButtonIrq, RISING);
}
uint32_t button_presses() { return button_count; }

// Only if open: Uart::end() waits for the UART's stop events, which a disabled UART never
// sends, so a second end() hangs (the loop watchdog rebooted the board, bench 2026-11-23).
// Serial1 is UARTE0 in the Adafruit core.
void gps_serial_end() {
  if (NRF_UARTE0->ENABLE != UARTE_ENABLE_ENABLE_Disabled) Serial1.end();
}
#endif

#ifdef DISPLAY_CLASS
  NullDisplayDriver display;
  UITask ui_task(&board, &display);
#endif

#ifndef LORA_CR
  #define LORA_CR      5
#endif

#ifdef RF_SWITCH_TABLE
static const uint32_t rfswitch_dios[Module::RFSWITCH_MAX_PINS] = {
  RADIOLIB_LR11X0_DIO5,
  RADIOLIB_LR11X0_DIO6,
  RADIOLIB_LR11X0_DIO7,
  RADIOLIB_LR11X0_DIO8, 
  RADIOLIB_NC
};

static const Module::RfSwitchMode_t rfswitch_table[] = {
  // mode                 DIO5  DIO6  DIO7  DIO8
  { LR11x0::MODE_STBY,   {LOW,  LOW,  LOW,  LOW  }},  
  { LR11x0::MODE_RX,     {HIGH, LOW,  LOW,  HIGH }},
  { LR11x0::MODE_TX,     {HIGH, HIGH, LOW,  HIGH }},
  { LR11x0::MODE_TX_HP,  {LOW,  HIGH, LOW,  HIGH }},
  { LR11x0::MODE_TX_HF,  {LOW,  LOW,  LOW,  LOW  }}, 
  { LR11x0::MODE_GNSS,   {LOW,  LOW,  HIGH, LOW  }},
  { LR11x0::MODE_WIFI,   {LOW,  LOW,  LOW,  LOW  }},  
  END_OF_MODE_TABLE,
};
#endif

bool radio_init() {
  //rtc_clock.begin(Wire);
  
#ifdef LR11X0_DIO3_TCXO_VOLTAGE
  float tcxo = LR11X0_DIO3_TCXO_VOLTAGE;
#else
  float tcxo = 1.6f;
#endif

  SPI.setPins(P_LORA_MISO, P_LORA_SCLK, P_LORA_MOSI);
  SPI.begin();
  int status = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR, RADIOLIB_LR11X0_LORA_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo);
  if (status != RADIOLIB_ERR_NONE) {
    Serial.print("ERROR: radio init failed: ");
    Serial.println(status);
    return false;  // fail
  }
  
  radio.setCRC(2);
  radio.explicitHeader();

#ifdef RF_SWITCH_TABLE
  radio.setRfSwitchTable(rfswitch_dios, rfswitch_table);
#endif
#ifdef RX_BOOSTED_GAIN
  radio.setRxBoostedGainMode(RX_BOOSTED_GAIN);
#endif

  return true;  // success
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}

void T1000SensorManager::start_gps() {
  _nmea->setGpsOn(true);
}

void T1000SensorManager::stop_gps() {
  _nmea->setGpsOn(false);
}


bool T1000SensorManager::begin() {
  _gps_driver->initialize();
#ifdef MOTION_WAKE_QMA6100P
  button_begin();   // the accelerometer is powered only while the geofence is on (motion_begin)
#endif
  return true;
}

bool T1000SensorManager::querySensors(uint8_t requester_permissions, CayenneLPP& telemetry) {
  if (requester_permissions & TELEM_PERM_LOCATION) {   // does requester have permission?
    telemetry.addGPS(TELEM_CHANNEL_SELF, node_lat, node_lon, node_altitude);
  }
  if (requester_permissions & TELEM_PERM_ENVIRONMENT) {
    // Firmware reports light as a 0-100 % scale, but expose it via Luminosity so app labels it "Luminosity".
    telemetry.addLuminosity(TELEM_CHANNEL_SELF, t1000e_get_light());
    telemetry.addTemperature(TELEM_CHANNEL_SELF, t1000e_get_temperature());
  }
  return true;
}

void T1000SensorManager::loop() {
  static uint32_t last_gps_update = 0;
#ifdef MOTION_WAKE_QMA6100P
  static uint32_t seen_irqs = 0;

  // INT1 is latched: read INT_ST0 to clear it, so the next motion gives a new edge
  if (motion_state.ok && (motion_state.irqs != seen_irqs || digitalRead(QMA_6100P_INT_PIN) == HIGH)) {
    seen_irqs = motion_state.irqs;
    uint8_t st0;
    if (motion.readAndClear(st0)) {
      motion_state.events++;
      motion_state.last_ms = millis();
      motion_state.last_st0 = st0;
    }
  }
#endif
  constexpr uint32_t GPS_UPDATE_INTERVAL_MS = 1000;

  _nmea->loop();

  if ((uint32_t)(millis() - last_gps_update) >= GPS_UPDATE_INTERVAL_MS) {
    if (_nmea->isGpsOn() && _nmea->hasValidFix()) {
      node_lat = ((double)_nmea->getLatitude())/1000000.;
      node_lon = ((double)_nmea->getLongitude())/1000000.;
      node_altitude = ((double)_nmea->getAltitude()) / 1000.0;
    }
    last_gps_update = millis();
  }
}

int T1000SensorManager::getNumSettings() const { return 1; }  // just one supported: "gps" (power switch)

const char* T1000SensorManager::getSettingName(int i) const {
  return i == 0 ? "gps" : NULL;
}
const char* T1000SensorManager::getSettingValue(int i) const {
  if (i == 0) {
    return _nmea->isGpsOn() ? "1" : "0";
  }
  return NULL;
}
bool T1000SensorManager::setSettingValue(const char* name, const char* value) {
  if (strcmp(name, "gps") == 0) {
    if (strcmp(value, "0") == 0) {
      stop_gps();
    } else {
      start_gps();
    }
    return true;
  }
  return false;  // not supported
}
