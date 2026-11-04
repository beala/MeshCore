#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>

AbLabsNiceRFLR2021Board board;

#ifndef PIN_USER_BTN
  #define PIN_USER_BTN (-1)
#endif

#ifdef DISPLAY_CLASS
  DISPLAY_CLASS display;
  MomentaryButton user_btn(PIN_USER_BTN, 1000, true, true);

  #if defined(PIN_USER_BTN_ANA)
  MomentaryButton analog_btn(PIN_USER_BTN_ANA, 1000, 20);
  #endif
#endif

RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);

WRAPPER_CLASS radio_driver(radio, board);

VolatileRTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);

EnvironmentSensorManager sensors;

// LoRa2021F33-2G4 front-end control, from the NiceRF block diagram.
// The LR2021 drives these itself in RF-switch mode, per radio state:
//   DIO5: 2.4 GHz FEM LNA_EN   (HIGH = LNA on; LOW = bypass, -12 dB sensitivity)
//   DIO6: sub-GHz TXEN         (antenna switch to the 5V 2W PA)
//   DIO7: 2.4 GHz Power_EN     (PMOS switch feeding VCC to the 2.4 GHz FEM)
//   DIO8: 2.4 GHz TXEN         (FEM PA)
// The module's IRQ pin is one of the remaining DIOs (see LR2021_IRQ_DIO).
static const uint32_t rfswitch_dios[Module::RFSWITCH_MAX_PINS] = {
  RADIOLIB_LR2021_DIO5,
  RADIOLIB_LR2021_DIO6,
  RADIOLIB_LR2021_DIO7,
  RADIOLIB_LR2021_DIO8,
  RADIOLIB_NC,
};

static const Module::RfSwitchMode_t rfswitch_table[] = {
  //                    DIO5  DIO6  DIO7  DIO8
  { LR2021::MODE_STBY,  { LOW,  LOW,  LOW,  LOW  } },  // everything off
  { LR2021::MODE_RX,    { LOW,  LOW,  LOW,  LOW  } },  // sub-GHz RX path, 2.4G FEM unpowered
  { LR2021::MODE_TX,    { LOW,  HIGH, LOW,  LOW  } },  // sub-GHz TX through the 2W PA
  { LR2021::MODE_RX_HF, { HIGH, LOW,  HIGH, LOW  } },  // 2.4G FEM powered, LNA on
  { LR2021::MODE_TX_HF, { LOW,  LOW,  HIGH, HIGH } },  // 2.4G FEM powered, PA on
  END_OF_MODE_TABLE,
};

// Sub-GHz PA config from the NiceRF demo code (LF PA, duty cycle 7, 6 slices),
// with TxPower = 2 * dBm (0.5 dB steps). This is the setup NiceRF's datasheet
// power table was measured with, so "drive N dBm" == "register value 2N" there.
// (RadioLib's default table varies duty cycle/slices per level instead.)
static LR2021PaTableEntry_t pa_table_lf[RADIOLIB_LR2021_PA_TABLE_LEN];

bool radio_init() {
  rtc_clock.begin(Wire);

  for (int i = 0; i < RADIOLIB_LR2021_PA_TABLE_LEN; i++) {  // entry i is -9 + i dBm
    pa_table_lf[i].paDutyCycle = 7;
    pa_table_lf[i].paSlices = 6;
    pa_table_lf[i].paVal = 2 * (i - 9);
  }
  radio.setPaTable(pa_table_lf, false);

  if (!radio.std_init(&SPI)) return false;

  radio.setRfSwitchTable(rfswitch_dios, rfswitch_table);
  return true;
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}
