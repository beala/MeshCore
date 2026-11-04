/*
  Copyright (c) 2014-2015 Arduino LLC.  All right reserved.
  Copyright (c) 2016 Sandeep Mistry All right reserved.
  Copyright (c) 2018, Adafruit Industries (adafruit.com)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
  See the GNU Lesser General Public License for more details.
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _VARIANT_AB_LABS_WISBLOCK_NICERF_LR2021F33_2G4_
#define _VARIANT_AB_LABS_WISBLOCK_NICERF_LR2021F33_2G4_

#define RAK4630

/** Master clock frequency */
#define VARIANT_MCK (64000000ul)

#define USE_LFXO // Board uses 32khz crystal for LF
// define USE_LFRC    // Board uses RC for LF

/*----------------------------------------------------------------------------
 *        Headers
 *----------------------------------------------------------------------------*/

#include "WVariant.h"

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

// Number of pins defined in PinDescription array
#define PINS_COUNT (48)
#define NUM_DIGITAL_PINS (48)
#define NUM_ANALOG_INPUTS (6)
#define NUM_ANALOG_OUTPUTS (0)

// LEDs
#define PIN_LED1 (35)
#define PIN_LED2 (36)

#define LED_BUILTIN PIN_LED1
#define LED_CONN PIN_LED2

#define LED_GREEN PIN_LED1
#define LED_BLUE PIN_LED2

#define LED_STATE_ON 1 // State when LED is litted

/*
 * Analog pins
 */
#define PIN_A0 (5)	//(3)
#define PIN_A1 (31) //(4)
#define PIN_A2 (28)
#define PIN_A3 (29)
#define PIN_A4 (30)
#define PIN_A5 (31)
#define PIN_A6 (0xff)
#define PIN_A7 (0xff)

	static const uint8_t A0 = PIN_A0;
	static const uint8_t A1 = PIN_A1;
	static const uint8_t A2 = PIN_A2;
	static const uint8_t A3 = PIN_A3;
	static const uint8_t A4 = PIN_A4;
	static const uint8_t A5 = PIN_A5;
	static const uint8_t A6 = PIN_A6;
	static const uint8_t A7 = PIN_A7;
#define ADC_RESOLUTION 14

// Power management boot protection threshold (millivolts)
// Set to 0 to disable boot protection
#define PWRMGT_VOLTAGE_BOOTLOCK 3300   // Won't boot below this voltage (mV)
// LPCOMP wake configuration (voltage recovery from SYSTEMOFF)
// AIN3 = P0.05 = PIN_A0 / PIN_VBAT_READ
#define PWRMGT_LPCOMP_AIN 3
#define PWRMGT_LPCOMP_REFSEL 4  // 5/8 VDD (~3.13-3.44V)

// Other pins
#define WB_I2C1_SDA (13) // SENSOR_SLOT IO_SLOT
#define WB_I2C1_SCL (14) // SENSOR_SLOT IO_SLOT

#define PIN_AREF (2)
#define PIN_NFC1 (9)
#define WB_IO5 PIN_NFC1
#define WB_IO4 (4)
#define PIN_NFC2 (10)

static const uint8_t AREF = PIN_AREF;

/*
 * Serial interfaces
 */
// TXD1 RXD1 on Base Board
#define PIN_SERIAL1_RX (15)
#define PIN_SERIAL1_TX (16)

// Connected to Jlink CDC
#define PIN_SERIAL2_RX (8)
#define PIN_SERIAL2_TX (6)

/*
 * SPI Interfaces
 */
#define SPI_INTERFACES_COUNT 2

#define PIN_SPI_MISO (45)
#define PIN_SPI_MOSI (44)
#define PIN_SPI_SCK (43)

#define PIN_SPI1_MISO (29)
#define PIN_SPI1_MOSI (30)
#define PIN_SPI1_SCK (3)

	static const uint8_t SS = 42;
	static const uint8_t MOSI = PIN_SPI_MOSI;
	static const uint8_t MISO = PIN_SPI_MISO;
	static const uint8_t SCK = PIN_SPI_SCK;

/*
 * Wire Interfaces
 */
#define WIRE_INTERFACES_COUNT 1

#define PIN_WIRE_SDA (WB_I2C1_SDA)
#define PIN_WIRE_SCL (WB_I2C1_SCL)

// QSPI Pins
// QSPI occupied by GPIO's
#define PIN_QSPI_SCK 3
#define PIN_QSPI_CS 26
#define PIN_QSPI_IO0 30
#define PIN_QSPI_IO1 29
#define PIN_QSPI_IO2 28
#define PIN_QSPI_IO3 2

// On-board QSPI Flash
// No onboard flash
#define EXTERNAL_FLASH_DEVICES IS25LP080D
#define EXTERNAL_FLASH_USE_QSPI

// NiceRF LoRa2021F33-2G4 (Semtech LR2021 + 2W sub-GHz PA + 1W 2.4 GHz FEM)
// on an AB Labs WisBlock IO-slot carrier.
//
// Carrier wiring (WisBlock IO slot -> module):
//   SPI_CS   (P0.26) -> NSS
//   SPI_CLK  (P0.03) -> SCK
//   SPI_MISO (P0.29) -> MISO
//   SPI_MOSI (P0.30) -> MOSI
//   IO1      (P0.17) -> CE     (module's internal 3.3V LDO enable; LOW = module off)
//   IO2      (P1.02) -> BOOST_EN (also the base board's 3V3_S enable)
//   IO4      (P0.04) -> RESET
//   IO5      (P0.09) -> BUSY
//   IO6      (P0.10) -> IRQ
// The module's VCC comes from a TPS61023 boost (VBAT -> ~5V) on the carrier.
//
// The external PA / LNA / antenna switches are driven by LR2021 DIO5..DIO8 in
// RF-switch mode (see target.cpp), so TX/RX switching is done by the radio itself.
#define USE_LR2021
#define LR2021_CS (26)
#define LR2021_IRQ (10)
#define LR2021_BUSY (9)
#define LR2021_RESET (4)
#define LR2021_CE (17)              // WB_IO1 -> module CE (internal LDO enable)

#define P_LORA_SCLK PIN_SPI1_SCK
#define P_LORA_MISO PIN_SPI1_MISO
#define P_LORA_MOSI PIN_SPI1_MOSI
#define P_LORA_NSS LR2021_CS
#define P_LORA_DIO_1 LR2021_IRQ
#define P_LORA_BUSY LR2021_BUSY
#define P_LORA_RESET LR2021_RESET
#define P_LORA_CE LR2021_CE

// enables 3.3V periphery like GPS or IO Module, and the carrier's 5V boost (BOOST_EN).
// Must stay HIGH while the radio is in use.
#define PIN_3V3_EN (34)
#define WB_IO2 PIN_3V3_EN

// No WisBlock GPS support: this carrier uses IO1/IO2/IO4/IO5/IO6, which the
// RAK GPS modules also use for PPS/reset/standby.

// Battery
// The battery sense is hooked to pin A0 (5)
#define BATTERY_PIN PIN_A0
// and has 12 bit resolution
#define BATTERY_SENSE_RESOLUTION_BITS 12
#define BATTERY_SENSE_RESOLUTION 4096.0
#undef AREF_VOLTAGE
#define AREF_VOLTAGE 3.0
#define VBAT_AR_INTERNAL AR_INTERNAL_3_0
#define ADC_MULTIPLIER 1.73

#define HAS_RTC 1

#define RAK_4631 1

#ifdef __cplusplus
}
#endif

/*----------------------------------------------------------------------------
 *        Arduino objects - C++ only
 *----------------------------------------------------------------------------*/

#endif
