# Notes: airport weather (FIS-B) on an LR2021

Parked on 2026-11-05: no FIS-B ground station could be heard from the bench (a basement near LMO,
Vance Brand Airport, Longmont, Colorado). Aircraft UAT on the same frequency was heard. These notes
are what's needed to pick it up again from a better spot.

## What it is

FIS-B (Flight Information Service – Broadcast) is free weather and airspace data that FAA ground
stations broadcast on **978 MHz** (UAT, the same link light aircraft use for ADS-B). It includes:

- METARs (current conditions) and TAFs (forecasts) for airports, as text
- SIGMETs, AIRMETs, convective SIGMETs, PIREPs, winds aloft
- NOTAMs and TFRs
- NEXRAD radar images (as compressed blocks)

Ground stations (GBTs) are towers spread out so that aircraft above a few thousand feet are
always in range. Near the ground the coverage has gaps, so hearing one from a house depends on
line of sight to a tower.

## The radio side

| | |
|---|---|
| Frequency | 978.000 MHz |
| Modulation | binary CPFSK, 1.041667 Mbit/s, modulation index ~0.6 (±312.5 kHz) |
| Ground station frame | 36-bit sync `0x153225B1D`, then 4416 bits (552 bytes) |
| Aircraft frame | 36-bit sync `0xEACDDA4E2`, then 240 bits (basic) or 384 bits (long) |
| Ground station timing | each station sends in its own time slots of a 1 s UTC frame (the first 176 ms are for ground stations) |

The 552-byte ground station frame is 6 Reed-Solomon (92,72) blocks, **interleaved byte by byte**:
byte i of the frame belongs to block i mod 6. Each block corrects up to 10 byte errors and leaves
72 data bytes, 432 in all. RS over GF(256), field polynomial 0x187, first root 120, primitive
element 1, 20 roots (as in FlightAware's dump978, `uat_protocol.h` and `fec.cc`).

## What already works

The aircraft receiver ([aircraft.md](aircraft.md)) uses the same frequency, modulation and sync
mechanism: an LR2021 receives UAT at 1.04 Mbit/s with a 36-bit sync word, no preamble and a
2222 kHz receiver, error-corrected with the same Reed-Solomon code. FIS-B needs the uplink sync
word `0x153225B1D`, a 552-byte frame and the steps below.

## Why it's harder than the aircraft messages

- **Length.** 552 bytes at 1.04 Mbit/s is 4.2 ms on air: more than the LR2021's packet engine holds
  at once. The receive FIFO has to be drained while the frame is still arriving: a FIFO-threshold
  IRQ and a fast SPI read loop on the MCU (about 130 kB/s), or the PRAM approach used for the
  Meshtastic scanner, where the chip's own CPU moves the bytes.
- **Error correction is required.** Deinterleave, then RS-decode each block. One corrupt byte in a
  block would otherwise ruin the whole METAR.
- **The payload.** The 432 bytes start with an 8-byte UAT-specific header (station position, slot
  ID, TIS-B site, ...), followed by information frames. FIS-B products are APDUs inside those
  frames, each with a product ID. Text products (METAR, TAF, SIGMET, ...) use product ID 413, with
  the text in **DLAC**, a 6-bit character set (4 characters in 3 bytes). Radar images are other
  product IDs and can be ignored.
- **Choosing what to show.** One station broadcasts METARs for many airports. Filter by airport ID
  (`set wx.airport KLMO,KBJC,KDEN`) and post each new report once.

What's easy: the frequency is close to 915 MHz, so the LR2021's matching (and probably the NiceRF's
front end) works there. Ground stations transmit around the clock, so it's easy to test once one
can be heard.

## What was measured

| Where | Antenna | 978 MHz ground stations | 978 MHz aircraft | 1090 MHz aircraft |
|---|---|---|---|---|
| Basement bench (RTL-SDR Blog V4, gain 49.6) | small stock | nothing in 10 s | nothing | – |
| Basement bench (RTL-SDR) | 915 MHz | nothing in 60 s, then nothing in 10 more minutes | yes: 8–22 bursts per 30 s, perfect sync | 310 bursts in 10 s |

Detection: FM discriminator on 2.083 MS/s IQ (2 samples per bit), sign slicer, correlation with
both 36-bit sync words, allowing 2 bit errors. Random noise over a minute reaches 30–31 of 36.

## Picking it up again

1. **Find a spot that hears a ground station.** Run the RTL-SDR on the 915 antenna from the attic,
   outdoors or a window facing open sky. Look for uplink sync words (any at all means a station is
   in range; they come every second). An airport ramp or a hill also works.
2. **Record a few minutes** at 2.083 MS/s, then decode offline (Python): deinterleave, RS, header,
   APDUs, DLAC. That makes test vectors for the C code.
3. **LR2021 receive.** GFSK 1041.667 kbit/s, deviation 312.5 kHz, receiver 2222 kHz, 36-bit sync
   (the chip's sync length is set in bits), fixed length 552 bytes. Drain the FIFO during the frame.
   Check with the RTL-SDR recording that the same frames arrive.
4. **Then the companion.** Decoder in `src/helpers/weather/` (RS, APDU, DLAC; tests and fuzzer like
   the sensors). The Weather channel already exists: add `METAR KLMO 052153Z 31012KT 10SM FEW080 ...`
   posts, filtered by airport.

No transmitting on 978 MHz, ever: it's an aviation band. Bench tests of the receive chain use the
XIAO's LR2021 as a 1 Mbit/s FSK transmitter at 915 MHz instead.
