# Aircraft (LR2021 companions)

Light aircraft in the US report their position about once a second on 978 MHz (UAT, the ADS-B
link most general aviation uses below 18,000 ft). A companion with an LR2021 radio can listen in
short breaks from the mesh and show each aircraft in the MeshCore app, in an "Aircraft" channel.
Nothing is ever sent on 978 MHz.

```
air on                      # listen 10% of the time
air scan on                 # or all the time (the mesh isn't heard meanwhile); each new aircraft
                            # shows in the Radio console the moment it's heard
```

Reconnect the app after `air on`; the channel comes after your own (and after Meshtastic's and
Weather's, if those are on). Each aircraft posts when first heard with a position, then every
10 minutes while it's around:

```
N501EL: 6,200 ft, 2.1 mi SW, 88 kt heading 214
```

- Posts read `callsign: details`, as channel texts are `sender: text` in the app. The callsign (tail
  number or flight) comes from the aircraft's mode-status messages, every few seconds; until one is
  heard, the 24-bit address stands in for it (`a63e16: 6,200 ft, ...`).
- Distance and direction are from this radio's location (set it in the app). Without one, the
  position shows as latitude, longitude.
- "(via radar)" marks traffic the FAA rebroadcasts (TIS-B), for aircraft without ADS-B.

## Settings

| Command | |
|---|---|
| `air on` / `air off` | start or stop (saved) |
| `air scan on` / `air scan off` | listen all the time, with a console note for each new aircraft (not saved) |
| `set air.every <minutes>` | how often the same aircraft is posted again (default 10; 0 = once) |
| `set air.range <miles>` | only aircraft closer than this (default 0 = any) |
| `set air.duty <percent>` | share of the time spent listening when not scanning all the time (default 10) |
| `air`, `get air` | the settings |
| `get air.planes` | aircraft heard in the last 5 minutes |
| `get air.stats` | messages (corrected by Reed-Solomon, and beyond repair), aircraft, posts, time listening |
| `get radio.fsk`, `get radio.fsk.rx` | the radio's listens, and its receiver counters |

## How it works

| | |
|---|---|
| Frequency | 978.000 MHz, on the LR2021's sub-GHz path (the same port and antenna as 915 MHz) |
| Modulation | 2-FSK, 1.041667 Mbit/s, ±312.5 kHz; receiver 2222 kHz wide (datasheet: 2 × deviation + bit rate + crystal error) |
| Sync | the 36-bit word `0xEACDDA4E2` (SetFskSyncword takes the length in bits; shorter words are the low bits of the 64) |
| Preamble | none: preamble detection off, so the chip looks for the sync word alone |
| Frame | 48 bytes: a long message (34 data + 14 Reed-Solomon) or a basic one (18 + 12, then noise) |
| Error correction | Reed-Solomon over GF(256), polynomial 0x187, first root 120: up to 7 (long) or 6 (basic) bad bytes repaired |

The message layout (header, state vector, mode status) follows DO-282B as documented by
FlightAware's dump978; the decoder was written from that description, not copied. The tests check
the Reed-Solomon decoder against vectors from an independent encoder (Python `reedsolo`) and decode
a frame recorded near LMO (Longmont, Colorado).

### A RadioLib detail that matters

`setPacketType()` and `setGfskModulationParams()` run RadioLib's DC-DC workaround, which ends by
retuning to RadioLib's cached frequency: the mesh's. An FSK listen therefore sets its own frequency
**after** those calls; before this was found, every listen sat on the mesh frequency (bench tests
passed only because the bench mesh was on the sensors' frequency). The listen also calibrates the
front end for its frequency once (the chip keeps three calibrations: mesh, listen, Meshtastic).

## Results

On a RAK3401 + NiceRF LoRa2021F33 companion with a 915 MHz antenna, in a basement near LMO, mesh on
910.525 MHz, listening all the time for 2.5 minutes: 116 messages from one aircraft (24 needed
correction, 4 couldn't be repaired), its callsign, altitude, position, speed and heading, and one
post. An RTL-SDR on the same bench heard the same aircraft (address a63e16).

## Code

| | |
|---|---|
| `src/helpers/aircraft/Uat.*` | Reed-Solomon, message decoding, distance and bearing |
| `examples/companion_radio/MyMeshAircraft.cpp` | the Aircraft channel, posts and commands |
| `src/helpers/radiolib/CustomLR2021.*`, `CustomLR2021Wrapper.h` | the FSK listen (shared with [weather sensors](weather_sensors.md)) |
| `test/test_uat`, `test/fuzz/fuzz_uat.cpp` | `pio test -e native_wxsensor` (ASAN + UBSan), and the fuzzer |

Weather from ground stations (FIS-B) uses the same frequency and modulation: see
[airport weather notes](airport_weather_notes.md).
