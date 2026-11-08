# Tire pressure (LR2021 companions)

Every car sold in the US since 2008 has a pressure sensor in each wheel (TPMS) that radios the
tire's pressure and temperature on **315 MHz**: about once a minute while the car moves, and at
once when the pressure changes fast. A companion with an LR2021 radio can hear your car's sensors
and show the pressures in the MeshCore app, in a "Tires" channel, with an alert when a tire runs
low or loses air quickly. Nothing is ever sent.

```
tpms on                          # start; sensors heard go in a table
get tpms.heard                   # strongest first: your car's are the closest
set tpms.ids 2fc871,2eaaf9,3495ac,2fc780   # show these four
set tpms.low 28                  # an alert below 28 psi
```

Reconnect the app after `tpms on`. The channel comes after your own, in a fixed slot after the
Meshtastic, Weather, Aircraft, Damaged, Airport weather and Meters ones (empty if those are off).

```
Tire c871: 35.5 psi, 72°F
Tire aaf9: 34.0 psi, 70°F
Tire c871 DROPPING: 31.0 psi, 74°F
Tire aaf9 LOW: 27.5 psi, 68°F
```

- Posts read `Tire <last 4 hex digits of the ID>: <pressure>, <temperature>`. Units follow
  `set wx.units` (psi and °F, or kPa and °C).
- A sensor's reading is posted when first heard, then when it changes by a psi or more, and at
  most every `tpms.every` minutes (30) otherwise.
- **Alerts** post at once: **LOW** below `set tpms.low` (off by default; most cars want 30-35 psi,
  on the door pillar sticker), **DROPPING** when a tire is 3 psi below its last post within 10
  minutes.
- **Only your car.** Every sensor heard goes in `get tpms.heard` (to find yours), but only the ones
  in `set tpms.ids` are ever posted: a passing car's sensors are its owner's.
- Sensors send while the car moves (and for a while after); a parked car's often stay quiet for
  hours. Drive with the radio in the car to hear them.
- Turning it on turns off Meshtastic, Weather, Aircraft, Airport weather or Meters (one listen at
  a time).

### Finding your car's sensors

Turn it on and drive for a few minutes with the radio in the car, then `get tpms.heard`: your four
are the strongest, heard many times, all the same make. A tire shop's TPMS tool also reads the IDs.
To find them faster, `set tpms.duty 100` while driving (the mesh isn't heard meanwhile), then back
to `set tpms.duty 10`.

Once one of your sensors has been heard, the radio listens only for that make, and hears the others
about 7 times as often.

## Makes

Each maker's sensors frame their data their own way. These follow rtl_433's decoders, and were
checked against rtl_433's recordings of real sensors and sent over the air on the bench:

| Make | Sensor | Radio | Over the air (bench) |
|---|---|---|---|
| Ford | Continental/VDO | FSK, 19.2 kbps, Manchester, a sum | 16 of 16 frames |
| Jeep, Chrysler, Dodge, Ram | Continental (the same frames as Citroen/Peugeot) | FSK, 19.2 kbps, Manchester, XOR | 16 of 16 |
| Toyota, Lexus (newer) | Pacific PMV-C210 | FSK, 19.2 kbps, differential Manchester, CRC-8 | 16 of 16 |
| Toyota, Lexus (older) | Pacific PMV-107J | FSK, 10 kbps, differential Manchester, CRC-8 | 16 of 16 |
| GM: Chevrolet, GMC, Buick, Cadillac | Schrader EG53MA4 | OOK, 8.1 kchip/s, Manchester, a sum | 16 of 16 |
| Honda | TRW PPA-GF33 | FSK, 20 kbps, Manchester, CRC-8 | 10 of 16 |
| Hyundai, Kia, Mazda, Mitsubishi | Continental/VDO | FSK, 19.2 kbps, Manchester, CRC-8 | (no recording to send) |
| Kia Rio, some Hyundai | | FSK, 20 kbps, Manchester, CRC-8 | (no recording to send) |

Nissan's FSK sensors are read from recordings (`test/test_tpms`), but their frames came through
garbled over the air on the bench at 8.33 kbps, so they aren't listened for yet.

Ford's, Jeep's, GM's and Nissan's checks are weak (a sum, an XOR or 2 bits): a frame from them only
counts when the same one comes again within 15 s. Sensors send several in a row, so a real one
always does.

## Settings

| Command | |
|---|---|
| `tpms on` / `tpms off` | start or stop (saved) |
| `set tpms.ids <IDs>` | the sensors to show, by hex ID, comma-separated, up to 47 characters (`none`, the default: none shown) |
| `set tpms.low <psi>` | an alert below this (default 0: off) |
| `set tpms.every <minutes>` | between a sensor's posts when nothing changes (default 30; 1-1440) |
| `set tpms.duty <percent>` | share of the time spent listening (default 10; 100 = all the time, and the mesh isn't heard) |
| `set tpms.freq <MHz>` | 315 (the default; cars sold in the US) or 433.92 (Europe) |
| `tpms`, `get tpms` | the settings |
| `get tpms.heard [start]` | the sensors heard (up to 32), strongest first: make, ID, pressure, signal, minutes since heard |
| `get tpms.stats` | frames (and those that didn't read), sensors, posts, time listening, frames read by each make |

## How it works

The LR2021 takes one make's framing at a time: its bit rate, its sync word (and for most FSK
makes, 8 bits of 1010.. preamble first), and a fixed number of bytes of raw chips after it. The
chips are read in `src/helpers/tpms` as rtl_433 reads them: the sync word put back in front, then
the make's search, Manchester or differential Manchester decoding, and its check. Ford and Jeep
share a sync word (`55 55 55 56`) and are read from the same listen. Listens of 1 s take each make
in turn; once one of the chosen sensors has been heard, only its make's.

| Setting | Bit rate | Sync word (bits) | Then | Preamble wait |
|---|---|---|---|---|
| Ford/Jeep | 19.23 kbps | `5556` (16) | 21 bytes | 8 bits |
| Hyundai | 19.23 kbps | `aaaaaaa9` (32) | 20 bytes | 8 bits |
| Toyota | 19.23 kbps | `a9e` (11) | 19 bytes | 8 bits |
| Kia | 20 kbps | `ed71` (16) | 18 bytes | none |
| Honda | 20 kbps | `dae354` (23) | 16 bytes | none (its frames start with the marker) |
| PMV-107J | 10 kbps | `fc` (8) | 18 bytes | 8 bits |
| GM | 8.13 kchip/s OOK | `5565a5` (24), after a `1010` detector pattern | 18 bytes | – |

FSK: 40 kHz deviation, 185 kHz receiver (the sensors' crystals are off by tens of kHz). GM's OOK:
a 38.5 kHz receiver, as the OOK receiver hears nothing much wider than a few times its chip rate
(see [utility meters](utility_meters.md)).

The boards' antennas are matched for 915 MHz. At 315 MHz they're much less sensitive, which matters
little for your own car's sensors a few metres away.

## Bench testing

`test/test_tpms/vectors.inc` holds frames from rtl_433's test recordings (github.com/merbanan/
rtl_433_tests), cut as the radio hands them over, with what rtl_433 reads from each. On all of
rtl_433's recordings of these makes (Ford 7 frames, Jeep/Citroen 9, Toyota 19, PMV-107J 29, Honda 5,
Nissan 30, GM 16), the C decoders read the same IDs and pressures as rtl_433, from the whole frame
and from the radio's cut, and nothing else.

A companion built with `-D FISB_BENCH_TX` (never in releases) sends them: `tpms tx <setting 0-7>
<MHz> <hex>`, at 902-909 or 922-928 MHz (bench tests use 925 MHz; never 315 MHz). A receiver with
`set tpms.freq 925` hears them. `tools/bench/tpms_bench.py <sender port> <receiver port>` sends each
vector 8 times and prints what the receiver read and posted.

```
PLATFORMIO_BUILD_FLAGS="-D FISB_BENCH_TX" pio run -e AB_Xiao_nrf52_LR2021_companion_radio_usb -t upload
tools/bench/tpms_bench.py /dev/serial/by-id/usb-Seeed_Studio_XIAO_* /dev/serial/by-id/usb-RAKwireless_*
```

`set tpms.dbg <rxbw kHz> <threshold dB> <setting 1-8> <preamble bits> <deviation kHz>` (0 = the
default) pins one setting and changes the receiver, for experiments; `get tpms.last` shows the raw
chips of the last frame that didn't read.

## Code

| | |
|---|---|
| `src/helpers/tpms/Tpms.*` | the makes' decoders (from rtl_433), their radio settings |
| `examples/companion_radio/MyMeshTpms.cpp` | the Tires channel, the table, listens, posts and alerts, commands, the bench sender |
| `test/test_tpms`, `test/fuzz/fuzz_tpms.cpp` | tests on real frames, and a fuzzer |
