# Airport weather (LR2021 companions)

FAA ground stations broadcast free weather on **978 MHz** (FIS-B, on the same UAT link light
aircraft use for ADS-B): METARs (current conditions at airports), TAFs (forecasts), and more. A
companion with an LR2021 radio listens in short breaks from the mesh and shows the reports for the
airports heard in the MeshCore app, in an "Airport weather" channel, in plain words. Nothing is ever
sent on 978 MHz.

```
metar on                          # listen 10% of the time; every airport heard
set metar.airports KLMO,KBJC      # or only these
```

Reconnect the app after `metar on`. The channel comes after your own, in a fixed slot after the
Meshtastic, Weather, Aircraft and Damaged ones (empty if those are off). Each report shows once:

```
KLMO: 53°F, humidity 43%. Few clouds at 8,000 ft, scattered clouds at 12,000 ft. Wind NW 14 mph. Visibility 10+ mi. Pressure 30.02 inHg. (7 min ago)
KMER: 46°F, humidity 100%. Overcast at 200 ft. Wind E 6 mph. Visibility 1 3/4 mi. Pressure 30.31 inHg. (12 min ago)
KBJC update: 50°F, humidity 66%. Thunderstorm with heavy rain, mist. Mostly cloudy at 4,000 ft (thunderstorm clouds), overcast at 9,000 ft. Wind WNW 29 mph, gusts 40. Visibility 3 mi. Pressure 29.98 inHg. (2 min ago)
```

- Posts read `airport: report`, as channel texts are `sender: text` in the app. "update" marks a
  SPECI, a special report issued when the weather changes fast.
- Humidity comes from the temperature and dew point. Cloud heights are above the ground. "Mostly
  cloudy" is a broken layer (BKN), which pilots count as a ceiling. "(7 min ago)" is by this
  radio's clock (set from the app); without one, the report's UTC time shows instead.
- Units follow `set wx.units`: US (°F, mph, miles, inHg) or metric (°C, km/h, km, hPa).
- `set metar.raw on` shows reports as sent instead: `KLMO: 052153Z 31012KT 10SM FEW080 12/M01 A3002 ...`.
  Forecasts (`set metar.taf on`) are always as sent: `KBJC: TAF 052320Z 0600/0624 30012G20KT ...`.
- One station sends reports for dozens of airports, each repeated every few minutes; a new report
  for an airport comes about once an hour, so a busy station posts dozens an hour. `set
  metar.airports` narrows it down; `get metar.heard` lists the airports heard.
- Long reports come in parts: `KBJC (cont.): ...`.
- Turning it on turns off Meshtastic, Weather or Aircraft (one listen at a time).

## Settings

| Command | |
|---|---|
| `metar on` / `metar off` | start or stop (saved) |
| `set metar.airports <IDs>` | only these airports, by ICAO ID, comma-separated, up to 39 characters (`all`, the default: every airport heard) |
| `set metar.raw on\|off` | reports as sent instead of in words (default off) |
| `set metar.taf on\|off` | forecasts (TAF) too (default off: METAR and SPECI only) |
| `set metar.duty <percent>` | share of the time spent listening (default 10; 100 = all the time, and the mesh isn't heard) |
| `set metar.freq <MHz>` | where to listen (default 978; other values are for bench tests) |
| `metar`, `get metar` | the settings |
| `get metar.heard` | airports heard since `metar on` (the last 96) |
| `get metar.stats` | frames (corrected by Reed-Solomon, and beyond repair), reports read, posts, time listening, and the last station: its slot, signal, and where it is (distance and direction from this radio's location, or latitude, longitude) |
| `get radio.fsk`, `get radio.fsk.rx` | the radio's listens and its receiver counters |

## How it works

### The radio side

| | |
|---|---|
| Frequency | 978.000 MHz, on the LR2021's sub-GHz path (the same port and antenna as 915 MHz) |
| Modulation | binary CPFSK, 1.041667 Mbit/s, modulation index ~0.6 (±312.5 kHz); receiver 2222 kHz |
| Ground station frame | 36-bit sync `0x153225B1D`, no preamble, then 4416 bits (552 bytes) |
| Timing | each station sends in its own slots in the first 176 ms of every UTC second |

The aircraft receiver ([aircraft.md](aircraft.md)) uses the same frequency and modulation, with the
aircraft sync word `0xEACDDA4E2`. The chip matches one sync word at a time, so ground station
frames get their own listen. Each listen lasts 1.1 s, a whole UTC second, so every station's slot
falls inside it.

552 bytes is 4.2 ms on air, more than the receive FIFO's usual 256 bytes. For these listens the FIFO
moves to its 1 KB region (datasheet 5.3.3: two register writes), so the whole frame is in the chip
when RxDone comes, and it's read in one go. The FIFO goes back to its usual place when the listen
ends. The move happens after the front end calibration, which overwrites that region.

### The frame

The 552 bytes are 6 Reed-Solomon (92,72) blocks, **interleaved byte by byte**: byte i of the frame
belongs to block i mod 6. Each block corrects up to 10 bad bytes and leaves 72 data bytes, 432 in
all. RS over GF(256), field polynomial 0x187, first root 120 (as in FlightAware's dump978).

The 432 bytes:

1. **The UAT header** (8 bytes): the station's latitude and longitude, its slot, a TIS-B site ID.
   Stations send their position with its "valid" bit clear, so it's read either way (as dump978
   does).
2. **Information frames**, one after another: a 9-bit length and a 4-bit type, then the data.
   Type 0 is a FIS-B APDU; a zero length and type end the list.
3. **The APDU**: flags, an 11-bit product ID, a time (hours and minutes, sometimes with the date
   or seconds), then the product. Text products (METAR, SPECI, TAF, PIREP, winds aloft, ...) are
   product 413, in **DLAC**: 6-bit characters, 4 in 3 bytes. A tab character is followed by a count
   of spaces. Reports are separated by a record separator (code 29) and padded with ETX (code 0).
   Stations send one report per APDU, ending in `=` and a newline.

Radar images and the other graphical products are other product IDs, and are skipped. So are
segmented APDUs (products split across frames): none of the text reports in dump978's samples are.

### Sharing the radio with the mesh

At the default 10%, the radio is away about 1.1 s in every 11, and mesh packets that arrive then
are missed. On the bench, 18 of 20 mesh messages arrived with airport weather on, 20 of 20 with it
off. Mesh transmits end a listen early; listens wait for a packet on its way in.

At 10% a radio hears about one frame in ten. Stations repeat each METAR every few minutes, so new
reports still show within minutes. `set metar.duty 100` hears every frame, and the mesh isn't
heard at all meanwhile.

## Hearing a station

Ground stations are towers spread out so that aircraft above a few thousand feet are always in
range. Near the ground the coverage has gaps, so hearing one from a house depends on line of sight
to a tower. In a basement near LMO (Vance Brand Airport, Longmont, Colorado), an RTL-SDR heard no
ground station at all:

| Where | Antenna | 978 MHz ground stations | 978 MHz aircraft | 1090 MHz aircraft |
|---|---|---|---|---|
| Basement bench (RTL-SDR Blog V4, gain 49.6) | small stock | nothing in 10 s | nothing | – |
| Basement bench (RTL-SDR) | 915 MHz | nothing in 60 s, then nothing in 10 more minutes | yes: 8–22 bursts per 30 s, perfect sync | 310 bursts in 10 s |

From an attic, outdoors, a window facing open sky, an airport ramp or a hill, `metar on` with
`set metar.duty 100` for a minute shows in `get metar.stats` whether frames arrive: stations send
every second. Then a lower duty for everyday use.

## Bench testing without a station

`tools/bench/fisb.py` builds ground station frames: METAR text in DLAC, in an APDU, in an
information frame, after the UAT header, Reed-Solomon encoded and interleaved. It also reads
them, and writes them as RTL-SDR samples for dump978:

```
tools/bench/fisb.py frame "METAR KLMO 052153Z 31012KT 10SM FEW080 12/M01 A3002"   # 552 bytes, hex
tools/bench/fisb.py iq out.cu8 "METAR ..."    # then: dump978 < out.cu8 | uat2text
tools/bench/fisb.py read sample-data.txt      # the text reports in dump978's '+' lines
```

A companion built with `-D FISB_BENCH_TX` (never in releases) can send a loaded frame, at 902–928
MHz only: `metar tx load <offset> <hex>` (64 bytes at a time), then `metar tx send <MHz>`.
`tools/bench/fisb_bench.py <sender port> <receiver port> "METAR ..."` sets up a receiver, loads and
sends the frame, and prints what the receiver posted (`--errors K` puts K bad bytes in every block,
`--data <hex>` sends a real frame's data instead).

```
PLATFORMIO_BUILD_FLAGS="-D FISB_BENCH_TX" pio run -e AB_Xiao_nrf52_LR2021_companion_radio_usb -t upload
tools/bench/fisb_bench.py /dev/serial/by-id/usb-Seeed_Studio_XIAO_* /dev/serial/by-id/usb-RAKwireless_* \
  --count 5 "METAR KLMO 052153Z 31012KT 10SM FEW080 12/M01 A3002"
```

### Results

- **The encoder against dump978.** mutability's dump978 demodulates `fisb.py` frames, corrects
  them (also with 10 bad bytes in every block) and `uat2text` prints their METARs. Its parity and
  interleaving are dump978's.
- **In words.** All 133 different METARs in dump978's samples are read (`test/test_fisb`
  checks several word for word, and storms, fog, fractions of a mile and metric reports).
- **Real frames.** dump978 ships 704 frames from real ground stations, already corrected. `fisb.py`
  and the C decoder read 147 METARs from them, as `uat2text` does, plus TAFs, SPECIs, PIREPs and
  winds aloft. Six of those frames are the C tests' vectors.
- **Over the air**, a XIAO + Wio-LR2021 sending at 915 MHz, 22 dBm, to a RAK3401 + NiceRF
  LoRa2021F33 companion (-61 dBm, in a shielded box):
  - 49 of 50 frames received, none bad (the one missed fell between two listens)
  - 10 bad bytes in every block: 5 of 5 corrected and posted; 11 in one block: 5 of 5 rejected, nothing posted
  - a real station's frame from dump978's sample data, sent again: its METARs posted for the
    airports chosen, the others not
  - each report posted once, however many times it was heard, for every airport in a real
    station's frame (7) or only the one chosen
  - in words, with the age by the radio's clock: `KLMO: 53°F, humidity 43%. ... (7 min ago)`
  - an RTL-SDR recording of the XIAO's frames: dump978 decoded 5 of 5
  - at 10%: 17 of 182 frames heard (9%); mesh messages 18 of 20 (20 of 20 with it off)
  - 90 s with nothing sent: no frames, so no false matches of the sync word

## Code

| | |
|---|---|
| `src/helpers/weather/Fisb.*` | Reed-Solomon (`uat::rsDecode`), the header, information frames, APDUs, DLAC, report words |
| `src/helpers/weather/Metar.*` | METARs in plain words: wind, visibility, weather, clouds, temperature and humidity, pressure |
| `examples/companion_radio/MyMeshMetar.cpp` | the Airport weather channel, posts and commands, the bench sender |
| `src/helpers/radiolib/CustomLR2021.*`, `CustomLR2021Wrapper.h` | the FSK listen with the 1 KB FIFO, and a slot for one long frame |
| `test/test_fisb`, `test/fuzz/fuzz_fisb.cpp` | `pio test -e native_wxsensor` (ASAN + UBSan), and the fuzzer |
| `tools/bench/fisb.py`, `tools/bench/fisb_bench.py` | frames for tests, and the over-the-air bench test |

The decoder was written from the format as dump978 documents it; no code was copied.
