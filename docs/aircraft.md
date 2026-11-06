# Aircraft (LR2021 companions)

Aircraft report their position about once a second over ADS-B: light aircraft in the US on
978 MHz (UAT, which most general aviation uses below 18,000 ft), airliners and most others on
1090 MHz (Mode S extended squitter). A companion with an LR2021 radio listens to both in short
breaks from the mesh, taking turns, and shows the aircraft near it in the MeshCore app, in an
"Aircraft" channel. Nothing is ever sent on 978 or 1090 MHz.

```
air on                      # listen 10% of the time
air scan on                 # or all the time (the mesh isn't heard meanwhile); each new aircraft
                            # shows in the Radio console the moment it's heard
```

Reconnect the app after `air on`; the channel comes after your own, in a fixed slot after the
Meshtastic and Weather ones (empty if those are off). Near a big airport 1090 MHz hears dozens of airliners an hour, so the
channel gets one digest every 10 minutes of the aircraft heard since the last one, closest first,
and only those within 10 miles and below 10,000 ft (local traffic: arrivals, departures,
training flights):

```
Nearby: N713SA 5,300 ft 2.1 mi N; N25430 6,100 ft 4.0 mi NE (+12 higher or farther)
```

- Nothing nearby: no post. `get air.planes` lists everything heard, at any distance or height.
- `set air.every 0` posts each nearby aircraft once instead, in more detail:
  `N501EL: 6,200 ft, 2.1 mi SW, 88 kt heading 214`. Posts read `callsign: details`, as channel
  texts are `sender: text` in the app.
- The callsign (tail number or flight) comes from the aircraft's identification messages, every
  few seconds; until one is heard, the 24-bit address stands in for it (`a63e16`).
- Distance and direction are from this radio's location (set it in the app). Without one, the
  range limit can't apply, the digest is sorted lowest first, and single posts show latitude,
  longitude.
- "(via radar)" marks traffic the FAA rebroadcasts (TIS-B), for aircraft without ADS-B.

## Settings

| Command | |
|---|---|
| `air on` / `air off` | start or stop (saved) |
| `air scan on` / `air scan off` | listen all the time, with a console note for each new aircraft (not saved) |
| `set air.every <minutes>` | minutes between digests (default 10; 0 = a post for each aircraft, once) |
| `set air.range <miles>` | only aircraft closer than this (default 10; 0 = any) |
| `set air.below <feet>` | only aircraft lower than this (default 10000; 0 = any) |
| `set air.band 978\|1090\|both` | which to listen to (default both, taking turns) |
| `set air.duty <percent>` | share of the time spent listening when not scanning all the time (default 10) |
| `air`, `get air` | the settings |
| `get air.planes` | aircraft heard in the last 5 minutes |
| `get air.list [start]` | the same for apps, as numbers, a page at a time (below) |
| `get air.stats` | messages (and how many on 1090; UAT ones corrected by Reed-Solomon, and beyond repair), aircraft, posts, time listening |
| `get radio.fsk`, `get radio.fsk.rx`, `get radio.ook.rx` | the radio's listens, and its receiver counters (UAT, 1090) |
| `air adsb <dB> <gain> <bw Hz>` | 1090 receiver experiments: threshold over the noise, fixed gain step, bandwidth (0 = default; not saved) |

Settings saved before these defaults existed keep their values: a radio that had `air.range 0`
still shows any distance until `set air.range 10`.

### On a map

The [fluxcore app](https://fluxcore.party/app/) connects to the radio over Bluetooth (Chrome or Edge
on a computer or Android, Bluefy on iPhone and iPad) and shows every aircraft the radio holds on a
map, with its trail, every 2 seconds, on its own Bluetooth channel (the fluxcore service in
[companion_protocol.md](companion_protocol.md)), so the MeshCore app can stay connected. It reads them with `get air.list`:

```
get air.list        > 3 0 a1b2c3,N123AB,4012345,-10512345,5800,79,299,-500,6,-92,1;a6ae97,,,,5475,,,,24,-84,2
get air.list 2      > 3 2 acbc30,,,,,,,,8,-84,2
```

The reply is the number of aircraft, the index of the first one in this reply, then one record per
aircraft, as many as fit: ICAO address (hex), callsign, latitude and longitude (degrees × 100000),
altitude in feet (`G` on the ground), speed in knots, track in degrees, vertical speed in feet per
minute, seconds since last heard, RSSI, and flags (1 heard on 978 MHz, 2 on 1090 MHz, 4 relayed by
radar, TIS-B). An empty field isn't known yet. Ask again from the next index until it reaches the
count. Test builds with `-DAIR_TEST` add `air test <n>` (and `air test off`): n made-up aircraft
circling the radio, for trying apps out with nothing on the air.

## How it works

### 978 MHz (UAT)

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

### 1090 MHz (Mode S extended squitter)

The LR2021 has a receiver for this built in: its OOK modem's detector is documented with the ADS-B
preamble (SetOokDetector, pattern `0x0285`), and RadioLib ships an LR2021 ADS-B example whose
settings this follows.

| | |
|---|---|
| Frequency | 1090 MHz, on the sub-GHz path (above its 960 MHz specification; it hears aircraft from a basement anyway) |
| Modulation | pulse position: 1 Mbit/s as 2 Mchip/s OOK, inverted Manchester; receiver 3076 kHz |
| Preamble | the 8 µs pulse pattern `1010000101000000`, found by the chip's OOK detector |
| Frame | 112 bits: format, address, 56-bit message, 24-bit parity (CRC-24, polynomial 0xFFF409), checked by the chip: only good frames reach the firmware |
| Threshold | measured noise + 10 dB at the start of each listen (datasheet section 22.1: the chip's own threshold is fixed by the bandwidth) |
| Position | CPR: each message carries half a position. Decoded next to the aircraft's last position, else from an even/odd pair within 10 s, else next to this radio's location |

Message layout from ICAO Annex 10 / DO-260B as explained in "The 1090 MHz Riddle" (Junzi Sun); the
tests decode that book's worked examples (identification, positions from a pair and from a
reference, both velocity kinds) and check CPR round trips around the world.

### Sharing the radio with the mesh

A listen never starts while a mesh packet is arriving, after this radio transmits (for two
repeater hops' worth of time, at least 5 s, so the repeats of what you sent are heard) or after a
mesh packet is heard (at least 1.5 s: other copies follow). A packet heard never shortens a wait
already running. A transmit ends a listen at once. Listens that run out of time meanwhile are
skipped (`get radio.fsk`: "skipped for mesh traffic"). The same holds with `air scan on`: the mesh
can't be heard between those waits, but what you send still goes out and its repeats come back.

Aircraft is one listen at a time with Meshtastic and weather: `air on` turns those off (the reply
says so). `radar`, copying a radio and `find range` pause it until they finish.

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

On the same radio, 1090 MHz only, listening all the time for 3 minutes: 374 messages from
5 aircraft, among them N25430 and N65251 near LMO with positions, altitudes and speeds. Taking
turns with 978 at 10% of the time: digests such as `Nearby: N713SA 5,750 ft (+1 higher or farther)`.

## Code

| | |
|---|---|
| `src/helpers/aircraft/Uat.*` | UAT: Reed-Solomon, message decoding, distance and bearing |
| `src/helpers/aircraft/AdsB.*` | 1090 MHz: parity, identification, velocity, CPR positions |
| `examples/companion_radio/MyMeshAircraft.cpp` | the Aircraft channel, posts and commands |
| `src/helpers/radiolib/CustomLR2021.*`, `CustomLR2021Wrapper.h` | the FSK and ADS-B listens (shared with [weather sensors](weather_sensors.md)) |
| `test/test_uat`, `test/test_adsb`, `test/fuzz/fuzz_uat.cpp` | `pio test -e native_wxsensor` (ASAN + UBSan), and the fuzzer (both bands) |

Weather from ground stations (FIS-B) uses the same frequency and modulation: see
[airport weather notes](airport_weather_notes.md).
