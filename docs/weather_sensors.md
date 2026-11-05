# Weather sensors (LR2021 companions)

A companion with an LR2021 radio can pick up wireless weather sensors (Ecowitt, Ambient Weather
and other Fine Offset models, and La Crosse View) as well as MeshCore. Their readings show in the MeshCore app as one
more channel, "Weather". The app is unchanged, and nothing is sent.

```
wx on                       # 915 MHz, US units; scans for Ecowitt and La Crosse sensors for 170 s
```

When the scan ends, the Radio console lists what it heard:

```
Weather scan done: 2 sensors.
WH65 5a: -108 dBm, heard 6 times
LTV-TH a1b2c3: -96 dBm, heard 3 times
```

Reconnect the app, and a channel named "Weather" appears after your own channels (and after the
Meshtastic one, if that's on). Each sensor posts its first reading, then one every 30 minutes:

```
WH65 5a: 68.0F 50% wind 6 N gust 10 mph rain 1.00 in UV 0.0 1234 lux
WH31 ch2: 65.3F 40%
Lightning 7 mi away. WH57 105c8: 3 strikes, storm 7 mi
Rain started. WS90 342b: 61.2F 88% wind 4 SW gust 9 mph rain 0.42 in raining UV 0.3 2380 lux
```

Lightning strikes and the start of rain post straight away.

**Looking for sensors** (eg. driving around the neighbourhood): `wx scan on` listens all the time,
and each new sensor shows in the Radio console the moment it's heard:

```
New sensor, -97 dBm: LTV-TH a1b2c3: 59.5F 60%
```

The mesh isn't heard meanwhile (sending still works). `wx scan off` goes back to normal and lists
everything heard; a restart does too.

## How it shares the radio

The sensors send FSK, not LoRa, so the radio has to leave the mesh to hear them. They send a
~15 ms packet at a fixed interval: 16 s for the WH65 outdoor array, 61 s for a WH31, 79 s for the
WH57 lightning sensor. The companion learns each sensor's interval and leaves the mesh only around
the moment its next packet is due:

1. **Scan.** `wx on` (and every restart) listens without a break for 85 s per brand (Ecowitt, then
   La Crosse), long enough to hear every sensor in range. The mesh isn't heard during the scan.
2. **Track.** After that, the radio steps away for about 0.3 s around each expected packet, then
   goes straight back to LoRa as soon as the packet is in. With a WH65 every 16 s, that's about 2%
   of the time.
3. **Hunt.** A sensor whose interval isn't known yet, or that missed 4 packets in a row (moved, new
   batteries), is hunted: 0.4 s listens at random gaps of 1.5–4.5 s until it's heard twice.

Mesh traffic comes first. A listen doesn't start while a mesh packet is coming in or waiting to
be read, and a mesh transmit ends a listen at once. The time a listen misses isn't held against
the sensor.

On the chip, a listen is a switch of packet type from LoRa to GFSK with raw commands. Its
frequency is set after the modulation parameters: RadioLib's DC-DC workaround in
`setPacketType()`/`setGfskModulationParams()` retunes to the mesh frequency, so a listen set up
the other way round sits on the mesh's frequency. (Before that was fixed, only a radio whose mesh
was on the sensors' frequency could hear them.) (17.24 kbit/s,
153.8 kHz receiver bandwidth, sync word 0x2DD4, 32 bytes fixed length, no CRC), and back to LoRa
with RadioLib's cached MeshCore settings. No reset, so the Meshtastic scanner blob stays loaded.

## Sensors

### Ecowitt, Ambient Weather and other Fine Offset models

One radio format covers the family: FSK at ~17.24 kbit/s, preamble `AA..`, sync word `2D D4`, then
a packet whose first byte is the model's family code. Each family is checked the same way: CRC-8
(polynomial 0x31) over the packet comes out 0, and the last byte is the sum of the others. A
corrupted packet is dropped.

| Model | Family | What it reports |
|---|---|---|
| WH65 (WH24, WS69; Ambient WS-2902 array) | 0x24 | temperature, humidity, wind, gust, direction, rain, UV, light |
| WH31 (Ambient WH31E, Ecowitt WN31) | 0x30 | temperature, humidity, channel 1–8 |
| WH40 | 0x40 | rain |
| WH57 | 0x57 | lightning: strike count, storm distance |
| WS80 | 0x80 | wind, temperature, humidity, UV, light |
| WS85 | 0x85 | wind, rain, raining |
| WS90 | 0x90 | WS80 plus rain, raining, pressure |
| WN34, WN38 | 0x34, 0x38 | probe or globe temperature |
| WH45 | 0x45 | PM2.5, PM10, CO2, temperature, humidity |
| WH51 | 0x51 | soil moisture |

The packet layouts follow the published protocol notes (rtl_433's device descriptions). The
decoder was written from those descriptions, and its tests use the example packets published with
them.

### La Crosse Technology View (915 MHz)

FSK at about 9.6 kbit/s (104–107 µs bits), preamble `AA..`, sync word `D2 AA 2D D4`, then a 3-byte
ID, a flags byte and the readings, checked with CRC-8 (polynomial 0x31). There's no model byte:
the length the CRC covers, filler bytes and plausible values tell the models apart.

| Model | What it reports |
|---|---|
| LTV-TH2, TH2i, TH3 | temperature, humidity (every 30 s) |
| LTV-WSDTH01 Breeze Pro | temperature, humidity, wind, direction (every 31 s, skipped when nothing changed) |
| LTV-W1, W2 | wind |
| LTV-R1 | rain (0.25 mm per tip) |

Sensors that skip unchanged readings get 12 missed packets before they're hunted again, instead of 4.
The receiver is 238 kHz wide here, which covers the Breeze Pro's 914.938 MHz as well as 915.

Not covered: LTV-WR1 and LTV-R3 (their rain fields aren't understood yet), OOK sensors (Acurite,
433 MHz La Crosse) and frequency-hopping ones (Davis).

## Settings

| Command | |
|---|---|
| `wx on` / `wx off` | start or stop (saved) |
| `wx scan` | listen for sensors without a break for 85 s per brand, then list them in the console |
| `wx scan on` / `wx scan off` | listen all the time, with a console note for each new sensor (not saved) |
| `set wx.kind ecowitt` / `lacrosse` / `both` | which brands to listen for (default both) |
| `set wx.freq <MHz>` | default 915 (US). 868 or 433 for other regions' models |
| `set wx.units us` / `metric` | °F, mph, inches, inHg / °C, m/s, mm, hPa |
| `set wx.every <minutes>` | how often each sensor posts (default 30; 0 = first reading and alerts only) |
| `set wx.only <labels>` / `all` | show and follow only these sensors, by the label in their posts (`5a,ch2`). Others aren't tracked either, so neighbours' sensors cost no air time |
| `wx`, `get wx` | the settings |
| `get wx.sensors` | each sensor: model, label, packets heard, interval, signal, last heard |
| `get wx.stats` | packets (and bad ones), posts, listens, and the share of time away from the mesh |
| `get radio.fsk` | the radio's side: listens, time, listens cut short by a transmit, packets |

These work from the companion CLI, the Radio console and remote CLI.

## Bench results

20 minutes on the bench at 908 MHz: a Heltec V4 played three sensors on exact schedules (`fsktx`)
and sent MeshCore packets in the gaps; the RAK3401 + NiceRF companion listened to both.

| | Sent | Heard |
|---|---|---|
| WH65, every 16 s | 75 | 74 (the last was sent as the run stopped) |
| WH31 channel 2, every 61 s | 20 | 20 |
| WH57, every 79 s, a new strike every 4th packet | 15 | 15, and 3 lightning alerts posted |
| MeshCore packets | 2065 | 1936 |

- Intervals learnt: 15.9, 60.x and 78.x s (the test script's own timing).
- Time away from the mesh: 8.3% over the 20 minutes, of which the 85 s start-up scan is 7.1%.
  While tracking, about 1%: 104 listens, 0 failed to start, 0 bad packets.
- The MeshCore packets lost (129) match the traffic sent during the start-up scan, when the mesh
  can't be heard by design.

## Code

| | |
|---|---|
| `src/helpers/weather/FineOffset.*` | packet checks, decoding and the one-line summary |
| `src/helpers/weather/LaCrosse.cpp` | La Crosse View decoding |
| `src/helpers/weather/SensorTracker.*` | interval learning and listen scheduling |
| `src/helpers/radiolib/CustomLR2021.*` | `fskStart`, `fskRead`, `fskStop`: GFSK and back |
| `src/helpers/radiolib/CustomLR2021Wrapper.h` | the listen itself: waits for a quiet mesh, reads packets, gives way to transmits |
| `examples/companion_radio/MyMeshWeather.cpp` | the Weather channel, posts and commands |
| `test/test_wxsensor`, `test/fuzz/fuzz_wxsensor.cpp` | `pio test -e native_wxsensor` (ASAN + UBSan), and the fuzzer |
| `tools/heltec_v4_tx` | `fsktx <MHz> <dev kHz> <hex>` plays an Ecowitt packet, `fskraw <MHz> <kbps> <dev> <sync> <hex>` any other (La Crosse: `9.6`, `d2aa2dd4`), for bench tests |
