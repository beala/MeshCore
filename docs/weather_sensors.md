# Weather sensors (LR2021 companions)

A companion with an LR2021 radio can pick up wireless weather sensors (Ecowitt, Ambient Weather
and other Fine Offset models, La Crosse View and IT+, ThermoPro) as well as MeshCore. Their readings show in the MeshCore app as one
more channel, "Weather". The app is unchanged, and nothing is sent.

```
wx on                       # 915 MHz, US units; scans for Ecowitt, La Crosse and ThermoPro sensors for 6 min
```

When the scan ends, the Radio console lists what it heard:

```
Weather scan done: 2 sensors.
WH65 5a: -108 dBm, heard 6 times
LTV-TH a1b2c3: -96 dBm, heard 3 times
```

Reconnect the app, and a channel named "Weather" appears after your own channels, in its own slot
(regular channels, then Meshtastic, Weather, Aircraft, Damaged: each always in the same place, so turning
one on or off never moves another). Each sensor posts its first reading, then one every 30 minutes:

```
WH65 5a: 68.0F 50% wind 6 N gust 10 mph rain 1.00 in UV 0.0 1234 lux
WH31 ch2: 65.3F 40%
Lightning 7 mi away. WH57 105c8: 3 strikes, storm 7 mi
Rain started. WS90 342b: 61.2F 88% wind 4 SW gust 9 mph rain 0.42 in raining UV 0.3 2380 lux
```

Lightning strikes, the start of rain, and a leak sensor finding water (`Water leak! WH55 30cf
ch1: LEAK`, then `Leak over.`) post straight away.

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

1. **Scan.** `wx on` (and every restart) listens without a break in each radio format in turn
   (see [Radio formats](#radio-formats)), long enough to hear every sensor in range: 85 s for
   Ecowitt's, 70 s for its wide-deviation one, 35 s for each of La Crosse View's three, 12 s for
   IT+, 30 s for the TX22U-IT, 60 s for ThermoPro: 6 minutes in all (`set wx.kind ecowitt`: 2.6
   minutes). The mesh isn't heard during the scan.
2. **Track.** After that, the radio steps away for about 0.3 s around each expected packet, then
   goes straight back to LoRa as soon as the packet is in. With a WH65 every 16 s, that's about 2%
   of the time.
3. **Hunt.** A sensor whose interval isn't known yet, or that missed 4 packets in a row (moved, new
   batteries), is hunted: 0.4 s listens at random gaps of 1.5–4.5 s until it's heard twice.

Mesh traffic comes first. A listen doesn't start while a mesh packet is coming in or waiting to
be read, and a mesh transmit ends a listen at once (it doesn't wait for the band to go quiet: the
radio can't hear the mesh from there anyway). After a transmit no listen starts for two repeater
hops' worth of time (1 s + 8 airtimes each, the wait flood retry uses for an echo; at least 5 s), so
the repeats of a message you send are heard, even during a scan; after a mesh packet is heard,
none for half a hop (at least 1.5 s), as other copies follow. A packet heard never shortens a wait
already running. The time a listen misses isn't held against the sensor.

Weather is one listen at a time with Meshtastic and aircraft: `wx on` turns those off (the reply
says so). `radar`, copying a radio and `find range` pause it until they finish.

On the chip, a listen is a switch of packet type from LoRa to GFSK with raw commands. Its
frequency is set after the modulation parameters: RadioLib's DC-DC workaround in
`setPacketType()`/`setGfskModulationParams()` retunes to the mesh frequency, so a listen set up
the other way round sits on the mesh's frequency. (Before that was fixed, only a radio whose mesh
was on the sensors' frequency could hear them.) (17.24 kbit/s,
153.8 kHz receiver bandwidth, sync word 0x2DD4, 32 bytes fixed length, no CRC), and back to LoRa
with RadioLib's cached MeshCore settings.

## Radio formats

The LR2021's FSK receiver is strict. Measured on the bench, with an SX1262 (whose bit rate and
deviation are set exactly) sending to it:

- **Bit rate**: within about ±0.3% of its setting at 17.22 kbit/s (17.18–17.30 heard, 17.15 and
  17.35 not), and about ±0.15% at 9.6 kbit/s (9.59–9.62; 9.57 and 9.63 not).
- **Deviation**: within about ±20% of its setting (set to 35 kHz: 31–40 heard, 25 and 50 not).
- **Sync word**: only where the preamble ends. A sync word of `2D D4` isn't found in `AA D2 AA 2D D4`
  (La Crosse View's lead-in): the listen has to look for all of `D2 AA 2D D4`.

Sensors don't all send at the round figures in their protocol notes, so the rates and deviations
here were measured on rtl_433's recordings of real sensors: each recording's signal matched against
its bits rebuilt at every rate in 0.04% steps, and the deviation read at the bit centres. Each group
that fits one setting is a listen of its own:

| Format | Bit rate | Deviation | Sync word | Sensors (measured) |
|---|---|---|---|---|
| Ecowitt | 17.22 kbit/s | 32 kHz | `2D D4` | every Fine Offset model below except the WH25: 17.18–17.26 kbit/s, 27–36 kHz |
| Ecowitt, wide | 17.235 | 55 | `2D D4` | WH25 (17.23–17.24, 60 kHz), La Crosse TX29-IT (17.23–17.24, 60–62 kHz) |
| La Crosse View | 9.606 | 35 | `D2 AA 2D D4` | TH3 9.616, R1 9.616, WR1 9.595 (31 kHz) |
| La Crosse View | 9.362 | 35 | `D2 AA 2D D4` | TH2 9.360 (35 kHz), Breeze Pro 9.364 (31 kHz) |
| La Crosse View | 9.329 | 35 | `D2 AA 2D D4` | W1 9.329 (31 kHz) |
| La Crosse IT+ | 9.577 | 20 | `2D D4` after 8 bits of preamble | TX35DTH-IT 9.577 (20 kHz) |
| La Crosse TX22U-IT | 8.624 | 35 | `2D D4` after 8 bits of preamble | TX22U-IT 8.624 (its on-off keyed recordings) |
| ThermoPro | 9.26 | 35 | `D2 55 2D D4` | TX-7B: no recording; 108 µs bits in rtl_433's notes |

Before this, one Ecowitt listen at 17.24 kbit/s and ±35 kHz missed the WH25, and one La Crosse
listen at 9.6 kbit/s missed the TH2, Breeze Pro and W1.

## Sensors

Every model rtl_433 reads in these radio formats at 915 MHz is read, except where noted below.
Each decoder follows rtl_433's device notes, and was checked against rtl_433's recordings of real
sensors (github.com/merbanan/rtl_433_tests) where there are any: 152 of 152 readings in 170
recordings came out the same (see [Checking against rtl_433](#checking-against-rtl_433)).

### Ecowitt, Ambient Weather and other Fine Offset models

They send FSK at about 17.22 kbit/s, preamble `AA..`, sync word `2D D4`, then a packet whose first
byte is the model's family code (two listens: most models at ±35 kHz, the WH25 and TX29-IT at ±60). Most families are checked the same way:
CRC-8 (polynomial 0x31) over the packet comes out 0, and the last byte is the sum of the others. A
corrupted packet is dropped.

| Model | Family | What it reports | Checked on (readings) |
|---|---|---|---|
| WH65 (WS69; Ambient WS-2902 array) | 0x24 | temperature, humidity, wind, gust, direction, rain, UV, light; the WS69's pressure | 15 |
| WH31 (Ambient WH31E; Ecowitt WN31, which sends as a WH31B) | 0x30, 0x37 | temperature, humidity, channel 1–8 | 42 |
| WH32B, WN32B (outdoor) | 0xE_ | temperature, humidity | 9 |
| WH25, WN32P (indoor) | 0xE_ | temperature, humidity, pressure | 6 |
| WH32 (older outdoor) | 0xD_ | temperature, humidity | 6 |
| WH40 | 0x40 | rain | 6 |
| WN20 | 0x20 | rain | 4 |
| WH57 | 0x57 | lightning: strike count, storm distance | |
| WS68 | 0x68 | wind, gust, direction, UV, light | |
| WS80 | 0x80 | wind, temperature, humidity, UV, light | |
| WS85 | 0x85 | wind, rain, raining | |
| WS90 | 0x90 | WS80 plus rain, raining, pressure | 2 |
| WN34, WN38 | 0x34, 0x38 | probe or globe temperature | 8 |
| WH41, WH0290 (Ambient PM25) | 0x41, 0x42 | PM2.5 | 8 |
| WH43 | 0x43 | PM2.5 | |
| WH45 | 0x45 | PM2.5, PM10, CO2, temperature, humidity | |
| WH46 | 0x46 | PM1, PM2.5, PM10, CO2, temperature, humidity | |
| WH51 | 0x51 | soil moisture | 18 |
| WH52 | 0xA2 | soil moisture, temperature, conductivity | 4 |
| WH55 | 0x55 | water leak, channel 1–4 | |
| La Crosse TX29-IT, TX29U-IT, TX25U-IT (IT+) | 0x9_ | temperature, humidity | 3 |

The WH32, WH32B and WN32B carry only an 8-bit sum (the WH25 adds an XOR), the WH55 and the IT+
sensors only a CRC-8. A packet from a sensor not heard before that's checked that weakly counts once
the same sensor is heard again within 15 minutes: one random packet in 256 passes an 8-bit check.

The WH41 and WH43 send a PM10 too, which Ecowitt's consoles don't show (the sensor estimates it from
the PM2.5): not shown here either. The WH31E's radio clock packets (family 0x52) are recognized and
skipped. The WH24 (sold outside the US) sends the WH65's packet with other wind and rain units, and
reads as a WH65.

### La Crosse and ThermoPro

They send FSK at 8.6–9.6 kbit/s, a preamble, and a sync word ending `2D D4`, each group at its own
rate (see [Radio formats](#radio-formats)); `set wx.kind lacrosse` listens for them all.

| Model | What it reports | Checked on (readings) |
|---|---|---|
| La Crosse View LTV-TH2, TH2i, TH3 | temperature, humidity (every 30 s) | 4 |
| LTV-WSDTH01 Breeze Pro | temperature, humidity, wind, direction (every 31 s, skipped when nothing changed) | 4 |
| LTV-W1, W2 | wind | 1 |
| LTV-WR1 | wind, direction (its rain isn't understood yet) | 3 |
| LTV-R1 | rain (0.25 mm per tip) | 4 |
| La Crosse TX35DTH-IT and other IT+ at 9.58k | temperature, humidity | 1 |
| La Crosse TX22U-IT (WS-1611-IT), TX31U-IT (WS-1910TWC-IT) | temperature, humidity, wind, gust, direction, rain | 4 |
| ThermoPro TX-7B | temperature, humidity, channel 1–3 | |

La Crosse View packets have no model byte: the length the CRC covers, filler bytes and plausible
values tell the models apart (an 8-byte packet followed by zeros also checks out over 11 bytes, so
those are read as 8). The TH and R1 have only a CRC-8, as do the IT+ and TX22U-IT: weakly checked,
as above. The TX22U-IT's recordings are of its on-off keyed version (the decoder is the same).

Sensors that skip unchanged readings get 12 missed packets before they're hunted again, instead of 4.
The receiver is 238 kHz wide here, which covers the Breeze Pro's 914.938 MHz as well as 915.

### Not covered

- LTV-R3 (its rain fields aren't understood yet, and there's no recording).
- IT+ sensors that send only 6 bits of preamble (some TX29-IT units, rtl_433 notes): the receiver
  needs more to lock on.
- Sensors at 433 MHz with on-off keying: Ambient Weather F007TH and TX8300, Ecowitt WH53, Acurite,
  La Crosse TX141 and others. They need the radio's OOK receiver, as the utility meters use.
- Frequency-hopping ones (Davis).
- European models at 868 MHz in other formats (Bresser, TFA, La Crosse WS6868 and TX34-IT).
  `set wx.freq 868` hears the Fine Offset and IT+ ones there.
- ThermoPro's meat thermometers and Maverick's (not weather sensors).


**In the [fluxcore app](https://fluxcore.party/app/)** (Chrome or Edge, or Bluefy on an iPhone), the Sensors tab lists everything heard with its latest readings: search and filter by name, ID or model, star the ones to post (it sets `wx.only`), name them, hide the neighbours', and see each one's readings over time (temperature, wind, rain and the rest, kept in the browser, exported as CSV). Settings and on/off are there too.

### Sensors the firmware doesn't know

A packet that doesn't decode but still checks out the way its format's packets do (a Fine Offset
one with a CRC-8 and sum at some length, or a 9.6 kbit/s one with a CRC-8, heard twice) is most
likely from a model this firmware doesn't know. They're kept, and `get wx.unknown` lists them:

```
> 1. Ecowitt 17.22k 631234.. 12B x3 -71dBm 2m ago
get wx.unknown 1
> Ecowitt 17.22k, 12 bytes:63123456010203040506def2aaaa...
```

The scan report says when there are any, and `wx scan on` notes each one as it's heard. The bytes
are what's needed to add the model.

## Settings

| Command | |
|---|---|
| `wx on` / `wx off` | start or stop (saved) |
| `wx scan` | listen for sensors without a break in each format in turn (6 minutes for both brands), then list them in the console |
| `wx scan on` / `wx scan off` | listen all the time, with a console note for each new sensor (not saved) |
| `set wx.kind ecowitt` / `lacrosse` / `both` | which formats to listen for: Ecowitt's two (also La Crosse TX29-IT), La Crosse's and ThermoPro's six, or all (default) |
| `set wx.dbg <kbps> <rxbw kHz> <dev kHz> <preamble bits, 255 none> [sync hex]` | every listen with these settings instead (0 = its own), until reboot: for experiments |
| `set wx.dbgmask <hex>` | listen in these formats only, until `set wx.kind`: 01 Ecowitt, 02 La Crosse View 9.61, 04 9.36, 08 IT+, 10 TX22U-IT, 20 ThermoPro, 40 Ecowitt wide, 80 La Crosse View 9.33 (for experiments) |
| `set wx.freq <MHz>` | default 915 (US). 868 or 433 for other regions' models |
| `set wx.units us` / `metric` | °F, mph, inches, inHg / °C, m/s, mm, hPa |
| `set wx.every <minutes>` | how often each sensor posts (default 30; 0 = first reading and alerts only) |
| `set wx.only <labels>` / `all` | show and follow only these sensors, by the label in their posts (`5a,ch2`). Others aren't tracked either, so neighbours' sensors cost no air time |
| `wx`, `get wx` | the settings |
| `get wx.sensors` | each sensor: model, label, packets heard, interval, signal, last heard |
| `get wx.stats` | packets (and bad ones), posts, listens, and the share of time away from the mesh |
| `get wx.list [start]` | the same for apps, as numbers, a page at a time: `> <sensors> <from> rec;rec..`, rec = key,model,label,format,packets,interval s,dBm,age s,flags (1 battery low, 2 posted),readings (`t215 h45 w12 ..`: t 0.1 °C, h %, w/g wind and gust 0.1 m/s, d °, r rain µm, x raining, u UV ×10, l lux, p 0.1 hPa, k strikes, K storm km, m soil %, a/b/c PM2.5/PM10/PM1 ×10, o CO₂ ppm, e µS/cm, L leak) |
| `get wx.unknown [n]` | packets that checked out but didn't decode (models not known yet); with a number, that one's bytes |
| `get radio.fsk` | the radio's side: listens, time, listens cut short by a transmit, packets |

These work from the companion CLI, the Radio console and remote CLI.

## Bench results

**Every sensor, over the air.** A Heltec V4 (SX1262) sent every test packet (rtl_433's recordings,
and the examples in its notes for models without one) at 925 MHz, each at its sensors' measured
bit rate and deviation and with its own lead-in, to the RAK3401 + NiceRF companion scanning all the
time (`tools/bench/wx_bench.py --heltec`): all 49 heard, each model posted with rtl_433's values
(the WH25, TX29-IT, TX35-IT, LTV-W1, TX-7B and TX22U-IT each read 16 of 16 in their own format). A
packet of a made-up family with the Fine Offset checks showed in `get wx.unknown` with its bytes.
Sent from the XIAO (an LR2021) instead, the same packets all read even at rates the receiver doesn't
take from a real sensor: the two LR2021s round a rate setting the same way. Test with the Heltec.

**Sharing the radio.** 20 minutes on the bench at 908 MHz: a Heltec V4 played three sensors on exact
schedules (`fsktx`) and sent MeshCore packets in the gaps; the RAK3401 + NiceRF companion listened
to both.

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

## Checking against rtl_433

`test/test_wxsensor/vectors.inc` holds two packets per model from rtl_433's recordings
(github.com/merbanan/rtl_433_tests), cut after the sync word as the radio hands them over, with what
rtl_433 reads from each. Over all 170 weather recordings there (rtl_433's raw bit rows at each
format's bit width, cut after every `2D D4`), the firmware's decoders read 152 of rtl_433's 152
readings the same (model, temperature, humidity, wind, direction, rain, pressure, PM2.5, moisture,
conductivity), and nothing rtl_433 doesn't, except where rtl_433 itself misreads (a TH3 as an R1
with 3.8 million mm of rain; a WN20 as a TX22U-IT) and the WH24 (the WH65's packet with other
units; sold outside the US). Writing the comparison found a bug of the La Crosse decoder's own: a
TH3 packet followed by zero bytes read as a Breeze Pro.

## Code

| | |
|---|---|
| `src/helpers/weather/FineOffset.*` | packet checks, decoding and the one-line summary |
| `src/helpers/weather/LaCrosse.cpp` | the slower formats' decoding: La Crosse View, IT+, TX22U-IT, ThermoPro |
| `src/helpers/weather/SensorTracker.*` | interval learning and listen scheduling |
| `src/helpers/radiolib/CustomLR2021.*` | `fskStart`, `fskRead`, `fskStop`: GFSK and back |
| `src/helpers/radiolib/CustomLR2021Wrapper.h` | the listen itself: waits for a quiet mesh, reads packets, gives way to transmits |
| `examples/companion_radio/MyMeshWeather.cpp` | the Weather channel, posts and commands |
| `test/test_wxsensor`, `test/fuzz/fuzz_wxsensor.cpp` | `pio test -e native_wxsensor` (ASAN + UBSan): rtl_433's recordings (`vectors.inc`), the examples in its notes; and the fuzzer |
| `tools/bench/wx_bench.py` | plays every test packet from a `-D FISB_BENCH_TX` companion (`wx tx <kbps> <MHz> <preamble+sync hex> <hex>`, at 902-909 or 922-928 MHz only) to a listening one |
| `tools/heltec_v4_tx` | `fsktx <MHz> <dev kHz> <hex>` plays an Ecowitt packet, `fskraw <MHz> <kbps> <dev> <sync> <hex>` any other (La Crosse: `9.6`, `d2aa2dd4`), for bench tests |
