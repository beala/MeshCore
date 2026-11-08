# Utility meters (LR2021 companions)

Many water, gas and electric meters have a radio module that sends the meter's reading every 15
seconds or so, around **915 MHz**, for the utility's drive-by readers. A companion with an LR2021
radio can hear your own meters and show their readings in the MeshCore app, in a "Meters" channel:
how much you used, and, for water meters, the leak and backflow flags the meter keeps. Nothing is
ever sent.

Two families are read:

| | Meters | Sends |
|---|---|---|
| **Neptune R900** | water meters with an R900 module | the reading, leak and backflow history, every 14.0 s |
| **Itron ERT** (SCM, SCM+) | gas meters, and some electric and water meters | the reading and tamper flags, every 15.000 s |

```
meter on                        # start; the meters around are listed as they're heard
get meter.heard                 # strongest first: yours are probably the strongest
set meter.ids 1234567890,87654321   # show these in the Meters channel
```

Reconnect the app after `meter on`. The channel comes after your own, in a fixed slot after the
Meshtastic, Weather, Aircraft, Damaged and Airport weather ones (empty if those are off).

```
Water 7890: 1,204,511
Gas 4321: 48,210
Water 7890: 1,204,568, +57 in 60 min. Leak: on and off (water in half the day's 15 min)
Water 7890: 1,204,601, +33 in 61 min. Leak: none now
```

- Posts read `<type> <last 4 digits of the ID>: <reading>`, as channel texts are `sender: text`
  in the app. The reading is the meter's register in its own units (often gallons, tenths of a
  gallon or cubic feet for water, cubic feet for gas, kWh for electric).
- A post comes when the reading is first heard, then at most every `meter.every` minutes (60), with
  how much was used since the last one. A leak or backflow flag that comes or goes is posted as
  soon as it's heard.
- **Leaks** (R900): "continuous" means water ran in every 15-minute period of the last 24 hours (a
  running toilet, a dripping tap, a broken pipe; also a long irrigation schedule or a water softener's
  regeneration). "On and off" means water in at least 50 of the day's 96 periods. "Leaking for 35+
  days" is how long the meter has seen it.
- **Only your meters.** Every meter in range is heard and listed in `get meter.heard` (to find
  yours), but only the ones in `set meter.ids` are ever posted: a neighbour's readings are theirs.
- Turning it on turns off Meshtastic, Weather, Aircraft or Airport weather (one listen at a time).

### Finding your meters

- **The label**: the ID is printed on the meter's radio module (a puck on the pit lid or a box on
  the wall for water; the ERT module on the gas meter).
- **The strongest**: `get meter.heard` lists the strongest first. Your own meters are usually a few
  metres away, the neighbours' tens of metres.
- **Run a tap**: for a few minutes, then see whose reading jumps.

Finding a meter for the first time can take a while (see [the search](#the-search)): at the
default 10%, often an hour or more. `set meter.duty 100` for half an hour finds them faster (the
mesh isn't heard meanwhile), then back to `set meter.duty 10`.

## Settings

| Command | |
|---|---|
| `meter on` / `meter off` | start or stop (saved) |
| `set meter.ids <IDs>` | the meters to show, by ID, comma-separated, up to 47 characters (`none`, the default: none shown) |
| `set meter.every <minutes>` | between a meter's posts (default 60; 1-1440) |
| `set meter.duty <percent>` | the search for meters not heard yet (default 10; 100 = all the time, and the mesh isn't heard) |
| `meter`, `get meter` | the settings |
| `get meter.heard [start]` | the meters heard (up to 40), strongest first: type, ID, reading, signal, minutes since heard |
| `get meter.stats` | frames (and those that didn't read), by kind; meters, posts; timed listens that caught their meter; time listening; "searching" while it is |
| `get radio.fsk`, `get radio.ook.rx` | the radio's listens and its OOK receiver counters |

## How it works

### The radio side

| | R900 | SCM+ | SCM |
|---|---|---|---|
| Modulation | on-off keying, 32.768 kchip/s | the same, Manchester coded (data 1 = chips `10`) | the same |
| Start | 31 chips `1010..`, sync `A9666965` | no preamble: the frame starts with its sync `16 A3` | no preamble: a 21-bit sync `1F2A60` |
| Then | 168 chips: 42 groups of 4, each one of six codes (a base-6 digit); two digits carry 5 bits: 104 bits | 14 bytes: protocol `1E`, endpoint type, ID (4), reading (4), tamper (2), CRC-16/CCITT (init `0971`) | 75 bits: ID, tamper, type, reading (24 bits), CRC-16 (poly `6F63`) |
| Checked by | the codes (no CRC: a stray frame passes all 42 code checks about once in 10^18) | the CRC | the CRC |
| Channels | 50 of 78 places 130.5 kHz apart (910.30-920.35 MHz), in a fixed order | 51, 200 kHz apart, 910.0-920.0 MHz | as SCM+ |
| Every | 14.000 s | 15.000 s | 15 s |

The LR2021's OOK receiver finds a frame by a detector pattern (up to 16 chips) and then a sync
word (up to 32 chips), and hands over a fixed number of bytes after it. It's set to take the raw
chips, with no Manchester decoding, CRC or whitening; `src/helpers/meters` reads them. The
detector pattern and sync word for each kind:

| | Pattern (first chip in the LSB) | Sync word | Then |
|---|---|---|---|
| R900 | `5555` (16 chips of `1010`) | `A9666965` | 21 bytes |
| SCM+ | `966A` (Manchester `16`) | `995A56A9` (Manchester `A3 1E`) | 26 bytes |
| SCM | `6955` (Manchester `F9`, the sync's first 8 bits) | `665A55` (its next 12) | 19 bytes |

**One channel at a time.** At 32.768 kchip/s the OOK receiver works up to a 153.8 kHz bandwidth
and hears nothing at 307 kHz or wider (on the bench, 15 of 15 frames at 76.9 and 153.8 kHz, 0 at
307-3076; at 38.5 kHz the chips smear and most frames don't read). So a listen covers one of a
meter's 50-78 channels, and a frame lands on it about one time in 50-78.

### Timed listens

Each meter sends like clockwork: an Itron module every 15.000 s to the millisecond, an R900 every
14.000 s within about 20 ms. Once one of your meters has been heard, the radio opens a short listen
just when its next frame is due (30-60 ms either side, more the longer it's been), and learns its
exact period from the frames it catches. That's under 1% of the mesh's time per meter. Meters not
heard for 3 hours are searched for again.

**Where to listen.** R900s hop through the same 50 channels in the same order, each meter at its own
place in the sequence: in an hour of RTL-SDR recordings across the band, every pair of frames from
one meter a multiple of 50 sends apart was on the same channel (114 of 114), and 6 meters all fit
one sequence. So one frame heard on a channel tells where that meter is in it, and each timed listen
after that goes to the channel its next frame will be on. Before that first catch, and for Itron
meters (they also repeat every 50 sends, but each seems to have its own order), each timed listen
takes the next of its channels in turn: one try in 50 or so hits.

### The search

Until every chosen meter has been heard (or while none is chosen), the radio also searches,
`meter.duty` of the time (10%): 1-second listens across the three kinds and all their channels in
turn. A given meter is caught about once every few hours at 10%, so finding one takes patience,
or `set meter.duty 100` for a while.

## Bench testing

`tools/bench/meters.py` reads meter frames from an RTL-SDR recording (any sample rate, the whole
band at once) and builds the chips a meter sends:

```
tools/bench/rtltcp_rec.py 192.168.1.205:1234 rec.cu8 --mhz 912.5 --rate 2400000 --gain 30 --secs 120
tools/bench/meters.py read rec.cu8            # every frame, with its frequency and level
tools/bench/meters.py chips r900 1234567890 1000 --leak 6 --leaknow 2
tools/bench/meters.py vectors                 # test/test_meters/vectors.inc (made-up meters)
```

A companion built with `-D FISB_BENCH_TX` (never in releases) sends them: `meter tx <MHz> <hex>`
once, or `meter tx every <ms> <MHz> <hex>` on its own clock like a meter (2 at once; `meter tx
stop`). It refuses 909-922 MHz, where real meters send, so a made-up meter never reaches a
utility's reader; bench tests use 925 MHz with made-up IDs. `set meter.center <MHz>` (until
reboot) makes a receiver listen there instead of the meters' channels.

```
PLATFORMIO_BUILD_FLAGS="-D FISB_BENCH_TX" pio run -e AB_Xiao_nrf52_LR2021_companion_radio_usb -t upload
tools/bench/meter_bench.py /dev/serial/by-id/usb-Seeed_Studio_XIAO_* /dev/serial/by-id/usb-RAKwireless_*
```

### Results

- **Real meters, from an RTL-SDR** in a window (2.4 MS/s at 912.5 MHz, 2 minutes): 9 R900 and 6
  SCM+ frames read by `meters.py`, with the same IDs, readings and flags as rtl_433 gives for those
  meters. The C decoder reads them the same way.
- **Where and when they send** (a scan of 904-926 MHz, 11 minutes, rtl_433): R900 at 910.2-920.4
  MHz, Itron at 910.2-920.0, nothing outside. Within the 2-minute recording, each meter's frames
  were a whole number of periods apart: 15.000 s for SCM+, 13.98-14.01 s for R900.
- **Over the air**, XIAO + Wio-LR2021 sending at 925 MHz, 22 dBm, to a RAK3401 + NiceRF
  LoRa2021F33 (both in a shielded box):
  - R900, SCM+ and SCM frames: 15 of 15 of each read, at 153.8 kHz
  - a made-up water meter with a continuous leak, every 14 s: found by the search in 4.5 minutes
    at 10%, then 16 of 17 timed listens caught it, and posts came every `meter.every`:
    `Water 7890: 7,000, +0 in 2 min. Leak: continuous (water every 15 min for a day), leaking for 35+ days`
  - a real gas meter outside the box was heard too, at -80 dBm

## Code

| | |
|---|---|
| `src/helpers/meters/Meters.*` | R900, SCM and SCM+ frames from raw chips; how each is found on the air; channels and periods |
| `examples/companion_radio/MyMeshMeters.cpp` | the Meters channel, the table, timed listens and the search, posts, commands, the bench sender |
| `src/helpers/radiolib/CustomLR2021.*`, `CustomLR2021Wrapper.h` | the raw OOK listen (`ookRawStart`, `MODEM_OOK`) and the bench OOK sender |
| `test/test_meters`, `test/fuzz/fuzz_meters.cpp` | tests on frames made by `meters.py`, and a fuzzer |
