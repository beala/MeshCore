# Radar sweep detector (LR2021 companions)

Ground radars find aircraft by interrogating their transponders on **1030 MHz** with a narrow
rotating beam. A radio on the ground hears a burst of pulses each time the beam (or a strong
sidelobe) points its way: once per turn. `radar` listens for a minute and works out how fast the
radars around are turning. Airport surveillance radars turn every **4.8 s**, long-range ones every
10–12 s. Nothing is ever sent.

```
radar                 # listen on 1030 MHz for 60 s; the result shows in the Radio console
```

```
Radar, 1030 MHz, 30 s: 3751 pulses, 8 bursts. one turning every 4.81 s (heard 5 of 6 turns).
```

The radio does nothing else while it listens: the mesh isn't heard (sending still works, and ends
the listen for a moment).

| Command | |
|---|---|
| `radar [seconds] [threshold] [MHz]` | listen for 20–90 s (default 60). Threshold: dB over the noise (default 1), or a fixed level as a negative number in dBm (e.g. `-94`) |
| `get radar` | the last result, or the progress |
| `get radar.bursts` | the last listen's bursts, in seconds from its start |
| `radar stop` | finish now and show the result |

## How it works

- **Pulses.** The LR2021's OOK receiver at 1030 MHz, 1 µs chips, 3 MHz wide, with its detector set
  to fire on any pulse above the threshold (pattern "10": a high chip, then a low one). Each
  detection is a 1-byte "packet": the firmware only notes when it came, in 10 ms bins. Nothing is
  decoded.
- **Bursts.** Noise triggers are spread evenly; a sweep piles detections into 50 ms. Bursts are
  50 ms windows more than 4 standard deviations over the average.
- **Periods.** For each period from 2 to 15 s (10 ms steps), the bursts that fall on one grid of
  that period, and the share of the grid's turns that had one: both near 1 for the true period,
  about half for twice or half of it. The best one is refined by a least-squares fit; its bursts are
  taken away and the search runs again, so a second radar isn't hidden behind multiples of the
  first. Code: `src/helpers/aircraft/RadarSweep.*`, tests in `test/test_adsb/test_radar.cpp`
  (synthetic listens: noise, missed sweeps, two radars at once), and the aircraft fuzzer.

## Results

RAK3401 + NiceRF LoRa2021F33 with a 915 MHz antenna, in a basement in Longmont, Colorado, about
30 km from Denver International Airport. 1000 MHz, where nothing transmits, is the control:

| Threshold | 1030 MHz | 1000 MHz |
|---|---|---|
| 1 dB over the noise, 30 s | 3751 pulses, 8 bursts: **4.81 s** (5 of 6 turns) | 470 pulses, no bursts |
| −94 dBm, 30 s | 3679 pulses, 10 bursts: 6.75 s (4 of 4 turns) | 74 pulses, no bursts |
| −92 dBm, 30 s | 337 pulses, no bursts | 1 pulse |
| 10 dB over the noise (the ADS-B setting) | nothing | nothing |

The pulses there are only a dB or two over the noise, so results vary from one listen to the next,
and several radars are heard at once. An RTL-SDR recording on the same bench found real Mode A/C
interrogations (P1–P3 pairs 8 and 21 µs apart, 60 times more often than chance) and a 6.72 s
periodicity. A window, the attic or outdoors should do much better.
