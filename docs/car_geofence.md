# Car repeater: sleep at home

## In plain terms

A T1000-E repeater can live in your car on its battery alone. While the car is parked at home it stops repeating and puts its radio and GPS to sleep, so the battery lasts. When you drive away it notices and starts repeating again.

**How it knows it's home.** You save your home Wi-Fi once. The T1000-E's LR1110 chip can listen for Wi-Fi access points without joining them, and it doesn't need a password. When the car has been still for 3 minutes, it listens once. If it hears your home Wi-Fi, it goes to sleep. If not, it tries once more a minute later, then every 15 minutes while the car stays put. While you're driving it doesn't scan at all.

**How it knows it's leaving.** Its motion sensor wakes it when the car moves. It listens for home Wi-Fi, and after two misses 30 seconds apart it starts repeating again. If it still hears home (someone shut the car door), it goes straight back to sleep. A car being jostled at home scans at most once every 2 minutes. As a backup, it also listens once an hour while asleep.

**Talking to it while it's asleep.** A sleeping repeater can't hear the mesh, so remote admin doesn't reach it. Press its button: the radio stays on for 10 minutes, then it goes back to sleep if it's still home.

How often it scans:

| Situation | Scans |
|---|---|
| Driving, or stops under 3 minutes | none |
| Parked away from home | 2 in the first 4 minutes, then 4 an hour |
| Parked at home, asleep | 1 an hour, plus 1 when the car is bumped (at most 1 every 2 minutes) |

### Setting it up

1. Flash the **Repeater** firmware for the SenseCAP T1000-E from the flasher.
2. Park at home, connect it over USB (or remote admin), and run `geo home set`. It listens three times and saves the home access points it heard strongly (up to 8).
3. Check them with `geo home`. If one is missing, run `geo home add` in another spot, for example nearer the garage.
4. Turn it on: `geo on`.
5. `geo` shows what it's doing, for example `home, 3 home APs, radio asleep 712s, scan in 190s`.

## Commands

From the repeater's command line, over USB or remote admin.

| Command | What it does |
|---|---|
| `geo` | State (`off`, `away`, `home`, `leaving`), saved access points, whether the radio is on, when the next scan is |
| `geo on` / `geo off` | Turn the geofence on or off. On needs saved home access points. Off keeps the radio on and the motion sensor powered down |
| `geo home` | The saved access points |
| `geo home set [dBm]` | Listen three times and save the home access points at least as strong as `dBm` (default -75, range -100 to -20). Replaces the list |
| `geo home add [dBm]` | Same, but adds to the list |
| `geo home clear` | Forget the home access points |
| `geo still [s]` | How long the car must be still before it checks for home. Default 180 s, 10 to 3600 |
| `geo check [min]` | How often it checks while asleep at home. Default 60 min, 5 to 1440 |
| `geo awake [min]` | How long a button press keeps the radio on. Default 10 min, 1 to 240 |
| `geo force home` | Sleep now and stay asleep without scanning, until `geo force auto` |
| `geo force away` | Stay awake and repeating without scanning, until `geo force auto` |
| `geo force auto` | Back to normal |
| `geo scan` | Scan now and say whether home was seen |
| `geo log` | The last 48 events with uptime, signal and battery (USB shows all, remote admin the newest that fit) |
| `geo stats` | Counts since boot: scans, home hits, misses, failures, state changes, motion, button, time asleep |

Commands for checking the hardware: `wifi scan [ms 20-190] [b|g|*] [mode]` lists the access points it hears, and `motion` shows the motion sensor's state.

## Technical details

**The state machine** (`src/helpers/GeoFence.h`, no hardware code, so it's tested on the host in `test/test_geofence` and fuzzed in `test/fuzz/fuzz_geo.cpp`):

- **away**: repeating. Still for `geo still` seconds → scan. Home heard → **home**. A miss is tried once more 60 s later, then every 15 minutes while still. Motion restarts the wait (and the retry).
- **home**: radio asleep. Motion, or a miss on the `geo check` backup scan → **leaving**.
- **leaving**: radio asleep. Scans at once, then every 30 s. Home heard → **home**. Two misses in a row → **away**. The first scan waits until 2 minutes after the previous one, so a car moved about at home (each movement goes home → leaving → home) scans at most once every 2 minutes; a real departure is noticed within about 2½ minutes.
- A scan that fails (radio busy, chip error) is retried after 10 s and never counts as a miss.

**Matching.** An access point that sends several networks gives each one a MAC address that differs only in the first byte, so matching ignores the first byte. A scan doesn't always hear every access point, so any one saved access point counts as home.

**Wi-Fi scan.** LR1110 passive scan, channels 1 to 11, 120 ms per channel, stopped by time (`WifiScanTimeLimit`). It scans 802.11b beacons first and then g/n. Access points send their beacons at b rates, so the b scan finds them about 10 times out of 10 at home. The command layout follows Semtech's SWDR001 driver; RadioLib's parser gets the signal strength wrong.

**Sleep.** At home the LR1110 sleeps with its settings kept (`sleep(true, 0)`), the GPS is switched off and its serial port closed, and the main loop runs every 200 ms only to watch the motion sensor and button. After each scan, LoRa settings, transmit power and receive gain are set again. The radio is put back to sleep every 5 minutes in case something woke it, and the battery voltage is logged every 30 minutes (`geo log`, letter `P`).

**Motion.** QMA6100P accelerometer, powered only while the geofence is on, with its motion interrupt on a pin. The button is counted by interrupt.

**Settings** are saved in `/geofence` and survive reboots and firmware updates.

Only the T1000-E repeater build (`t1000e_repeater`, flags `GEOFENCE_WIFI` and `MOTION_WAKE_QMA6100P`) has it.
