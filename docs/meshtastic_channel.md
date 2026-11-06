# Meshtastic channel (LR2021 companions)

A companion with an LR2021 radio can listen to a Meshtastic channel as well as MeshCore. The
radio's own CPU hops between the two networks, and Meshtastic texts show in the MeshCore app as
one more channel. The app is unchanged; nothing is sent on either network.

```
mt on                       # LongFast on its default US frequency, default key
```

Reconnect the app, and a channel named "Meshtastic LongFast" appears after your own channels. The synthetic channels keep fixed slots (Meshtastic, Weather,
Aircraft), so turning one on or off never moves another; a slot whose feature is off is empty.
Its messages read `Name: text`, with the sender's long name once their NodeInfo has been heard
(`!a1b2c3d4` until then).

## Settings

| Command | |
|---|---|
| `mt on` / `mt off` | start or stop listening (saved) |
| `set mt.preset <name>` | `LongFast` (default), `LongModerate`, `LongSlow`, `MediumFast`, `MediumSlow`, `ShortFast`, `ShortSlow`, `ShortTurbo` |
| `set mt.freq <MHz>` / `auto` | `auto` is the preset's default US frequency: slot = hash of the channel name mod the number of slots, so LongFast is on 906.875 MHz |
| `set mt.channel <name>` / `default` | the channel name, which sets the channel hash (and the `auto` frequency). Default: the preset's name, as for a primary channel |
| `set mt.key <base64>` / `default` / `none` | the channel key as the Meshtastic apps show it. Default `AQ==` |
| `mt`, `get mt` | the settings |
| `get mt.stats` | packets heard: texts (and how many reached the app), names, repeats, other channels, DMs, undecodable |
| `get mt.last` | the last packet heard, raw |
| `get radio.scan` | the scanner: CADs, false alarms, packets lost after a preamble, packets per network, restarts |

These work from the companion CLI, the Radio console and remote CLI.

## What shows, what doesn't

- **Texts** (port 1) broadcast on the channel. Long ones are split into several messages.
- **NodeInfo** (port 4) isn't shown; it gives senders their names. The radio keeps the last 24.
- **Repeats** of a packet relayed by other nodes are dropped (same sender and packet id).
- **Not shown:** DMs (they need the node's own keys), position, telemetry and other ports, and
  other channels.
- **Receive only.** A text typed into the Meshtastic channel isn't sent anywhere: the radio answers
  "Not sent: the Meshtastic channel is receive-only". The channel can't be edited from the app.
- The SNR in the app is the packet's; the path length is the number of hops it took.

## How it works

**On the radio chip.** The LR2021 runs a small program from its Patch RAM
(`tools/lr2021_scan/scan.c`, built into `src/helpers/radiolib/lr2021_scan_blob.h`). It is the
background scanner from the LR2021 reverse-engineering notes (lr2021-re, `firmware/pram/scan.c`
and `docs/pram-scanner.md`), extended for this:

- Each channel has its own frequency, modulation, preamble **and sync word** (MeshCore 0x12,
  Meshtastic 0x2B). The scanner sets the sync word with the chip's raw sync command (0x022D, ROM
  handler 0xF3FC) on every hop where it changes.
- After each modulation change it updates the DC-DC settings that follow the receiver's decimation,
  as RadioLib does after `setLoRaModulationParams`.
- On each channel it runs a 2-symbol, preamble-only CAD. On a detection it stays in RX on that
  channel; otherwise it moves on. A full round takes about 20 ms, well inside both preambles
  (MeshCore SF7: 65 ms; Meshtastic LongFast: 131 ms).
- A packet ends with RxDone on the IRQ pin, as normal reception does. The scan parks until the
  radio driver has read it, then the driver resumes it and the response says which channel the
  packet came from.
- Stopping it puts MeshCore's frequency, modulation, preamble and sync word back, so RadioLib's
  view of the radio is right again.

**In the radio driver** (`CustomLR2021`, `CustomLR2021Wrapper`):

- The scanner replaces Semtech's PRAM patch while Meshtastic is on (both need PRAM). `mt on` resets
  the radio chip, loads the scanner and applies the radio settings again; `mt off` resets it and
  loads Semtech's patch. This is the unpatched ROM the scanner research used.
- Starting reception starts the scan. Standby, sleep, any transmit (RadioLib's `stageMode`), the AGC
  reset and ranging stop it first, so the radio always transmits with MeshCore's settings.
- Packets from channel 0 go to the mesh as usual. Packets from the Meshtastic channel never reach
  the mesh: they go into a 4-packet queue that the companion reads.
- Once a second the driver checks the scan is still running on the chip, and restarts it if not
  (`get radio.scan.restarts` says why).
- While on, the noise floor isn't sampled, so `int.thresh` (RSSI-based listen-before-talk) has
  no effect. Hardware CAD before transmit (`set cad on`) still works.

**In the companion** (`examples/companion_radio/MyMeshMeshtastic.cpp`): settings, commands, and the
extra channel. The device info reports one channel more than the radio has; `GET_CHANNEL` for that
index returns "Meshtastic <channel>" with a made-up secret that matches no MeshCore channel.

**Decoding** (`src/helpers/meshtastic/MeshtasticRx.cpp`) is written from the on-air format: the
16-byte clear header, the channel hash (XOR of the name and key bytes), AES-CTR with the packet
id and sender as the nonce, and a protobuf reader for the `Data` and `User` fields it needs. No
Meshtastic code is used.

## Costs

- While a Meshtastic packet is being received, MeshCore isn't heard. A LongFast text takes 0.3 to
  2 s on air, and the radio receives every packet on the channel (position, telemetry, NodeInfo)
  before it can tell what it is. On a busy LongFast mesh this costs MeshCore packets.
- CAD instead of continuous reception: the scanner's catch rate at the weakest signals hasn't been
  compared with continuous reception.
- Semtech's PRAM patch is off while Meshtastic is on.

## Tests

- `pio test -e native_meshtastic`: decoding under AddressSanitizer + UBSan, against packets made by
  lr2021-re-public's `tools/meshtastic_node.py`.
- `test/fuzz/run.sh` includes `fuzz_meshtastic` (packets into the decoder, and the splitting into
  app messages, into buffers of a frame's exact size).

Bench (2026-11-05): RAK3401 + NiceRF LR2021 companion; an AB XIAO LR2021 and a Heltec V4
(SX1262) as the other nodes; dummy loads; Meshtastic channel on 907.5 MHz so nothing reached real
LongFast nodes.

| Test | Result |
|---|---|
| MeshCore packets (908 MHz, SF7/62.5, 32-symbol preamble) at random moments, scanning | 100/100 |
| MeshCore and Meshtastic packets interleaved at random, XIAO sending | 100/100 and 100/100 |
| Same, Heltec V4 sending | 100/100 and 100/100 |
| The companion's adverts heard by the other node on MeshCore's settings, with Meshtastic packets in between | 20/20 (XIAO), 30/30 (Heltec) |
| `mt off`, `mt on`, `mt off`, `mt on`: 20 + 20 packets after each | MeshCore 20/20 every time; Meshtastic 19/20 once, then 20/20 |
| A 246-byte Meshtastic text with multi-byte characters | received whole, shown as two messages |
| NodeInfo then a text | the text shows the sender's long name |
| The same text relayed with one hop less; a DM; a position packet | not shown (repeat, DM, other port) |
| A text typed into the Meshtastic channel in the app | nothing transmitted; the radio answers in the channel |

Across the runs the chip ran over 150,000 CADs with no false alarms and no packet lost after a
preamble. The first version transmitted with the scan still running (RadioLib's transmit doesn't
go through standby): the other node heard 1 advert in 10. Stopping the scan in `stageMode()`
fixed it.
