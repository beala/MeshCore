# Telling transmitters apart by frequency (LR2021)

No two radios transmit on exactly the same frequency. Each one's crystal is a little off, by an amount
that stays about the same for that radio. The LR2021 measures this for every LoRa packet it hears
(datasheet 9.9.9, `GetLoraPacketStatus`, the frequency error in Hz), so the reading works as a rough
fingerprint of the radio that sent the packet. It's there for packets that failed their CRC too.

## Each radio's fingerprint: `get nodes.freq`

The radio keeps a table of the radios it hears, one row per radio, with its usual frequency error:

```
> 4 radios; 2 share 4c; 88a1 Hilltop: -1125Hz ~2, 240, 2m; 4c07 Sender: -390Hz ~2, 6, 7m; 4c: +23Hz ~9, 12, 5s; 7a: +310Hz ~4, 40, 1m
```

Per radio: its ID (2 or 3 bytes and a contact's name once it's known for sure, else its 1-byte ID), its
usual frequency error, how far its readings stray from that (`~2`: ±2 Hz), how many packets were put
under it, and when it was last heard. Most heard first; `get nodes.freq 4` starts at the 5th.
`2 share 4c`: two radios whose IDs start with `4c`, told apart by their frequencies.
`nodes.freq reset` clears the table.

How the table is built, from each packet that passes its CRC:

- **The ID the packet gives.** The radio we heard it from: the last repeater in a flood packet's path
  (1 to 3 bytes, the mesh's path hash size), or a direct advert's key (the first 4 bytes), as in
  [Who sent it](damaged_packets.md#who-sent-it). Some packets give none (a channel message straight
  from its author).
- **A row is a radio.** A packet goes under the row whose ID fits (the bytes both have are the same)
  and whose band holds its reading. The band is 40 Hz, or 3 times the radio's own scatter if that's
  more, so it follows slow drift (heat moves a radio by 150 Hz over minutes). A reading that fits no
  row starts a new one: a radio not heard before, or another radio with the same ID.
- **Certain rows.** A direct advert whose signature checks out, or a packet with an ID of 2 bytes or
  more (3 is the most a path hash has), makes its row certain: only certain rows are shown with 2 or 3
  bytes and a name. A row started
  from 1-byte IDs stays unnamed (1 in 256 radios share each) until such a packet confirms it, at the
  same frequency.
- **Learning.** A row learns its frequency from packets whose ID fits only that row: a 1-byte ID
  plus the frequency agreeing is good enough to follow the radio's drift, though never to name it.
  A packet with no ID never teaches a row; it's only counted under one if exactly one row's band holds
  it.
- **Weak packets.** Below −5 dB SNR readings scatter, and can be a whole step (488 Hz) off: they're
  only matched (with a band 40 Hz wider), never learned from.
- 16 radios are kept; when full, the one heard least lately goes, an unnamed one before a named one.

Two radios less than about 40 Hz apart can't be told apart: they share a row if their IDs fit, and a
packet with no ID between them isn't put under either.

For apps, `get nodes.list [n]` gives the same rows as numbers, a page at a time:
`> <radios> <from> <id>,<named 0/1>,<name>,<error Hz>,<scatter Hz>,<learned>,<matched>,<age s>;...`
(the ID in hex: every byte known for a named radio, else 1). The [fluxcore app](https://fluxcore.party/app/)'s
Radios tab uses it: every radio as a band on one frequency axis (radios sharing a first ID byte
outlined, unconfirmed ones dashed), and each radio's drift since the app connected.

### Naming the sender of a packet

When a packet gives less than 2 bytes of ID, or none, the radio it came from is taken from its
frequency, if exactly one certain row fits its ID and frequency. Damaged packets show it with a `~`
(`~88a1 Hilltop: [advert, -9dB] ...`), and `get dmg.from` counts them under that radio. A damaged
packet's reading is never learned from.

## Each packet's reading: `get radio.freq`

`get radio.freq` lists the last packets with their readings, for checking the table or for scripts:

```
> 41;37 -1125 54 15 88 92733861;38 -1122 53 22 ? 314174f6;39 -766 -40 15 ? 00000000!;40 ...
```

The first number is how many packets have been logged since boot. Then, for each packet:

| Field | |
|---|---|
| `37` | the packet's number |
| `-1125` | the frequency error in Hz: how far the sender's carrier was from this radio's |
| `54` | SNR × 4 (54 = 13.5 dB) |
| `15` | the packet's first byte (route and type) |
| `88` | the radio it came from, by [the same rule as damaged packets](damaged_packets.md#who-sent-it), in hex; `?` unknown |
| `92733861` | the first 4 bytes of its payload (an advert: the start of its key) |
| `!` | it failed its CRC |

`get radio.freq <n>` lists only packets numbered `n` and after, oldest first, so a script can poll
without missing any. 16 are kept.

The reading is relative: it includes this radio's own crystal error. The same transmitter reads
differently on two receivers, but the difference between two transmitters is the same on both.

On the bench, with a Heltec V4 sending as a repeater with a 2-byte ID (`a2b3`), as `a2`, as `4c` (the
first byte of the XIAO's key) and with no ID, while the XIAO and the RAK sent signed adverts, the RAK's
table showed 3 radios: `a2b3` (its 1-byte `a2` packets joined it), `4c07 Sender` (the XIAO), and an
unnamed `4c` 410 Hz away from it, flagged `2 share 4c`. Weak `a2` packets that failed their CRC on the
XIAO were posted as `~a2b3`.

## What the tests showed

Three radios on the bench (a Heltec V4 with an SX1262, a RAK3401 with a NiceRF LR2021, a XIAO with a Wio
LR2021), at 908 MHz, SF7, 62.5 kHz:

- **Steady.** At a good signal, a radio reads within ±4 Hz from packet to packet. The readings come
  in steps of about 4 Hz.
- **Weak signals.** Near the edge of range (SNR around −10 dB) the spread is wider, and now and then a
  reading is off by exactly 488 Hz: one step of the chip's internal frequency grid (62,500 / 128 Hz).
- **Radios are spread out, but not always far apart.** The XIAO was 360 Hz from the other two; the
  Heltec and the RAK were only 10 to 16 Hz apart, too close to tell apart from one packet (an average
  of many still does).
- **Heat moves it.** Two minutes of sending back to back at 22 dBm moved the Heltec's frequency by
  150 Hz, and it took several minutes to come back. A receiver drifts too: the XIAO moved 40 Hz in the
  7 minutes after it was flashed. Both receivers saw the same change in the Heltec, so the gap between
  them stayed the same (360 ± 5 Hz).
- **On the live mesh** (listening only, 20 minutes), nearly every packet was relayed by one repeater.
  It read at a steady −1125 ± 2 Hz on one receiver and −765 ± 6 Hz on the other. A packet that
  claimed another sender (a direct-routed reply on its last leg) read at exactly the repeater's
  frequency: the repeater had sent it. That's why damaged packets now give no sender for those.

So a reading can separate radios that are more than about 50 Hz apart, with care about heat. It
can't separate radios that happen to sit close together.

## What it isn't

It isn't security: a sender can move their frequency on purpose, and an SDR can be set to any
frequency. It tells ordinary radios apart, it doesn't prove who sent a packet.

Only the LR2021 reports this: other radios reply `Unknown command`.

## Code

`CustomLR2021::readLastStatus()` reads the error; `CustomLR2021Wrapper` keeps the log
(`src/helpers/radiolib/`). The table is `src/helpers/FreqPrint.*` (tests: `test/test_freqprint`), and
the companion's side `examples/companion_radio/MyMeshFreq.cpp`.
