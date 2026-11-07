# Telling transmitters apart by frequency (LR2021)

No two radios transmit on exactly the same frequency. Each one's crystal is a little off, by an amount
that stays about the same for that radio. The LR2021 measures this for every LoRa packet it hears
(datasheet 9.9.9, `GetLoraPacketStatus`, the frequency error in Hz), so the reading works as a rough
fingerprint of the radio that sent the packet. It's there for packets that failed their CRC too.

`get radio.freq` lists the last packets with their readings:

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
(`src/helpers/radiolib/`).
