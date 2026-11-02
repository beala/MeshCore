# Finding a lost radio

## In plain terms

**Make it beep.** Run `find me` on a companion radio and it beeps for 2 minutes, so you can find it by ear. Radios with a vibration motor vibrate too. It beeps even if you've turned the buzzer off. Press its button, or run `find me stop`, to stop it.

**Make it beep from another radio.** If your radio is lost, you can't type commands into it. So you can also ask it to beep from a second radio you own, or a friend's radio:

1. On the radio you might lose, allow the other radio once: `set find.allow <its contact name>`.
2. When it's lost, run `find beep <lost radio's name>` on the other radio.
3. A few seconds later, `get find` shows the answer, for example `beeping for 120 s`.

Only radios you've allowed can do this, and they can't do anything else. The request is encrypted and signed like a direct message, so nobody else can send it or replay an old one.

**Measure how far away it is.** If both radios have an LR2021 chip (for example the SenseCAP MeshTracker X1), run `find range <name>`. The radios measure the time a signal takes to get there and back, and `get find` shows the distance, for example `42 m (+/- 4 m, 30/32 answers, -97 dBm)`. Walk around and run it again: if the number goes down, you're getting closer.

Limits:
- **Experimental.** It hasn't been tested on real radios yet.
- The radios must hear each other directly, not through a repeater.
- The distance is uncalibrated and can be off by several metres. Walls and bodies make it read longer.
- It only works on 902–928 MHz (US, Canada, Australia, New Zealand), because the measurement uses a 500 kHz wide signal.

## Technical details

### Messages

The finder sends a CLI command message (`TXT_TYPE_CLI_COMMAND`) to the target: `find me`, `find me stop`, or `find range`. It's encrypted with the pair's shared secret, like any direct message.

The target handles it only if the finder is on its allow list (`set find.allow`, up to 8 entries, stored in `/find_allow`) or has remote CLI access. It replies with a CLI data message starting `find: `, which the finder saves for `get find` and also passes to the app.

For each allowed finder, the target stores the newest request timestamp it has accepted, and ignores any request that isn't newer. That stops replays, including after a reboot. If the finder's clock goes backwards, its requests are refused with `find: old request ignored (is your clock set?)` until the clock is set.

### Ranging

This uses the LR2021's round-trip time-of-flight mode (RTToF). The command sequence follows Semtech's usp v1.2.1 radio layer and the bench tests in [beala/lr2021-re](https://github.com/beala/lr2021-re/blob/main/docs/ranging.md).

1. The finder sends `find range`. The target replies `find: ranging` and waits until that reply has been transmitted.
2. The target switches to RTToF subordinate and answers ranging requests for 3 seconds.
3. The finder hears the reply, switches to RTToF manager, and runs up to 32 exchanges in 2.5 seconds. Each exchange is given up after 100 ms.
4. Both radios return to normal LoRa: standby, packet type LoRa, sync word, then the usual frequency, bandwidth, SF, CR, preamble and side-detector settings.

The settings are:
- SF9, BW 500 kHz, CR 4/5, preamble 12, explicit header, CRC, on the current frequency.
- 15 response symbols, normal mode.
- TxRxDelay 20305, Semtech's value for BW 500 kHz, SF9.
- The ranging address is the first 4 bytes of the target's public key, all 4 checked, so it ignores other ranging sessions.

The reported distance is the median of the valid exchanges, at 150 / (4096 × 0.5 MHz) = 7.3 cm per raw unit. The ± figure is half the interquartile range, and the RSSI is the median.

After every packet type change, the code applies the same DC-DC workaround as RadioLib's own `setPacketType()`: the DCDC_SWITCHER bits, DCDC_FREQ_LF, and setting the frequency again.

Each radio is blocked for up to 3 seconds while ranging, and can't receive mesh traffic during that time. A target accepts at most one ranging session every 5 seconds.

### Accuracy

On the bench, with the antenna ports on dummy loads, a single exchange at SF9 was good to about 4 m (σ), and the median of 200 was within a couple of metres. The fixed offset hasn't been calibrated for any board, and in the bench tests it moved with SF from −4 to +7 m. Multipath indoors adds more.

### Not done yet

- Hardware testing between two MeshTracker X1s, including whether the X1's RF switch follows the chip when the subordinate answers by itself (it did on the NiceRF bench board).
- Calibrating TxRxDelay per board.
- Extended mode (two exchanges that cancel Doppler), and the narrower bandwidths other regions would need.
