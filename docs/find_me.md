# Finding a lost radio

## In plain terms

**Make it beep.** Run `find me` on a companion radio and it beeps for 2 minutes, so you can find it by ear. Radios with a vibration motor vibrate too. It beeps even if you've turned the buzzer off. Press its button, or run `find me stop`, to stop it.

**Make it beep from another radio.** If your radio is lost, you can't type commands into it. So you can also ask it to beep from a second radio you own, or a friend's radio:

1. On the radio you might lose, allow the other radio once: `set find.allow <its contact name>`.
2. When it's lost, run `find beep <lost radio's name>` on the other radio.
3. A few seconds later, `get find` shows the answer, for example `beeping for 120 s`.

Only radios you've allowed can do this, and they can't do anything else. The request is encrypted and signed like a direct message, so nobody else can send it or replay an old one.

**Measure how far away it is.** If both radios have an LR2021 chip (for example the SenseCAP MeshTracker X1), run `find range <name>`. The radios measure the time a signal takes to get there and back, and `get find` shows the distance, for example `42 m (+/- 4 m, 30/32 answers, -97 dBm)`. Walk around and run it again: if the number goes down, you're getting closer.

**Extended ranging (opt-in).** `set find.extended on` makes `find range` use the LR2021's extended mode. Each measurement takes two exchanges instead of one. That keeps the distance right when the radios are moving relative to each other, which can otherwise throw it off by tens of metres. It also reports the relative speed, but only roughly: in steps of about 20 m/s (70 km/h), so it can tell a car driving away from a parked one, not walking pace. Both radios need firmware with this feature.

Limits:
- The radios must hear each other directly, not through a repeater.
- The distance is uncalibrated and can be off by several metres. Walls and bodies make it read longer.
- It only works on 902–928 MHz (US, Canada, Australia, New Zealand), because the measurement uses a 500 kHz wide signal.

## Technical details

### Messages

The finder sends a CLI command message (`TXT_TYPE_CLI_COMMAND`) to the target: `find me`, `find me stop`, `find range`, or `find range ext`. It's encrypted with the pair's shared secret, like any direct message.

The target handles it only if the finder is on its allow list (`set find.allow`, up to 8 entries, saved in the `find` section of `/prefs.json`; older builds used `/find_allow`, which is moved over on first boot) or has remote CLI access. It replies with a CLI data message starting `find: `, which the finder saves for `get find` and also passes to the app.

For each allowed finder, the target stores the newest request timestamp it has accepted, and ignores any request that isn't newer. That stops replays, including after a reboot. If the finder's clock goes backwards, its requests are refused with `find: old request ignored (is your clock set?)` until the clock is set.

### Ranging

This uses the LR2021's round-trip time-of-flight mode (RTToF). The command sequence follows Semtech's usp v1.2.1 radio layer and the bench tests in [beala/lr2021-re](https://github.com/beala/lr2021-re/blob/main/docs/ranging.md).

1. The finder sends `find range`. The target picks a random ranging address for this session, replies `find: ranging <address>` (8 hex digits), and waits until that reply has been transmitted.
2. The target switches to RTToF subordinate and answers ranging requests for 5 seconds.
3. The finder hears the reply, switches to RTToF manager, and runs up to 32 exchanges in 2.5 seconds. Each exchange is given up after 100 ms.
4. Both radios return to normal LoRa: standby, packet type LoRa, sync word, then the usual frequency, bandwidth, SF, CR, preamble and side-detector settings.

Meshtastic, weather or aircraft, whichever is on, pauses on both radios for the session (the Meshtastic scanner comes out of the chip, which has Semtech's patch back), and comes back after it.

The settings are:
- SF9, BW 500 kHz, CR 4/5, preamble 12, explicit header, CRC, on the current frequency.
- 15 response symbols, normal mode.
- TxRxDelay 20305, Semtech's value for BW 500 kHz, SF9.
- The ranging address is random for each session and only sent inside the encrypted reply. All 4 bytes are checked, so the target ignores other ranging sessions. If the reply has no address (older firmware), the finder uses the first 4 bytes of the target's public key, as before.

The reported distance is the median of the valid exchanges, at 150 / (4096 × 0.5 MHz) = 7.3 cm per raw unit. The ± figure is half the interquartile range, and the RSSI is the median.

After every packet type change, the code applies the same DC-DC workaround as RadioLib's own `setPacketType()`: the DCDC_SWITCHER bits, DCDC_FREQ_LF, and setting the frequency again.

The target is blocked for 5 seconds and the finder for up to 2.5 seconds while ranging, and can't receive mesh traffic during that time. A target accepts at most one ranging session every 5 seconds.

### Security

The request and the reply are encrypted and signed, so only allowed radios can start a ranging session. The ranging exchange itself is plain LR2021 RTToF packets, with no encryption or signature.

Because the ranging address is random and only travels inside the encrypted reply, another radio can't easily answer the finder's requests (to fake a distance), or send its own requests to the target while it's listening (to measure its distance to it).

A determined attacker could still fake the distance: listen for the requests on the air, then answer faster or slower than the target would. Preventing that needs a distance-bounding protocol, which the LR2021's RTToF mode doesn't support. Treat the distance as a guide for finding your own radio, not as proof of where it is.

### Extended mode

With `set find.extended on`, the finder sends `find range ext` and both radios set the extended bit in SetRangingParams for that session. The target needs no setting of its own.

Each extended exchange is two round trips, both started by the finder, about 100 ms in all (normal: about 50 ms), so about 26 exchanges fit in the 2.5 s instead of 32. GetRangingResult type 1 returns two results, Rng1 and Rng2.

Why it helps: a frequency offset makes a LoRa receiver misjudge when a chirp arrives. A fixed offset between the two radios' crystals cancels over a round trip, because each radio sees it with the opposite sign. Doppler doesn't cancel, because both radios see the same shift. The chip corrects the arrival time from its frequency estimate, but only in steps of 1/8 of a LoRa bin (122 Hz at SF9 / 500 kHz), so the error comes in jumps of 512 raw units (37 m) per step. Extended mode's second exchange has the opposite error, so:

- distance = (Rng1 + Rng2 − 1120) / 2
- Rng1 − Rng2 + 1120 grows by about 16.5 raw units per Hz of Doppler on each leg. Positive means moving apart. Speed = Doppler × wavelength (0.33 m at 910 MHz).

The 1120 is a fixed offset of extended mode: Rng2 − Rng1 at rest. It was 1110 to 1135 in both directions between two boards on the bench, and didn't change when TxRxDelay changed. Semtech's own driver never uses extended mode, so there's no reference value.

Bench test (RAK3401 + NiceRF and a XIAO, both LR2021, on dummy loads). Doppler was emulated by moving the finder's receive frequency by δ during its receive windows (at TX_DONE), and back at RX_DONE. That's the same as δ/2 of Doppler on each leg, and a δ of 125 Hz is one step. Normal mode read 11 m, 48 m and 85 m for δ = 0, 60 and 175 Hz. Extended mode read 8 to 9 m for δ = 0, 80 and 200 Hz, with "moving apart at ~21 m/s" and "~41 m/s", and "closing" for negative δ. At rest it reads "not moving fast". Any speed under 10 m/s is reported that way, because the steps are 20 m/s.

### Accuracy

On the bench, with the antenna ports on dummy loads, a single exchange at SF9 was good to about 4 m (σ), and the median of 200 was within a couple of metres. The fixed offset hasn't been calibrated for any board, and in the bench tests it moved with SF from −4 to +7 m. Multipath indoors adds more.

### Not done yet

- Calibrating TxRxDelay per board.
- The narrower bandwidths other regions would need. A higher SF or narrower bandwidth would also give extended mode finer speed steps (they scale with the LoRa bin width, BW / 2^SF).
