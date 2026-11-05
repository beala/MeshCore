# Memory safety checks

How this fork catches buffer overruns and other memory errors before they reach a radio, and the
plan for the part that isn't covered yet: the companion firmware's own code.

## What runs today

| Check | Where | What it catches |
|---|---|---|
| `-Wall -Werror` on MeshCore's own code | `platformio.ini` `[arduino_base]` `build_src_flags` | anything gcc can see at build time, e.g. a string copied into a buffer too small for it |
| Stack canaries (`-fstack-protector-strong`) | `[nrf52_base]`, `[esp32_base]` | a write past the end of a stack buffer, when the function returns. nRF52 reboots and the next `uptime` says "The run before crashed: stack overwrite" |
| Hard faults and hangs reboot and report (nRF52) | `src/helpers/NRF52Board.cpp` | a fault (bad pointer, bus error) or a CPU stuck for 30 s without the main loop coming round. Without this, the default fault handler spins forever and the board, USB included, stays frozen. Instead it reboots and the next `uptime` says eg. "The run before crashed: hard fault at 0x00032e36 (lr ..., cfsr ..., task loop)"; `arm-none-eabi-addr2line -f -C -e firmware.elf 0x00032e36` gives the function |
| Host tests under AddressSanitizer + UBSan | `env:native_asan`, `native_crypto`, `native_entropy`, `native_kiss_modem`, `native_cli`, `native_meshtastic` | out-of-bounds reads and writes, use after free, leaks, undefined behavior, in the code the tests run |
| Every repeater/room CLI command | `env:native_cli`, `test/test_common_cli` | a reply or argument copy that doesn't fit the firmware's 160-byte buffers |
| Fuzzers (libFuzzer + ASAN + UBSan) | `test/fuzz/` | the same errors, on millions of generated inputs: CLI command sequences (`fuzz_cli`), radio packets into a chat node (`fuzz_mesh`) and Meshtastic packets into the decoder (`fuzz_meshtastic`) |

The Custom Builds workflow runs all the host test envs and a minute of each fuzzer before every
release; a failure stops the release.

Run them locally:

```
pio test -e native_asan -e native_kiss_modem -e native_crypto -e native_entropy -e native_cli -e native_meshtastic
test/fuzz/run.sh          # a minute per fuzzer; test/fuzz/run.sh 3600 for an hour
```

A fuzzer finding is saved in `.pio/fuzz/findings/` and replays with `.pio/fuzz/fuzz_<name> <file>`.

### Notes on the fuzzers

- `fuzz_mesh` uses pass-through crypto (`test/fuzz/mocks`): AES leaves bytes as they are, every MAC
  is `00 00` and every signature checks. Encrypted payloads are their own plaintext, so the fuzzer
  reaches the message parsers instead of stopping at the MAC.
- `FUZZ_WRITE_SEEDS=<dir> .pio/fuzz/fuzz_mesh` writes one valid packet of each kind, built by a
  second node with the mesh's own `create*()` functions. `run.sh` does this every run.
- `FUZZ_STATS=1 .pio/fuzz/fuzz_mesh -runs=0 <corpus>` prints how often each handler ran, to check
  the fuzzer gets past the outer layers.
- Each input gets a fresh node, so a finding replays from its file alone. After each input the
  harness checks every pool packet came back; a packet the mesh code never frees would slowly empty
  the pool on a radio.

## Not covered yet: the companion's own code

No host test compiles `examples/companion_radio/MyMesh.cpp` (about 3,500 lines),
`MyMeshFind.cpp` or `DataStore.cpp`. They get the compiler checks and stack canaries, and the
layers under them (`Mesh`, `BaseChatMesh`, `CommonRadioPrefs`, `NodePrefs`) are tested and fuzzed.
But the companion's own handling isn't: its CLI and console (about 130 writes into reply buffers),
the phone protocol frames, slash commands, clone takeover, find/range, and the push frames it
sends the app. Most of this fork's features live there, and the console overrun that froze the
NiceRF was there.

### Plan

**1. `env:native_companion`: build the real companion on the PC.** Model it on `env:native_cli`:

- Sources: `examples/companion_radio/MyMesh.cpp`, `MyMeshFind.cpp`, `DataStore.cpp`, plus what
  `native_cli` builds and `Dispatcher.cpp`, `Mesh.cpp`, `CryptoV2.cpp`, `AesSiv.cpp`,
  `helpers/BaseChatMesh.cpp`, `helpers/StaticPoolPacketManager.cpp`, `helpers/EntropyPool.cpp`.
  Real crypto (rweather Crypto, `lib/ed25519`) for the tests; pass-through crypto for the fuzzers.
- `-I test/cli_mocks` first, as in `native_cli`. It already has `Arduino.h`, an in-memory `fs::FS`,
  `RTClib.h` and `Stream.h`. On the host neither `ESP32` nor `NRF52_PLATFORM` is defined, so
  `IdentityStore.h` already falls back to `fs::FS`.
- New stand-ins needed:
  - `target.h` for the companion: `board` (a `mesh::MainBoard` that records `reboot()`/`powerOff()`
    instead of doing them), `sensors` (`SensorManager`), `rtc_clock`, and `radio_driver` with what
    `MyMesh.cpp` calls: `setParams`, `setTxPower`, `setTxLedEnabled`, `setRxBoostedGainMode`,
    `getRxBoostedGainMode`, `getLastRSSI`, `getLastSNR`, the packet counters. Extend
    `test/cli_mocks/target.h` or give the companion its own.
  - `DataStore.cpp`: its LittleFS block counting (`_getLfsUsedBlockCount`, `lfs_traverse`) is
    nRF52-only; check the host build takes the other branch, or add a stub that reports a fixed size.
  - A fake phone link: a `BaseSerialInterface` whose `checkRecvFrame()` hands out queued frames and
    whose `writeFrame()` records what the radio sends back, each in a buffer of `MAX_FRAME_SIZE`.
  - A radio like `FuzzRadio` in `test/fuzz/fuzz_mesh.cpp`, so the companion can receive packets.
- Leave out the screen and other extras: build without `DISPLAY_CLASS`, `HAS_RANGING`,
  `ENABLE_WIFI_INTERFACE` or `HAS_DRV2605`, and set `MAX_GROUP_CHANNELS` and `MAX_CONTACTS` as the
  release builds do. Ranging can come later with a stand-in for `LR2021Ranging`.
- Wiring: build `MyMesh(radio, rng, rtc, tables, store)` with a `DataStore` over the in-memory FS,
  call `begin()` and `startInterface(fake_link)`, then push frames and call `loop()`.

**2. Every companion command under ASAN** (`test/test_companion_cli`), like `test_common_cli`:

- Send each command as a CLI frame (code 66) through the fake link, with the same argument list
  `test_common_cli` uses: empty, numeric limits, 150-character strings, `%n`, multi-byte UTF-8,
  comma lists. Take the command words from the `strcmp`/`memcmp` strings in `MyMesh.cpp`.
- Do the same through the Radio console (a DM to the console contact), whose reply buffer is 256
  bytes and which splits replies longer than 140 bytes.
- Do the same for slash commands in a DM and in a channel (`/help`, `/range`, `/beep`, `/crypto`,
  `/path`, unknown ones).
- Check every frame the radio writes back fits `MAX_FRAME_SIZE`, and every reply fits its buffer.

**3. `fuzz_companion_frames`: fuzz what a connected app sends.** Input: a series of
length-prefixed frames handed to `handleCmdFrame()` through the fake link. Seed it with one valid
frame of each command code from `docs/companion_protocol.md`: send message, add/update contact,
set channel, import/export key, set radio, set name, get contacts and so on. A dictionary of the
command codes helps. Checks: ASAN, UBSan, every reply frame within `MAX_FRAME_SIZE`, and every pool
packet back after a drain loop, as `fuzz_mesh` does.

**4. `fuzz_companion_radio`: the radio fuzzer, pointed at the full companion.** Reuse
`fuzz_mesh.cpp`'s radio, input format, seed writer and lost-packet check, with `MyMesh` in place of
`FuzzChat`. Incoming messages then go through the companion's own handling: chat commands, clone
takeover, find/range replies, contact discovery and the push frames to the phone. Mix in phone
frames (for example, a first byte choosing radio or phone for each item) so it can interleave
"app sends", "packet arrives" and "app reads".

**5. Add them to CI.** Add `native_companion` to the `pio test` line and the two fuzzers to
`test/fuzz/build.sh` and `run.sh`. The release job then runs them like the rest.

Order: 1 and 2 first, since they target the bug class that already froze a radio, then 3, then 4.
Most of the effort is in step 1's stand-ins; steps 2–5 reuse what `native_cli` and `fuzz_mesh`
already have.
