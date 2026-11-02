# Randomness for keys

## In plain terms

The first time a radio starts, it makes its own private key, a secret number that everything private depends on. Every direct message to or from that radio is protected with it. The key is only as good as the randomness used to pick it: if that randomness were predictable, someone could work out the key and read those messages.

**What was wrong.** On ESP32 boards (such as the Heltec V3 and V4), the chip has a good built-in random number generator, but a quirk in how the firmware starts up switched it off. The key came only from the LoRa radio's noise reading. There's no known problem with that reading, but nobody has checked its quality, so the key rested on one unchecked source while a better one went unused.

**What changed.** Every source is now mixed together: the chip's random generator, many samples of radio noise, and tiny timing differences. They're mixed in a way that makes the key as strong as the best source. A weak or broken source can't make it worse.

**Existing keys don't change.** A radio keeps the key it already has. To get a key made the new way, erase the radio fully when flashing (or reset its identity some other way). That gives it a new identity, so contacts will need to add it again.

The random Bluetooth pairing PIN shown on companion boards with a screen now comes from the same mix.

## Technical details

**Before.** `RadioNoiseListener::random()` set each byte to `randomByte() ^ random(0, 256)`, also XORed with the CC310 TRNG on nRF52. On ESP32, `randomSeed()` at boot (`StdRNG::begin`) switches Arduino `random()` from `esp_random()` to the newlib PRNG. That PRNG is seeded from 31 bits of the same radio, so the SX126x noise sampler was effectively the only source.

**After.** `EntropyPool` (`src/helpers/EntropyPool.cpp`) is a SHA-256 pool:
- `add()` mixes in a tag, the 32-byte state, `micros()`, the length and the data: `state = SHA256(tag ‖ state ‖ micros ‖ len ‖ data)`.
- `generate()` first mixes in 32 bytes from the MCU's hardware RNG: the CC310 via `nRFCrypto.Random` on nRF52, or `esp_fill_random()` on ESP32. It then outputs blocks of `SHA256("O" ‖ state ‖ counter)`, and finally moves the state forward with `add()`.

`RadioNoiseListener` feeds 64 `randomByte()` samples, and a `micros()` timestamp for each, into the pool before drawing from it. If the samples have fewer than 32 distinct values, it takes up to 3 more rounds. That covers drivers such as the LR11x0 and LR2021, which return 0 when the read fails.

The companion's random BLE PIN comes from `EntropyPool::generate()`. The pool is also seeded at boot with the radio seed that was already being read for `fast_rng`.

**Cost.** About 0.6 seconds extra when a new identity is created on an SX126x radio, which waits about 10 ms per sample. Up to about 2.5 seconds if the radio looks stuck. Nothing changes after that.

**Limits.**
- The ESP32 RNG is only fully random while Wi-Fi or Bluetooth is running. At first boot it's one source among several.
- RP2040 and STM32 have no hardware source wired in yet. On those boards the gain is the hashing and the extra radio samples.
- Packet-uniqueness values (`fast_rng`) still use the Arduino PRNG. They aren't secrets.
