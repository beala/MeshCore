# Randomness for keys

## In plain terms

The first time a radio starts, it makes its own private key, a secret number that everything private depends on. Every direct message to or from that radio is protected with it. The key is only as good as the randomness used to pick it. If that randomness were predictable, someone could work out the key and read those messages.

**What was wrong.**
- **Heltec V3 and V4 (ESP32):** the chip has a good random generator, but a quirk in how the firmware starts switched it off. The key came only from the LoRa radio's noise reading, which nobody has checked.
- **All boards:** the firmware never checked whether its sources were working. If they all failed, it would still have made a key and kept it forever.

**What changed.**
- **Only proven sources count.** The radio now counts how much randomness it has from sources it can trust:
  - The chip's random generator counts only when it reports that it worked, and only when it's known to be truly random at that moment.
  - Radio noise counts only if it passes standard checks for a stuck or lopsided signal, and even then it's credited at a fraction of what it probably holds.
  - Timing measurements are mixed in but don't count, because start-up timing can repeat from boot to boot.
- **No key is kept without enough.** A key is only saved once at least 256 bits of trusted randomness have been gathered. If the radio can't get that much, it uses a temporary key for this session and tries again at the next boot. It never keeps a key that might be weak.
- **ESP32 turns its generator's noise source on.** Right at power-on, before anything else starts, the chip briefly switches on the internal noise source its random generator needs.
- **A standard generator.** Keys are drawn from HMAC-DRBG, the NIST-standard random generator, checked against NIST's official test vectors.

**Existing keys don't change.** A radio keeps the key it already has. To get a key made the new way, erase the radio fully when flashing. That gives it a new identity, so contacts will need to add it again.

The random Bluetooth pairing PIN shown on companion boards with a screen comes from the same generator. Every PIN is equally likely.

On a companion radio, `get entropy` shows which sources worked at this boot and whether there was enough for keys.

## Technical details

### Before

`RadioNoiseListener::random()` set each byte to `randomByte() ^ random(0, 256)`, also XORed with the CC310 TRNG on nRF52.

On ESP32, `randomSeed()` at boot (`StdRNG::begin`) switches Arduino `random()` from `esp_random()` to the newlib PRNG. That PRNG is seeded from 31 bits of the same radio, so the SX126x noise sampler was effectively the only source.

No failure was detected anywhere. The return values of `nRFCrypto.begin()` and `Random.generate()` were ignored, and a key was always generated and saved.

### After (`src/helpers/EntropyPool.cpp`)

**Pool.** Every input is conditioned into a 32-byte SHA-256 pool: `pool = SHA256(tag ‖ pool ‖ micros ‖ len ‖ data)`.

**Generator.** Output comes from HMAC-DRBG with SHA-256 (NIST SP 800-90A 10.1.2, no prediction resistance):
- Instantiated, then reseeded, with `pool ‖ "MeshCore EntropyPool"` whenever new input has arrived since the last seeding.
- Each reseed moves the pool on.
- `HmacDrbg` is tested against 20 NIST CAVP vectors (SHA-256, no additional input, with and without reseed).

**Credited entropy.** Keys may only be kept when `EntropyPool::readyForKeys()` is true, meaning at least 256 credited bits.

| Source | Credited |
|---|---|
| nRF52 CC310 TRNG (`nRFCrypto.Random.generate`) | 256 bits per 32 bytes, only if `generate()` returns true |
| ESP32 RNG, in `collectEarly()` | 256 bits. Collected while the SAR ADC entropy source is on (`bootloader_random_enable()`). |
| ESP32 RNG at any other time | 0. It's only truly random while Wi-Fi or BT is on, so it's mixed in but not counted. |
| Radio noise, batch of ≥ 512 samples that passes the health tests | 1 bit per sample |
| Radio noise, smaller batches or failed tests | 0 |
| Timestamps, seeds, keypress timing (`addUntrusted`) | 0 |

**Health tests.** These are the SP 800-90B 4.4 continuous health tests, with an assumed min-entropy of H = 1 bit per sample and α = 2⁻²⁰:
- **Repetition count:** fail on 21 identical samples in a row.
- **Adaptive proportion:** window of 512, fail if the first value occurs 410 or more times.

They catch a stuck or heavily biased radio. They can't detect a predictable one: a counter passes them. That's why radio noise is credited at only 1 bit per sample, and why it's the main source only on platforms without a trusted hardware RNG.

**ESP32: `collectEarly()`.** This is called first thing in every firmware's `setup()`: companion, repeater, room server, sensor, KISS modem and terminal chat. ESP-IDF requires `bootloader_random_enable()` and `bootloader_random_disable()` to run before RF, the ADC or I2S are initialized. `collectEarly()` turns the source on, takes 128 bytes from `esp_fill_random()`, and turns it off again. It's skipped on chips whose SDK has no `bootloader_random.h` (ESP32-C6 here), which then rely on radio noise.

**Radio collection (`RadioNoiseListener`).**
- It first tries the hardware RNG.
- If the pool still isn't ready for keys, it takes batches of 512 radio samples, up to 3 batches. Otherwise it takes a 64-sample extra batch.
- The low byte of `micros()` for each sample is mixed in as untrusted input.

**Fail closed.** Every place that creates and saves an identity saves it only if `readyForKeys()`: companion `MyMesh::begin`, and the repeater, room server, sensor, KISS modem and terminal chat `setup()`. Otherwise the key is used for this boot only and a warning is logged. The terminal chat example used to make its key from the Arduino PRNG seeded with `millis()` at a keypress, and now uses `radio_new_identity()`.

**BLE PIN.** Drawn from the DRBG with rejection sampling, so all 900,000 PINs are equally likely.

**Clearing.** Temporary buffers are cleared with `secureZero()`, which writes through a `volatile` pointer so the compiler can't drop it.

**Threads.** Not thread-safe. Call only from `setup()` and the main loop.

### Cost

| Board | First boot | Every boot |
|---|---|---|
| nRF52 and ESP32 (trusted hardware) | About 0.6 s, for 64 SX126x samples at ~10 ms each | Negligible |
| No trusted hardware (e.g. ESP32-C6, RP2040, STM32) | About 5 s per 512-sample batch on an SX126x, up to 15 s in the worst case | Negligible |

Static buffers take 1 KB.

### Limits

- This is a source review plus tests. No hardware has been measured.
- The ESP32 credit assumes ESP-IDF's statement that the RNG is truly random while the SAR ADC entropy source is enabled.
- RP2040 and STM32 have no hardware RNG wired in, so they depend on radio noise passing the health tests.
- Cold boots across devices haven't been checked for repeated or correlated outputs.
