# Hardware test plan: beala/MeshCore PRs #1–#4 and follow-ups

All of this is merged on `beala/main`. Test at `c70fdf8` or later.

| Change | Commits | What it touches |
|---|---|---|
| PR #1 | `41f1330`, `a0de2ab` | ed25519 `sha512.h` → `ed25519_sha512.h`; unused BSEC variable |
| PR #2 | `3481eea` | New OPT3001 (RAK1903) light sensor driver; INA226 ID check |
| follow-up | `dfed5fe` | Lux clamped to 65535; INA226 die-ID check ignores the revision nibble |
| PR #3 | `3c1fd70`, `fa926e6` | simple_sensor / T096 `-Werror` cleanups; T096 DIO2 macro |
| follow-up | `28d929c` | DIO2 macro set to `true` in 10 more `variant.h` files |
| PR #4 | `0a1a66b`, `e62995c` | T1000-E heater NTC table bounds; GPS loops survive the `millis()` wrap |
| follow-up | `c70fdf8` | Open NTC reads −30 °C instead of 0 °C; MeshTracker X1 GPS loop |

**What has been verified so far:** code review only.
- No CI ran on any PR.
- Nothing has been built for firmware. The author reports `-Werror` builds with gcc 14.2.1 for the environments named below.
- Two host-side checks were run: `lib/ed25519` compiles under `-Wall -Wextra -Werror`, and the NTC function was run under ASan/UBSan for every input from 0 to 3300 mV.
- **The three follow-up commits have never been compiled.** Build them first.

---

## 0. Build check (no hardware)

Build every environment below with the repo's normal flags (`build_src_flags = -Wall -Werror -Wno-error=cpp`). Each should build cleanly.

- **Known-good per the author:**
  - `RAK_4631_repeater`, `RAK_4631_companion_radio_ble`, `RAK_4631_sensor`, `RAK_3401_sensor`
  - `t1000e_repeater`, `t1000e_companion_radio_ble`
  - `Heltec_v3_repeater`, `Heltec_v3_sensor`, `heltec_v4_sensor`
  - `Heltec_t096_sensor`, `Heltec_t096_repeater`, `Heltec_t096_companion_radio_ble`
  - `Heltec_Wireless_Tracker_repeater`, `wio-e5-mini_sensor`, `Xiao_S3_WIO_sensor`, `ProMicro_sensor`
- **New, never built** (follow-up commits):
  - `MeshTracker_X1_repeater`
  - one environment for each board in the DIO2 list in §3: e.g. `Heltec_t114_repeater`, `Heltec_mesh_solar_repeater`, `Nano_G2_Ultra_repeater`, `ThinkNode_M1_repeater`, `ThinkNode_M8_repeater`, `LilyGo_T-Echo_repeater`, `RAK_3401_repeater`, `RAK_WisMesh_Tag_repeater`, `Heltec_tower_v2_repeater`, `LilyGo_TBeam_1W_repeater`
- **Expected to still fail, and not caused by these PRs:**
  - `Meshadventurer_*`: `1 << P_LORA_DIO_1` with GPIO33 shifts past the width of `int`.
  - Any board with a duplicate `PIN_USER_BTN`. The author mentions one of mesh solar, Nano G2 Ultra or Thinknode M1. Record which.
- **macOS:** if a Mac is available, build any one environment on a case-insensitive filesystem. Before PR #1 every build failed there with `'SHA512' was not declared in this scope`.

---

## 1. PR #1: ed25519 rename, BSEC

- **Crypto regression:** on any two boards, make sure adverts, signed messages and channel messages still verify. The rename touches the ed25519 sign/verify/keypair sources. Also run `native_asan` and `native_clone` if available; the author reports 124 passed and 1 skipped.
- **BSEC (RAK4631 + BME680, `ENV_INCLUDE_BME680_BSEC`):**
  - Let the sensor run until IAQ accuracy reaches 3.
  - Confirm the state gets saved, then saved again every 8 hours. A shorter `BSEC_SAVE_INTERVAL_MS` in a test build makes the second save quicker to see.
  - Reboot and confirm accuracy comes back quickly from the saved state.

## 2. PR #2 + `dfed5fe`: OPT3001 / RAK1903 (RAK4631)

- **Detection:** with only a RAK1903 at 0x44, the debug log should print `Found OPT3001 at address: 44`. SHT4X and INA226 should report "failed to initialize" there, and no INA226 calibration write should reach the chip.
- **Readings (LPP luminosity):** compare against a phone lux meter.
  - Dark / covered: about 0. Under 1 lux reads as 0, which is expected.
  - Indoor: tens to hundreds of lux.
  - Flashlight up close: thousands of lux.
  - **Direct sun or a strong lamp at full scale: must read 65535, not a small number.** This is the clamp fix. Before it, full scale (83,865 lux) came out as 18,329.
- **First read:** right after boot, telemetry may leave luminosity out for about 0.8 s, until the first conversion is ready. After that it should be in every reply.
- **Address-sharing regressions** (whichever parts are available):
  - SHT4X alone at 0x44: still detected as SHT4X, with temperature and humidity correct.
  - INA226 alone at 0x44: still detected, with bus voltage, current and power correct. The new manufacturer/die-ID check must not reject a real INA226. Note its die-ID register value if you can, especially on cheap or clone modules.
- **Separate env I2C bus:** if a board defines `ENV_PIN_SDA`/`ENV_PIN_SCL`, check the OPT3001 is found on that bus.
- **Not covered:** a sensor brown-out or reset puts it back in shutdown mode, and the driver never re-arms it, so readings freeze at the last value. That's a known edge case, not a regression.

## 3. PR #3 + `28d929c`: simple_sensor and DIO2 macro

These are meant to be no-ops at run time. Test for regressions.

- **simple_sensor** (`RAK_4631_sensor` or `Heltec_v3_sensor`):
  - Telemetry, min/max/avg series, and alert pushes work as before.
  - A subscribe request is accepted; the reserved byte is now ignored.
  - The ACL list request returns every client and doesn't truncate early.
  - Serial CLI: a command close to 159 characters is still accepted.
- **`io` command:** try `io`, `io 5`, `io s2`, `io r1`, `io t3`. Reads print hex and the GPIO state changes as expected. **Known bug, don't count it as a regression:** `io s` with no value, or a bad hex value, writes an uninitialized value, because `sscanf`'s result is never checked.
- **DIO2 RF switch:** run a TX/RX check (send/receive a message and check RSSI) on whichever of these you have:
  - T096 (PR #3)
  - T114, mesh solar, tower v2 (Heltec)
  - T-Echo, T-Beam 1W (LilyGo)
  - Nano G2 Ultra, RAK3401, WisMesh Tag
  - Thinknode M1, Thinknode M8

  Radio behaviour should not change: the call used to compile as `setDio2AsRfSwitch()` and pick up RadioLib's default of `true`, and now it passes `true` explicitly. **If any board's TX or RX gets worse, that board probably wanted DIO2 off.** Flag it immediately.
- **T096 boot:** check the Vext peripheral power pin comes up. Its constructor order was changed.

## 4. PR #4 + `c70fdf8`: T1000-E NTC, GPS loops

### T1000-E heater NTC
- **Normal reading:** compare telemetry temperature with a reference thermometer at room temperature. In a fridge or freezer, check it tracks down towards the cold end.
- **Range:** readings should stay between −30 °C and 105 °C (the table ends).
- **Open NTC:** if you can disconnect the NTC or ground the ADC pin, it should read **−30 °C**, not 0 °C (`c70fdf8`). Skip this if you'd have to open the case destructively.

### GPS loops (`millis()` wrap)
Affected boards: T1000-E, MeshTracker X1, Heltec mesh solar, Heltec Wireless Tracker, Meshadventurer, Nano G2 Ultra, Thinknode M1.

- **Basic:** with a GPS fix, location updates about once a second, and telemetry/adverts carry the right position. The first update now arrives about 1 s after boot instead of immediately, which is expected.
- **Thinknode M1:** toggling the GPS switch still starts and stops the GPS, checked about once a second.
- **Wrap test:** don't wait 49.7 days. In a **test build only**, add this at the top of the affected `target.cpp`, after the includes:
  ```cpp
  #define millis() (millis() + 0xFFFFF000u)  // starts about 4 s before the wrap
  ```
  `millis()` then wraps about 4 s after boot.
  - **Pass:** location keeps updating at about 1 Hz through the wrap.
  - **Fail (the old behaviour):** updates fire on every loop pass just before the wrap, or stop afterwards.
  - Use `0x7FFFF000u` to test T1000-E at the 2^31 mark (24.8 days), where its old `(long) millis()` comparison broke.
  - **Don't commit the shim.**

---

## Still open (for reference, don't fix unless asked)
- Meshadventurer wake-bit shift (`1 << 33`); needs `1ULL`. The author plans a bug-fix PR.
- `io` command: unchecked `sscanf`. Same planned PR.
- Duplicate `PIN_USER_BTN` on at least one board, which breaks `-Werror` builds.
- Many UI timers (`_auto_off`, `next_batt_chck` and others in the `UITask.cpp` files) use `millis() > deadline`. A wrap there would only make the display misbehave around day 49.7, not fail outright.
- Upstream copies: the lux clamp needs to go to meshcore-dev/MeshCore#3171, and the NTC −30 °C change to the author's upstream version of #4.

## Report back
For each test: board, firmware environment, pass / fail / not run (with why), plus logs or numbers for anything that fails. List the INA226 die-ID values seen, and any board where DIO2 behaviour changed.
