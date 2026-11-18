# Bluetooth pairing: design

Status: proposal, not built. nRF52 first; ESP32 and RP2040 follow once their libraries are checked.

## The problem today

A companion radio advertises all the time and accepts a pairing from anyone who knows the PIN.
On nRF52 every pairing is LE Legacy, and the PIN is usually fixed. Together that means:

- **Anyone nearby can pair with the default PIN.** Boards without a working screen use
  `BLE_PIN_CODE=123456` (`examples/companion_radio/main.cpp:198-215`), even when the app shows
  "random PIN": the app reports the saved setting (0), not the PIN in use
  (`MyMesh.cpp:3488`). This includes the T1000-E, whose `NullDisplayDriver::begin()` returns false.
- **A recorded pairing gives away the bond.** `Bluefruit.Security.setPIN()` sets
  `_sec_param.lesc = 0` (`BLESecurity.cpp:197` in the pinned framework, commit `d541301`), and
  the radio sends those parameters in its pairing response (`BLESecurity.cpp:307`). Legacy
  pairing derives its keys from the 6-digit passkey, so someone who records one pairing can
  brute-force it offline and get the long-term key. With it they can decrypt the link, connect
  as the phone and pose as the radio. Random-PIN display boards are affected too: they also
  go through `setPIN()`.
- **A fixed passkey leaks even under Secure Connections.** Passkey entry checks one bit per
  round, in the clear. A recording, or about 20 active attempts, recovers the passkey (not the
  key).
- **Nothing limits attempts.** Failed pairings have no back-off, and a connection that never
  secures holds the only slot forever (`nrf52/SerialBLEInterface.cpp:30-37`).
- **A bond can do everything.** Any bonded link can export the private key
  (`CMD_EXPORT_PRIVATE_KEY`, enabled by `ENABLE_PRIVATE_KEY_EXPORT=1`, `platformio.ini:37`), copy
  the radio with `clone send`, and push firmware through the DFU service
  (`nrf52/SerialBLEInterface.cpp:215-216`).

## Goals

- A new bond needs someone physically at the radio.
- A recorded pairing gives away nothing usable.
- Devices that are already paired, and other apps on the same phone (the fluxcore web app),
  connect as they do now, without a press.
- Taking the identity or the firmware needs someone at the radio, even with a bond.

## The design

### 1. Secure Connections on nRF52

Stop calling `setPIN()`. Configure security ourselves so that `lesc` stays 1:

- `setMITM(true)` and `setIOCaps(true, false, false)` (display only), as now.
- Set the passkey with `sd_ble_opt_set(BLE_GAP_OPT_PASSKEY, …)` directly. The pointer must
  stay valid, so keep the 6 digits in a static buffer.
- `LESC_SUPPORTED` is 1 on the nRF52840 (CryptoCell). Bluefruit already answers the
  DH-key request (`BLESecurity.cpp:338-371`). The nRF52832 has no CryptoCell and stays Legacy;
  those boards rely on the pairing window below.

The Nordic header doesn't say the passkey option is Legacy-only: it only warns that "repeated
pairing attempts using the same preprogrammed passkey makes pairing vulnerable to MITM
attacks" (`ble_gap.h:1600-1618`, S140 7.3.0). The "Legacy" rule is Bluefruit's. **This needs a
bench test first** (see Testing).

**Fallback** if the SoftDevice won't combine a static passkey with Secure Connections:
Secure Connections "Just Works" on boards without a screen, protected by the pairing window.
All characteristics then drop from `SECMODE_ENC_WITH_MITM` to `SECMODE_ENC_NO_MITM`, since Just
Works can't give MITM protection. The physical press takes over that job: an attacker would
have to pair during the 60 s you opened, while you're pairing your own device.

### 2. The pairing window

**Five quick presses** open a window of 60 s for **one** new bond.

- Outside the window the passkey option is set to NULL, so the SoftDevice uses a random passkey
  for each attempt and shows it nowhere. Pairing fails at the passkey check and no bond is
  written: Bluefruit only saves a bond on success (`BLESecurity.cpp:384-394`).
- Inside the window the passkey is:
  - on boards with a screen: a fresh random PIN, generated when the window opens and shown on
    screen;
  - on boards without one: the PIN set with `set pin` (or 123456 if none is set).
- The window closes after one successful bond, after 60 s, or when the button is pressed five
  times again.
- **Every pairing request counts as new**, including from an address that already has a bond.
  Bluefruit lets a pairing overwrite an existing bond, so a bonded address is no exemption.
  Reconnects using an existing bond (`BLE_GAP_EVT_SEC_INFO_REQUEST`) need no window.
- While open: a distinct LED pattern, and a beep that sounds even when the buzzer is quiet
  (the T1000-E ships with `BUZZER_DEFAULT_OFF=1`). On a new bond, the Radio console says so.

Why tap first rather than approve a pending request: a request that waits for a press can be
kept pending by an attacker, and then any habitual press approves it.

**Button.** `ui-orig/Button.cpp` counts up to four clicks (`:154`). Add a fifth
(`onQuintuplePress`), with the same 500 ms gap. `ui-new` and `ui-tiny` use `MomentaryButton`,
which needs the same. Five presses is free in all three UIs.

**Boards without a user button** (no `PIN_USER_BTN`): the window opens for 60 s after power-on.
Power-cycling is the physical step.

**From the Radio console:** `ble pair` opens the same window from a bonded phone, for adding a
laptop without walking to the radio. It opens pairing only, not the presence window below: an
attacker holding a stolen bond gains nothing from adding another one.

### 3. A second device while a phone is connected

Today a second central is disconnected in `onConnect` (`nrf52/SerialBLEInterface.cpp:30-34`),
before it can pair. While the window is open, it's held instead:

- It may pair (the window rules apply). On success it takes over: the first phone is
  disconnected, and the new device becomes the one link. The companion protocol serves one
  client at a time.
- If it doesn't secure within 60 s, it's disconnected.
- Outside the window, a second central is dropped as now.

`Bluefruit.begin(2, 0)` already allows two links.

### 4. Presence for dangerous commands

Five presses also open a **presence window** of 60 s. Without it, these are refused over
Bluetooth (they still work over USB):

- `CMD_EXPORT_PRIVATE_KEY` and `CMD_IMPORT_PRIVATE_KEY`
- `clone send` and `clone receive`
- `set pin`
- the DFU service: register it with a write handler that refuses entry into the bootloader
  unless the presence window is open. (Once in the bootloader's DFU mode, the update itself is
  not authenticated. That's outside this design; gating the entry is what we control.)

The same rules apply on the fluxcore side channel, which runs the full CLI
(`MyMesh.cpp:3554`).

### 5. Limits

- **Unsecured connections time out.** A link that hasn't secured within 60 s of connecting is
  disconnected, so nobody can hold the only slot.
- **Back-off.** After 3 failed pairings in a row *while the window is open*, the window closes
  and can't be reopened for 1 min, then 5, 30 and 60 (cap). A success resets it. The Radio
  console notes when back-off starts. Failures outside the window don't count: they fail anyway,
  and counting them would let anyone nearby lock the owner out.

### 6. Bonds

- `ble clear bonds` (CLI, needs the presence window over Bluetooth; also in the USB rescue CLI)
  calls `Bluefruit.Periph.clearBonds()` and drops the current link.
- **One-time wipe on upgrade.** Bonds made before this change were made with Legacy pairing,
  often with 123456. On first boot of the new firmware, clear them and set a flag in prefs so it
  happens once. Everyone pairs again, using the window. Release notes must say so, including
  that iPhones need "Forget This Device" first.

### 7. PIN reporting

Device info reports the PIN in use (`_active_ble_pin`), not the saved setting, so the app no
longer shows "random" for a radio using 123456.

## What this does and doesn't protect

| Threat | After this change |
|---|---|
| Pairing with the default PIN from nearby | Needs five presses on the radio |
| Recording a pairing to get the key | Nothing usable (Secure Connections), nRF52840 |
| Recovering a fixed passkey by repeated attempts | Fails outside the window; back-off inside |
| Holding the only connection slot | Times out after 60 s |
| Stolen bond: read messages, use the radio | Still possible until bonds are cleared |
| Stolen bond: take the key, clone, flash firmware | Needs presence at the radio |
| Fake radio fooling the phone | Not addressed (phone and app side) |
| Someone holding the radio | Not addressed |

## Fluxcore

- On the same phone it shares the phone's bond and link: no change, no press.
- In desktop Chrome it's a separate device: pair it once during a window.

## Testing (on a T1000-E)

1. **Secure Connections.** Pair with Android's Bluetooth HCI snoop log on. In Wireshark, the
   radio's Pairing Response must show `Secure Connections: True`. If it doesn't, take the
   fallback in section 1.
2. Pairing outside the window fails, and no bond file is written.
3. Pairing inside the window works; the window closes after it.
4. A bonded phone reconnects with no press. The fluxcore web app on that phone connects with no
   press.
5. Pairing from a bonded address outside the window fails, and the existing bond still works.
6. A second device during the window pairs and takes over; outside the window it's dropped.
7. Key export, `clone send`, `set pin` and DFU entry are refused without presence and work with
   it.
8. A connection that never pairs is dropped after 60 s.
9. Back-off starts after 3 failures.
10. `ble clear bonds` and the one-time upgrade wipe remove old bonds.
11. Device info shows the PIN in use.

## Other platforms (not checked yet)

- **ESP32** asks for Secure Connections (`ESP_LE_AUTH_REQ_SC_MITM_BOND`,
  `esp32/SerialBLEInterface.cpp:33`). The window could gate `onSecurityRequest()` or swap the
  static passkey. `onWrite` doesn't check the connection; add that.
- **RP2040** sets no Secure Connections flag (`rp2040/SerialBLEInterface.cpp:55`), so it likely
  pairs Legacy: add `SM_AUTHREQ_SECURE_CONNECTION`. The window could use `sm_bonding_decline()`.

Both need checking against their library sources before work starts.

## Order of work

1. Bench test of section 1 on nRF52 (decides passkey or Just Works).
2. Pairing window and five-press gesture (2), unsecured timeout and back-off (5).
3. Presence gating (4).
4. Bonds: clear command and upgrade wipe (6); PIN reporting (7).
5. Second device during the window (3).
6. ESP32, then RP2040.

## Until this ships

Change the PIN from 123456 (`set pin <6 digits>`), reboot, forget the radio on the phone and
pair again somewhere private. That stops pairing with the default PIN. It doesn't stop someone
recording that pairing.
