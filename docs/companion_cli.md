# Companion CLI

Since version 1.18 meshcore companion radio firmware has a CLI interface, which can be accessed locally (through companion radio protocol) or remotely via the network.

## Navigation
- [Operational](#operational)
- [Configuration](#configuration)
  - [System](#system)
  - [Radio](#radio)
  - [BLE](#ble)
  - [Wifi](#wifi)
  - [UI](#ui)
  - [Encryption](#encryption)

## Operational

### Reboot the node
**Usage:** 
- `reboot`

**Note:** No reply is sent.

---

### Power-off the node
**Usage:**
- `poweroff`, or
- `shutdown`

**Note:** No reply is sent.

---

## Configuration

### System

#### View or change this node's name
**Usage:**
- `get name`
- `set name <name>`

**Parameters:**
- `name`: Node name

**Set by build flag:** `ADVERT_NAME`

**Default:** Varies by board

**Note:** Advertised names can use up to 23 bytes when location is included and 31 bytes otherwise. Emoji and Unicode characters may take more than one byte. Names that exceed the available advert space are truncated at a valid UTF-8 code point boundary.

---

#### View where this node's randomness came from
**Usage:**
- `get entropy`

**Note:** Shows the random sources, whether there's enough trusted randomness to make new keys, and where the current key came from. For example:

`> hardware RNG: ok; radio noise: not sampled this boot; 256 bits, enough for new keys; key: loaded from flash`

- If the hardware RNG hasn't been used yet this boot, it's tested when you run the command. The radio is only sampled when a new key is made, because sampling stops it receiving.
- `key: made this boot, NOT saved` means there wasn't enough trusted randomness. The key is only used until the next boot, when the radio tries again.

See [entropy.md](entropy.md).

---

#### View this node's firmware version
**Usage:** `ver`

---

#### Configure this node's timezone
**Usage:** 
- `set tz.offset <offset>`
- `get tz.offset`

**Parameters:**
- `offset`: float value of the offset in hours

---

### Radio

Radio parameters are common to all roles and handled by `CommonRadioPrefs`.

#### View or change this node's radio parameters
**Usage:**
- `get radio`
- `set radio <freq>,<bw>,<sf>,<cr>`

**Parameters:**
- `freq`: Frequency in MHz
- `bw`: Bandwidth in kHz
- `sf`: Spreading factor (5-12)
- `cr`: Coding rate (5-8)

**Set by build flag:** `LORA_FREQ`, `LORA_BW`, `LORA_SF`, `LORA_CR`

**Default:** `869.618,62.5,8,5`

**Note:** Requires reboot to apply

---

#### View or change this node's transmit power
**Usage:**
- `get tx`
- `set tx <dbm>`

**Parameters:**
- `dbm`: Power level in dBm (1-22)

**Set by build flag:** `LORA_TX_POWER`

**Default:** Varies by board

**Notes:** This setting only controls the power level of the LoRa chip. Some nodes have an additional power amplifier stage which increases the total output. Refer to the node's manual for the correct setting to use. **Setting a value too high may violate the laws in your country.**

---

#### View or change this node's frequency
**Usage:**
- `get freq`
- `set freq <frequency>`

**Parameters:**
- `frequency`: Frequency in MHz

**Default:** `869.618`

**Note:** Requires reboot to apply
**Serial Only:** `set freq <frequency>`

---

#### View or change this node's rx boosted gain mode (SX12xx and LR1110)
**Usage:**
- `get radio.rxgain`
- `set radio.rxgain <state>`

**Parameters:**
  - `state`: `on`|`off`

**Default:** `on`

---

#### View or change the LoRa FEM receive-path gain state on supported boards
**Usage:**
- `get radio.fem.rxgain`
- `set radio.fem.rxgain <state>`

**Parameters:**
- `state`: `on`|`off`

**Notes:**
- This controls the external LoRa FEM receive-path LNA where the board supports it.
- This is separate from `radio.rxgain`, which controls the radio chip receive gain mode.

---

#### View or change the LoRa FEM transmit-path gain state on supported boards
**Usage:**
- `get radio.fem.txgain`
- `set radio.fem.txgain <state>`

**Parameters:**
- `state`: `on`|`off`

**Notes:**
- This controls a software-selectable external LoRa FEM transmit gain where the board supports it.
- On Station G3, remove the PA PL1 jumper to allow software control. `on` selects PA PL1 high/short and `off` selects PA PL1 low/open. The PA PL2 hardware jumper determines whether this switches between power levels 1/3 or 2/4.
- Select an operating level and SX1262 transmit power that comply with local RF limits and the Station G3 power-supply requirements.
- The setting is saved immediately, but on Station G3 the level is applied to the hardware at the start of the next transmit, so that the PA supply rail is never re-targeted while the PA is being driven. `get` reports the configured state, which may lead the hardware until the node next transmits.

---

#### View or change the duty cycle limit
**Usage:**
- `get dutycycle`
- `set dutycycle <value>`

**Parameters:**
- `value`: Duty cycle percentage (1-100)

**Default:** `50%` (equivalent to airtime factor 1.0)

**Examples:**
- `set dutycycle 100` — no duty cycle limit
- `set dutycycle 50` — 50% duty cycle (default)
- `set dutycycle 10` — 10% duty cycle
- `set dutycycle 1` — 1% duty cycle (strictest EU requirement)

> **Note:** Added in firmware v1.15.0

---

#### View or change the airtime factor (duty cycle limit)
> **Deprecated** as of firmware v1.15.0. Use [`get/set dutycycle`](#view-or-change-the-duty-cycle-limit) instead.

**Usage:**
- `get af`
- `set af <value>`

**Parameters:**
- `value`: Airtime factor (0-9). After each transmission, the repeater enforces a silent period of approximately the on-air transmission time multiplied by the value. This results in a long-term duty cycle of roughly 1 divided by (1 plus the value). For example:
  - `af = 1` → ~50% duty
  - `af = 2` → ~33% duty
  - `af = 3` → ~25% duty
  - `af = 9` → ~10% duty
  You are responsible for choosing a value that is appropriate for your jurisdiction and channel plan (for example EU 868 Mhz 10% duty cycle regulation).

**Default:** `1.0`

---

#### View or change the local interference threshold
**Usage:**
- `get int.thresh`
- `set int.thresh <value>`

**Parameters:**
- `value`: Interference threshold value

**Default:** `0.0`

---

#### Enable or disable hardware Channel Activity Detection (CAD)
**Usage:**
- `get cad`
- `set cad <on|off>`

**Description:** When enabled, the radio performs a hardware Channel Activity Detection scan before transmitting and defers if the channel is busy. Runs independently of `int.thresh` — either, both, or none may be active.

**Parameters:**
- `on|off`: Enable or disable hardware CAD

**Default:** `off`

---

#### View or change the AGC Reset Interval
**Usage:**
- `get agc.reset.interval`
- `set agc.reset.interval <value>`

**Parameters:**
- `value`: Interval in seconds, 0-1020, rounded down to a multiple of 4 (17 becomes 16). 0 to disable.

**Default:** `0.0`

---

#### Enable or disable Multi-Acks support
**Usage:**
- `get multi.acks`
- `set multi.acks <state>`

**Parameters:**
- `state`: `0` (disable) or `1` (enable)

**Default:** `0`

---

#### View or change this node's advert path hash size
**Usage:**
- `get path.hash.mode`
- `set path.hash.mode <value>`

**Parameters:**
- `value`: Path hash size (0-2)
  - `0`: 1 Byte hash size (256 unique ids)[64 max flood]
  - `1`: 2 Byte hash size (65,536 unique ids)[32 max flood]
  - `2`: 3 Byte hash size (16,777,216 unique ids)[21 max flood]
  - `3`: DO NOT USE (Reserved) 

**Default:** `0`

**Note:** the 'path.hash.mode' sets the low-level ID/hash encoding size used when the repeater adverts. This setting has no impact on what packet ID/hash size this repeater forwards, all sizes should be forwarded on firmware >= 1.14. This feature was added in firmware 1.14
#### View or change the retransmit delay factor for flood traffic
**Usage:**
- `get txdelay`
- `set txdelay <value>`

**Parameters:**
- `value`: Transmit delay factor (0-2)

**Default:** `0.5`

**Note:** When multiple nearby repeaters all hear the same flood packet, each waits a random amount of time before retransmitting to avoid simultaneous collisions. This factor scales the size of that random window. Higher values reduce collision risk at the cost of added latency. `0` disables the window entirely.

---

#### View or change the retransmit delay factor for direct traffic
**Usage:**
- `get direct.txdelay`
- `set direct.txdelay <value>`

**Parameters:**
- `value`: Direct transmit delay factor (0-2)

**Default:** `0.3` (Repeater) - `0.2` (Room Server, Sensor)

**Note:** Same collision-avoidance random window as `txdelay`, but applied to direct (non-flood, routed) traffic. The default is lower because direct packets are addressed to a specific next hop, so far fewer nodes compete to retransmit them.

---

#### [Experimental] View or change the processing delay for received traffic
**Usage:**
- `get rxdelay`
- `set rxdelay <value>`

**Parameters:**
- `value`: Receive delay base (0-20)

**Default:** `0.0`

**Note:** When enabled, repeaters that received a flood packet with a weak signal are held in a delay queue before processing, while those that received it with a strong signal process it immediately. This gives strong-signal paths forwarding priority. By the time weak-signal nodes process their copy, the packet may have already propagated and will be suppressed as a duplicate, reducing redundant retransmissions.

---

#### View recent transmit faults (LR2021 only)
**Usage:** `get radio.faults`

**Example reply:** `> 3 since boot: 12s OCP; 95s ERR=0004; 300s NODONE`

**Notes:**
- Shows how many transmits have gone wrong since boot, then the most recent ones (up to 8, newest first, as many as fit in the reply), each with its age in seconds and what went wrong:
  - `NODONE`: the transmit did not finish (TX_DONE not set)
  - `OCP`: the power amplifier hit its over-current or over-voltage limit
  - `ERR=<hex>`: the chip reported an error; the value is its error register (eg. `0004` is a PLL lock failure)
  - `CMD`: the chip rejected a command
  - `TIMEOUT`, `EOL`: the chip's timeout and end-of-life IRQs
- Not available on other radios (`Unknown command`).

---

#### View the receiver gain of recent packets (LR2021 only)
**Usage:** `get radio.agc`

**Example reply:** `> G13 -112dBm -6.5dB 4s; G9 -71dBm 9.2dB 31s`

**Notes:**
- For the most recent received packets (up to 8, newest first, as many as fit in the reply): the gain step the chip's automatic gain control used (`G1` to `G13`, 13 = most gain), the packet's RSSI and SNR, and its age in seconds.
- Strong signals should use lower gain steps. A high gain step with a strong RSSI can point at interference or a receiver problem.
- Not available on other radios (`Unknown command`).

---

#### Listen to a Meshtastic channel (LR2021 only)
**Usage:**
- `mt on`, `mt off`
- `mt` or `get mt`: the settings
- `set mt.preset <name>`: `LongFast` (default), `MediumFast`, `ShortFast`, ...
- `set mt.freq <MHz>` or `set mt.freq auto` (default: the preset's US frequency, 906.875 MHz for LongFast)
- `set mt.channel <name>` or `set mt.channel default` (the preset's name)
- `set mt.key <base64>`, `set mt.key default` (`AQ==`) or `set mt.key none`
- `get mt.stats`, `get mt.last`: what was heard
- `get radio.scan`, `get radio.scan.restarts`, `get radio.counts`: the on-chip scanner

**Example reply:** `> Meshtastic on: LongFast, 906.875 MHz (auto), channel LongFast, key default`

**Notes:**
- The radio also listens to a Meshtastic channel, and its texts show in the app as one more channel, "Meshtastic LongFast", after your own. Receive only: text typed there is not sent. See [Meshtastic channel](meshtastic_channel.md).
- Settings are saved. Reconnect the app after `mt on` so it lists the new channel.

#### Weather sensors (LR2021 only)
**Usage:**
- `wx on`, `wx off`
- `wx` or `get wx`: the settings
- `wx scan`: listen for sensors without a break for 85 s per brand (the mesh isn't heard meanwhile), then list them in the console
- `wx scan on`, `wx scan off`: listen all the time, with a console note for each new sensor (eg. while driving around; not saved)
- `set wx.kind ecowitt|lacrosse|both` (default both)
- `set wx.freq <MHz>` (default 915)
- `set wx.units us|metric` (default `us`: °F, mph, inches)
- `set wx.every <minutes>`: how often each sensor's readings are posted (default 30; 0 = only the first post and alerts)
- `set wx.only <labels>` or `set wx.only all`: show and follow only these sensors, by the label in their posts (eg. `5a,ch2`)
- `get wx.sensors`: the sensors heard, with packet count, interval, signal and when last heard
- `get wx.stats`, `get radio.fsk`: packets, listens, and the share of time away from the mesh

**Example reply:** `> WH65 5a x39 every 15s -108dBm 0s ago; WH31 ch2 x10 every 60s -107dBm 51s ago`

**Notes:**
- Ecowitt, Ambient Weather, other Fine Offset and La Crosse View sensors show in the app as one more channel, "Weather", after your own (and after Meshtastic's). Receive only. See [Weather sensors](weather_sensors.md).
- Settings are saved. Reconnect the app after `wx on` so it lists the new channel.

---

### Power

#### How long the radio has been running
**Usage:**
- `uptime` (or `get uptime`)

**Example reply:** `> up 2d 3h 14m 5s`

**Notes:**
- Counted from the last start or restart. Boards with power management (`NRF52_POWER_MANAGEMENT`) also say what started them, for example `, started by: Wake from VBUS`.
- Also works in the Radio console contact.

---

#### Stay off when a charger is plugged in (nRF52 boards)
**Usage:**
- `get charger.wake`
- `set charger.wake <state>`

**Parameters:**
- `state`: `on` (plugging in a charger turns the node on) or `off` (it stays off and charges)

**Default:** `on` (or `off` with the `CHARGER_WAKE_DEFAULT_OFF` build flag)

**Note:** The nRF52 always wakes up when power is plugged in. With this `off`, the firmware notices that the charger was the only reason it woke and switches straight back off, before the buzzer, vibration or LED start. The button, the reset button, and a node switched off for low battery still power it on as usual.

---

### BLE

#### Change BLE PIN
**Usage:**
- `set pin <pin>`

**Parameters:**
- `pin`: New BLE PIN

**Set by build flag:** `BLE_PIN_CODE`

---

### Alerts and lights

#### Find a lost radio
**Usage:**
- `find me`
- `find me <seconds>`
- `find me stop`

**Parameters:**
- `seconds`: how long to beep, `1` to `600`

**Default:** 120 seconds (2 minutes)

**Note:** Beeps three times every 1.4 s so you can find the radio by ear. Radios with a vibration motor also vibrate every few seconds. It works even if the buzzer or vibration motor is turned off. Pressing the radio's button or running `find me stop` stops it. Only on boards with a buzzer or vibration motor.

---

#### Find a radio from another radio
**Usage:**
- `find beep <name>`: make it beep for 2 minutes
- `find stop <name>`: stop it beeping
- `find range <name>`: measure the distance to it (LR2021 radios only)
- `get find.extended`, `set find.extended on|off`: use extended ranging for `find range` (off by default). The distance stays right while moving, and it adds a rough relative speed
- `get find`: the answer to your last request

**Parameters:**
- `name`: the other radio's contact name (exact, or the start of it)

**Note:** The other radio must allow you first, see below. Answers take a few seconds to come back, so check them with `get find`. See [find_me.md](find_me.md).

---

#### Let other radios find this one
**Usage:**
- `set find.allow <name>`
- `set find.deny <name>`
- `get find.allow`

**Parameters:**
- `name`: the contact name of the radio that may find this one

**Note:** Up to 8 contacts. An allowed contact can make this radio beep, stop it, and measure the distance to it. Nothing else. Contacts with remote CLI access are always allowed.

---

#### Turn the buzzer on or off
**Usage:**
- `get buzzer`
- `set buzzer <state>`

**Parameters:**
- `state`: `on` or `off`

**Default:** `on` (or `off` with the `BUZZER_DEFAULT_OFF` build flag)

**Note:** Only on boards with a buzzer. Takes effect immediately. Triple-pressing the button also toggles it.

---

#### Turn the vibration motor on or off
**Usage:**
- `get vibe`
- `set vibe <state>`

**Parameters:**
- `state`: `on` or `off`

**Default:** `on` (or `off` with the `VIBE_DEFAULT_OFF` build flag)

**Note:** Only on boards with a DRV2605 haptic driver (eg. MeshTracker X1). Independent of the buzzer. Takes effect immediately. Like the buzzer, it only goes off for new messages while the app isn't connected.

---

#### Turn the LEDs on or off
**Usage:**
- `get led`
- `set led <state>`

**Parameters:**
- `state`: `on` or `off`

**Default:** `on` (or `off` with the `STATUS_LED_DEFAULT_OFF` build flag)

**Note:** Covers the status LED (heartbeat, unread messages, charging) and the flash of the TX LED on transmit. Only on boards with one of them. Takes effect immediately.

**Build flag defaults** apply to a new device, and once to an existing device the first time it boots a firmware with this setting. After that the saved settings win.

---

### Wifi

#### Get status
**Usage:**
- `get wifi.status`
- `get wifi.ip`

---

#### Toggle
**Usage:**
- `set wifi.enabled <value>`
- `get wifi.enabled`

**Parameters:**
- `value`: `0` (disable) or `1` (enable)

---

#### Set SSID
**Usage:**
- `set wifi.ssid <value>`
- `get wifi.ssid`

**Parameters:**
- `value`: ssid as a string

---

#### Set password
**Usage:**
- `set wifi.pwd <value>`
- `get wifi.pwd`

**Parameters:**
- `value`: password string

---

### UI

#### Show clock
**Usage:**
- `set ui.show_clock <state>`
- `get ui.show_clock`

**Parameters:**
- `state`: `0` (disable) or `1` (enable)

**Default:** `0` (or `UI_SHOW_CLOCK` build flag)

---

#### Node discovery screen shows nodes names
**Usage:**
- `set ui.nd_name <state>`
- `get ui.nd_name`

**Parameters:**
- `state`: `1` (show name) or `0` (show pubkey_prefix)

**Default:** `1`

**Note:** When showing name, there is not always enough space to draw both incoming and outgoing snr values.

---

#### Auto-off screen
**Usage:**
- `set ui.auto_off_delay <delay>`
- `get ui.auto_off_delay`

**Parameters:**
- `delay`: in seconds (`0` means always on)

**Default:** `15` (or set by `AUTO_OFF_MILLIS` build flag (in ms))

**Note:**
On e-ink displays, when turned off, the screen is not necessarily blanked, see `ui.auto_off_blank` and `ui.backlight_delay`.

When screen is not blanked, it is not refreshed any more. To let the user aware of that, a sleep icon is shown.

---

#### Display backlight timeout
**Usage:**
- `set ui.backlight_delay <delay>`
- `get ui.backlight_delay`

**Parameters:**
- `delay`: in seconds 
  - `0` means no timeout
  - `-2` means always off
  - `-1` means always on

**Note:**
When set to `0`, backlight can only be triggered using backlight btn.

---

#### When to turn backlight on
**Usage:**
- `set ui.backlight_on_keys <state>`
- `get ui.backlight_on_keys`
- `set ui.backlight_on_msgs <state>`
- `get ui.backlight_on_msgs`

**Parameters:**
- `state`: `0` (disable) or `1` (enable)

**Default:** 
- `ui.backlight_on_msgs = 0`
- `ui.backlight_on_keys = 0` if there is a backlight button on the board, else `1`

**Note:**
By default backlight is triggered by backlight button if present (as long as the button is pressed backlight is on, and is turned off after a delay).
These toggles permits to toggle backlight when keys are pressed or when a message arrives (it acts as a notification signal).
If `backlight_delay` is set to `0` then this setting has no effect, backlight won't be turned on.

---

#### Control if eink screen should be blanked
**Usage:**
- `set ui.auto_off_blank <state>`
- `get ui.auto_off_blank`

**Parameters:**
- `state`: `0` (disable) or `1` (enable)

**Default:** `0` (or set by `UI_SCREENOFF_BLANK` build flag) 

**Note:**
If disabled, when screen is shut the displays stays on screen and is not updated (an sleep icons covers battery to show the screen is sleeping).

When screen is blanked, the controller is also put into hibernation, which should preserve the screen a little and some battery ...

---

#### Maximum number of partial refreshes
**Usage:**
- `set ui.max_partial <value>`
- `get ui.max_partial`

**Parmeters:**
- `value`: max partial refreshes before doing a full refresh

**Default:** 0 (no partial refresh or set by `EINK_MAX_PARTIAL_REFRESH` build flag)

**Note:**
Forcing full refresh helps revives the screen when some tearing appears (under certain environmental conditions). If you see some tearing appearing, you can force full refresh on your screen manually by double clicking the backlight button. If tearing reappears often, use this setting to force full refresh every `value` partial refreshes.

---

### Encryption

Experimental. See [crypto_v2.md](crypto_v2.md) for the packet format and what it does and doesn't protect.

Each contact and channel has an encryption policy:

| Policy | Sends | Accepts |
|---|---|---|
| `legacy` (default) | v1 (AES-ECB, 2-byte MAC) | v1 and v2 |
| `v2` | v2 (AES-SIV, 16-byte tag) | v1 and v2 |
| `v2only` | v2 | v2 only |

Firmware with v2 support always understands v2 packets. Firmware without it silently drops them, so only switch a contact or channel to `v2` once the other side (for a channel, every member) runs v2 firmware.

#### View the encryption policies
**Usage:**
- `get crypto`

Lists channels that aren't `legacy`, and how many contacts are on `v2` or `v2only`.

---

#### View or change a contact's encryption policy
**Usage:**
- `get crypto <contact>`
- `set crypto <policy> <contact>`

**Parameters:**
- `policy`: `legacy`, `v2` or `v2only`
- `contact`: the contact's exact name (not case-sensitive), or the start of its public key in hex (at least 4 characters)

**Default:** `legacy`

**Note:** When a contact sends you a verified v2 packet, the contact is switched from `legacy` to `v2` automatically, since it can clearly receive v2. Nothing ever lowers a policy automatically (a missing ACK never causes a fallback to v1). `v2only` is only ever set by you: use it once you know the contact will only send v2, so forged or replayed v1 packets from that contact are dropped.

Policies can only be changed on the device itself (the app or USB), not by a remote admin with Remote CLI access. A remote admin can still read them. If saving fails, the command reports an error and the policy stays as it was.

Repeaters and room servers with v2 firmware accept v2 requests but still reply in v1, so use `v2`, not `v2only`, for them. Logins to a repeater or room server without v2 firmware fail if its contact is set to `v2`.

---

#### View or change a channel's encryption policy
**Usage:**
- `get crypto.ch <channel>`
- `set crypto.ch <policy> <channel>`

**Parameters:**
- `policy`: `legacy`, `v2` or `v2only`
- `channel`: the channel's name (not case-sensitive) or its number

**Default:** `legacy`

**Note:** Channels never switch automatically: one member sending v2 doesn't mean every member can read it. Anyone with the channel key can still read and send on the channel, and can claim any sender name.

---

#### Time v2 decryption on this radio
**Usage:**
- `get crypto.bench`

**Note:** Times v2 decryption with a fixed test key, so nothing secret is used. The reply looks like `> aes=hw us: ok20/80/160 a/b/c bad@0 d bad@15 e padretry f kdf g v1bad h`, in microseconds per call:
- `ok…`: valid packets of 20, 80 and 160 bytes
- `bad@0`, `bad@15`: a tag that's wrong in its first byte, or only in its last byte (these should be about equal)
- `padretry`: the worst case for a bogus packet
- `kdf`: key derivation
- `v1bad`: v1 rejecting a bad MAC, for comparison

`aes=hw` means AES runs on the chip's hardware (nRF52 CC310, ESP32), and `aes=sw` means software. It takes a moment to run.

---

#### Recover after lost encryption policies
**Usage:**
- `set crypto.recover`

**Note:** Policies are saved to two alternating files with checksums, and prefs record which save is the newest. If the newest save can't be loaded at boot (corrupt or missing), the device doesn't fall back to accepting v1: it treats every contact and channel as `v2only`, and `get crypto` shows a warning. `set crypto.recover` accepts whatever policies did load (an older save, or none), so check your `v2only` contacts and channels afterwards. Only works on the device itself.
