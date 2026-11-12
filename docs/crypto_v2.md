# Packet encryption v2 (AES-SIV)

**Status:** experimental and opt-in. It needs independent review before anyone relies on it for anything sensitive.

## In plain terms

### What encryption has to do

When your radio sends a private message, the encryption has two jobs:

1. **Scramble it**, so anyone listening on the radio can't read it.
2. **Seal it**, so the person receiving it can tell it really came from you and wasn't changed or made up along the way.

Both use a secret key that only you and the other person (or the members of a channel) know.

### Why the current encryption is weak

**The scrambling leaks patterns.** MeshCore scrambles a message in 16-character pieces, and the same piece always scrambles to the same result. An eavesdropper can't read the message, but can spot repeats. Send the same words twice and they can see it. It's like a code where every common word always has the same codeword: you don't learn the words, but you learn which ones keep coming up. (The first piece of every message includes the time, so that piece always differs. The repeats show up after it.)

**The seal is far too short.** The check that says "this really came from someone with the key" is only 2 bytes, so there are just 65,536 possible seals. Someone without the key can keep sending fakes, and about 1 in 65,536 will be accepted as genuine. Worse, because each piece is scrambled on its own, a forger can cut and paste pieces from real messages you've sent before. The fake that gets through then reads as real text, made of your own earlier words, rather than as obvious garbage.

### What v2 changes

v2 replaces this with **AES-SIV**, a published, standardized encryption method ([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297)). It isn't a home-made scheme.

- **No more patterns.** The whole message is scrambled together, starting from a value worked out from the message itself. Repeated words and repeated pieces no longer look alike. Only a completely identical message, down to its timestamp, would scramble the same way.
- **A seal that can't be guessed.** The seal is 16 bytes instead of 2. There are about 3 × 10^38 possible seals, so guessing one is less likely than winning a 1-in-300-million lottery jackpot four times in a row.
- **No cut and paste.** The seal covers the whole message, plus who it's from, who it's to and what kind of message it is. Change, swap or reuse any part and the seal no longer matches, so the message is thrown away.
- **Separate keys.** The key that scrambles and the key that seals are different, both derived from the secret you already share. Contacts and channels don't need setting up again.

### How it fits with radios that don't have it

- **Repeaters need no update.** A v2 message looks like any other message from the outside, so every repeater relays it.
- **Radios without v2 ignore v2 messages.** Since v1.18.0 they drop them cleanly instead of showing junk.
- **You choose who gets v2.** Each contact and channel starts on the old format (`legacy`). You switch one to `v2` once the other side has v2 firmware (for a channel, every member). It also switches by itself when a v2 message arrives from that contact or on that channel (see below).
- **It upgrades by itself, but never downgrades.** If a contact sends you a v2 message, your radio starts replying in v2. The same goes for a channel: one member sending v2 switches the channel to v2 on your radio, so members still on old firmware stop being able to read what you send there. Nothing ever switches a contact or channel back to the old format automatically, so an attacker can't trick your radio into falling back by jamming replies.
- **`v2only` locks out the old format.** Set a contact or channel to `v2only` and your radio refuses old-format messages from it entirely, closing off the weak 2-byte seal for good.
- **Your phone app keeps working.** Phone apps only understand the old format. Your radio translates v2 messages it can read into the old format before passing them to the app's packet log, so features like "heard N repeats" still recognise your messages.

### What it costs

About 7 more bytes per message on average, which means slightly more airtime. The longest possible message gets a little shorter, but 160-character texts still fit.

### What it doesn't fix

- **Channel members can still read and impersonate each other.** Everyone in a channel shares one key, so any member can read every message and send under any name.
- **Public and hashtag channels aren't private.** Their keys are known to anyone who knows the channel.
- **Recorded messages can be read later if your key is stolen.** If someone records your messages and later gets hold of your radio's private key, they can read them.
- **Recorded messages can be replayed.** A genuine message can be recorded and sent again later.
- **Who is talking is still visible.** Which radios are talking, how often, and how long the messages are can still be seen.

---

# Technical details

v2 replaces the encryption of these payload types, while staying compatible with existing nodes and repeaters:
- direct payloads: `REQ`, `RESPONSE`, `TXT_MSG` and `PATH`
- `ANON_REQ`
- `GRP_TXT` and `GRP_DATA`

The v2 cipher is standard AES-SIV ([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297)). No new cryptographic construction is introduced.

## Weaknesses in v1

- **ECB mode.** v1 uses AES-128-ECB with zero padding. Identical 16-byte blocks at the same position encrypt identically.
- **A 2-byte MAC.** A forgery is accepted about 1 time in 65,536 tries. Combined with ECB, the forged ciphertext can be pieced together from blocks of real messages.
- **Key reuse.** The same secret keys both AES and HMAC.

## Compatibility constraints

- **The outer packet version can't change.** `Dispatcher::tryParsePacket` drops packets with a payload version above 1, and every repeater on old firmware would do the same. v2 packets therefore keep the normal header and layout. Only the encrypted part, called the *envelope*, changes.
- **v1 envelopes have a fixed length shape.** A v1 envelope is `MAC(2) || AES-ECB blocks(16·n)`, so its length is always ≡ 2 (mod 16). v2 envelopes never use that length class. This lets a receiver tell v1 from v2 by length alone, with no trial decryption. Firmware from v1.18.0 onward rejects any envelope whose length isn't ≡ 2 (mod 16) (`Utils::MACThenDecrypt`). Such firmware therefore always drops v2 packets and never shows garbage.

  Firmware older than v1.18.0 lacks that length check. It runs the 2-byte MAC check first, so about 1 v2 packet in 65,536 passes it and is decrypted into garbage. That firmware also has the stack overflow fixed in v1.18.0.

## Envelope format

```
envelope = V(16) || C(L) [ || 0x00 ]
```

| Field | Meaning |
|---|---|
| `V` | AES-SIV synthetic IV, which is also the authentication tag (16 bytes) |
| `C` | AES-SIV ciphertext, exactly `L` bytes (the plaintext length, with no block padding) |
| `0x00` | One padding byte, present **only** when `L % 16 == 2`. Without it, `16 + L` would fall in the v1 length class. It must be exactly `0x00`. |

The fields before the envelope are unchanged:
- direct payloads: `dest_hash`, `src_hash`
- `ANON_REQ`: `dest_hash`, `sender_pub_key`
- group payloads: `channel_hash`

### Key

```
PRK = HMAC-SHA256(key = 32 zero bytes, msg = secret)             ; HKDF-Extract
K   = HMAC-SHA256(key = PRK, msg = "MeshCore AES-SIV v2 key" || 0x01)   ; HKDF-Expand, L = 32
```

`secret` is the same 32 bytes v1 uses as its HMAC key:
- **Contacts:** the X25519 shared secret.
- **Channels:** the channel's `secret[32]`. A 16-byte PSK is followed by 16 zero bytes.

The AES-SIV key is `K`. As RFC 5297 specifies, `K[0..15]` keys S2V (AES-CMAC) and `K[16..31]` keys AES-CTR. The v2 key is independent of the v1 key and of the v1 HMAC key.

Strings are ASCII with no terminating NUL.

### Associated data

S2V is given exactly two associated data strings, followed by the plaintext:

1. `"MeshCore AEAD v2"` (16 bytes), for protocol and version domain separation
2. `ctx`, the immutable header fields:

| Payload type | `ctx` |
|---|---|
| `REQ`, `RESPONSE`, `TXT_MSG`, `PATH` | `payload_type(1) ‖ dest_hash(1) ‖ src_hash(1)` |
| `ANON_REQ` | `payload_type(1) ‖ dest_hash(1) ‖ sender_pub_key(32)` |
| `GRP_TXT`, `GRP_DATA` | `payload_type(1) ‖ channel_hash(1)` |

`payload_type` is the 4-bit type value (for example `0x02` for `TXT_MSG`) in one byte.

Some fields change as a packet is forwarded: the route type, path, path length and transport codes. They are **not** authenticated.

S2V encodes each input unambiguously, so the plaintext length is authenticated implicitly.

### Counter block

This is as in RFC 5297. The CTR initial counter is `V` with bit 63 and bit 31 cleared, counting from the rightmost bit as bit 0. That means clearing the top bit of byte 8 and of byte 12. The counter is incremented as a 128-bit big-endian integer.

## Sending

1. Seal the plaintext with AES-SIV: `V || C = AES-SIV(K, ["MeshCore AEAD v2", ctx], plaintext)`.
2. If `(16 + L) % 16 == 2`, append `0x00`.

The overhead is 16 bytes, plus 1 byte in 1 of every 16 lengths. v1's overhead is 2 bytes plus 0 to 15 bytes of padding (9.5 on average), so v2 costs about 6.6 more bytes per packet on average.

The largest plaintext is:

| Payload | v2 | v1 |
|---|---|---|
| Direct message | 165 bytes | 167 bytes |
| Group message | 166 bytes | 168 bytes |

Existing text limits (160 characters) still fit. A create call returns `NULL` if the payload doesn't fit, and never falls back to v1 for size.

## Receiving

Let `n` be the envelope length.

1. If `n % 16 == 2`, it's **v1**. If the contact's or channel's policy is `v2only`, reject it. Otherwise verify and decrypt as before (`Utils::MACThenDecrypt`).
2. Otherwise it's **v2**:
   - Reject if `n <= 16`.
   - Decrypt and verify with AES-SIV over the whole envelope.
   - If that fails, and `n % 16 == 3` and the last byte is `0x00`, try again with the last byte removed. This is the padded case.
   - Plaintext is released only after the tag verifies. The tag comparison is constant-time. On failure, the output buffer is wiped.

A packet can't be both v1 and v2, so a node never tries a v2 packet as v1, or a v1 packet as v2.

## Policy

Each contact and each channel has a policy:

| Policy | Sends | Accepts |
|---|---|---|
| `legacy` (default) | v1 | v1, v2 |
| `v2` | v2 | v1, v2 |
| `v2only` | v2 | v2 |

- **Automatic upgrade.** A verified v2 packet from a known contact switches that contact from `legacy` to `v2`, because it can clearly receive v2.
- **Channels switch too.** A verified v2 packet on a channel switches that channel from `legacy` to `v2`. One member on v2 is taken as the signal that the channel is moving to v2: members still on old firmware can no longer read what this radio sends there. Only someone holding the channel key can trigger it.
- **No automatic downgrade.** A missing ACK, a timeout or anything else an attacker can cause never lowers a policy. Only the user lowers a policy.
- **`v2only` is only set by the user.** Accepting v1 is a deliberate migration trade-off: v1's 2-byte MAC is still accepted from that contact or channel until the user sets `v2only`.
- **Storage.** Policies are stored by an 8-byte ID: `SHA256("MeshCore policy id" || secret)[0..7]`. A policy therefore follows the key, not the contact's slot or the channel's slot.
- **Saving fails closed.**
  - Policies are written alternately to `/crypto_pa` and `/crypto_pb`. Each file holds a magic number, version, sequence number, count, the records and a truncated SHA-256 checksum.
  - A save is reported as successful only after the file is read back and checks out. A failed or interrupted write leaves the previous file intact. If a command's save fails, the policy change is undone and an error is returned.
  - After each save, the sequence number is also stored in prefs (`crypto_seq`). At boot, the newest valid file is loaded. If its sequence number is lower than the one in prefs, a newer save was lost. The device then treats everything as `v2only` until the user runs `set crypto.recover`, rather than silently accepting v1 again.
- **Only changed locally.** `set crypto*` commands are refused when they come from a remote admin over the Remote CLI. Only the device's owner, through the app or USB, can lower a policy.

## Decrypted payloads

A valid tag proves the sender knows the key, not that the payload is well formed.
- **Zero-filled buffers.** After decryption, everything past the plaintext in the receive buffer is zeroed, for v1 and v2 alike. Parsers that read slightly past the end, as v1's block padding used to allow, see zeroes, never stale stack data.
- **Length checks.** Fixed alongside v2:
  - `PATH` payloads whose declared path doesn't fit are rejected. Before this fix, `extra_len` could wrap around and over-read the stack. This also affected v1.
  - Signed text messages shorter than 9 bytes are dropped.
  - The ACK's extra attempt byte is read only when the message carries one. Otherwise it is 0.
- **Testing.** `test_crypto_v2_mesh` runs under AddressSanitizer and UBSan. It sends random plaintexts of every encrypted type and length through the receive path.

## Apps that only understand v1

Companion apps get every packet the radio hears (`PUSH_CODE_LOG_RX_DATA`). They use these packets to spot echoes of the user's own messages ("heard N repeats"), and they can only decode v1. So before logging a packet to the app, the companion calls `Mesh::toLegacyForm()`. If the packet is v2, and the radio holds its key, it is rewritten as v1. The key can come from a channel the radio has, or from a contact for a direct packet to us or one of our own heard again.
- The header, transport codes and path are kept.
- The envelope is replaced by the v1 encryption of the same plaintext. v1 encryption is deterministic, so the result is byte-identical to what a v1 sender transmits, including its packet hash.
- Packets the radio can't decrypt, and v1 packets, are passed through unchanged.

This only happens on the local link to the app, which already has the keys and the plaintext. Nothing v1 is transmitted over the air.

## Timing and side channels

**AES implementation.**
- **nRF52:** v2 uses the CryptoCell CC310 hardware engine for every AES block, in both CTR and CMAC. Software AES uses lookup tables, so its memory access patterns depend on the key and data. The CC310 doesn't. It is also faster.
- **CC310 self-test:** on first use, the CC310 path has to reproduce RFC 5297 vector A.1, and the test only passes if the hardware actually produced the result. If the self-test fails, or a CC310 call fails later, that work is done in software instead. A hardware problem can therefore never produce wrong output.
- **ESP32:** rweather's `AES128` already uses the chip's AES peripheral.
- **Other platforms** (RP2040, STM32) use rweather's table-based software AES.
- **Not covered:** none of this is a defence against power or electromagnetic analysis by someone with the device in hand.

**Tag comparison.** The comparison is constant-time. It ORs the XOR of every byte into a `volatile` accumulator and has no early exit. The ARM `-Os` output was checked: it is a fixed loop plus a branch-free `clz` at the end.

**Padding retry.** An envelope of length ≡ 3 (mod 16) that ends in `0x00` is tried twice when its tag doesn't verify. An attacker can build such packets on purpose, doubling the cost of a bogus packet. Whether the retry happens depends only on public bytes, and neither attempt releases plaintext, so nothing secret leaks. The cost is CPU time only.

**Candidate keys.** A bogus packet costs one attempt per contact or channel whose 1-byte hash matches. Each attempt is the key derivation (HKDF, 4 SHA-256 blocks), AES-CTR over the payload (up to 11 blocks) and S2V (about 15 blocks). Each packet also needs tens to hundreds of milliseconds of airtime, which limits how many an attacker can deliver.

**Measuring it.** `get crypto.bench` on a companion radio times the following, using a fixed test key and averaging over 8 runs:

| Field | What it times |
|---|---|
| `ok20/80/160` | Decrypting valid packets of 20, 80 and 160 bytes |
| `bad@0`, `bad@15` | A 160-byte packet whose tag is wrong in its first byte, or only in its last byte. These should match. |
| `padretry` | The two-attempt worst case |
| `kdf` | Key derivation |
| `v1bad` | v1 rejecting a bad MAC, for comparison |

The reply also says whether AES is running on hardware (`aes=hw`) or in software (`aes=sw`). These numbers haven't been collected on real boards yet.

**Auto-upgrade write.** When a contact or channel is upgraded to v2 automatically, the upgrade applies at once. The flash write waits 5 seconds, so it doesn't delay that packet or its ACK. If the radio reboots before the write, it is back on `legacy`, which still accepts v2, and the upgrade is relearned from the next v2 packet.

## What v2 does not do

- **Replay protection.** A recorded v2 packet still verifies when sent again later. Duplicate detection (`MeshTables`) is bounded, and timestamp checks differ by message type. Replay protection needs a separate mechanism, such as per-sender sequence numbers or a freshness window.
- **Sender authentication in channels.** The channel key only proves the sender knows the key. Any member can send as any name.
- **Public and hashtag channels.** Their keys are known to everyone.
- **Forward secrecy.** Contact secrets are static ECDH secrets. Anyone who obtains a private key can decrypt every message they recorded.
- **Metadata.**
  - Hashes, path and payload type stay visible.
  - Lengths are now exact, where v1 rounded them to 16 bytes.
  - Encryption is deterministic: an identical plaintext with an identical `ctx` under the same key gives an identical envelope. Message timestamps make that rare.
- **ACKs are unchanged.** The 4-byte ACK hash is sent unencrypted and isn't authenticated by the key.

## Test vectors

Verified against an independent implementation that uses Python's `cryptography` (`AESSIV`) and `hmac`. The checks are in `test/test_crypto_v2`. All values are hex.

```
DM secret      000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
K              dbb80697d72a9f61ae29ba20e4586bddc1a5e402188d26bcf3b703dcd4c75fd4
policy id      94378da118ec4565

1) TXT_MSG, ctx 02abcd, L = 10
   plaintext   010203040068656c6c6f
   envelope    43d8ef705e43ef0a7701aad7e7ac509ef67110b835789d6d3561

2) TXT_MSG, ctx 02abcd, L = 18 (L % 16 == 2, so padded)
   plaintext   010203040030313233343536373839616263
   envelope    7011ef3aea99ae36f9cf7e0eff9bdb0212ac7fe36294d60b98cd7cbefeb0d6f1057800

3) GRP_TXT, channel secret 8b3387e9c5cdea6ac9e5edbaa115cd72 + 16 zero bytes, ctx 0511, L = 39
   plaintext   0a0b0c0d00416c6963653a2068692074686572652065766572796f6e652c206c6f6e67206d7367
   envelope    6f4adb014482402dbb31b8e6412f6095b41370de30d0038453d4a4c21ae53682c54d0ff19ece929e79859ca3c0902de99c3c75c32362a2
```

The AES-SIV code is also checked against the RFC 5297 A.1 and A.2 vectors and the RFC 4493 CMAC vectors.

## Code

| Area | Files |
|---|---|
| AES-SIV, on the CC310 on nRF52 and otherwise the rweather Crypto library's AES-128 | `src/AesSiv.cpp` |
| Envelope, key derivation and padding | `src/CryptoV2.cpp` |
| v1/v2 choice on send and receive | `src/Mesh.cpp` (`encryptPayload`, `decryptPayload`, `getCryptoPolicy`, `onPeerCryptoV2Recv`) |
| Companion firmware: policy table, storage (`/crypto_pol`) and CLI | `examples/companion_radio/` |
| Tests | `pio test -e native_crypto`. This covers RFC vectors, the reference vectors, and end-to-end runs through `Mesh` / `BaseChatMesh`: v1/v2 delivery, rejection by old firmware, `v2only`, tampering, channels, and exact `PATH` lengths. |

Repeater and room server firmware get v2 *receiving* from the shared `Mesh` code. They have no policy table yet, so they reply in v1.
