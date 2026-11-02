# Packet encryption v2 (AES-SIV)

**Status:** experimental and opt-in. It needs review before anyone relies on it.

v2 replaces the encryption of these payload types, while staying compatible with existing nodes and repeaters:
- direct payloads: `REQ`, `RESPONSE`, `TXT_MSG` and `PATH`
- `ANON_REQ`
- `GRP_TXT` and `GRP_DATA`

The v2 cipher is standard AES-SIV ([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297)). No new cryptographic construction is introduced.

## Why

The v1 encryption has three weaknesses:
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
- **Channels never switch automatically.** One member sending v2 says nothing about the others.
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

## Cost of invalid packets

v1 checks its 2-byte MAC before decrypting. v2 has to decrypt before it can check the tag. An invalid v2 packet aimed at a node therefore costs one decryption attempt per candidate key, or two in the rare padded case. Each attempt is roughly:
- the HKDF (4 SHA-256 blocks)
- AES-CTR over the payload (up to 11 AES blocks)
- S2V (about 15 AES blocks)

The number of candidate keys is the number of contacts or channels whose 1-byte hash matches.

That cost hasn't been measured on hardware yet. Each packet also needs tens to hundreds of milliseconds of airtime, which limits how many an attacker can deliver, so the CPU cost should stay small next to the radio's receive power. This should be benchmarked on nRF52 before relying on it.

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
| AES-SIV, built on the rweather Crypto library's AES-128 | `src/AesSiv.cpp` |
| Envelope, key derivation and padding | `src/CryptoV2.cpp` |
| v1/v2 choice on send and receive | `src/Mesh.cpp` (`encryptPayload`, `decryptPayload`, `getCryptoPolicy`, `onPeerCryptoV2Recv`) |
| Companion firmware: policy table, storage (`/crypto_pol`) and CLI | `examples/companion_radio/` |
| Tests | `pio test -e native_crypto`. This covers RFC vectors, the reference vectors, and end-to-end runs through `Mesh` / `BaseChatMesh`: v1/v2 delivery, rejection by old firmware, `v2only`, tampering, channels, and exact `PATH` lengths. |

Repeater and room server firmware get v2 *receiving* from the shared `Mesh` code. They have no policy table yet, so they reply in v1.
