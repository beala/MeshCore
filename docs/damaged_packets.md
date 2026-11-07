# Damaged packets (companions)

A packet that arrives with a few bad bits fails the radio's CRC check, and MeshCore normally throws it
away. With `dmg on`, the companion keeps it and reads what came through. Those messages show in
the MeshCore app as one more channel, "Damaged", with ▒▒▒▒ where text was lost:

```
dmg on
```

```
Bob: [#Public, 1 of 5 lost] running late, be there ▒▒▒▒ minutes
Alice: [#Public, fixed] anyone on the hill tonight?
▒▒▒▒: [#Public, 2 of 4 lost] ▒▒▒▒ the trailhead at 6▒▒▒▒
Carol: [direct, 2 of 6 lost] ▒▒▒▒the gate code is 4471, ▒▒▒▒
```

Reconnect the app after `dmg on`, and the channel appears after your own channels. It keeps a fixed
slot after Meshtastic, Weather and Aircraft. Receive only: text typed there is not sent. Any radio
works (SX1262, LR2021, others), on its own or with the other channels on.

With `set dmg.all on` the channel shows everything: also damaged copies of messages that arrived whole,
your own echoes, and every damaged packet that couldn't be read, with what it was and which radio sent
it:

```
7a Hilltop: [advert, -9dB] from 5e, named "Hklltop Rptr"
7a Hilltop: [channel message, -10dB] on channel 99, not one of yours
7a Hilltop: [direct message, -10dB] from 44 to 33 Ridge
?: [unknown, -11dB] header hit: 61 bytes, can't tell what it was
```

Everything below is a best guess from damaged bytes, and each guess has a rule. The rules, what they
rest on and how they can go wrong are in [How it decides](#how-it-decides).

## Reading a post

Each post starts with a sender, because the app takes what's before the first `: ` as the name.

- **A message that was read**: the sender is its author. For a channel message the author's name is
  part of the encrypted text (`Bob: ...`), so it's only known if that part came through; otherwise the
  sender shows as `▒▒▒▒`. For a direct message it's the contact whose key read it.
- **A packet that wasn't read** (only with `dmg.all`): the sender is the radio that sent it to you
  (see [Who sent it](#who-sent-it)), `?` if the packet doesn't say.

In the brackets:

| Label | Meaning |
|---|---|
| `#Public`, `direct` | the channel, or a direct message to you |
| `2 of 5 lost` | the message has 5 pieces of 16 bytes; 2 didn't read as text and show as ▒▒▒▒ |
| `start lost`, `start and 2 more lost` | where the message starts wasn't found (see below), so how much is missing in front isn't known |
| `unchecked` | every piece read as text, but the MAC doesn't match: the damage was in the header, the path or the MAC itself |
| `fixed` | the MAC matches after flipping one bit back |
| `from copies`, `fixed from copies` | joined from damaged copies heard through different repeaters (and then the MAC matched) |
| `also heard whole` | an intact copy arrived too (or it's your own message); shown only with `dmg.all` |
| `advert`, `ack`, `channel message`... `-9dB` | a packet that wasn't read: its type from the header, and its SNR |

## How it decides

### Background

MeshCore encrypts a text message in 16-byte pieces, each scrambled on its own (AES-128 in ECB mode),
with a 2-byte MAC in front. A few bad bits spoil only the pieces they land in: a changed bit in a
piece turns all 16 decrypted bytes to noise, and leaves every other piece as it was. LoRa errors come in
short bursts (one bad symbol spoils up to a few bytes), so most damaged packets lose one or two pieces.

The packet's first bytes, its header and path, are not encrypted. They usually come through too, and
say what the packet is, where it went and who it's for.

### Which pieces read right

- **A piece of text.** A decrypted piece counts as text when every byte is printable ASCII, a newline or
  part of a well-formed UTF-8 character (emoji included). A character may run in from the piece before
  or out to the piece after. Zero bytes are allowed only as the message's padding: from the first zero
  to the end of the piece. Tested on 20 million random pieces, noise passes this about once in 87,000
  tries.
- **The first piece.** The first piece of a message holds a 4-byte timestamp, then a flags byte, then
  text (a signed direct message has 4 bytes of the sender's key before the text). It counts when the
  timestamp is after 2023-01-01 and no more than a year ahead of the radio's clock (or before 2038 when
  the clock isn't set), the flags are a known kind (a channel message: plain text; a direct message:
  plain, command or signed), and the rest is text that doesn't start with an empty message. Noise
  never passed this in 2 million random pieces.
- **Where the pieces are.** The encrypted part always ends at the end of the packet, so the pieces are
  counted back from the end: they can be found even when the header or path was hit. Where the message
  starts is, in order: a piece that reads as a first piece (preferring the one the header points to),
  else where the header says (when its sizes add up), else the first piece that reads as text. In the
  last case the start is unknown, and the post says `start lost`.

### Which key

- **Channels**: every channel the radio has is tried. A key is used when, with it, the first piece
  reads right, or two pieces read as text, or one piece reads as text and the packet's channel byte is
  that channel's. The key with the most pieces read wins.
- **Direct messages**: only to this radio. The destination byte must be this radio's ID: where the header
  says, or else at each place it could be counting back from the end. Then the contacts whose ID
  matches the source byte are tried (at most 6), and one piece read is enough, since the ID bytes
  already pointed to them.
- With 20 channel keys tried against 3,000 random packets, no key was ever taken.

### Repair

When the first piece read and at most one piece didn't, the radio tries to put the message back
exactly:

- if every piece read, it checks the MAC as is, then with each of its 16 bits flipped (the damage may be
  in the MAC);
- if one piece didn't, it flips each of that piece's 128 bits in turn, checking the MAC each time.

A match counts only if every piece then reads as text: with a 2-byte MAC, 1 in 65,536 wrong guesses
matches by chance, and the text check catches those. On the bench, about 1 damaged packet in 6 was
fixed this way.

### Copies

A flood message comes in once from each repeater that passes it on, with the same encrypted bytes. A
damaged message waits 6 seconds for other copies (at most 3 wait at once; a fourth sends the oldest
out early). Two copies are taken as the same message when, lined up from the end of the packet:

- every piece that read in both is the same, and those include the first piece (it has the timestamp)
  or are at least two pieces. One shared piece isn't enough: with ECB, the same text at the same
  place encrypts the same, so common endings ("lol", "thanks") match across different messages;
- or, when they share no piece, both start where the header says, have the same length and carry
  the same MAC.

The pieces one copy lost are taken from the other. If the message is then whole and either copy's MAC
matches, it's `fixed from copies`.

### Intact copies and your own messages

- The radio keeps a fingerprint of every intact packet it heard in the last 30 seconds (a 16-bit hash of
  each 16-byte block, counted from the end). A damaged message whose pieces that read match an intact
  packet's (the first piece, or two pieces) was also heard whole, and isn't shown, unless `dmg.all`
  is on. It's checked when the damaged copy arrives and again when it's posted, so the intact copy can
  come before or after.
- A damaged channel message whose text starts with this radio's name and `: ` is your own, heard back
  from a repeater. It isn't shown, unless `dmg.all` is on.
- A damaged copy with only one readable piece can't be matched either way, and is shown.

### What a packet that wasn't read was

The header's first byte says the packet's type. Since nothing checks the header on its own, a hit there
files the packet under the wrong type. To catch most of those, the payload's size must fit the type,
or the packet counts as `too damaged`:

| Type | Size of the payload (after the header and path) |
|---|---|
| ack | 4 to 8 bytes |
| advert | a 32-byte key, a 4-byte timestamp, a 64-byte signature, then 1 to 32 bytes of data |
| direct message, request, response, path | 2 ID bytes, then an encrypted part* |
| channel message, group data | 1 channel byte, then an encrypted part* |
| anonymous request | 1 ID byte and a 32-byte key, then an encrypted part* |
| trace | at least 9 bytes |
| reserved types (12-14) | never sent: always too damaged |
| others | any size |

\* an encrypted part: a 2-byte MAC and whole 16-byte pieces, or (v2 encryption) more than 16 bytes.

The path must fit the packet too (hop count times hash size, at most 64 bytes), and the version bits
must be v1. Then, by type and the bytes after the path:

| `dmg` count | Log | When |
|---|---|---|
| adverts | `a` | an advert. Not encrypted, so nothing to decrypt; its name shows in the post if the name came through (ASCII; a bad byte shows as `?`) |
| acks | `k` | an ack: no text |
| for others | `o` | a channel message or group data whose channel byte is none of your channels; a direct message, request, response, path or anonymous request whose destination byte isn't your ID |
| other | `x` | group data on one of your channels; a request, response, path or anonymous request for you; traces, control, multipart, custom packets |
| too damaged | `-` | the header or sizes don't add up; or a text message for you or on one of your channels where no piece read |

How it can go wrong: a hit on a channel or ID byte can make your own message look like someone else's
(`for others`); a hit on the type byte that still leaves a size that fits files it under the wrong
type. On the bench, the first byte was hit in 2 of 17 damaged packets.

### Who sent it

The sender of a packet is the radio you heard it from:

- **a flood packet with hops**: the last repeater on its path (each repeater adds its ID to the end);
- **a packet with no hops**: its originator: an advert's key, or a direct message's (request's,
  response's, path's) source byte;
- **otherwise `?`**: a channel message straight from its author (channel messages carry no source
  byte), a direct-routed packet (each hop removes its own ID from the path, so the last sender isn't
  in it), or a header that didn't add up.

IDs are 1 byte (the first byte of the radio's key), so 1 in 256 radios share each. A name is the first
contact with that ID, so it's the likely radio, not a certain one. A path or ID byte that was hit names
the wrong radio.

## Where the damage comes from

`get dmg.from` lists the radios damaged packets came from, most first: damaged packets out of all
packets heard from that radio (intact ones are counted too, while `dmg` is on), then the average SNR
of the damaged ones and of the intact ones:

```
> 7a Hilltop: 9/18 -9dB/+6; 5e: 12/12 -9dB; ?: 13/15 -9dB/-9
```

- **Damage at low SNR** (around −7 dB and below at SF7) means a weak link: that radio is near the edge of
  range for you.
- **Damage at a good SNR** points to collisions with other packets, or to interference.

The table keeps 12 radios; when full, a new one replaces the one heard least.

## What it isn't

None of this is authenticated. The MAC failed, or matched only after a repair or a join, and a 2-byte
MAC with 128 or more tries no longer proves much. Someone without the key could also splice together
pieces of your earlier messages. So damaged messages are only shown:

- never in the channel or chat they were for,
- never acked, forwarded or repeated,
- never used to add or update a contact or a path.

Packets in [v2 encryption](crypto_v2.md) aren't read: they're scrambled as a whole, not in pieces.

## Commands

| Command | |
|---|---|
| `dmg on` / `dmg off` | start or stop (saved) |
| `set dmg.all on` / `off` | also show damaged copies of messages heard whole, your own echoes, and every damaged packet that couldn't be read (saved; default off) |
| `dmg`, `get dmg` | damaged packets heard; those read (shown, fixed, joined from copies, heard whole too); and those not read, by why |
| `get dmg.from` | which radios the damaged packets come from, with SNR |
| `get dmg.log` | the last 8 damaged packets, oldest first: age, length, then what became of it: `w` waiting for copies, `j` joined to a waiting one, `i` an intact copy was heard (after these: the slot and the pieces read, as a bit mask; bit 15: has the timestamp, bit 14: starts where the header says), or why it wasn't read: `a` advert, `k` ack, `o` for others, `x` other traffic, `-` too damaged |
| `dmg reset` | start the counts again |

These work from the companion CLI, the Radio console and remote CLI.

## Code

| File | |
|---|---|
| `src/helpers/DamagedRx.*` | the decoding: text tests, keys' readings, repair, copies, fingerprints, sizes, sender |
| `examples/companion_radio/MyMeshDamaged.cpp` | the companion: keys to try, waiting and posting, counts, commands |
| `src/helpers/radiolib/RadioLibWrappers.cpp` | keeping a packet that failed its CRC (`keepDamaged`) |
| `test/test_damaged`, `test/fuzz/fuzz_damaged.cpp` | tests (`pio test -e native_crypto`) and the fuzzer |
