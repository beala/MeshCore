# Damaged packets (companions)

A packet that arrives with a few bad bits fails the radio's CRC check, and MeshCore normally throws it
away. With `dmg on`, the companion keeps it and reads what came through. Those messages show in
the MeshCore app as one more channel, "Damaged", with ▒▒▒▒ where text was lost:

```
dmg on
```

```
[#Public, 1 of 5 lost] Bob: running late, be there ▒▒▒▒ minutes
[#Public, fixed] Alice: anyone on the hill tonight?
[from Carol, 2 of 6 lost] ▒▒▒▒the gate code is 4471, ▒▒▒▒
```

Reconnect the app after `dmg on`, and the channel appears after your own channels. It keeps a fixed
slot after Meshtastic, Weather and Aircraft. Receive only: text typed there is not sent. Any radio
works (SX1262, LR2021, others), on its own or with the other channels on.

## How it works

MeshCore encrypts a message in 16-byte pieces, each scrambled on its own (AES-128 in ECB mode). A few
bad bits spoil only the pieces they land in, and the other pieces still decrypt to the right text.

- **Finding the pieces.** The encrypted pieces always end at the end of the packet, so they can be
  found even when the header or the path was hit.
- **Which key.** The radio tries every channel key it has. For a direct message to this radio, it also
  tries the contacts whose ID byte matches the sender's.
- **Judging a piece.** A piece is kept when it decrypts to text: printable characters, newlines or
  well-formed UTF-8 (emoji too), ending in the message's zero padding. A garbled piece passes that
  test about once in 87,000 tries. The first piece also has to hold a sensible timestamp and flags.
  A key is used when its first piece reads right, or two pieces read right, or the packet's channel
  or contact byte points to it and one piece reads right.
- **Repair.** When exactly one piece is bad, the radio flips each of its 128 bits in turn and checks the
  message's 2-byte MAC. On a match, with every piece then reading as text, the message is marked
  `fixed`. The same check covers a MAC that took the hit.
- **Copies.** A flood message comes in once from each repeater that hears it. Copies with different
  bad pieces are joined: a message waits 6 seconds for other copies before it shows. Two copies are
  the same message when pieces both read are identical and include the timestamp piece, or two pieces;
  or else when both have the same length and MAC. A joined message that's whole and matches the MAC
  is marked `fixed from copies`.
- **Intact copies.** If any copy arrives intact, through another repeater, before or after, the
  damaged one isn't shown: the message is already in its own channel.
- **Your own messages.** A damaged echo of your own channel message, repeated back, isn't shown.

On the bench (an SX1262 sending to an LR2021 near the edge of range, −121 dBm), 6 in 10 pieces of
damaged packets came through. In 10 of 17 damaged packets only one piece was bad.

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
| `dmg`, `get dmg` | packets heard with a bad CRC; read (some text found); shown; fixed; joined from copies; also heard intact |
| `get dmg.log` | the last 8 damaged packets, oldest first: age, length, then `-` nothing read, `i` an intact copy was heard, `w` waiting for copies, `j` joined to a waiting one. After `w`/`j`: the slot and the pieces read, as a bit mask (bit 15: has the timestamp, bit 14: starts where the header says) |

These work from the companion CLI, the Radio console and remote CLI.
