# Several radios with one key

You can load the same private key onto more than one companion radio, for example a radio at home
and one you carry. All of them then show your messages. The problem starts when more than one is
switched on: a message that arrives by flood reaches each of them, and each sends its own reply
(the acknowledgement and the path back). The sender gets two replies and two different paths,
keeps whichever arrived last, and from then on sends its direct messages to that one radio only.

With this firmware, you pick one radio as the main radio. The others become backups: they still
show the messages they hear, but never answer them. Only the main radio sends ACKs and paths, so
"delivered" in the sender's app means the main radio has the message.

## Copy a radio

To set up a second radio with your key, copy your radio onto it. The copy gets the key, contacts,
channels, encryption policies and settings, and restarts as a backup of the radio it came from.

1. Put the two radios next to each other.
2. On the new radio, send `clone receive`. It replies with a code, for example
   "On the radio to copy, send: clone send 482913", and waits 5 minutes.
   Everything on the new radio is replaced by the copy.
3. Connect the app to the radio you're copying and send `clone send 482913`.

A few seconds later the console says "Copied to the other radio: 17 KB in 1.5 s". The new radio
restarts with your key, as a backup. The radio you copied from becomes the main radio.

The new radio keeps its own transmit power, receiver gain, BLE PIN and GPS settings. Routes to
contacts come along, so if the two radios are in different places the copy learns its own as
messages fail.

Both radios leave the mesh while the copy runs, and Meshtastic, weather or aircraft, whichever is
on, pauses until it's over. `clone stop` ends it early, and `clone` shows progress. Both radios need
an LR2021.

### How the copy is protected

- **Short code, strong key.** The radios run CPace (the password-authenticated key exchange in
  [draft-irtf-cfrg-cpace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/), on X25519 with
  SHA-512) with the code as the password. Someone listening learns nothing they could test guesses of
  the code against. A radio pretending to be the other one gets a single guess, a 1 in a million
  chance: on a wrong code both radios stop, and a new try needs a new code.
- **Key confirmation.** Each radio proves it has the same key (CPace's key-confirmation tags, HMAC-SHA-512)
  before anything is sent.
- **Encrypted data.** Everything is encrypted with ChaCha20-Poly1305 (RFC 8439), under a key derived
  with HKDF-SHA256 (RFC 5869). A chunk that's been tampered with fails its tag and is sent again, and the
  whole copy is checked against a SHA-256 hash before the new radio saves any of it.
- **Close by only.** The radios transmit at 0 dBm and ignore each other's opening messages if they're
  heard weaker than -70 dBm.
- **Randomness.** The code and CPace's secret values come from the radio's hardware random number
  generator, through an HMAC-DRBG (NIST SP 800-90A). A radio without enough trusted randomness refuses
  to copy.

### Link

The copy uses the LR2021's FLRC mode: 1.3 Mbps with 3/4 error correction, 32-bit CRC, on 920 MHz in
the US band (clear of the mesh, Meshtastic, weather sensors and LoRaWAN), or on the mesh's own
frequency elsewhere. Give a frequency to both commands to use another. Data goes in chunks of 200
bytes, 32 at a time. The new radio checks off what it has after each 32, and missing chunks are sent
again. It keeps the copy in temporary files and only replaces its own once the whole copy has
checked out, so a copy that fails leaves the new radio as it was.

## The Radio console contact

Every radio with this firmware adds a contact called **Radio console** to the app's contact list.
It isn't a real node: messages to it never go on air. The radio runs what you send as a command,
and replies in the same chat. It also uses this chat to tell you things, like another radio with
your key being heard.

Send `help` to see the commands. Every command from the app's command line works there too, such
as `get flood.retry` or `uptime`. A reply too long for one message comes as several.

A contact on the mesh whose name reads as "Radio console" (any case or spacing, emoji or invisible
characters added, 0/1 for o/i, or lookalike letters such as a Cyrillic "о") shows in the app as
"(fake) Radio console", so it can't pass for this contact. The real one is recognised by its key.
Commands aren't case sensitive, so a capital letter added by your phone is fine.

In a DM or channel, messages starting with `/` run commands for that chat, such as `/range` or
`/crypto v2`: see [chat_commands.md](chat_commands.md).

## How it works

1. When a radio hears another radio with the same key, its console posts:
   "Another radio with this key is active: it sent to Bob. Make this the main radio, so the others
   stay quiet? Reply "yes"." The radios notice each other by their replies to the same contacts:
   they share the key, so each can read the other's packets.
2. Reply `yes`, or send `takeover`, on the radio you want as main. It floods a short claim that only
   radios with your key can read. Every other radio with the key that hears it becomes a backup and
   says so in its console.
3. A backup shows every message it receives, but sends no ACK, no path and no response. Senders only
   hear from the main radio, so they learn one path to your key, however long the mesh takes to
   carry the replies.
4. If you send a message from a backup, its console asks: "This radio is a backup, so it doesn't
   answer messages, and replies to you may go to the main radio. Make this the main radio? Reply
   "yes"." It asks at most every 30 minutes.

To go back to normal, send `clone off` on each radio. The role is saved and survives a reboot.

If a radio was off when you took over, it won't know. The main radio offers to send the takeover
again when it hears that radio reply.

## Commands

| Command | What it does |
|---|---|
| `takeover` | Make this the main radio for this key |
| `yes` | Accept the takeover the console just offered |
| `clone` | Role, messages a backup left unanswered since it became one, and when another radio was last heard |
| `clone off` | Answer as normal again |
| `clone receive [MHz]` | Wait 5 minutes to become a copy of another radio; shows the code |
| `clone send <code> [MHz]` | Copy this radio to the one showing the code |
| `clone stop` | End a copy that's running |

## Limits

- When the main radio is off or out of range, nothing answers: senders see their messages fail,
  even if a backup received them. Take over on the radio you have with you.
- Senders keep one path for your key, to the main radio, and send direct messages along it. A
  backup somewhere else only gets messages that come by flood, or pass close by.
- After a takeover, senders keep their old path until a direct message to it fails.
- Messages you send from one radio don't show up on the others.

## Bench results

Two companions with the same key (an AB XIAO with an LR2021 and a Heltec V4 with an SX1262) and a
third companion sending, on 908 MHz, SF7 / 62.5 kHz.

| Test | Result |
|---|---|
| Both normal (2 flood messages) | 2 replies each; both consoles posted the alert |
| `takeover` sent to the Heltec's console | Heltec main; XIAO became a backup and said so |
| Reboot both radios | roles kept |
| `takeover` on the other radio | roles swapped, 1 reply per message |
| Live mesh, 2 direct messages to a phone companion, one from each radio | both acknowledged in 0.9 s |
| Backup alone, flood message to it | message shown on the backup; no ACK sent, sender saw no "delivered" |
| Message sent from the backup | delivered; console offered the takeover once, not again on the next message |
| `Yes` to the offer | backup became main; the next message to it was acknowledged in 0.9 s |
| `Clone` with a capital C; a command sent twice by the app | recognised; the repeat was confirmed but not run again |
| Both radios on, after `takeover` (5 flood messages) | 1 reply each, acknowledged in 0.7 s; the backup showed every message |
| Message sent from the backup, then `yes` | roles swapped; still 1 reply per message |

On the bench, with no repeater, two radios side by side rarely notice each other while both answer:
they hear the message at the same moment and reply at the same moment, and a radio can't receive
while it transmits. On a mesh, each hears the other's reply when a repeater passes it on.


### Copying

An AB Labs WisBlock NiceRF (sender, 83 contacts) and an AB Labs XIAO (receiver), both with an LR2021,
side by side on dummy loads, FLRC on 920 MHz (bench build: 22 dBm, no signal-strength limit, since dummy
loads leave only -74 dBm between them).

| Test | Result |
|---|---|
| Copy, 5 times (3 on 920 MHz, 2 on 915 MHz) | 16-17 KB in 1.4-1.5 s each, no chunks resent; the XIAO restarted with the NiceRF's key, name, 83 contacts and channels, as a backup; the NiceRF main |
| Wrong code | both said "Copy failed: wrong code"; the XIAO unchanged |
| `clone stop` while waiting | "Copy failed: stopped. This radio is unchanged." |
| Opening messages at -90 dBm with the normal limit | ignored: no copy |

On the PC (`pio test -e native_clone`): CPace and X25519 against the draft's and RFC 7748's test
vectors, and copies over a simulated link that loses, repeats, corrupts or cuts frames. The fuzzer
(`test/fuzz/run.sh`) mangles frames in flight between a real sender and receiver.
