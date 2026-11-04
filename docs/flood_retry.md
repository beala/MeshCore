# Flood retry

When a radio sends a channel message, it listens for a repeater passing it on. If it hears
nothing, it sends the same message again, byte for byte.

## Why resending is safe

Every node remembers the messages it has seen and drops copies of them. That check looks at
the message contents only, not the list of hops, so the resend is the same message to every
node:

- A repeater or radio that got the first copy drops the resend. Nobody sees the message twice,
  and no repeater passes it on twice.
- A repeater that missed the first copy treats the resend as new and passes it on.

The resend is the stored packet, not a rebuilt one, so it matches exactly, down to the
timestamp.

## How it decides

After a flood packet goes out, the radio waits for an echo: a copy of the same packet with more
hops in its path than ours. Hearing one means at least one node got it and passed it on.

If no echo comes within the wait time, it resends. It does this up to the set number of times,
then stops. If the echo arrives while a resend is still queued, the resend is cancelled.

The wait is 1 second plus 8 airtimes of the packet, about 2.5 s for a short message at
SF7 / 62.5 kHz. That covers a repeater's own random delay before it forwards (up to 2.5 airtimes
at the default `txdelay`), plus its transmit time.

## Companion

On by default, with 1 resend. It covers the radio's own channel messages (text and channel
data). It doesn't cover direct messages, which already have acknowledgements and retries, or
adverts.

## Repeater

Off by default. When on, a repeater watches every flood packet it forwards, except adverts. If
it hears nothing go further, it resends its copy. This helps on links with a single path, for
example one repeater bridging two areas, where a single lost packet stops the flood.

Guardrails:

- Adverts are never resent. They're most of the flood traffic, and losing one costs little.
- A resend is skipped when 2 or more packets are already waiting to go out, so it doesn't add
  to a busy channel.
- A repeater at the edge of the mesh (nobody further out) will resend each packet once,
  because no echo comes. Leave it off on such repeaters.

## Commands

The same commands work on the companion (through the app's CLI or companion frame 66) and on
the repeater (serial or remote admin CLI).

| Command | What it does |
|---|---|
| `get flood.retry` | Number of resends, and the wait |
| `set flood.retry <0-3>` | Number of resends. `0` or `off` turns it off |
| `set flood.retry.wait <ms>` | How long to wait for an echo, 500 to 30000 ms |
| `set flood.retry.wait auto` | Use the automatic wait (the default) |
| `get flood.retry.stats` | Counters since boot |

`get flood.retry.stats` replies with, for example:

```
> watched 18, echoed 15 (9 after a resend), resends 12, no echo 3, skipped 0
```

- **watched**: packets watched for an echo
- **echoed**: echo heard. "After a resend" means the first send didn't get through and a resend did
- **resends**: resends transmitted
- **no echo**: nothing heard after the last resend
- **skipped**: not watched or not resent: too many packets waiting at once, or a busy channel

## Bench results

Two LR2021 boards on 908 MHz, SF7 / 62.5 kHz. The bench repeater could be told to ignore the
first copy of each packet, to stand in for a lost packet.

| Test | Result |
|---|---|
| Companion, repeater working (5 messages) | 5 echoed, 0 resends |
| Companion, repeater misses the first copy (9 messages) | 9 resent once, 9 echoed after the resend |
| Companion, no repeater forwarding, 2 resends set (3 messages) | 2 resends each, then stopped |
| Companion, set to 0 | nothing watched or resent |
| Repeater, next repeater passes it on (8 packets) | 8 echoed, 0 resends |
| Repeater, next repeater misses the first copy (8 packets) | 8 resent once, 8 echoed after the resend |
| Repeater, nobody passes it on (3 packets) | 1 resend each, then stopped |
| Companion on the live mesh, private channel (3 messages) | 3 echoed by local repeaters, 0 resends |

An RTL-SDR recording of the companion test showed exactly three transmissions: the message,
the resend 2.7 s after it, and the repeater forwarding the resend 0.1 s later.
