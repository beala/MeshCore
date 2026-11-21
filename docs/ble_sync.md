# Faster Bluetooth sync (nRF52 companions)

The app fetches what the radio has for it one request at a time: each queued message, each channel, each contact.
Each fetch is a round trip over Bluetooth, so a backlog of 100 messages is 100 round trips, and how long a round
trip takes is set by the Bluetooth connection, not by the radio.

## What changed

- **Fast while busy.** When the app connects, and whenever it writes after a quiet spell, the radio asks the phone
  for a 15 ms connection interval with slave latency 0. After 15 s with nothing from the app it asks for
  15-30 ms with latency 4 again (what it always asked for before), to save power while connected and idle.
  `BLE_IDLE_AFTER_MS` sets the 15 s; `-D BLE_FAST_MODE=0` builds the idle settings only.
- **Replies go out at once.** A reply with nothing queued ahead of it is sent from `writeFrame()`, not on the next
  pass of the main loop, and the main loop doesn't sleep while a reply waits to go out (`hasPendingWrite()`).
- `MultiSerialInterface` passes `hasPendingWrite()`, `lastRecvMillis()` and `describeLink()` on to the interfaces
  it holds.

Slave latency lets the radio sleep through connection events it has nothing to send in. That saves power, but a
write from the app then waits until the radio next listens: up to (latency + 1) intervals, ~150 ms at 4 and 30 ms.
The phone chooses the interval; iPhones give 30 ms for the old 15-30 ms request, and gave 15 ms when asked for
exactly 15 ms.

## Bench results

MeshTracker X1, iPhone, 100 or so queued channel messages (`/fill`), per message:

| Build | Link | Per message | 100 messages |
|---|---|---|---|
| Before (latency 4) | 30 ms, latency 4 | 223 ms | 22.5 s |
| Latency 0 all the time | 30 ms, latency 0 | 126 ms | 12.7 s |
| Fast while busy | 15 ms, latency 0 | 66 ms | 6.7 s |

The radio's part of each round trip measured 0 ms in all three: the rest is the phone and the link, about four
connection events per message. Going much below that needs the app to ask for more than one message at a time.
The switch back to idle was seen working: a message that came in after a quiet spell was synced at 30 ms, latency
4, and the next one at 15 ms, latency 0.

Not done: the ESP32 and RP2040 Bluetooth interfaces (the ESP32 one spaces writes at least 60 ms apart), and
fetching channels and contacts, which are the same one-at-a-time round trips (every connect asks for all 40 channel
slots and the built-in channels).

## Measuring it

`set dbg on` in the Radio console (off again with `set dbg off`, and at power-on) turns on two test aids:

- **`/fill <n>` in a channel**: n test messages ("Test: message 12 of 100, ...") go into that channel's queue
  when the app next disconnects, so they wait as a backlog for the next connect. 1 to `OFFLINE_QUEUE_SIZE`;
  `/fill 0` cancels; `/fill` shows what's waiting. Nothing goes on air. Use a channel of its own for it.
- **A SYNC note in the Radio console** after each sync of 10 or more messages:
  `SYNC: 100 messages in 6675 ms (66 ms each: radio 0, phone+link 65). Link: interval 15.00 ms, latency 0, MTU 247 (fast asked)`.
  *radio* is from a request arriving to the reply going out, *phone+link* from the reply going out to the next
  request arriving, and *Link* is the connection as it is when the note is written, and which settings the radio
  last asked for.

Builds with `-D BLE_DEBUG_LOGGING=1` also print each frame in and out on USB serial, with `millis()` timestamps,
and each change of connection parameters.
