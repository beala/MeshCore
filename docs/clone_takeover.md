# Several radios with one key

You can load the same private key onto more than one companion radio, for example a radio at home
and one you carry. All of them then show your messages. The problem starts when more than one is
switched on: a message that arrives by flood reaches each of them, and each sends its own reply
(the acknowledgement and the path back). The sender gets two replies and two different paths,
keeps whichever arrived last, and from then on sends its direct messages to that one radio only.

With this firmware, you pick one radio as the main radio. The others become backups and stay
quiet when the main radio answers.

## The Radio console contact

Every radio with this firmware adds a contact called **Radio console** to the app's contact list.
It isn't a real node: messages to it never go on air. The radio runs what you send as a command,
and replies in the same chat. It also uses this chat to tell you things, like another radio with
your key being heard.

Send `help` to see the commands. Other radio commands work there too, such as `get flood.retry`.

## How it works

1. When a radio hears another radio with the same key, its console posts:
   "Another radio with this key is active: it sent to Bob. Send "takeover" to make this the main
   radio; the others will stay quiet." The radios notice each other by their replies to the same
   contacts: they share the key, so each can read the other's packets.
2. Send `takeover` to the console of the radio you want as main. It floods a short claim that only
   radios with your key can read. Every other radio with the key that hears it becomes a backup
   and says so in its console.
3. A backup still shows every message. When it would reply to a message that came by flood, it
   waits 1.5 s first. If it hears the main radio's reply to the same message in that time, it
   drops its own. If not (the main radio is off or out of range), its reply goes out, so the
   sender still gets an acknowledgement.
4. A backup also leaves the reciprocal path, sent when a contact replies to a flood message, to
   the main radio, so contacts learn one path to your key.

To switch, send `takeover` on the other radio. To go back to normal, send `clone off` on each radio.
The role is saved and survives a reboot.

If a radio was off when you took over, it won't know. The main radio posts a reminder if it
hears that radio reply: send `takeover` again.

## Commands

| Command | What it does |
|---|---|
| `takeover` | Make this the main radio for this key |
| `clone` | Role, wait, replies held and dropped, and when another radio was last heard |
| `clone off` | Answer as normal again |
| `set clone.wait <ms>` | How long a backup waits for the main radio, 300 to 5000 ms (default 1500) |

## Limits

- Senders keep one path for your key. Direct messages follow it to the radio that answered last,
  usually the main radio. Backups still get every message that comes by flood.
- After a takeover, senders keep their old path until a direct message to it fails.
- Messages you send from one radio don't show up on the others.
- A backup's wait has to fit inside the sender's acknowledgement timeout, about 3.5 s for a short
  message at SF7 / 62.5 kHz. With the main radio off, acknowledgements take about 2 s instead
  of under 1 s.

## Bench results

Two companions with the same key (an AB XIAO with an LR2021 and a Heltec V4 with an SX1262) and a
third companion sending, on 908 MHz, SF7 / 62.5 kHz.

| Test | Result |
|---|---|
| Both normal (2 flood messages) | 2 replies each; both consoles posted the alert |
| `takeover` sent to the Heltec's console | Heltec main; XIAO became a backup and said so |
| Main and backup on (5 flood messages) | 1 reply each, acknowledged in 0.6 s; backup held 5, dropped 5 |
| Main moved off frequency (3 flood messages) | backup replied, acknowledged in 2.1 s |
| Main back (2 flood messages) | 1 reply each, 0.6 s |
| Reboot both radios | roles kept |
| `takeover` on the other radio | roles swapped, 1 reply per message |
| Live mesh, 2 direct messages to a phone companion, one from each radio | both acknowledged in 0.9 s |
