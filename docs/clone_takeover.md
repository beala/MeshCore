# Several radios with one key

You can load the same private key onto more than one companion radio, for example a radio at home
and one you carry. All of them then show your messages. The problem starts when more than one is
switched on: a message that arrives by flood reaches each of them, and each sends its own reply
(the acknowledgement and the path back). The sender gets two replies and two different paths,
keeps whichever arrived last, and from then on sends its direct messages to that one radio only.

With this firmware, you pick one radio as the main radio. The others become backups: they still
show the messages they hear, but never answer them. Only the main radio sends ACKs and paths, so
"delivered" in the sender's app means the main radio has the message.

## The Radio console contact

Every radio with this firmware adds a contact called **Radio console** to the app's contact list.
It isn't a real node: messages to it never go on air. The radio runs what you send as a command,
and replies in the same chat. It also uses this chat to tell you things, like another radio with
your key being heard.

Send `help` to see the commands. Other radio commands work there too, such as `get flood.retry`.
Commands aren't case sensitive, so a capital letter added by your phone is fine.

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
| `clone` | Role, how often a backup stayed quiet, and when another radio was last heard |
| `clone off` | Answer as normal again |

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
