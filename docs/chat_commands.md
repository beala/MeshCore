# Commands in a chat

On a companion with this firmware, a message that starts with `/` in a DM or a channel isn't sent.
The radio runs it as a command for that chat, and the reply shows up in the same chat, starting with
⚙ so it doesn't read as a message from the contact. The reply stays on your radio and phone; the
contact never sees the command or the reply.

Send `/help` in any chat to see what works there.

## In a DM

| Command | What it does |
|---|---|
| `/help` | List these commands |
| `/range` | Measure the distance to this contact (two LR2021 radios, 902-928 MHz). The answer shows in the chat a few seconds later |
| `/beep` | Make this contact's radio beep, if they've allowed you (`set find.allow`) |
| `/beep stop` | Stop it beeping |
| `/crypto` | Show the encryption used with this contact |
| `/crypto legacy`, `/crypto v2`, `/crypto v2only` | Change it |
| `/path` | Show the route to this contact: flood, direct, or the repeaters it goes through |
| `/path reset` | Forget the route, so the next message goes by flood and finds a new one |

## In a channel

| Command | What it does |
|---|---|
| `/help` | List these commands |
| `/crypto` | Show the encryption used on this channel |
| `/crypto legacy`, `/crypto v2`, `/crypto v2only` | Change it |

## Details

- Only a `/` followed by a letter is a command. To send text that starts with `/`, type `//`: the
  radio sends it with one `/`. A mistyped command gets "Unknown command" back and isn't sent.
- Commands aren't case sensitive, so a capital letter added by your phone is fine.
- Commands only run when you type them in your own app. A message starting with `/` that someone
  else sends you is shown as normal text.
- A DM command shows as delivered as soon as the radio has taken it.
- `/help` also works in the Radio console, which runs every other radio command (see
  [clone_takeover.md](clone_takeover.md)). Results of `find beep|stop|range <name>` typed in the
  console now show up in the console too.
- Anyone can name themselves "⚙ Radio" or start a message with ⚙. If a ⚙ reply surprises you, check it
  with the command again.

## Bench results

A RAK3401 + NiceRF companion sending to a Heltec V4 on 908 MHz:

| Test | Result |
|---|---|
| `/help`, `/Crypto`, `/crypto v2`, `/crypto legacy`, `/path`, `/path reset`, `/bogus` in a DM | right reply in the DM each time, marked delivered; the Heltec received nothing |
| `/path reset` | the app was told the path changed; `/path` then showed "No route" |
| `/beep`, `/beep stop`, `/range` | "Asked CloneH", then the Heltec's answer in the DM, once |
| `//hello slash` | sent; the Heltec received `/hello slash` |
| `/help`, `/crypto`, `/nope` in a channel | replies in the channel as "⚙ Radio: ..."; nothing sent |
| `find stop CloneH` in the Radio console | the answer showed in the console |
