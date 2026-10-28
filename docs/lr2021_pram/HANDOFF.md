# Handoff: LR2021 ROM dump and AGC readout

Branch `lr2021-rom-dump` = `beala/ab_xiao_nrf52_lr2021` + the 3 PRAM commits from
`lr2021-pram-notes` (load Semtech PRAM patch at init, local PRAM addresses, RE notes).
Nothing below is implemented yet. The next session has the hardware plugged in.

## Goal
1. Read the LR2021's AGC gain step (G1..G13, + boost levels on G12/G13), ideally per
   received packet, for deployment diagnostics.
2. To get there (and to patch/add chip commands safely), dump and disassemble the chip ROM.

Target board: AB Xiao nRF52 LR2021. Build env for debugging:
`pio run -e AB_Xiao_nrf52_LR2021_companion_radio_usb` (or `_repeater`, which has the
serial CLI in `src/helpers/CommonCLI.cpp`). Radio class: `src/helpers/radiolib/CustomLR2021.h`.

## Read first
- `NOTES.md` (this folder): what the PRAM patch does, its hooks, memory layout.
- `dis.txt`: full ARCv2 disassembly of the patch (CPU addresses, patch at 0x101000).
  Made with `arc-linux-gnu-objdump` from Ubuntu `binutils-arc-linux-gnu`
  (`-b binary -m arc -M cpu=em --adjust-vma=...`, ARC EM / ARCv2).
- Semtech driver: github.com/Lora-net/usp tag v1.2.1, `smtc_rac_lib/radio_drivers/lr20xx_driver`.

## Facts established so far
- Host reads/writes chip memory with ReadRegMem32 (0x0106) / WriteRegMem32 (0x0104); RadioLib
  `RADIOLIB_LR2021_CMD_READ_REG_MEM_32`. `CustomLR2021::readWord()` already
  does a single-word read (24-bit address).
- Address views differ: PRAM is CPU 0x101000 but host 0x801000. RAM looks identical
  (host reads 0x800FF8/0x800FFC, which the patch writes at the same CPU addresses).
  So the ROM may be at host 0x000000, somewhere else, or not host-visible.
- Known ROM landmarks (CPU addresses, called from the patch): 0x24E0 (default radio-cmd
  dispatcher), 0xB3A4 (builds RAM JLI table, arg 460), 0xBC88 (swap JLI entry), 0x1101C,
  0x113B0, 0x7E30, 0x19B8, 0x58CC, 0x12478. ROM spans at least 0x0000..0x12500.
- After the patch is active, host 0x8018C0..0x801FF0 should hold the RAM copy of the
  ROM's 460-entry JLI table (some entries swapped for patch functions). Each entry points
  into ROM, so reading it gives ~440 ROM function addresses for free.
- AGC: `SetAgcGainManual` 0x021A forces a gain step (RadioLib `setGain(0..13)`, 0 = auto).
  No public "get AGC gain" command, except RTToF GetResults type 2 (ranging only).
  RSSI calibration tables are per gain step, so ROM's GetRssiInst (0x020B) must read the
  gain register: finding that code in the ROM gives the address.

## Plan
### Step 1 - probe whether the host can read ROM (Plan A)
Add a debug serial command (e.g. `romprobe` / `romdump <start> <words>`) on the repeater
CLI or a temporary hook in companion USB. Use ReadRegMem32 with multi-word reads (len byte
up to 32 words; reply is 4*len bytes, big-endian).
- Print the JLI table at host 0x8018C0 (460 words) first.
- Try candidate ROM bases: 0x000000, 0x100000-0x101000 offsets, 0x400000, 0xC00000... For each,
  read words at base+0x24E0 and base+0xB3A4 and check they decode as ARC function prologues
  (e.g. `enter_s`/`push_s blink`, 16-bit 0xC0F1 / 0xC2Ex patterns), and that addresses from
  the JLI table land on prologues.
- Note: SPI command may return an error status for unmapped addresses; log it, don't abort.
- If found: dump ~0x14000+ bytes as hex lines (`addr: w0 w1 ...`) over serial, user saves
  the log, convert with a small script to a .bin, disassemble with objdump as above.

### Step 2 - if not host-visible: make the chip copy it out (Plan B)
Use the patch's built-in extension hook (see NOTES.md, dispatcher at 0x10120C):
- For radio commands 0x02xx, the patched dispatcher first calls a function pointer stored
  at RAM 0x8077F8 if the word at 0x800968 != 0. Args: r0 = opcode low byte, r1, r2 (params),
  r3 = response struct (word +0 = response length, word +4 = response buffer pointer).
  Returning 255 means "not handled" -> falls through to normal handling. Other patch
  handlers return 2 (ok) or 3 (ok with response data), setting [r3+0] = byte count.
  Exact meaning of r1/r2 needs confirming (one is param length, one param pointer).
- Semtech's own enable entry (0x10100C -> 0x101018) sets 0x800968=1 and calls an init at
  CPU 0x102000 with r0=0x8077F8 (init stores its handler there). On warm wake the install
  routine re-calls 0x102000 if 0x800968!=0. 0x102000 is just past the patch's JLI table:
  Semtech planned an add-on blob there. We don't know which host command triggers 0x10100C.
- Plan: write a tiny ARC EM blob (handler at 0x102000 = host 0x802000) for a new opcode,
  e.g. 0x02F0 <addr24> <nwords>, that copies nwords from CPU addr into the response buffer.
  Upload with WriteRegMem32 after the PRAM load, then write 0x8077F8 = handler address and
  0x800968 = 1 from the host. Also make 0x102000 a valid init (store handler to *r0, return)
  in case warm wake re-calls it.
- First verify PRAM exists past 0x102000: write a pattern at host 0x802000, read back.
- Toolchain: ARC GCC (`arc-linux-gnu-gcc` or `arc-elf32-gcc`, `-mcpu=em`), or just
  hand-assemble with `arc-linux-gnu-as` and link at 0x102000. Response size limit unknown;
  start with 8 words per call.
- Worst case the radio hangs; a reset (re-init) clears PRAM. ROM can't be damaged.

### Step 3 - find the AGC gain register
Independent of the ROM dump (can run in parallel):
- In RX (LoRa, continuous), for gain in 1..13: `setGain(g)`, wait ~10 ms, dump
  0xF30000..0xF30FFF (also try 0xF20000 and 0xF40000 blocks), then diff the dumps.
  The field that tracks g is the gain step. Then `setGain(0)` and confirm it moves with
  signal strength (near/far transmitter or attenuator).
- Cross-check against ROM GetRssiInst (0x020B) once the ROM is disassembled.
- Then decide the readout: read right after RxDone before standby (simple, host-only), or
  add a PRAM hook that snapshots it at packet end (pattern: the patch's hook 276 +
  GetFlrcPacketStatus override adds a field to FLRC packet status the same way).

## Things on this branch to keep in mind
- `CustomLR2021::resetAGC()` does a warm sleep + wake + recalibrate. Per the notes, warm
  wake keeps PRAM (install just restores jli_base), but this is untested; check the
  "PRAM loaded" magic at 0x800FF8 after a resetAGC().
- `LR2021_USE_SIMO` switches to the DC-DC (SIMO) regulator. The PRAM patch's DC-DC config
  (rise time / switching freq by RF band) only matters in that mode, so it now applies on
  boards that set this flag.
- Keep ROM dumps out of public branches (Semtech copyright). Commit notes/findings only.
