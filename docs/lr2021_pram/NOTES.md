# LR2021 PRAM patch (level 2, type 3, ver 0x13) - reverse engineering notes

Disassembled with Ubuntu binutils-arc-linux-gnu (objdump), ARCv2 / ARC EM ISA.
Full listing: dis.txt (addresses = chip CPU view, patch at 0x101000).

## Layout
0x101000  magic 0x600DB002
0x101004  type/version 0x00031304 (type 3, version 0x13)
0x101008  entry: install            -> 0x10104C
0x10100C  entry: extension enable   -> 0x101018
0x101018-0x101876  code
0x101878  "INI\x02" init table; (0x8077F8, 0x14) zero-inits the patch's 5 RAM vars
0x1018B0  8-byte coefficient table (used by 0x101744)
0x1018C0  (end of image) RAM copy of the ROM's 460-entry JLI jump table

## Install (0x10104C)
- cold boot: ROM 0xB3A4(460) builds RAM JLI table, then ROM 0xBC88(idx, fn) x21
  swaps entries for patch functions; copies magic+version to 0x800FF8/0x800FFC
  (this is what the host reads back as "PRAM loaded").
- warm wake (retention): just points jli_base back at 0x1018C0.

## Hooks (JLI index -> patch fn -> what it does)
61  (0x3D) 0x10120C  radio-cmd dispatcher. Overrides 0x0200 SetRfFrequency,
                     0x029F SetOqpskParams, 0x024B GetFlrcPacketStatus,
                     0x029A GetZwavePacketStatus; else ROM 0x24E0.
                     Optional extension callback at [0x8077F8] if [0x800968]!=0.
389, 53, 246         re-run DC-DC config (0x1012D4) when RX-path flag
                     [0x800773] changes / state change / RF freq moves >= 10 MHz.
414, 417             clear / set bit 13 of DC-DC switcher reg 0xF20024 around ROM fns.
267, 268, 274, 275   RTToF: zero low 7 bits of PLL freq 0xF40144 while ranging
                     (pkt type 4), restore after. = removed rttof_truncate_pll_freq_step.
224 (0xE0)           RTToF: 0xF30B50 bits 24-26. = removed rttof_extended_stuck_second_request.
220 (0xDC)           reads 0xF30B74/78, converts via ROM 0x7E30 into result (likely RTToF RSSI fix).
69, 71, 72           BLE: 0xF30C14 low7=0x7C (improve_blocking), 0xF30C28[9:5]=30
                     (freq_drift), 0xF30814[21:19] (2 Mbps). = removed BLE workarounds.
276 + 0x024B         FLRC packet status gains a 24-bit field from 0xF30D3C (scaled).
450 + 0x029A         Z-Wave packet status reports channel of last packet (changelog v2.0.2).
0x029F override      OQPSK params: new length-check-bypass bit -> 0xF30830 bit 25 (changelog v2.0.2).
435, 439             OOK/RAW demod reconfig with coefficient table (purpose unclear).
390, 130             small tweaks (unclear).

## DC-DC config (0x1012D4) vs removed host workaround
- RX HF path: rise=15.
- DC-DC freq 4.3 MHz if ADC decimation==1 else 2.8 MHz (0x80004C = Hz*1.048576), same as old workaround.
- NEW: RF < 720 MHz -> rise=8; RF >= 720 MHz -> rise=13 and DC-DC freq halved.
- Only matters with DC-DC (SIMO) regulator. Chip default is LDO; RadioLib never enables DC-DC.

## Unit decoding (Semtech formulas)
PLL steps -> Hz: x*15625/2^14.  0x2D000000=720 MHz, 0xA00000=10 MHz, 0x39300000=915 MHz.
