# LR2021 dual-band scan: bench results (2026-10-29)

**Verdict: go.** Switching bands takes 1.2 ms, a full A+B scan cycle is 8.7 ms, and scanning
catches 97.5–100% of packets per band against 100% for a radio parked on one band.

## Setup

- Receiver (board under test): AB Labs WisBlock + NiceRF LoRa2021F33-2G4 (RAK3401),
  env `ab_labs_wisblock_nicerf_LoRa2021F33-2G4_dualband_bench`.
- Transmitter: AB Labs Xiao nRF52 + Wio-LR2021, env `AB_Xiao_nrf52_LR2021_dualband_bench`.
  It has one radio, so it alternates bands at random and never sends on both at once.
- Dummy loads on all antenna ports.

| | Band A | Band B |
|---|---|---|
| Frequency | 908.0 MHz (clear of MeshCore 910.525) | 2478.0 MHz (above Wi-Fi ch 11) |
| LoRa | BW 62.5 kHz, SF7, CR 4/5 | BW 203.125 kHz, SF8, CR 4/5 |
| TX power (xiao) | +20 dBm | +6 dBm |
| At receiver | −103 dBm, SNR 13.5 | −92 dBm, SNR 8.7 |
| Symbol / 32-symbol preamble | 2.05 ms / 65.5 ms | 1.26 ms / 40.3 ms |

Traffic: numbered packets of 10–160 bytes at random times, so they land on every point
of the scan cycle. The receiver's preamble setting always equals the transmitter's.

## Step 1: switch time (no transmitter, 1000 iterations)

All times are averages. A switch is standby + retune + CAD start.

| Variant | Switch | Notes |
|---|---|---|
| **Both bands pre-calibrated, same RX boost, standby XOSC** | **1.23 ms** | first switch the same: the chip keeps both calibrations |
| RX boost differs per band (RadioLib default LF 0 / HF 4) | 5.9 ms | SetRxPath costs 4.8 ms whenever the boost changes |
| Standby RC instead of XOSC | 2.28 ms | TCXO restart |
| Recalibrate on every switch (what RadioLib `setFrequency` does) | 10.9 ms | CalibFE 9.7 ms |

Breakdown of the 1.23 ms: each SPI command costs 160–190 µs (standby, SetRfFrequency,
SetRxPath, SetLoraModulationParams, SetLoraCadParams, ClearIrq + SetLoraCad).

| CAD duration (2 symbols) | Band A | Band B |
|---|---|---|
| Standard | 4.06 ms | 2.51 ms |
| Fast CAD (pnr_delta 8) | 2.13 ms | 1.37 ms |

False CAD detections on an idle channel: 0–0.4%.

## Steps 2–3: catch rate

"Fixed" means continuous RX on one band. "Scan" means the dual-band CAD loop.

| Case | A | B |
|---|---|---|
| Fixed, 32-symbol preamble | 1000/1000 = 100% | 500/500 = 100% (an earlier 1000-packet run: 94.9%, from interference) |
| Scan, traffic on one band only | 497/500 = 99.4% | 488/500 = 97.6% |
| Scan, both bands, low load (0.5–2 s gaps) | 199/204 = 97.5% | 195/196 = 99.5% |
| Scan, both bands, medium load (0.1–1 s gaps) | 286/286 = 100% | 309/314 = 98.4% |
| Scan, both bands, high load (0–0.2 s gaps) | 296/296 = 100% | 299/304 = 98.4% |

### Preamble margin sweep (band A, scan, 300 packets each)

| Preamble (symbols) | 24 | 16 | 12 | 10 | 8 | 8, fixed RX |
|---|---|---|---|---|---|---|
| Catch | 98.7% | 98.3% | 98.7% | 98.3% | 98.7% | 100% |

There's no drop-off point down to 8 symbols (16 ms, still almost two scan cycles). The
1–2% scan loss doesn't depend on the preamble length. It comes from:

- **False CAD hits.** A CAD detection with no packet behind it keeps the radio in RX for the
  48-symbol post-CAD timeout (98 ms on A, 60 ms on B), so a packet starting on the other band
  during that window is missed. Band B gets far more of these (138–209 per 10 min), probably
  from Wi-Fi and Bluetooth energy. Most misses classified as `cad_timeout` are this.
- A few header CRC errors (`rx_error`), most likely CAD firing late in the preamble.

### Frequency error

Received-packet frequency offset has the same spread while scanning as on fixed RX:
A sd 10–14 Hz, B sd 14–40 Hz. The mean drifts slowly with temperature (A −370 to −450 Hz,
B −890 to −1150 Hz). There's no sign of the PLL settling after a switch.

### Not measured

Truly simultaneous packets on both bands, because there's only one transmitter. With real
traffic, a packet on one band is lost when the radio is busy receiving on the other band
for the whole of its preamble, so the extra loss is roughly the other band's airtime
fraction (about 1–5% for a typical mesh).

## Problems found on the way (RadioLib @6d89348 and this setup)

1. `RADIOLIB_LR2021_CAD_EXIT_MODE_RX` is 0x02. The datasheet (Table 6-18) and the chip say
   CAD_RX = 0x01; RadioLib's `..._TX` (0x01) actually does RX.
2. `startChannelScan()` never calls SetRxPath, so a CAD at 2.4 GHz runs on the LF path.
3. `setOutputPower()` sends SetPaConfig before SetTxParams. Switching from sub-GHz at
   +20 dBm to the HF PA (max +12 dBm) is rejected with CMD_FAIL (−706). Fix: lower the
   power first.
4. `setFrequency()` recalibrates only CalibFE slot 1 on every ≥ 20 MHz jump (about 10 ms).
   The chip stores up to 3 calibrations, so calibrating both bands once is enough.
5. Default RX boost LF 0 / HF 4 adds 4.8 ms to every band switch. Use one value.
6. The LR2021 RX preamble length must match the TX preamble. RX 8 with TX 32 gives
   header CRC errors on almost every packet.
7. The CAD-RX timeout tick is 32.768 kHz (as RadioLib assumes), not 32 MHz as the
   datasheet text says.
8. Adafruit nRF52 core: `micros()` ticks at 1024 Hz until the DWT cycle counter is enabled,
   then becomes CYCCNT/64, which wraps every 67 s. RadioLib's `transmit()` timeout then fires
   spuriously and cuts packets short.
9. A cut-short packet leaves fewer bytes in the RX FIFO than its header length. Reading by
   header length then misaligns every later packet. Read by GetRxFifoLevel.
10. Wi-Fi channel 6 overlaps 2440 MHz. Long packets there failed CRC about 50% of the time.
11. Host side: USB serial output from these boards stops after about 2–3 s of silence, so
    the bench prints a heartbeat every second.

## Step 4 plan: firmware change

1. **`DualBandLR2021Wrapper`** (a new `RadioLibWrapper`), owning two band configs (freq, BW,
   SF, CR, preamble, TX power):
   - Init: one CalibFE with both frequencies; the same RX boost on both paths; fallback
     STBY_XOSC; CAD exit 0x01 (CAD_RX); IRQ on CAD_DONE | CAD_DETECTED | RX_DONE |
     TIMEOUT | CRC | HDR_ERR.
   - `loop()` / IRQ handling runs the scan state machine from this bench (`cmdScan`).
     Received packets carry the band they arrived on.
   - TX: `startSendRaw(bytes, len, band)` stops the scan, retunes without calibration,
     lowers the power, then sets the PA and power, transmits, and resumes the scan.
   - Per-band noise floor, AGC reset (re-run CalibFE for both bands), airtime and
     duty-cycle accounting.
2. **Cut false-CAD cost:** shorten the post-CAD RX timeout to preamble + about 8 symbols,
   or use StopTimeoutOnPreamble plus the PREAMBLE_DETECTED IRQ to bail out early; raise
   det_peak on 2.4 GHz; try fast CAD.
3. **`Dispatcher` / `Mesh`:** add a band field to `mesh::Packet`, set on receive.
   - Outbound direct packets go on the band the destination was last heard on.
   - Floods go on both bands (two sequential TXs); repeaters forward on both.
   - Duty-cycle and airtime budgets are kept per band.
   - Policy (which bands, cross-band forwarding) is a pref.
4. **Upstream:** RadioLib issues/PRs for items 1–5.

## Reproduce

```
pio run -e ab_labs_wisblock_nicerf_LoRa2021F33-2G4_dualband_bench -t upload   # receiver
pio run -e AB_Xiao_nrf52_LR2021_dualband_bench -t upload                      # transmitter
# receiver: bench 1000 0 | rx A | rx B | scan        transmitter: tx AB 600 100 1000 32 10 160
```
