// LR2021 dual-band scan bench.
//
// One firmware for both boards; the role is picked over serial (115200, line-based).
// The board under test (RX) runs everything time-critical on its own, so the
// transmitter only has to send numbered packets at random times.
//
// Commands (case-sensitive, one per line):
//   help                                  list commands and current config
//   band <A|B> <MHz> <bw kHz> <sf>        set a band's LoRa params (both boards must match)
//   pwr <A|B> <dBm>                       TX power per band (transmitter)
//   cad <nsym> <fast 0|1> <peak|0=auto>   CAD settings (receiver)
//   stby <rc|xosc>                        standby / fallback mode between operations
//   tunit <ns>                            CAD-RX timeout tick (30518 = 32.768 kHz, measured correct)
//   rxpre <n>                             preamble length configured on the receiver (match the TX)
//   rxpath <0|1>                          0: SetRxPath(path, boost)  1: SetRxPath(path) only
//   boost <lf> <hf>                       RX boost per path (different values cost ~4.8 ms/switch)
//   caltest                               measure the real CAD-RX timeout tick
//   bench <n> <cal 0|1>                   step 1: n x (A switch+CAD, B switch+CAD) timings
//   rx <A|B>                              step 2: continuous RX on one band
//   scan                                  step 3: dual-band CAD scan (CAD -> RX in hardware)
//   tx <A|B|AB> <count> <gapMin ms> <gapMax ms> <preamble> <lenMin> <lenMax>
//   x                                     stop the running rx/scan/tx and print a summary
//   hfpa / hfpwr / pdbg                   HF PA debug helpers (see handleLine)
//
// The receiver polls the IRQ pin in a tight loop rather than using an ISR: the loop does
// nothing else, so the latency is the same (~1 us) and no IRQ edge can be lost.
// Output lines are CSV with a leading tag so the logs are easy to parse:
//   T,...  packet sent         R,...  packet received     E,...  RX error
//   F,...  CAD hit with no packet (timeout)               S,...  periodic scan stats
//   B,...  bench result        #...   human-readable info

#include <Arduino.h>
#include <target.h>

extern RADIO_CLASS radio;  // CustomLR2021, defined in the variant's target.cpp

// RADIOLIB_GODMODE opens up LR2021 but not its LRxxxx base, so reach the few
// protected members we need through a derived view of the same object.
struct LRAccess : public CustomLR2021 {
  static LRAccess& of(CustomLR2021& r) { return static_cast<LRAccess&>(r); }
  using LRxxxx::bandwidth;
  using LRxxxx::codingRate;
  using LRxxxx::crcTypeLoRa;
  using LRxxxx::SPIcommand;
  using LRxxxx::highFreq;
};
static LRAccess& lr = LRAccess::of(radio);

// ---------------------------------------------------------------- config

struct Band {
  char name;
  float freq;    // MHz
  float bw;      // kHz
  uint8_t sf;
  int8_t txPower;
  // derived
  uint8_t bwCode;
  bool hf;
  uint32_t symUs;
  uint8_t peak;
  uint32_t cadTimeoutRaw;
};

static Band bands[2] = {
  // TX powers are for the bench setup (dummy loads on both boards): A gives ~-104 dBm / SNR 13,
  // B ~-92 dBm / SNR 9 at the receiver.
  { 'A', 908.0f, 62.5f, 7, 20 },     // clear of MeshCore US 910.525
  { 'B', 2478.0f, 203.125f, 8, 6 },  // above Wi-Fi ch 11; inside Wi-Fi ch 6 long packets got CRC errors
};

static uint8_t cadSym = 2;
static bool cadFast = false;
static uint8_t cadPeakOverride = 0;
static bool stbyXosc = true;
static uint32_t timeoutTickNs = 30518;  // 32.768 kHz (RadioLib's assumption); caltest checks it
static uint16_t rxPreamble = 32;  // must match the TX preamble (RX 8 vs TX 32 -> header CRC errors)
static const uint16_t CAD_RX_TIMEOUT_SYMBOLS = 48;  // 32-symbol preamble + sync + header, plus margin

// datasheet Table 6-18 (RadioLib's RADIOLIB_LR2021_CAD_EXIT_MODE_* values don't match it)
static const uint8_t CAD_EXIT_ONLY = 0x00;
static const uint8_t CAD_EXIT_RX = 0x01;

// datasheet Table 6-19, det_peak by symbol count (1..4) and SF (5..12)
static const uint8_t DET_PEAK[4][8] = {
  { 60, 60, 60, 64, 64, 66, 70, 74 },
  { 56, 56, 56, 58, 58, 60, 64, 68 },
  { 51, 51, 52, 54, 56, 60, 60, 65 },
  { 51, 51, 51, 54, 56, 60, 60, 64 },
};

static const uint8_t PKT_MAGIC = 0xDB;

// ---------------------------------------------------------------- helpers

// micros() on the Adafruit nRF52 core only ticks at 1024 Hz, so time with the
// 64 MHz DWT cycle counter instead, extended past its 67 s wrap.
// Caveat: once DWT is on, the core's micros() becomes CYCCNT/64, which jumps back to 0
// every 67 s, and RadioLib's transmit() timeout then fires spuriously. So DWT is only
// enabled while a receiver measurement runs (bench/rx/scan), never during tx.
static void usInit() {
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
static void usStop() { DWT->CTRL &= ~DWT_CTRL_CYCCNTENA_Msk; }
static uint32_t us() {
  static uint32_t last = 0;
  static uint64_t hi = 0;
  uint32_t c = DWT->CYCCNT;
  if (c < last) hi += 1ULL << 32;
  last = c;
  return (uint32_t)((hi | c) / 64);
}

static bool irqHigh() { return digitalRead(P_LORA_DIO_1) == HIGH; }

static bool check(int16_t st, const char* what) {
  if (st != RADIOLIB_ERR_NONE) {
    Serial.printf("# ERR %s -> %d\n", what, st);
    return false;
  }
  return true;
}

static uint8_t bwCodeFor(float bw) {
  // reuse RadioLib's table; this also sends the modulation params, which is harmless here
  radio.setBandwidth(bw);
  return lr.bandwidth;
}

static void deriveBand(Band& b) {
  b.bwCode = bwCodeFor(b.bw);
  b.hf = b.freq > RADIOLIB_LR2021_LF_CUTOFF_FREQ;
  b.symUs = (uint32_t)((float)(1UL << b.sf) * 1000.0f / b.bw + 0.5f);
  uint8_t n = cadSym < 1 ? 1 : (cadSym > 4 ? 4 : cadSym);
  b.peak = cadPeakOverride ? cadPeakOverride : DET_PEAK[n - 1][b.sf - 5];
  uint64_t tUs = (uint64_t)b.symUs * CAD_RX_TIMEOUT_SYMBOLS;
  b.cadTimeoutRaw = (uint32_t)(tUs * 1000ULL / timeoutTickNs);
  if (b.cadTimeoutRaw > 0xFFFFFF) b.cadTimeoutRaw = 0xFFFFFF;
}

static void deriveAll() {
  radio.standby();
  for (auto& b : bands) deriveBand(b);
}

static uint8_t ldroFor(const Band& b) { return b.symUs >= 16000 ? 1 : 0; }

static uint8_t stbyMode() { return stbyXosc ? RADIOLIB_LR2021_STANDBY_XOSC : RADIOLIB_LR2021_STANDBY_RC; }

static int16_t calibrateBoth() {
  uint16_t f[3] = {
    (uint16_t)((uint16_t)(bands[0].freq / 4.0f + 0.5f) | (bands[0].hf ? RADIOLIB_LR2021_CALIBRATE_FE_HF_PATH : RADIOLIB_LR2021_CALIBRATE_FE_LF_PATH)),
    (uint16_t)((uint16_t)(bands[1].freq / 4.0f + 0.5f) | (bands[1].hf ? RADIOLIB_LR2021_CALIBRATE_FE_HF_PATH : RADIOLIB_LR2021_CALIBRATE_FE_LF_PATH)),
    0,
  };
  return radio.calibrateFrontEnd(f);
}

static int16_t calibrateOne(const Band& b) {
  uint16_t f[3] = {
    (uint16_t)((uint16_t)(b.freq / 4.0f + 0.5f) | (b.hf ? RADIOLIB_LR2021_CALIBRATE_FE_HF_PATH : RADIOLIB_LR2021_CALIBRATE_FE_LF_PATH)),
    0, 0,
  };
  return radio.calibrateFrontEnd(f);
}

// rxPathMode 0: SetRxPath(path, boost); 1: SetRxPath(path) only (boost byte is optional)
static uint8_t rxPathMode = 0;
static int16_t setPath(const Band& b) {
  uint8_t buff[2] = { (uint8_t)(b.hf ? RADIOLIB_LR2021_RX_PATH_HF : RADIOLIB_LR2021_RX_PATH_LF),
                      (uint8_t)(b.hf ? radio.gainModeHf : radio.gainModeLf) };
  return lr.SPIcommand(RADIOLIB_LR2021_CMD_SET_RX_PATH, true, buff, rxPathMode == 1 ? 1 : 2);
}

// Retune for RX/CAD on band b. Chip must be in standby. No calibration.
// If sub is given, it gets the time of each of the 4 commands.
static int16_t tuneRx(const Band& b, uint8_t exitMode, uint32_t* sub = nullptr) {
  uint32_t t0 = us();
  int16_t st = radio.setRfFrequency((uint32_t)(b.freq * 1000000.0f));
  if (st) return st;
  uint32_t t1 = us();
  st = setPath(b);
  if (st) return st;
  uint32_t t2 = us();
  st = radio.setLoRaModulationParams(b.sf, b.bwCode, lr.codingRate, ldroFor(b));
  if (st) return st;
  uint32_t t3 = us();
  st = radio.setLoRaCadParams(cadSym, false,
                              cadFast ? RADIOLIB_LR2021_LORA_CAD_PNR_DELTA_FAST : RADIOLIB_LR2021_LORA_CAD_PNR_DELTA_STANDARD,
                              exitMode, b.cadTimeoutRaw, b.peak);
  if (sub) {
    uint32_t t4 = us();
    sub[0] = t1 - t0; sub[1] = t2 - t1; sub[2] = t3 - t2; sub[3] = t4 - t3;
  }
  return st;
}

static int16_t startCad() {
  int16_t st = radio.clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
  if (st) return st;
  return radio.setLoRaCad();
}

static const uint32_t RX_IRQS = RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_TIMEOUT |
                                RADIOLIB_LR2021_IRQ_CRC_ERROR | RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR |
                                RADIOLIB_LR2021_IRQ_LEN_ERROR;
static const uint32_t CAD_IRQS = RADIOLIB_LR2021_IRQ_CAD_DONE | RADIOLIB_LR2021_IRQ_CAD_DETECTED;

static int16_t prepRx() {
  int16_t st = radio.standby(stbyMode());
  if (st) return st;
  st = radio.setRxTxFallbackMode(stbyXosc ? RADIOLIB_LR2021_FALLBACK_MODE_STBY_XOSC : RADIOLIB_LR2021_FALLBACK_MODE_STBY_RC);
  if (st) return st;
  st = radio.setDioIrqConfig(radio.irqDioNum, RX_IRQS | CAD_IRQS);
  if (st) return st;
  // explicit header, max length, CRC on, normal IQ
  st = radio.setLoRaPacketParams(rxPreamble, RADIOLIB_LRXXXX_LORA_HEADER_EXPLICIT, 255, lr.crcTypeLoRa, 0);
  if (st) return st;
  return calibrateBoth();
}

static uint32_t staleBytes = 0;  // bytes found ahead of a packet in the RX FIFO

struct RxPkt {
  uint16_t fifoLevel, shortBy;
  uint8_t len;
  float rssi, snr;
  int32_t foff;
  uint8_t buf[256];
  bool crcErr, hdrErr;
};

static int16_t readPacket(RxPkt& p, uint32_t irq) {
  uint8_t s[9] = { 0 };
  int16_t st = lr.SPIcommand(RADIOLIB_LR2021_CMD_GET_LORA_PACKET_STATUS, false, s, sizeof(s));
  if (st) return st;
  p.len = s[1];
  p.snr = (float)((int8_t)s[2]) / 4.0f;
  uint16_t raw = ((uint16_t)s[3] << 1) | ((s[5] & 0x02) >> 1);
  p.rssi = (float)raw / -2.0f;
  int32_t fo = ((int32_t)s[6] << 16) | ((int32_t)s[7] << 8) | s[8];
  if (fo & 0x800000) fo -= 0x1000000;
  p.foff = fo;
  p.crcErr = irq & RADIOLIB_LR2021_IRQ_CRC_ERROR;
  p.hdrErr = irq & RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR;
  uint16_t len = 0;
  st = radio.getRxPktLength(&len);
  if (st) return st;
  if (len > 255) len = 255;
  // Read by FIFO level, not just the header length: after a truncated packet (CRC error)
  // the FIFO held fewer bytes than len, a len-byte read ate into the next packet, and
  // every payload after that was misaligned. The packet is the last `len` bytes.
  uint16_t level = 0;
  st = radio.getRxFifoLevel(&level);
  if (st) return st;
  p.fifoLevel = level;
  uint16_t skip = level > len ? level - len : 0;
  staleBytes += skip;
  while (skip) {
    uint8_t junk[64];
    uint16_t n = skip > sizeof(junk) ? sizeof(junk) : skip;
    st = radio.readRadioRxFifo(junk, n);
    if (st) return st;
    skip -= n;
  }
  uint16_t avail = level < len ? level : len;
  p.len = avail;
  p.shortBy = len - avail;
  if (avail) {
    st = radio.readRadioRxFifo(p.buf, avail);
    if (st) return st;
  }
  return radio.clearRxFifo();
}

// ---------------------------------------------------------------- stats

struct Stat {
  uint32_t n = 0, mn = UINT32_MAX, mx = 0;
  uint64_t sum = 0;
  void add(uint32_t v) { n++; sum += v; if (v < mn) mn = v; if (v > mx) mx = v; }
  void print(const char* label) const {
    if (!n) { Serial.printf("B,%s,0,,,\n", label); return; }
    Serial.printf("B,%s,%lu,%lu,%lu,%lu\n", label, (unsigned long)n, (unsigned long)mn,
                  (unsigned long)(sum / n), (unsigned long)mx);
  }
};

struct SeqSet {
  uint8_t bits[512];  // seq 0..4095
  uint32_t uniq, dups;
  void clear() { memset(bits, 0, sizeof(bits)); uniq = dups = 0; }
  void add(uint16_t s) {
    s &= 4095;
    if (bits[s >> 3] & (1 << (s & 7))) { dups++; return; }
    bits[s >> 3] |= 1 << (s & 7);
    uniq++;
  }
};

struct RxCounters {
  SeqSet seq[2];
  uint32_t cad[2], det[2], rx[2], fto[2], crc[2], hdr[2], foreign[2], wrongBand[2];
  Stat cadUs[2], switchUs[2];
  void clear() {
    for (int i = 0; i < 2; i++) {
      seq[i].clear();
      cad[i] = det[i] = rx[i] = fto[i] = crc[i] = hdr[i] = foreign[i] = wrongBand[i] = 0;
      cadUs[i] = Stat(); switchUs[i] = Stat();
    }
  }
};
static RxCounters rc;

static void printRxSummary(uint32_t elapsedMs) {
  Serial.printf("# summary after %lu ms, stale RX FIFO bytes %lu\n", (unsigned long)elapsedMs, (unsigned long)staleBytes);
  Serial.println("#,band,uniq,dups,rx,crc,hdr,foreign,wrongband,cad,cad_det,cad_no_pkt");
  for (int i = 0; i < 2; i++) {
    Serial.printf("SUM,%c,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", bands[i].name,
                  (unsigned long)rc.seq[i].uniq, (unsigned long)rc.seq[i].dups, (unsigned long)rc.rx[i],
                  (unsigned long)rc.crc[i], (unsigned long)rc.hdr[i], (unsigned long)rc.foreign[i],
                  (unsigned long)rc.wrongBand[i], (unsigned long)rc.cad[i], (unsigned long)rc.det[i],
                  (unsigned long)rc.fto[i]);
  }
  for (int i = 0; i < 2; i++) {
    char l[24];
    snprintf(l, sizeof(l), "cad_us_%c", bands[i].name); rc.cadUs[i].print(l);
    snprintf(l, sizeof(l), "switch_us_%c", bands[i].name); rc.switchUs[i].print(l);
  }
}

static bool stopRequested() {
  while (Serial.available()) {
    int c = Serial.read();
    if (c == 'x' || c == 'X') return true;
  }
  return false;
}

static void logPacket(int bandIdx, const RxPkt& p, uint32_t tUs, uint32_t sinceSwitchUs) {
  if (p.crcErr || p.hdrErr) {
    if (p.crcErr) rc.crc[bandIdx]++;
    if (p.hdrErr) rc.hdr[bandIdx]++;
    // E,t_ms,band,kind,len,rssi,snr,foff,bytes_missing_from_fifo
    Serial.printf("E,%lu,%c,%s,%u,%.1f,%.2f,%ld,%u\n", (unsigned long)(tUs / 1000), bands[bandIdx].name,
                  p.hdrErr ? "hdr" : "crc", p.len, p.rssi, p.snr, (long)p.foff, p.shortBy);
    return;
  }
  if (p.len < 6 || p.buf[0] != PKT_MAGIC) {
    rc.foreign[bandIdx]++;
    Serial.printf("E,%lu,%c,foreign,%u,%.1f,%.2f,%ld\n", (unsigned long)(tUs / 1000), bands[bandIdx].name,
                  p.len, p.rssi, p.snr, (long)p.foff);
    return;
  }
  uint8_t txBand = p.buf[1];
  uint16_t seq = p.buf[2] | (p.buf[3] << 8);
  uint8_t pre = p.buf[4];
  rc.rx[bandIdx]++;
  if (txBand != bandIdx) rc.wrongBand[bandIdx]++;
  rc.seq[txBand & 1].add(seq);
  // R,t_ms,rx_band,seq,tx_band,len,preamble,rssi,snr,freq_off_hz,us_since_switch
  Serial.printf("R,%lu,%c,%u,%c,%u,%u,%.1f,%.2f,%ld,%lu\n", (unsigned long)(tUs / 1000), bands[bandIdx].name,
                seq, bands[txBand & 1].name, p.len, pre, p.rssi, p.snr, (long)p.foff,
                (unsigned long)sinceSwitchUs);
}

// ---------------------------------------------------------------- step 1: switch bench

static void cmdBench(int n, bool calEach) {
  Serial.printf("# bench n=%d cal_each=%d stby=%s cad_sym=%u fast=%d\n", n, calEach, stbyXosc ? "xosc" : "rc",
                cadSym, cadFast);
  if (!check(prepRx(), "prepRx")) return;

  Stat stby[2], tune[2], cadStart[2], cad[2], sw[2], first[2], cal[2];
  Stat sub[2][4];
  uint32_t dets[2] = { 0, 0 }, timeouts = 0;
  uint32_t t_all = millis(), tProg = millis();

  for (int it = 0; it < n; it++) {
    for (int bi = 0; bi < 2; bi++) {
      const Band& b = bands[bi];
      uint32_t t0 = us();
      radio.standby(stbyMode());
      uint32_t t1 = us();
      if (calEach) calibrateOne(b);
      uint32_t t1c = us();
      uint32_t subUs[4] = { 0 };
      int16_t st = tuneRx(b, CAD_EXIT_ONLY, subUs);
      uint32_t t2 = us();
      st |= startCad();
      uint32_t t3 = us();
      if (st) { Serial.printf("# ERR it=%d band=%c st=%d\n", it, b.name, st); radio.standby(); return; }
      uint32_t deadline = t3 + 200000;
      // IRQ pin is polled (a tight loop gives ~1 us resolution, same as an ISR timestamp)
      while (!irqHigh() && (int32_t)(us() - deadline) < 0) {}
      uint32_t t4 = us();
      if (!irqHigh()) { timeouts++; continue; }
      uint32_t irq = radio.getIrqStatus();
      if (irq & RADIOLIB_LR2021_IRQ_CAD_DETECTED) dets[bi]++;

      if (it == 0) first[bi].add(t3 - t0);
      else {
        stby[bi].add(t1 - t0);
        if (calEach) cal[bi].add(t1c - t1);
        for (int k = 0; k < 4; k++) sub[bi][k].add(subUs[k]);
        tune[bi].add(t2 - t1);
        cadStart[bi].add(t3 - t2);
        sw[bi].add(t3 - t0);
      }
      cad[bi].add(t4 - t3);
    }
    // USB serial output gets lost after a few seconds of silence, so keep talking
    if (millis() - tProg >= 1000) { tProg = millis(); Serial.printf("# it=%d\n", it + 1); }
    if ((it & 63) == 0 && stopRequested()) break;
  }
  radio.standby();

  Serial.println("#,metric,n,min_us,avg_us,max_us");
  for (int bi = 0; bi < 2; bi++) {
    char l[32];
    char c = bands[bi].name;
    snprintf(l, sizeof(l), "first_switch_%c", c); first[bi].print(l);
    snprintf(l, sizeof(l), "standby_%c", c); stby[bi].print(l);
    if (calEach) { snprintf(l, sizeof(l), "calib_fe_%c", c); cal[bi].print(l); }
    static const char* subName[4] = { "set_rf_freq", "set_rx_path", "set_mod_params", "set_cad_params" };
    for (int k = 0; k < 4; k++) { snprintf(l, sizeof(l), "%s_%c", subName[k], c); sub[bi][k].print(l); }
    snprintf(l, sizeof(l), "tune_%c", c); tune[bi].print(l);
    snprintf(l, sizeof(l), "cad_start_%c", c); cadStart[bi].print(l);
    snprintf(l, sizeof(l), "switch_total_%c", c); sw[bi].print(l);
    snprintf(l, sizeof(l), "cad_%c", c); cad[bi].print(l);
  }
  Serial.printf("# cad detections (idle channel => false alarms): A=%lu B=%lu, irq timeouts=%lu, %lu ms total\n",
                (unsigned long)dets[0], (unsigned long)dets[1], (unsigned long)timeouts,
                (unsigned long)(millis() - t_all));
}

// Measure the CAD-RX timeout tick: force a CAD hit with det_peak=1 and time CAD start -> TIMEOUT.
static void cmdCalTest() {
  if (!check(prepRx(), "prepRx")) return;
  const Band& b = bands[0];
  const uint32_t raw = 3277;  // 100 ms if the tick is 32.768 kHz, ~102 us if 32 MHz
  radio.setRfFrequency((uint32_t)(b.freq * 1000000.0f));
  setPath(b);
  radio.setLoRaModulationParams(b.sf, b.bwCode, lr.codingRate, ldroFor(b));
  for (int i = 0; i < 3; i++) {
    radio.setLoRaCadParams(cadSym, false, RADIOLIB_LR2021_LORA_CAD_PNR_DELTA_STANDARD, CAD_EXIT_RX, raw, 1);
    startCad();
    uint32_t t0 = us();
    uint32_t tCad = 0, tEnd = 0, irqAll = 0;
    while ((us() - t0) < 2000000) {
      if (irqHigh()) {
        uint32_t irq = radio.getIrqStatus();
        irqAll |= irq;
        radio.clearIrqState(irq);
        if ((irq & RADIOLIB_LR2021_IRQ_CAD_DONE) && !tCad) tCad = us() - t0;
        if (irq & (RADIOLIB_LR2021_IRQ_TIMEOUT | RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR)) {
          tEnd = us() - t0;
          break;
        }
      }
    }
    radio.standby();
    Serial.printf("# caltest raw=%lu: cad_done@%lu us, end@%lu us, irq=0x%08lX (det=%d timeout=%d)\n",
                  (unsigned long)raw, (unsigned long)tCad, (unsigned long)tEnd, (unsigned long)irqAll,
                  !!(irqAll & RADIOLIB_LR2021_IRQ_CAD_DETECTED), !!(irqAll & RADIOLIB_LR2021_IRQ_TIMEOUT));
  }
  Serial.println("# ~100000 us after CAD => 32.768 kHz tick (tunit 30518); ~100 us => 32 MHz (tunit 31)");
}

// ---------------------------------------------------------------- step 2: fixed-band RX

static void cmdRx(int bi) {
  const Band& b = bands[bi];
  Serial.printf("# rx band %c %.3f MHz bw %.3f sf %u rxpre %u\n", b.name, b.freq, b.bw, b.sf, rxPreamble);
  if (!check(prepRx(), "prepRx")) return;
  rc.clear();
  staleBytes = 0;
  if (!check(tuneRx(b, CAD_EXIT_ONLY), "tune")) return;
  radio.clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
  if (!check(radio.setRx(RADIOLIB_LR2021_RX_TIMEOUT_INF), "setRx")) return;
  uint32_t tStart = millis(), tBeat = millis();
  static RxPkt p;
  while (true) {
    if (irqHigh()) {
      uint32_t tUs = us();
      uint32_t irq = radio.getIrqStatus();
      radio.clearIrqState(irq);
      if (irq & (RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_CRC_ERROR | RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR)) {
        // continuous RX let the FIFO drift out of step after a while (every payload then
        // looked foreign), so restart RX from standby with an empty FIFO after each packet
        radio.standby(stbyMode());
        readPacket(p, irq);
        radio.clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
        radio.setRx(RADIOLIB_LR2021_RX_TIMEOUT_INF);
        logPacket(bi, p, tUs, 0);
      }
    }
    if (millis() - tBeat >= 1000) { tBeat = millis(); Serial.printf("H,%lu\n", (unsigned long)tBeat); }
    if (stopRequested()) break;
  }
  radio.standby();
  printRxSummary(millis() - tStart);
}

// ---------------------------------------------------------------- step 3: dual-band scan

static void cmdScan() {
  Serial.printf("# scan A=%.3f/%.3f/sf%u B=%.3f/%.3f/sf%u cad_sym=%u fast=%d stby=%s rxpre=%u\n",
                bands[0].freq, bands[0].bw, bands[0].sf, bands[1].freq, bands[1].bw, bands[1].sf,
                cadSym, cadFast, stbyXosc ? "xosc" : "rc", rxPreamble);
  for (int i = 0; i < 2; i++)
    Serial.printf("# band %c sym=%lu us, peak=%u, cad_rx_timeout raw=%lu\n", bands[i].name,
                  (unsigned long)bands[i].symUs, bands[i].peak, (unsigned long)bands[i].cadTimeoutRaw);
  if (!check(prepRx(), "prepRx")) return;
  rc.clear();
  staleBytes = 0;

  enum { S_CAD, S_RX } state = S_CAD;
  int cur = 0;
  uint32_t tSwitch = 0, tCadStart = 0, tState = 0;
  uint32_t tStart = millis(), tLastStat = millis();
  static RxPkt p;

  // A stuck BUSY line used to stall the scan for RadioLib's 1 s SPI timeout plus the 3 s
  // watchdog. Catch it in 20 ms instead, log what the chip was doing, and re-arm at once.
  Module* mod = radio.getMod();
  uint32_t savedSpiTimeout = mod->spiConfig.timeout;
  mod->spiConfig.timeout = 20;
  uint32_t recoveries = 0, recoveryUs = 0;

  auto beginCad = [&](int bi) {
    cur = bi;
    tSwitch = us();
    int16_t st = tuneRx(bands[bi], CAD_EXIT_RX);
    if (st == RADIOLIB_ERR_NONE) st = startCad();
    if (st != RADIOLIB_ERR_NONE) {
      uint32_t tFail = us();
      bool busy = digitalRead(P_LORA_BUSY);
      while (digitalRead(P_LORA_BUSY) && us() - tFail < 2000000) {}
      uint32_t busyFor = us() - tFail;
      uint32_t irq = radio.getIrqStatus();
      radio.standby(stbyMode());
      st = tuneRx(bands[bi], CAD_EXIT_RX);
      if (st == RADIOLIB_ERR_NONE) st = startCad();
      recoveries++;
      recoveryUs += us() - tSwitch;
      Serial.printf("# RECOVER %c at %lu ms: busy=%d for %lu us more, irq=0x%08lX, retry st=%d, lost %lu us\n",
                    bands[bi].name, (unsigned long)(tSwitch / 1000), busy, (unsigned long)busyFor,
                    (unsigned long)irq, st, (unsigned long)(us() - tSwitch));
    }
    tCadStart = us();
    tState = tCadStart;
    rc.switchUs[bi].add(tCadStart - tSwitch);
    rc.cad[bi]++;
    state = S_CAD;
  };

  beginCad(0);
  while (true) {
    if (irqHigh()) {
      uint32_t tIrq = us();
      uint32_t irq = radio.getIrqStatus();
      radio.clearIrqState(irq);
      if (state == S_CAD && (irq & RADIOLIB_LR2021_IRQ_CAD_DONE)) {
        rc.cadUs[cur].add(tIrq - tCadStart);
        if (irq & RADIOLIB_LR2021_IRQ_CAD_DETECTED) {
          rc.det[cur]++;
          state = S_RX;  // chip went to RX by itself (CAD_RX exit mode)
          tState = us();
          if (!(irq & RX_IRQS)) continue;
        } else {
          beginCad(cur ^ 1);
          continue;
        }
      }
      if (state == S_RX) {
        if (irq & (RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_CRC_ERROR | RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR | RADIOLIB_LR2021_IRQ_LEN_ERROR)) {
          int done = cur;
          uint32_t since = tIrq - tSwitch;
          readPacket(p, irq);
          beginCad(done ^ 1);  // re-arm first, log after
          logPacket(done, p, tIrq, since);
        } else if (irq & RADIOLIB_LR2021_IRQ_TIMEOUT) {
          int done = cur;
          rc.fto[done]++;
          beginCad(done ^ 1);
          Serial.printf("F,%lu,%c\n", (unsigned long)(tIrq / 1000), bands[done].name);
        }  // else: header valid etc.; keep waiting
      }
    }

    // watchdog: nothing should take longer than this
    if ((us() - tState) > 3000000UL) {
      Serial.printf("# WDT state=%d band=%c irq=0x%08lX\n", state, bands[cur].name, (unsigned long)radio.getIrqStatus());
      radio.standby(stbyMode());
      beginCad(cur ^ 1);
    }

    if (millis() - tLastStat >= 1000) {
      tLastStat = millis();
      // S,t_ms,cadA,cadB,detA,detB,rxA,rxB,ftoA,ftoB,avg_cadA_us,avg_cadB_us,avg_switchA_us,avg_switchB_us
      Serial.printf("S,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", (unsigned long)tLastStat,
                    (unsigned long)rc.cad[0], (unsigned long)rc.cad[1], (unsigned long)rc.det[0], (unsigned long)rc.det[1],
                    (unsigned long)rc.rx[0], (unsigned long)rc.rx[1], (unsigned long)rc.fto[0], (unsigned long)rc.fto[1],
                    (unsigned long)(rc.cadUs[0].n ? rc.cadUs[0].sum / rc.cadUs[0].n : 0),
                    (unsigned long)(rc.cadUs[1].n ? rc.cadUs[1].sum / rc.cadUs[1].n : 0),
                    (unsigned long)(rc.switchUs[0].n ? rc.switchUs[0].sum / rc.switchUs[0].n : 0),
                    (unsigned long)(rc.switchUs[1].n ? rc.switchUs[1].sum / rc.switchUs[1].n : 0));
      if (stopRequested()) break;
    }
  }
  radio.standby();
  mod->spiConfig.timeout = savedSpiTimeout;
  printRxSummary(millis() - tStart);
  Serial.printf("# scan recoveries %lu, %lu us lost\n", (unsigned long)recoveries, (unsigned long)recoveryUs);
}

// ---------------------------------------------------------------- transmitter

static int curTxBand = -1;
static uint16_t curTxPre = 0;

static bool txStep(int16_t st, const char* what) {
  if (st == RADIOLIB_ERR_NONE) return true;
  uint16_t err = 0;
  radio.getChipErrors(&err);
  Serial.printf("# ERR %s -> %d, chip errors 0x%04X\n", what, st, err);
  radio.clearChipErrors();
  return false;
}

// SetPaConfig is rejected (CMD_FAIL) while the stored TX power is out of range for the
// new PA, e.g. +20 dBm left over from sub-GHz when switching to the HF PA (max +12 dBm).
// RadioLib's setOutputPower() sends SetPaConfig before SetTxParams, so drop the power first.
static uint32_t paRetries = 0;
static int16_t setPowerRetry(int8_t p) {
  radio.setTxParams(0, 0);
  int16_t st = radio.setOutputPower(p);
  if (st != RADIOLIB_ERR_NONE) {
    paRetries++;
    st = radio.setOutputPower(p);
  }
  return st;
}

static bool txSetBand(int bi, uint16_t pre) {
  if (bi == curTxBand && pre == curTxPre) return true;
  const Band& b = bands[bi];
  radio.standby();
  // skip the RX front-end calibration: TX doesn't use it, and after a 908 -> 2440 jump it
  // made the following SetPaConfig fail
  bool ok = txStep(radio.setFrequency(b.freq, true), "setFrequency")
         && txStep(setPowerRetry(b.txPower), "setOutputPower")
         && txStep(radio.setBandwidth(b.bw), "setBandwidth")
         && txStep(radio.setSpreadingFactor(b.sf), "setSF")
         && txStep(radio.setPreambleLength(pre), "setPreamble");
  curTxBand = ok ? bi : -1;
  curTxPre = pre;
  return ok;
}

static void cmdTx(const char* which, int count, int gapMin, int gapMax, int pre, int lenMin, int lenMax) {
  if (lenMin < 6) lenMin = 6;
  if (lenMax > 255) lenMax = 255;
  if (lenMax < lenMin) lenMax = lenMin;
  if (gapMax < gapMin) gapMax = gapMin;
  bool useA = strchr(which, 'A'), useB = strchr(which, 'B');
  if (!useA && !useB) { Serial.println("# ERR bands"); return; }
  Serial.printf("# tx %s count=%d gap=%d..%d ms pre=%d len=%d..%d pwrA=%d pwrB=%d\n", which, count, gapMin, gapMax,
                pre, lenMin, lenMax, bands[0].txPower, bands[1].txPower);
  curTxBand = -1;
  static uint8_t buf[256];
  uint32_t sent[2] = { 0, 0 }, fail = 0;
  uint32_t tStart = millis(), tBeat = millis();
  for (int seq = 0; seq < count; seq++) {
    int bi = (useA && useB) ? (int)random(2) : (useA ? 0 : 1);
    if (!txSetBand(bi, pre)) { fail++; continue; }
    int len = random(lenMin, lenMax + 1);
    buf[0] = PKT_MAGIC; buf[1] = bi; buf[2] = seq & 0xFF; buf[3] = seq >> 8; buf[4] = pre; buf[5] = len;
    for (int i = 6; i < len; i++) buf[i] = (uint8_t)(seq + i);
    uint32_t t0 = millis();
    // not radio.transmit(): its timeout uses micros(), which on this core wraps every
    // 67 s when the DWT cycle counter is on, cutting packets short
    int16_t st = radio.startTransmit(buf, len);
    if (st == RADIOLIB_ERR_NONE) {
      uint32_t limit = radio.getTimeOnAir(len) / 1000 * 2 + 200;
      while (digitalRead(P_LORA_DIO_1) == LOW && millis() - t0 < limit) {}
      st = digitalRead(P_LORA_DIO_1) == HIGH ? radio.finishTransmit() : RADIOLIB_ERR_TX_TIMEOUT;
      if (st != RADIOLIB_ERR_NONE) radio.finishTransmit();
    }
    uint32_t t1 = millis();
    if (st == RADIOLIB_ERR_NONE) sent[bi]++; else fail++;
    // T,t_ms,seq,band,len,preamble,airtime_ms,status
    Serial.printf("T,%lu,%d,%c,%d,%d,%lu,%d\n", (unsigned long)t0, seq, bands[bi].name, len, pre,
                  (unsigned long)(t1 - t0), st);
    tBeat = millis();
    uint32_t gap = random(gapMin, gapMax + 1);
    uint32_t tEnd = millis() + gap;
    while ((int32_t)(millis() - tEnd) < 0) {
      if (stopRequested()) { count = 0; break; }
      // USB serial output is lost after ~2-3 s of silence, so keep talking during long gaps
      if (millis() - tBeat >= 1000) { tBeat = millis(); Serial.printf("H,%lu\n", (unsigned long)tBeat); }
    }
  }
  radio.standby();
  Serial.printf("# tx done: sentA=%lu sentB=%lu fail=%lu in %lu ms (PA config retries %lu)\n", (unsigned long)sent[0],
                (unsigned long)sent[1], (unsigned long)fail, (unsigned long)(millis() - tStart), (unsigned long)paRetries);
}

// ---------------------------------------------------------------- command line

static void printConfig() {
  for (auto& b : bands)
    Serial.printf("# band %c: %.3f MHz bw %.3f sf %u pwr %d dBm | sym %lu us, peak %u, hf=%d\n", b.name, b.freq,
                  b.bw, b.sf, b.txPower, (unsigned long)b.symUs, b.peak, b.hf);
  Serial.printf("# cad sym=%u fast=%d peak_override=%u stby=%s tunit=%lu ns rxpre=%u rxpath_mode=%u boost=%u/%u\n",
                cadSym, cadFast, cadPeakOverride, stbyXosc ? "xosc" : "rc", (unsigned long)timeoutTickNs, rxPreamble,
                rxPathMode, radio.gainModeLf, radio.gainModeHf);
}

static int bandIdx(const char* s) { return (s && (s[0] == 'B' || s[0] == 'b')) ? 1 : 0; }

static void handleLine(char* line) {
  char* argv[10];
  int argc = 0;
  for (char* tok = strtok(line, " \t"); tok && argc < 10; tok = strtok(NULL, " \t")) argv[argc++] = tok;
  if (!argc) return;
  const char* c = argv[0];

  if (!strcmp(c, "help")) {
    Serial.println("# band <A|B> <MHz> <bw> <sf> | pwr <A|B> <dBm> | cad <nsym> <fast> <peak|0> | stby <rc|xosc>");
    Serial.println("# tunit <ns> | rxpre <n> | caltest | bench <n> <cal> | rx <A|B> | scan");
    Serial.println("# tx <A|B|AB> <count> <gapMin> <gapMax> <pre> <lenMin> <lenMax> | x = stop");
    printConfig();
  } else if (!strcmp(c, "band") && argc >= 5) {
    Band& b = bands[bandIdx(argv[1])];
    b.freq = atof(argv[2]); b.bw = atof(argv[3]); b.sf = atoi(argv[4]);
    deriveAll(); curTxBand = -1; printConfig();
  } else if (!strcmp(c, "pwr") && argc >= 3) {
    bands[bandIdx(argv[1])].txPower = atoi(argv[2]); curTxBand = -1; printConfig();
  } else if (!strcmp(c, "cad") && argc >= 4) {
    cadSym = atoi(argv[1]); cadFast = atoi(argv[2]); cadPeakOverride = atoi(argv[3]);
    deriveAll(); printConfig();
  } else if (!strcmp(c, "stby") && argc >= 2) {
    stbyXosc = !strcmp(argv[1], "xosc"); printConfig();
  } else if (!strcmp(c, "tunit") && argc >= 2) {
    timeoutTickNs = atol(argv[1]); deriveAll(); printConfig();
  } else if (!strcmp(c, "rxpath") && argc >= 2) {
    rxPathMode = atoi(argv[1]); printConfig();
  } else if (!strcmp(c, "boost") && argc >= 3) {
    radio.gainModeLf = atoi(argv[1]); radio.gainModeHf = atoi(argv[2]); printConfig();
  } else if (!strcmp(c, "hfpa") && argc >= 4) {
    // hfpa <hf duty 16..31> <tx_power half-dB> <ramp code>: send the HF PA commands one by one
    radio.standby();
    int16_t st = radio.setFrequency(bands[1].freq);
    Serial.printf("# setFrequency %d\n", st);
    st = radio.setPaConfig(1, RADIOLIB_LR2021_PA_LF_MODE_FSM, RADIOLIB_LR2021_PA_LF_DUTY_CYCLE_UNUSED,
                           RADIOLIB_LR2021_PA_LF_SLICES_UNUSED, atoi(argv[1]));
    Serial.printf("# setPaConfig(hf, duty %d) %d\n", atoi(argv[1]), st);
    st = radio.setTxParams(atoi(argv[2]), atoi(argv[3]));
    Serial.printf("# setTxParams(%d, %d) %d\n", atoi(argv[2]), atoi(argv[3]), st);
    uint16_t err = 0; radio.getChipErrors(&err); Serial.printf("# chip errors 0x%04X\n", err);
    curTxBand = -1;
  } else if (!strcmp(c, "hfpwr") && argc >= 2) {
    radio.standby();
    int16_t st = radio.setFrequency(bands[1].freq);
    int p = atoi(argv[1]);
    LR2021PaTableEntry_t* t = radio.paOptTable[1];
    Serial.printf("# setFrequency %d highFreq=%d table=%p\n", st, lr.highFreq, t);
    if (t) Serial.printf("# entry[%d]: duty %u slices %u val %d\n", p + 19, t[p + 19].paDutyCycle, t[p + 19].paSlices, t[p + 19].paVal);
    st = radio.setOutputPower(p);
    Serial.printf("# setOutputPower(%d) %d\n", p, st);
    curTxBand = -1;
  } else if (!strcmp(c, "pdbg")) {
    // one band-A packet, then the HF PA commands one at a time
    static uint8_t pk[20] = { 0 };
    curTxBand = -1;
    bool ok = txSetBand(0, 32);
    int16_t st = radio.transmit(pk, sizeof(pk));
    Serial.printf("# A set %d tx %d irq=0x%08lX\n", ok, st, (unsigned long)radio.getIrqStatus());
    st = radio.standby(); Serial.printf("# standby %d\n", st);
    st = radio.setFrequency(bands[1].freq, true); Serial.printf("# setFrequency %d\n", st);
    for (int i = 0; i < 3; i++) {
      st = radio.setPaConfig(1, RADIOLIB_LR2021_PA_LF_MODE_FSM, RADIOLIB_LR2021_PA_LF_DUTY_CYCLE_UNUSED, RADIOLIB_LR2021_PA_LF_SLICES_UNUSED, 28);
      Serial.printf("# setPaConfig %d\n", st);
      st = radio.setTxParams(2, 5); Serial.printf("# setTxParams %d\n", st);
    }
    uint16_t err = 0; radio.getChipErrors(&err); Serial.printf("# chip errors 0x%04X irq=0x%08lX\n", err, (unsigned long)radio.getIrqStatus());
    curTxBand = -1;
  } else if (!strcmp(c, "rxpre") && argc >= 2) {
    rxPreamble = atoi(argv[1]); printConfig();
  } else if (!strcmp(c, "caltest")) {
    usInit(); cmdCalTest(); usStop();
  } else if (!strcmp(c, "bench")) {
    usInit(); cmdBench(argc >= 2 ? atoi(argv[1]) : 1000, argc >= 3 ? atoi(argv[2]) : 0); usStop();
  } else if (!strcmp(c, "rx")) {
    usInit(); cmdRx(bandIdx(argc >= 2 ? argv[1] : "A")); usStop();
  } else if (!strcmp(c, "scan")) {
    usInit(); cmdScan(); usStop();
  } else if (!strcmp(c, "tx") && argc >= 8) {
    cmdTx(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
  } else {
    Serial.printf("# unknown or incomplete command: %s (try help)\n", c);
  }
  Serial.println("# ready");
}

void setup() {
  Serial.begin(115200);
  uint32_t t0 = millis();
  while (!Serial && millis() - t0 < 3000) delay(10);

  board.begin();
  if (!radio_init()) {
    Serial.println("# radio init FAILED");
    while (true) delay(1000);
  }
  pinMode(P_LORA_DIO_1, INPUT);
  // same RX boost on both paths: changing it in SetRxPath costs ~4.8 ms per band switch
  radio.gainModeLf = 4;
  radio.gainModeHf = 4;
  randomSeed(DWT->CYCCNT ^ (uint32_t)radio.randomByte() << 8 ^ radio.randomByte());

  deriveAll();
  Serial.printf("# dualband_bench ready on %s\n", board.getManufacturerName());
  printConfig();
  Serial.println("# ready");
}

void loop() {
  static char line[128];
  static size_t n = 0;
  while (Serial.available()) {
    int ch = Serial.read();
    if (ch == '\r') continue;
    if (ch == '\n') {
      line[n] = 0;
      handleLine(line);
      n = 0;
    } else if (n < sizeof(line) - 1) {
      line[n++] = (char)ch;
    }
  }
}
