// LR2021 on-chip scanner for MeshCore: runs on the radio's own CPU from Patch RAM and hops between
// up to 8 LoRa channels, each with its own frequency, modulation, preamble and sync word. It runs a
// CAD on each one in turn; on a real preamble it stays in RX and the packet arrives like any other.
// The MCU only gets RxDone. One radio can then hear MeshCore and, for example, Meshtastic LongFast.
//
// Based on the background scanner from lr2021-re-public (firmware/pram/scan.c,
// docs/pram-scanner.md), with a sync word per channel, the DC-DC setting RadioLib makes after
// each modulation change, and a stop that puts channel 0's settings back so RadioLib's view of the
// radio is right again.
//
// How it runs: the ROM main loop hands every radio event (CAD done, preamble, RX timeout, RxDone)
// to the state handler at gp+0x34. Starting the scan puts bg_state in that slot; it calls the ROM's
// handler first, then reads the IRQ status and takes the next step itself:
//   CadDone, nothing         -> next channel
//   CadDone + detected       -> the chip is in RX on that channel: wait for a preamble
//   preamble / header        -> stay; on RxDone park until the host has read the packet
//   RX timeout, header error -> false alarm, next channel
// Any host command that replaces the state handler (SetStandby, SetTx...) stops the scan.
//
// Channel table at TAB, written by the host with WriteRegMem32 (3 words per channel):
//   u32 freq_hz
//   u8  mod0 = sf << 4 | bw code, mod1 = cr code << 4 | ldro, peak (CAD detect peak), pre (preamble)
//   u8  sync1, sync2 (raw sync symbols, as command 0x022D: 0x12 is 2,4, 0x2B is 4,22), 0, 0
//
// Entry 1, params: op (1)
//   op 1 start: n (1), CAD symbols (1), symbols to wait for a preamble after a detection (1),
//        CAD flags (1: bit 4 preamble-only, bits 3:0 pnr_delta; 0x18 is what the scanner bench uses)
//   op 3 resume after the host has read a packet
//   op 2 status
//   op 0 stop: leave RX/CAD, put channel 0's settings back, give the state slot back. Send
//        SetStandby next.
// All return 10 LE words: state | last hit << 8 | channel << 16 | hooked << 24, CADs, false alarms,
// lost after a preamble, packets, passes, events, packets on channel 0, packets on other channels,
// IRQ status.
// Entry 2 returns "MCS1".
typedef unsigned int u32;
typedef unsigned char u8;

struct resp { u32 len; u8 *buf; };
typedef int (*handler_t)(u32 len, const u8 *p, struct resp *r);
#define H_SET_RF_FREQ ((handler_t)0xFC00)   // 0x0200
#define H_LORA_MOD    ((handler_t)0xF238)   // 0x0220
#define H_LORA_PKT    ((handler_t)0xF274)   // 0x0221
#define H_CAD_PARAMS  ((handler_t)0xF188)   // 0x0227
#define H_SET_CAD     ((handler_t)0xF178)   // 0x0228
#define H_RAW_SYNC    ((handler_t)0xF3FC)   // 0x022D: two raw sync symbols
#define H_SET_FS      ((handler_t)0xEB40)   // 0x0129

#define REG(a) (*(volatile u32 *)(a))
#define IRQ          REG(0xF2A00C)          // IRQ status, write 1 to clear
#define IRQ_GATE     REG(0x80060C)          // global mask the ROM applies before the status
#define IRQ_PREAMBLE (1u << 5)
#define IRQ_HDR      (1u << 6)
#define IRQ_CAD_DET  (1u << 7)
#define IRQ_HDR_ERR  (1u << 9)
#define IRQ_RX_DONE  (1u << 18)
#define IRQ_CAD_DONE (1u << 20)
#define IRQ_TIMEOUT  (1u << 21)
#define IRQ_CRC      (1u << 22)
#define IRQ_OWN      (IRQ_PREAMBLE | IRQ_HDR | IRQ_CAD_DET | IRQ_HDR_ERR | IRQ_CAD_DONE | IRQ_TIMEOUT)

// DC-DC settings that follow the receiver's decimation (RadioLib LR2021::setDCDCworkaround)
#define DCDC_ADC_CTRL REG(0xF40200)
#define DCDC_SWITCHER REG(0xF20024)
#define DCDC_FREQ_LF  REG(0x80004C)

// The RX timeout, armed by SetRx through 0xC7F4 and stopped through 0xC828 (no-op when not armed)
#define ROM_RX_TIMEOUT_ARM  ((u32 (*)(u32))0xC7F4)
#define ROM_RX_TIMEOUT_STOP ((u32 (*)(void))0xC828)

#define GP 0x806000u
#define STATE_SLOT (*(volatile u32 *)(GP + 0x34))

#define MAX_CHAN 8
struct chan { u32 freq; u8 mod0, mod1, peak, pre, sync1, sync2, rsv0, rsv1; };
#define TAB ((const struct chan *)0x807800)

enum { S_OFF, S_CAD, S_WAIT, S_RX, S_PARK };
struct bgs {
  u32 orig;                            // the ROM's state handler we stand in front of
  u32 running, state, n, c, wsym, gate_saved;
  u32 last_mod, last_pre, last_sync;
  u32 cads, falses, hdr_err, hits, rounds, last_hit, events, hits0, hits_other;
  u8 cadp[8];
};
#define BG ((struct bgs *)0x807A00)    // after the channel table
#define RUNNING 0x5CA90002u            // RAM isn't cleared at load: a magic, not just nonzero
#define NONE    0xFFFFFFFFu

u32 bg_state(u32 ev);

// RX timeout ticks (32.768 kHz) for `sym` symbols of this modulation: sym * 2^sf / bw * 32768
static u32 wait_ticks(u32 mod0, u32 sym) {
  u32 sf = mod0 >> 4, bw_div;
  switch (mod0 & 0x0F) {
    case 0x2: bw_div = 31250; break;
    case 0x3: bw_div = 62500; break;
    case 0xA: bw_div = 41667; break;
    case 0xB: bw_div = 83333; break;
    case 0xC: bw_div = 101563; break;
    case 0x4: bw_div = 125000; break;
    case 0xD: bw_div = 203125; break;
    case 0x5: bw_div = 250000; break;
    case 0x6: bw_div = 500000; break;
    default:  bw_div = 125000; break;
  }
  u32 chips = sym << sf;                              // <= 255 * 4096
  u32 q = chips / bw_div, rem = chips % bw_div;       // chips * 32768 / bw without overflowing 32 bits
  u32 t = (q << 15) + ((((rem << 8) / bw_div)) << 7) + 1;
  return t > 0xFFFFFFu ? 0xFFFFFFu : t;
}

static void dcdc_follow_decimation(void) {
  u32 dec = (DCDC_ADC_CTRL >> 8) & 0x7;
  u32 sw = DCDC_SWITCHER & ~(0xFFu << 16);
  if (dec == 1 || dec == 2) {
    sw |= (11u << 20) | (13u << 16);
  } else {
    sw |= (15u << 20) | (15u << 16);
  }
  DCDC_SWITCHER = sw;
  DCDC_FREQ_LF = dec == 1 ? 4508876u : 2936012u;
}

// Tune the radio to channel ch; parameters that didn't change since the last call are skipped
static void apply_chan(struct bgs *b, const struct chan *ch) {
  u8 buf[4];
  u32 m = ch->mod0 | (ch->mod1 << 8);
  if (m != b->last_mod) {
    buf[0] = ch->mod0; buf[1] = ch->mod1;
    H_LORA_MOD(2, buf, 0);
    dcdc_follow_decimation();
    b->last_mod = m;
  }
  u32 f = ch->freq;
  buf[0] = f >> 24; buf[1] = f >> 16; buf[2] = f >> 8; buf[3] = f;
  H_SET_RF_FREQ(4, buf, 0);
  if (ch->pre && ch->pre != b->last_pre) {
    buf[0] = 0; buf[1] = ch->pre; buf[2] = 0; buf[3] = 0x02;   // explicit header, CRC on, standard IQ
    H_LORA_PKT(4, buf, 0);
    b->last_pre = ch->pre;
  }
  u32 s = ch->sync1 | (ch->sync2 << 8);
  if (s && s != b->last_sync) {
    buf[0] = ch->sync1; buf[1] = ch->sync2;
    H_RAW_SYNC(2, buf, 0);
    b->last_sync = s;
  }
}

static void forget_params(struct bgs *b) {
  b->last_mod = NONE; b->last_pre = NONE; b->last_sync = NONE;
}

static void hook_in(struct bgs *b) {
  u32 cur = STATE_SLOT;
  if (cur != (u32)bg_state) { b->orig = cur; STATE_SLOT = (u32)bg_state; }
}

static void start_cad(struct bgs *b) {
  const struct chan *ch = &TAB[b->c];
  apply_chan(b, ch);
  b->cadp[6] = ch->peak;
  u32 wt = wait_ticks(ch->mod0, b->wsym);
  b->cadp[3] = wt >> 16; b->cadp[4] = wt >> 8; b->cadp[5] = wt;
  H_CAD_PARAMS(7, b->cadp, 0);
  IRQ = IRQ_OWN;
  H_SET_CAD(0, 0, 0);
  b->cads++;
  b->state = S_CAD;
  hook_in(b);                          // SetLoraCad installed the ROM's CAD handler: get in front again
}

static void next_chan(struct bgs *b) {
  if (++b->c >= b->n) { b->c = 0; b->rounds++; }
  start_cad(b);
}

// Leave RX for the scan: a header error doesn't end RX, and SetLoraCad from RX starts nothing
static void rx_abandon(struct bgs *b) {
  ROM_RX_TIMEOUT_STOP();
  H_SET_FS(0, 0, 0);
  forget_params(b);                    // re-send the params after an RX
  next_chan(b);
}

u32 bg_state(u32 ev) {
  struct bgs *b = BG;
  u32 (*h)(u32) = (u32 (*)(u32))b->orig;
  if (h) ev = h(ev);
  if (b->running != RUNNING) {         // stopped: step aside
    if (STATE_SLOT == (u32)bg_state) STATE_SLOT = b->orig;
    return ev;
  }
  hook_in(b);                          // the ROM handler may have installed its successor
  b->events++;
  u32 s = IRQ;
  switch (b->state) {
    case S_CAD:
      if (!(s & IRQ_CAD_DONE)) break;
      if (!(s & IRQ_CAD_DET)) { next_chan(b); break; }
      b->state = S_WAIT;
      __attribute__((fallthrough));   // the preamble may already be there
    case S_WAIT:
      if (s & (IRQ_PREAMBLE | IRQ_HDR | IRQ_RX_DONE)) {
        b->state = S_RX;
        b->last_hit = b->c;
        // A preamble stopped the RX timeout. Re-arm it until the header, so a preamble that never
        // becomes a header can't leave the radio in RX with nothing to wake the scan.
        if (!(s & (IRQ_HDR | IRQ_RX_DONE))) {
          const struct chan *ch = &TAB[b->c];
          ROM_RX_TIMEOUT_ARM(wait_ticks(ch->mod0, (ch->pre ? ch->pre : 32) + 16));
        }
      } else {
        if (s & (IRQ_TIMEOUT | IRQ_HDR_ERR)) { b->falses++; rx_abandon(b); }
        break;
      }
      __attribute__((fallthrough));
    case S_RX:
      if (s & (IRQ_HDR | IRQ_RX_DONE)) ROM_RX_TIMEOUT_STOP();   // the header came: no limit on the payload
      if (s & IRQ_RX_DONE) {
        b->hits++;
        if (b->c == 0) b->hits0++; else b->hits_other++;
        b->state = S_PARK;
      } else if (s & (IRQ_TIMEOUT | IRQ_HDR_ERR)) {
        b->hdr_err++;
        rx_abandon(b);
      }
      break;
    default:
      break;
  }
  return ev;
}

static void put32(u8 *p, u32 v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

static void bg_resp(struct bgs *b, struct resp *r) {
  u32 v[10] = { b->state | (b->last_hit << 8) | (b->c << 16) | ((STATE_SLOT == (u32)bg_state) << 24),
                b->cads, b->falses, b->hdr_err, b->hits, b->rounds, b->events, b->hits0, b->hits_other, IRQ };
  for (u32 i = 0; i < 10; i++) put32(&r->buf[4 * i], v[i]);
  r->len = 40;
}

int bg_cmd(u32 len, const u8 *p, struct resp *r) {
  struct bgs *b = BG;
  if (len < 1) return 1;
  u32 op = p[0];
  if (op == 1) {
    if (len < 5 || p[1] == 0 || p[1] > MAX_CHAN) return 1;
    if (b->running != RUNNING || STATE_SLOT != (u32)bg_state) b->gate_saved = IRQ_GATE;  // not a restart
    // the ROM records only gated flags in the status: the scan's own, and RxDone/CRC for the host
    IRQ_GATE |= IRQ_OWN | IRQ_RX_DONE | IRQ_CRC;
    b->n = p[1]; b->wsym = p[3]; b->c = 0;
    for (u32 i = 0; i < 8; i++) b->cadp[i] = 0;
    b->cadp[0] = p[2]; b->cadp[1] = p[4]; b->cadp[2] = 1;   // exit mode RX
    forget_params(b);
    b->cads = b->falses = b->hdr_err = b->hits = b->rounds = b->events = b->hits0 = b->hits_other = 0;
    b->last_hit = 0xFF;
    b->orig = 0;
    b->running = RUNNING;
    start_cad(b);
  } else if (op == 3) {
    if (b->running != RUNNING) return 1;
    IRQ = IRQ_RX_DONE | IRQ_CRC | IRQ_OWN;
    forget_params(b);
    next_chan(b);
  } else if (op == 0) {
    if (b->running == RUNNING) {
      b->running = 0;
      if (STATE_SLOT == (u32)bg_state) STATE_SLOT = b->orig;
      ROM_RX_TIMEOUT_STOP();
      H_SET_FS(0, 0, 0);
      forget_params(b);
      apply_chan(b, &TAB[0]);          // back to what the host configured
      IRQ = IRQ_OWN;
      IRQ_GATE = b->gate_saved;
    }
    b->state = S_OFF;
  } else if (op != 2) {
    return 1;
  }
  bg_resp(b, r);
  return 3;
}
