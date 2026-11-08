#pragma once
// Utility meters on 915 MHz (docs/utility_meters.md): Neptune R900 water meters and Itron ERT
// modules (SCM, SCM+) on gas, electric and water meters. All send on-off keyed chips at 32.768
// kchip/s, hopping around 910-920 MHz. The radio finds a frame by its sync word and hands over the
// raw chips after it; these read them. No allocation.

#include <stdint.h>
#include <stddef.h>

namespace meters {

enum { KIND_R900 = 1, KIND_SCM = 2, KIND_SCMPLUS = 3 };
enum { UTIL_UNKNOWN = 0, UTIL_WATER, UTIL_GAS, UTIL_ELECTRIC };

struct Reading {
  uint8_t kind;          // KIND_*
  uint8_t utility;       // UTIL_*
  uint32_t id;           // as printed on the meter's radio module
  uint32_t total;        // the meter's register, in its own units
  uint8_t type;          // R900 meter type; SCM ERT type; SCM+ endpoint type
  // R900 only (each over the meter's own time span):
  uint8_t leak_days;     // 0 none, 1: 1-2 days, 2: 3-7, 3: 8-14, 4: 15-21, 5: 22-34, 6: 35+ days
  uint8_t leak_now;      // last 24 h: 0 none, 1 intermittent (water in 50+ of 96 quarter-hours), 2 continuous
  uint8_t backflow;      // last 35 days: 0 none, 1 low, 2 high
  uint8_t no_use;        // days with no use, coded as leak_days
  uint16_t tamper;       // SCM: physical << 2 | encoder; SCM+: the tamper field
};

// How each kind is found on the air (1 = carrier on): the radio's detector pattern (first chip in
// the LSB), then the sync word, then pkt_bytes of raw chips (first chip in each byte's top bit).
struct Air {
  uint16_t pattern;
  uint8_t pattern_bits;
  uint8_t sync[4];
  uint8_t sync_len;
  uint8_t pkt_bytes;
};
// R900:  31 chips of 1010.., sync A9666965, 168 chips (42 groups of 4)
// SCM+:  no preamble: Manchester (data 1 = chips 10) 16 A3 1E is the pattern (16 A) and sync (A3 1E),
//        then 13 bytes: endpoint type, id (4), consumption (4), tamper (2), CRC (2)
// SCM:   no preamble: Manchester, its 21-bit sync 1F2A60 is the pattern (first 8 bits) and sync
//        (the next 12), then 76 bits: the sync's last one, and the 75 of the frame
static const int KINDS = 3;   // KIND_R900 .. KIND_SCMPLUS
const Air& air(uint8_t kind);

// chips: as the radio hands them over after the sync. Return false if it isn't a whole, checked frame.
bool readR900(const uint8_t* chips, int n_bytes, Reading* r);
bool readScmPlus(const uint8_t* chips, int n_bytes, Reading* r);
bool readScm(const uint8_t* chips, int n_bytes, Reading* r);
bool read(uint8_t kind, const uint8_t* chips, int n_bytes, Reading* r);
const char* kindName(uint8_t kind);   // "R900", "SCM", "SCM+"

// Where and how often each kind sends, as measured near the bench (an RTL-SDR, 2026-11-07): R900s
// hop over channels 130.5 kHz apart (910.30-920.35 MHz) every 14.000 s; Itron SCM+ over a 200 kHz grid
// (910.0-920.0 MHz) every 15.000 s (SCM taken as the same). The LR2021's OOK receiver takes one
// channel at a time: 153.8 kHz is its widest bandwidth that works at 32.768 kchip/s.
int channels(uint8_t kind);
// R900s all hop through the same 50 channels in the same order, each meter at its own place in it
// (measured with an RTL-SDR: frames a multiple of 50 sends apart always on the same channel). One
// frame heard on a channel tells where a meter is; its next frame is on the following one.
static const int R900_HOPS = 50;
int r900HopChannel(int pos);       // the channel (0..77) at a place in the sequence (any int: taken mod 50)
int r900HopPos(int ch);            // the place of a channel in the sequence, -1 if it isn't in it
float channelMHz(uint8_t kind, int i);   // i in 0 .. channels(kind)-1
uint32_t periodMs(uint8_t kind);
static const float RX_BW_KHZ = 153.8f;

// From an ERT type (SCM's, or the low 4 bits of SCM+'s endpoint type), as rtlamr lists them
uint8_t ertUtility(uint8_t type);
const char* utilityName(uint8_t utility);   // "water", "gas", "electric", "meter"

// CRC-16, MSB first, no reflection (exposed for tests)
uint16_t crc16(const uint8_t* data, int len, uint16_t poly, uint16_t init);

}  // namespace meters
