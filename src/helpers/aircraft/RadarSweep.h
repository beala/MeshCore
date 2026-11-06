#pragma once
// Radar rotation periods from pulse detections at 1030 MHz. Ground radars interrogate transponders
// with a narrow rotating beam, so a receiver on the ground hears a burst of pulses each time the
// beam (or a strong sidelobe) points at it: once per rotation, about 4.8 s for an airport radar
// and 10-12 s for a long-range one. Several radars can be heard at once.
//
// Input: detections counted in 10 ms bins. Bursts are runs of bins well above the average
// (detections from noise are spread evenly; a sweep piles them up). A period P is scored by the
// share of bursts that fall on one P-spaced grid times the share of the grid's slots that have a
// burst: both are near 1 for the true period, about 1/2 for P/2 or 2P, and low for anything else.
// No allocation; float maths, for the companion and the PC tests.

#include <stdint.h>
#include <stddef.h>

namespace radar {

static const uint32_t BIN_MS = 10;
static const int MAX_BURSTS = 48;

struct Burst {
  float t;        // seconds from the start (weighted centre)
  float weight;   // detections above the average
};

// Finds bursts in counts[n] (detections per BIN_MS). Returns how many were written (the strongest
// MAX_BURSTS, in time order).
int findBursts(const uint8_t* counts, int n, Burst* out);

struct Period {
  float seconds;
  float score;    // 0..1: hits x explained
  float hits;     // share of the period's slots that had a burst
  float explains; // share of all bursts on this period's grid
  int bursts;     // bursts on the grid
};

// The radars' periods between min_s and max_s over a listen of total_s seconds, the one with the
// most bursts first; each next one from the bursts the earlier ones don't explain (explains and
// hits are of those). Returns how many (up to max_out; 0 with fewer than 4 bursts).
int findPeriods(const Burst* b, int nb, float total_s, Period* out, int max_out, float min_s = 2.0f, float max_s = 15.0f);

}  // namespace radar
