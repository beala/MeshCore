#include "RadarSweep.h"
#include <math.h>
#include <string.h>

namespace radar {

static const int WIN = 5;            // bins summed: 50 ms, about a beam's dwell
static const float TOL_S = 0.12f;    // a burst within this of the grid counts as on it

int findBursts(const uint8_t* counts, int n, Burst* out) {
  if (!counts || !out || n < WIN * 4) return 0;
  // average of the 50 ms sums, and the threshold: average + 4 sigma (Poisson) + 1
  float total = 0;
  for (int i = 0; i < n; i++) total += counts[i];
  float mu = total * WIN / n;
  float thr = mu + 4.0f * sqrtf(mu + 0.25f) + 1.0f;

  Burst all[MAX_BURSTS * 2];
  int nb = 0;
  int run_start = -1, last_hot = -1000;
  float wsum = 0, tsum = 0;
  int s = 0;
  for (int i = 0; i < WIN && i < n; i++) s += counts[i];
  for (int i = 0; i + WIN <= n; i++) {   // window i..i+WIN-1, centred at i + WIN/2
    if (i > 0) s += counts[i + WIN - 1] - counts[i - 1];
    bool hot = s > thr;
    if (hot) {
      if (run_start < 0 || i - last_hot > WIN) {   // a new burst: close the previous
        if (run_start >= 0 && wsum > 0) {
          if (nb < MAX_BURSTS * 2) { all[nb].t = tsum / wsum; all[nb].weight = wsum; nb++; }
        }
        run_start = i; wsum = tsum = 0;
      }
      float w = s - mu;
      float c = (i + WIN * 0.5f) * BIN_MS / 1000.0f;
      wsum += w; tsum += w * c;
      last_hot = i;
    }
  }
  if (run_start >= 0 && wsum > 0 && nb < MAX_BURSTS * 2) { all[nb].t = tsum / wsum; all[nb].weight = wsum; nb++; }

  // keep the strongest MAX_BURSTS, in time order
  while (nb > MAX_BURSTS) {
    int weakest = 0;
    for (int i = 1; i < nb; i++) if (all[i].weight < all[weakest].weight) weakest = i;
    memmove(&all[weakest], &all[weakest + 1], (nb - weakest - 1) * sizeof(Burst));
    nb--;
  }
  memcpy(out, all, nb * sizeof(Burst));
  return nb;
}

// Score of period P: the best grid anchored on one of the bursts
static void scorePeriod(const Burst* b, int nb, float total_s, float P, Period* r) {
  memset(r, 0, sizeof(*r));
  r->seconds = P;
  int slots = (int)(total_s / P);
  if (slots < 2) return;
  for (int a = 0; a < nb; a++) {
    // which slots (cycle numbers) have a burst on this grid
    uint8_t seen[64];
    memset(seen, 0, sizeof(seen));
    int on = 0, slots_hit = 0;
    for (int i = 0; i < nb; i++) {
      float ph = (b[i].t - b[a].t) / P;
      float k = floorf(ph + 0.5f);
      if (fabsf(ph - k) * P < TOL_S) {
        on++;
        int slot = (int)floorf(b[i].t / P);
        if (slot >= 0 && slot < 512 && !(seen[slot >> 3] & (1 << (slot & 7)))) {
          seen[slot >> 3] |= (uint8_t)(1 << (slot & 7));
          slots_hit++;
        }
      }
    }
    float hits = (float)slots_hit / slots;
    if (hits > 1.0f) hits = 1.0f;
    float explains = (float)on / nb;
    float score = hits * explains;
    if (score > r->score) { r->score = score; r->hits = hits; r->explains = explains; r->bursts = on; }
  }
}

// Least-squares period from the bursts on the best grid (anchor = strongest on it)
static float refine(const Burst* b, int nb, float P) {
  int best_a = 0, best_on = -1;
  for (int a = 0; a < nb; a++) {
    int on = 0;
    for (int i = 0; i < nb; i++) {
      float ph = (b[i].t - b[a].t) / P;
      if (fabsf(ph - floorf(ph + 0.5f)) * P < TOL_S) on++;
    }
    if (on > best_on) { best_on = on; best_a = a; }
  }
  double sn = 0, st = 0, snn = 0, snt = 0;
  int m = 0;
  for (int i = 0; i < nb; i++) {
    float ph = (b[i].t - b[best_a].t) / P;
    float k = floorf(ph + 0.5f);
    if (fabsf(ph - k) * P >= TOL_S) continue;
    sn += k; st += b[i].t; snn += (double)k * k; snt += (double)k * b[i].t; m++;
  }
  double den = m * snn - sn * sn;
  if (m < 3 || fabs(den) < 1e-9) return P;
  double p = (m * snt - sn * st) / den;
  return (p > P * 0.9 && p < P * 1.1) ? (float)p : P;
}

int findPeriods(const Burst* b, int nb, float total_s, Period* out, int max_out, float min_s, float max_s) {
  if (!b || !out || max_out <= 0 || nb < 4 || total_s <= 0) return 0;
  // Peel: the best period over the bursts left, then take its bursts away and look again, so a
  // second radar isn't hidden behind multiples of the first (9.6 s fits every other 4.8 s burst)
  Burst left[MAX_BURSTS * 2];
  int nl = nb < MAX_BURSTS * 2 ? nb : MAX_BURSTS * 2;
  memcpy(left, b, nl * sizeof(Burst));
  int n = 0;
  while (n < max_out && nl >= 4) {
    Period best;
    memset(&best, 0, sizeof(best));
    for (float P = min_s; P <= max_s; P += 0.01f) {
      Period r;
      scorePeriod(left, nl, total_s, P, &r);
      if (r.score > best.score) best = r;
    }
    if (best.score < 0.2f || best.bursts < 3) break;
    best.seconds = refine(left, nl, best.seconds);
    out[n++] = best;
    // remove the bursts on its grid (anchored where the most of them line up)
    int best_a = 0, best_on = -1;
    for (int a = 0; a < nl; a++) {
      int on = 0;
      for (int i = 0; i < nl; i++) {
        float ph = (left[i].t - left[a].t) / best.seconds;
        if (fabsf(ph - floorf(ph + 0.5f)) * best.seconds < TOL_S) on++;
      }
      if (on > best_on) { best_on = on; best_a = a; }
    }
    float anchor = left[best_a].t;
    int k = 0;
    for (int i = 0; i < nl; i++) {
      float ph = (left[i].t - anchor) / best.seconds;
      if (fabsf(ph - floorf(ph + 0.5f)) * best.seconds >= TOL_S) left[k++] = left[i];
    }
    nl = k;
  }
  return n;
}

}  // namespace radar
