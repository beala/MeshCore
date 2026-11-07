#!/usr/bin/env python3
"""Find UAT bursts on 978 MHz in an RTL-SDR recording: ground station frames (FIS-B) and aircraft.

  rtl_sdr -f 978000000 -s 2083334 -g 49.6 -n $((2083334*60)) rec.cu8
  uat_hunt.py rec.cu8 [--db 8] [--list]

Every burst above the noise is measured: length (a ground station frame is 4.3 ms, an aircraft
message 0.3 or 0.4 ms), level, frequency offset from the tuning, where it falls in the second, and
the best match of its first bits to each sync word (bit errors, and whether the bits came out
inverted). That tells a missing station from one the radio hears but can't sync to.
Then 'dump978 < rec.cu8 | uat2text' decodes what it can.
"""
import argparse
import sys

import numpy as np

FS = 2083334.0
UP = 0x153225B1D     # ground station
DOWN = 0xEACDDA4E2   # aircraft (its bit-opposite)


def bits_of(word):
    return np.array([(word >> (35 - i)) & 1 for i in range(36)], dtype=np.int8)


UPB, DOWNB = bits_of(UP), bits_of(DOWN)


def best_sync(dphi):
    """Best match of a 36-bit sync word in the first bits of a burst: (name, errors, bit offset, phase)."""
    best = ("none", 99, 0, 0)
    for phase in (0, 1):
        b = (dphi[phase::2] > 0).astype(np.int8)
        n = min(len(b) - 36, 300)
        for i in range(max(n, 0)):
            w = b[i:i + 36]
            for name, ref in (("up", UPB), ("down", DOWNB)):
                e = int(np.count_nonzero(w != ref))
                if e < best[1]:
                    best = (name, e, i, phase)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--db", type=float, default=8.0, help="burst threshold over the noise")
    ap.add_argument("--list", action="store_true", help="print every burst")
    a = ap.parse_args()

    raw = np.memmap(a.file, dtype=np.uint8, mode="r")
    n = len(raw) // 2
    chunk = int(FS)   # a second at a time
    bursts = []
    noise_db = []
    for start in range(0, n, chunk):
        x = raw[2 * start:2 * min(n, start + chunk)].astype(np.float32) - 127.5
        z = x[0::2] + 1j * x[1::2]
        p = np.abs(z) ** 2
        sm = np.convolve(p, np.ones(16) / 16, mode="same")
        floor = np.median(sm)
        noise_db.append(10 * np.log10(floor + 1e-9))
        on = sm > floor * 10 ** (a.db / 10)
        edges = np.flatnonzero(np.diff(on.astype(np.int8)))
        if on[0]:
            edges = np.r_[0, edges]
        if on[-1]:
            edges = np.r_[edges, len(on) - 1]
        for s, e in zip(edges[0::2], edges[1::2]):
            dur_us = (e - s) / FS * 1e6
            if dur_us < 60:
                continue
            seg = z[s:e]
            d = np.angle(seg[1:] * np.conj(seg[:-1]))
            q = len(d) // 4   # the middle half (no power ramps)
            mid = d[q:len(d) - q] if q else d
            # the centre between the two tones: a few estimates (one tone can dominate), the best sync wins
            best = None
            for c in (float(np.mean(mid)), float(np.percentile(mid, 2) + np.percentile(mid, 98)) / 2,
                      float(np.percentile(mid, 10) + np.percentile(mid, 90)) / 2):
                m = best_sync(d - c)
                if best is None or m[1] < best[0][1]:
                    best = (m, c)
            (name, err, at, ph), c = best
            off_hz = c / (2 * np.pi) * FS
            t = (start + s) / FS
            bursts.append((t, dur_us, 10 * np.log10(p[s:e].mean() / floor), off_hz, name, err))

    print(f"{n / FS:.1f} s recorded, noise {np.median(noise_db):.1f} dB (raw units)")
    if not bursts:
        print("no bursts above the noise")
        return
    kinds = {"ground station (3.5-5 ms)": [], "aircraft long (0.38-0.5 ms)": [], "aircraft basic (0.25-0.38 ms)": [], "other": []}
    for b in bursts:
        d = b[1]
        k = ("ground station (3.5-5 ms)" if 3500 <= d <= 5000 else "aircraft long (0.38-0.5 ms)" if 380 <= d <= 500
             else "aircraft basic (0.25-0.38 ms)" if 250 <= d < 380 else "other")
        kinds[k].append(b)
    for k, v in kinds.items():
        if not v:
            print(f"{k}: none")
            continue
        lv = np.array([b[2] for b in v])
        off = np.array([b[3] for b in v])
        syncs = {}
        for b in v:
            key = f"{b[4]}<={b[5]}" if b[5] <= 4 else f"{b[4]} {b[5]} errors"
            syncs[key] = syncs.get(key, 0) + 1
        ms = np.array([(b[0] % 1) * 1000 for b in v])
        print(f"{k}: {len(v)}, level {lv.min():.0f}..{lv.max():.0f} dB over noise, offset {np.median(off) / 1000:+.1f} kHz "
              f"(spread {off.std() / 1000:.1f}), ms in second {ms.min():.0f}..{ms.max():.0f}; best sync: "
              + ", ".join(f"{s} x{c}" for s, c in sorted(syncs.items(), key=lambda i: -i[1])[:5]))
    if a.list:
        for t, d, lv, off, name, err in bursts:
            print(f"{t:9.4f} s  {d:6.0f} us  {lv:5.1f} dB  {off / 1000:+6.1f} kHz  {name} {err} errors")


if __name__ == "__main__":
    main()
