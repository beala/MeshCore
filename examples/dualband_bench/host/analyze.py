#!/usr/bin/env python3
"""Summarise dualband_bench runs: results/<case>.tx + results/<case>.dut -> table + miss analysis."""
import sys, os, statistics as st, glob

def parse(path):
    rows = []
    for line in open(path, errors="replace"):
        parts = line.rstrip("\n").split(" ", 1)
        if len(parts) < 2:
            continue
        rows.append(parts[1])
    return rows

def load(case, d="results"):
    tx, rx, err, fto, scan = {}, {}, [], [], []
    for l in parse(f"{d}/{case}.tx"):
        if l.startswith("T,"):
            _, t, seq, band, ln, pre, air, status = l.split(",")
            if int(status) == 0:
                tx[int(seq)] = dict(t=int(t), band=band, len=int(ln), pre=int(pre), air=int(air))
    for l in parse(f"{d}/{case}.dut"):
        f = l.split(",")
        if f[0] == "R":
            seq = int(f[3])
            if seq not in rx:
                rx[seq] = dict(t=int(f[1]), rxband=f[2], band=f[4], len=int(f[5]), rssi=float(f[7]),
                               snr=float(f[8]), foff=int(f[9]))
        elif f[0] == "E":
            err.append(dict(t=int(f[1]), band=f[2], kind=f[3]))
        elif f[0] == "F":
            fto.append(dict(t=int(f[1]), band=f[2]))
        elif f[0] == "SUM":
            scan.append(f)
    return tx, rx, err, fto

def clock_offset(tx, rx):
    # DUT rx time (end of packet) ~= TX start + airtime + offset
    offs = [rx[s]["t"] - (tx[s]["t"] + tx[s]["air"]) for s in rx if s in tx]
    return st.median(offs) if offs else None

def summarize(case):
    tx, rx, err, fto = load(case)
    off = clock_offset(tx, rx)
    out = {"case": case}
    # intervals when the DUT was receiving a packet (in DUT time)
    busy = [(rx[k]["t"] - tx[k]["air"], rx[k]["t"], rx[k]["rxband"]) for k in rx if k in tx]
    for b in "AB":
        sent = [s for s in tx if tx[s]["band"] == b]
        got = [s for s in sent if s in rx]
        out[b] = dict(sent=len(sent), got=len(got),
                      rate=(100.0 * len(got) / len(sent)) if sent else None,
                      crc=sum(1 for e in err if e["band"] == b and e["kind"] == "crc"),
                      hdr=sum(1 for e in err if e["band"] == b and e["kind"] == "hdr"),
                      fto=sum(1 for e in fto if e["band"] == b))
        fo = [rx[s]["foff"] for s in got]
        if fo:
            out[b]["foff"] = (st.mean(fo), st.pstdev(fo), min(fo), max(fo))
            out[b]["rssi"] = st.mean(rx[s]["rssi"] for s in got)
            out[b]["snr"] = st.mean(rx[s]["snr"] for s in got)
        # classify misses by what the DUT was doing when the packet was on air
        cls = {"busy_rx_other": 0, "busy_rx_same": 0, "cad_timeout": 0, "rx_error": 0, "unexplained": 0}
        missed = [s for s in sent if s not in rx]
        details = []
        for s in missed:
            p = tx[s]
            if off is None:
                cls["unexplained"] += 1
                continue
            t0 = p["t"] + off  # TX start in DUT time
            t1 = t0 + p["air"]
            reason = None
            for e in err:
                if t0 <= e["t"] <= t1 + 50:
                    reason = "rx_error"
            if not reason:
                for q0, q1, qb in busy:
                    if q0 < t1 and q1 > t0:
                        reason = "busy_rx_other" if qb != b else "busy_rx_same"
                        break
            if not reason:
                for e in fto:
                    # a CAD hit that timed out keeps the radio parked for ~48 symbols before e["t"]
                    if t0 - 20 <= e["t"] <= t1 + 150:
                        reason = "cad_timeout"
                        break
            cls[reason or "unexplained"] += 1
            details.append((s, p["len"], p["air"], reason or "unexplained"))
        out[b]["miss"] = cls
        out[b]["missed"] = details
    return out

def main():
    cases = sys.argv[1:] or sorted(os.path.basename(p)[:-3] for p in glob.glob("results/*.tx"))
    print(f"{'case':14} {'band':4} {'sent':>5} {'got':>5} {'catch%':>7} {'crc':>4} {'hdr':>4} {'cadTO':>5}"
          f" {'rssi':>7} {'snr':>6} {'foff mean/sd/min/max Hz':>26}  misses")
    for c in cases:
        try:
            o = summarize(c)
        except FileNotFoundError:
            continue
        for b in "AB":
            r = o[b]
            if not r["sent"]:
                continue
            fo = r.get("foff")
            fos = f"{fo[0]:7.0f}/{fo[1]:4.0f}/{fo[2]:5d}/{fo[3]:5d}" if fo else ""
            miss = ",".join(f"{k}={v}" for k, v in r["miss"].items() if v)
            print(f"{c:14} {b:4} {r['sent']:5d} {r['got']:5d} {r['rate']:7.2f} {r['crc']:4d} {r['hdr']:4d} {r['fto']:5d}"
                  f" {r.get('rssi', 0):7.1f} {r.get('snr', 0):6.2f} {fos:>26}  {miss}")
    if "-v" in os.environ.get("ANALYZE", ""):
        for c in cases:
            o = summarize(c)
            for b in "AB":
                for d in o[b]["missed"]:
                    print(c, b, *d)

if __name__ == "__main__":
    main()
