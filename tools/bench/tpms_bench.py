#!/usr/bin/env python3
"""Bench test of tire pressure (docs/tire_pressure.md): one LR2021 companion built with
-D FISB_BENCH_TX plays recorded sensor frames (test/test_tpms/vectors.inc: rtl_433's captures) at
925 MHz, another listens with 'tpms on'. Never 909-922 MHz (the sender refuses it).

  tpms_bench.py <tx port> <rx port> [--mhz 925] [--count 8] [--only FORD_0,GM_1] [--rxbw kHz]
"""
import argparse
import re
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from fisb_bench import Companion  # noqa: E402


def vectors(path):
    s = open(path).read()
    out = []
    for name, hexes in re.findall(r"static const uint8_t (\w+)\[\] = \{([^}]*)\};", s):
        m = re.search(name + r"_EXP = \{ (\d+), 0x([0-9a-f]+), (-?\d+) \}", s)
        b = bytes(int(x, 16) for x in hexes.split(","))
        out.append((name, int(m.group(1)), int(m.group(2), 16), int(m.group(3)), b))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tx")
    ap.add_argument("rx")
    ap.add_argument("--mhz", type=float, default=925.0)
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--gap", type=float, default=0.3)
    ap.add_argument("--only")
    ap.add_argument("--rxbw", default="0")
    ap.add_argument("--vectors", default=__file__.rsplit("/", 3)[0] + "/test/test_tpms/vectors.inc")
    a = ap.parse_args()
    tx, rx = Companion(a.tx), Companion(a.rx)
    vs = vectors(a.vectors)
    if a.only:
        vs = [v for v in vs if v[0] in a.only.split(",")]
    print("rx>", rx.cli("tpms on"), "|", rx.cli(f"set tpms.freq {a.mhz}"), "|", rx.cli("set tpms.duty 100"),
          "|", rx.cli("set tpms.ids " + ",".join("%x" % v[2] for v in vs)))
    for name, air, sid, kpa10, chips in vs:
        print("rx>", rx.cli(f"set tpms.dbg {a.rxbw} 0 {air + 1}"))
        time.sleep(0.5)
        before = rx.cli("get tpms.stats")
        sent = 0
        for _ in range(a.count):
            r = tx.cli(f"tpms tx {air} {a.mhz} {chips.hex()}")
            sent += bool(r and r.startswith("OK"))
            time.sleep(a.gap)
        time.sleep(1.0)
        print(f"{name}: sent {sent}; before: {before}")
        print(f"   after: {rx.cli('get tpms.stats')}")
    print("heard:", rx.cli("get tpms.heard"))
    for ch, text in rx.channel_posts(3.0):
        print("post:", text)
    print("rx>", rx.cli("set tpms.dbg 0 0 0"))


if __name__ == "__main__":
    main()
