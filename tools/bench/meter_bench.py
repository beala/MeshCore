#!/usr/bin/env python3
"""Bench test of utility meters (docs/utility_meters.md): one LR2021 companion built with
-D FISB_BENCH_TX sends made-up meter frames (tools/bench/meters.py 'chips'), another listens with
'meter on'. Made-up IDs only: never a real meter's.

  meter_bench.py <tx port> [<rx port>] [--mhz 925] [--count 10] [--gap 1500] [--kinds r900,scmplus,scm]
                 [--leak 0..6] [--leaknow 0..2]

With an rx port: sets it up (meter on, meter.center at --mhz, duty 100, meter.ids the made-up
IDs, a post every minute), sends, then prints the Meters channel posts, 'get meter.stats' and
'get meter.heard'. Without one, it only sends (eg. for rtl_433 on an SDR). 925 MHz by default:
never 909-922 MHz, where real meters send (the sender refuses it).
"""
import argparse
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import meters  # noqa: E402
from fisb_bench import Companion  # noqa: E402

FAKE = {"r900": 1234567890, "scmplus": 87654321, "scm": 23456789}


def chips_hex(kind, meter_id, total, leak, leaknow):
    if kind == "r900":
        c = meters.r900_chips(meter_id, total, leak=leak, leaknow=leaknow)
    elif kind == "scmplus":
        c = meters.manchester(meters.int_to_bits(int.from_bytes(meters.scmplus_bytes(meter_id, total), "big"), 128))
    else:
        c = meters.manchester(meters.scm_bits(meter_id, total))
    return meters.bits_to_bytes(c + [0] * (-len(c) % 8)).hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tx")
    ap.add_argument("rx", nargs="?")
    ap.add_argument("--mhz", type=float, default=925.0)   # outside the meters' 910-921 MHz
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--gap", type=int, default=1500)
    ap.add_argument("--kinds", default="r900,scmplus,scm")
    ap.add_argument("--leak", type=int, default=0)
    ap.add_argument("--leaknow", type=int, default=0)
    ap.add_argument("--duty", type=int, default=100)
    a = ap.parse_args()
    kinds = a.kinds.split(",")
    tx = Companion(a.tx)
    rx = Companion(a.rx) if a.rx else None
    if rx:
        for c in ("meter on", f"set meter.center {a.mhz}", f"set meter.duty {a.duty}", "set meter.every 1",
                  "set meter.ids " + ",".join(str(FAKE[k]) for k in kinds)):
            print("rx>", c, "->", rx.cli(c))
        rx.channel_posts(1.0)   # old posts out of the way
    total = {k: 1000 for k in kinds}
    sent = 0
    for i in range(a.count):
        for k in kinds:
            total[k] += 7
            r = tx.cli(f"meter tx {a.mhz} " + chips_hex(k, FAKE[k], total[k], a.leak, a.leaknow))
            if r and r.startswith("OK"):
                sent += 1
            else:
                print("tx>", r)
            time.sleep(a.gap / 1000 / len(kinds))
    print(f"sent {sent} frames ({a.count} of each of {', '.join(kinds)})")
    if rx:
        time.sleep(1.5)
        for ch, text in rx.channel_posts(3.0):
            print(f"post [{ch}]: {text}")
        print("stats:", rx.cli("get meter.stats"))
        print("heard:", rx.cli("get meter.heard"))
        print("rx>", rx.cli("set meter.center auto"))


if __name__ == "__main__":
    main()
