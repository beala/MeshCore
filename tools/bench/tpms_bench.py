#!/usr/bin/env python3
"""Bench test of tire pressure (docs/tire_pressure.md): one LR2021 companion built with
-D FISB_BENCH_TX plays recorded sensor frames (test/test_tpms/vectors.inc: rtl_433's captures) at
925 MHz, another listens with 'tpms on'. Never 909-922 MHz (the sender refuses it).

  tpms_bench.py <tx port> <rx port> [--mhz 925] [--count 8] [--only FORD_0,GM_1] [--rxbw kHz]
               [--heltec <port>]

--heltec sends the FSK makes from a Heltec V4 console (tools/heltec_v4_tx, an SX1262) instead, at
the rates and deviations measured on real sensors (the receiver's settings), so a wrong setting
shows: the XIAO's LR2021 rounds its rates as the receiving LR2021 does.
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


# what the sensors send (measured on rtl_433's recordings): bit rate, deviation, by setting
REAL = {0: (19.21, 41), 1: (19.231, 40), 2: (20.15, 25), 3: (20.0, 40), 4: (20.29, 28), 5: (8.198, 41), 6: (9.915, 41)}
SYNCS = {0: ("5556", 16), 1: ("aaaaaaa9", 32), 2: ("a9e0", 11), 3: ("ed71", 16), 4: ("dae354", 23), 5: ("f5555555e0", 36),
         6: ("fc", 8)}


def heltec_frame(air, chips):
    """sync bits then chips, as one bit string padded to bytes; the Heltec puts 40 bits of 1010.. first"""
    sh, sb = SYNCS[air]
    bits = bin(int(sh, 16))[2:].zfill(len(sh) * 4)[:sb] + "".join(f"{b:08b}" for b in chips)
    bits += "0" * (-len(bits) % 8)
    return "%0*x" % (len(bits) // 4, int(bits, 2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tx")
    ap.add_argument("rx")
    ap.add_argument("--mhz", type=float, default=925.0)
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--gap", type=float, default=0.3)
    ap.add_argument("--only")
    ap.add_argument("--rxbw", default="0")
    ap.add_argument("--heltec")
    ap.add_argument("--vectors", default=__file__.rsplit("/", 3)[0] + "/test/test_tpms/vectors.inc")
    a = ap.parse_args()
    tx, rx = Companion(a.tx), Companion(a.rx)
    h = None
    if a.heltec:
        import serial
        h = serial.Serial(a.heltec, 115200, timeout=0.3)
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
            if h is not None and air in REAL:
                kbps, dev = REAL[air]
                fr = heltec_frame(air, chips)
                # the Heltec needs a sync word: the first byte of the frame
                h.reset_input_buffer()
                h.write(f"fskraw {a.mhz} {kbps} {dev} {fr[:2]} {fr[2:]}\n".encode())
                time.sleep(0.15)
                sent += "OK" in h.read(200).decode(errors="replace")
            else:
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
