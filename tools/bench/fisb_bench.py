#!/usr/bin/env python3
"""Bench test of airport weather (docs/airport_weather.md): one LR2021 companion sends made FIS-B
frames at 915 MHz (a build with -D FISB_BENCH_TX), another receives them with 'metar on'.

  fisb_bench.py <tx port> <rx port> [--count N] [--gap MS] [--errors K] [--mhz F] "METAR KLMO ..." [...]

Sets up the receiver (metar on, metar.freq F, metar.airports from the reports), loads the frame
into the sender ('metar tx load'), sends it N times, then prints the receiver's channel posts and
'get metar.stats'. --errors K: K bad bytes in every Reed-Solomon block (10 is the most it fixes).
Never on 978 MHz: the sender refuses anything outside 902-928 MHz.
"""
import argparse
import random
import struct
import sys
import time

import serial

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import fisb  # noqa: E402


def frame(payload):
    return b"<" + struct.pack("<H", len(payload)) + payload


def read_frames(s, secs):
    end = time.time() + secs
    buf = b""
    out = []
    while time.time() < end:
        buf += s.read(4096)
        while True:
            i = buf.find(b">")
            if i < 0 or len(buf) < i + 3:
                break
            n = struct.unpack("<H", buf[i + 1:i + 3])[0]
            if len(buf) < i + 3 + n:
                break
            out.append(buf[i + 3:i + 3 + n])
            buf = buf[i + 3 + n:]
    return out


class Companion:
    def __init__(self, port):
        self.s = serial.Serial(port, 115200, timeout=0.1)
        self.s.write(frame(bytes([1, 3]) + b"fisb"))   # APP_START
        read_frames(self.s, 0.5)

    def cli(self, cmd, wait=1.0):
        self.s.write(frame(bytes([66]) + cmd.encode()))
        for f in read_frames(self.s, wait):
            if f[0] in (1, 29):
                return f[1:].decode(errors="replace")
        return None

    def channel_posts(self, secs):
        posts = []
        end = time.time() + secs
        while time.time() < end:
            self.s.write(frame(bytes([10])))   # SYNC_NEXT_MESSAGE
            for f in read_frames(self.s, 0.3):
                if f[0] in (8, 17):
                    off = 4 if f[0] == 17 else 1
                    posts.append((f[off], f[off + 7:].decode(errors="replace")))
        return posts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tx")
    ap.add_argument("rx")
    ap.add_argument("reports", nargs="*")
    ap.add_argument("--data", help="432 data bytes in hex (eg. a dump978 '+' line) instead of reports")
    ap.add_argument("--airports", help="for 'set metar.airports' (default: those in the reports)")
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--gap", type=int, default=1000)
    ap.add_argument("--errors", type=int, default=0)
    ap.add_argument("--mhz", type=float, default=915.0)
    ap.add_argument("--duty", type=int, default=100)
    a = ap.parse_args()
    if not 902 <= a.mhz <= 928:
        sys.exit("902-928 MHz only")

    if a.data:
        data = bytes.fromhex(a.data.lstrip("+").split(";")[0])
        a.reports = fisb.read_data(data)
        f = bytearray(fisb.interleave(data))
    else:
        f = bytearray(fisb.build_frame(a.reports))
    rnd = random.Random(1)
    for b in range(fisb.BLOCKS):
        for i in rnd.sample(range(fisb.BLOCK_LEN), a.errors):
            f[i * fisb.BLOCKS + b] ^= rnd.randrange(1, 256)
    airports = a.airports or ",".join(sorted({r.split()[1] for r in a.reports if r.startswith(("METAR", "SPECI", "TAF"))}))[:39]

    rx = Companion(a.rx)
    for c in ["metar on", "set metar.freq %g" % a.mhz, "set metar.airports " + airports,
              "set metar.taf on", "set metar.duty %d" % a.duty]:
        print("rx:", c, "->", rx.cli(c))
    rx.channel_posts(1.0)   # old ones
    before = rx.cli("get metar.stats")

    tx = Companion(a.tx)
    for off in range(0, len(f), 64):
        r = tx.cli("metar tx load %d %s" % (off, f[off:off + 64].hex()))
        if not r or not r.startswith("OK"):
            sys.exit("load failed at %d: %r" % (off, r))
    print("tx: loaded", len(f), "bytes;", "errors per block:", a.errors)
    sent = 0
    for i in range(a.count):
        if i:
            time.sleep(a.gap / 1000)
        r = tx.cli("metar tx send %g" % a.mhz, wait=0.3)
        sent += bool(r and r.startswith("OK"))
    print("tx: sent %d of %d" % (sent, a.count))

    posts = rx.channel_posts(3.0)
    for ch, text in posts:
        print("rx post (channel %d): %s" % (ch, text))
    print("rx before:", before)
    print("rx after: ", rx.cli("get metar.stats"))
    print("rx radio: ", rx.cli("get radio.fsk"))


if __name__ == "__main__":
    main()
