#!/usr/bin/env python3
"""Bench test of weather sensors (docs/weather_sensors.md): one LR2021 companion built with
-D FISB_BENCH_TX plays sensor packets (test/test_wxsensor/vectors.inc: rtl_433's recordings, and
the examples from rtl_433's notes for models without one) at 925 MHz, each at its own bit rate and
with its own preamble and sync word; another listens with 'wx on'. Never 909-922 MHz (the sender
refuses it).

  wx_bench.py <tx port> <rx port> [--mhz 925] [--count 40] [--only WH25,TX22U] [--heltec <port>]
"""
import argparse
import re
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from fisb_bench import Companion  # noqa: E402

# how each format's sensors send, measured on rtl_433's recordings: bit rate (kbit/s), deviation
# (kHz) and what comes before the packet (the Heltec adds 40 bits of preamble of its own). The
# receiver takes only rates within about 0.1-0.3% of its own, deviations within about 20%.
AIR = {
    0: (17.21, 35, "aaaaaaaaaa2dd4"),    # Fine Offset/Ecowitt
    1: (9.606, 31, "aaaaaad2aa2dd4"),    # La Crosse View TH3, R1, WR1
    2: (9.362, 33, "aaaaaad2aa2dd4"),    # La Crosse View TH2, Breeze Pro
    3: (9.577, 20, "aaaaaa2dd4"),        # La Crosse IT+ TX35
    4: (8.624, 35, "aaaa2dd4"),          # TX22U-IT
    5: (9.26, 35, "aaaad2552dd4"),       # ThermoPro TX-7B
    6: (17.235, 60, "aaaaaaaaaa2dd4"),   # Fine Offset WH25, La Crosse TX29-IT
    7: (9.329, 31, "aaaaaad2aa2dd4"),    # La Crosse View W1
}
# units measured at the edges of their format's spread
EDGE = {"ecowitt/WN34L/14.1C_915M_1000k.cu8": 17.181, "fineoffset/fineoffset_wh65b/01/g001_915.05M_250k.cu8": 17.263}
# models with no recording: rtl_433's published examples (made-up IDs where they had real ones)
EXTRA = [
    ("WH46 (notes)", 0, "WH46", "460027f102b53340324039030b002a0036019 0e416".replace(" ", "")),
    ("WH55 (notes)", 0, "WH55", "5530cf55040289beaea42010"),
    ("WS68 (notes)", 0, "WS68", "680000c501074b0fffff002e0002a663"),
    ("WH41 (notes)", 0, "WH41", "41c741ae01c2f9b3"),
    ("TX-7B (notes)", 5, "TX-7B", "e800293017aa55aa83d2d2d2d2"),
    ("TX22U (notes)", 4, "TX22U", "a2a5057210582000380040 00fc00".replace(" ", "")),
]


def vectors(path):
    out = []
    for name, proto, hx, model in re.findall(r'\{ "([^"]+)", (\d), "([0-9a-f]+)", "([^"]+)"', open(path).read()):
        out.append((name, int(proto), model, hx))
    return out + EXTRA


def good(rx):
    """packets heard that read (or checked out as a model not known yet)"""
    m = re.match(r"> (\d+) packets \((\d+) bad", rx.cli("get wx.stats") or "")
    return int(m.group(1)) - int(m.group(2)) if m else 0


def crc8(b):
    c = 0
    for x in b:
        c ^= x
        for _ in range(8):
            c = ((c << 1) ^ 0x31) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tx")
    ap.add_argument("rx")
    ap.add_argument("--mhz", type=float, default=925.0)
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--gap", type=float, default=0.2)
    ap.add_argument("--only")
    ap.add_argument("--heltec", help="send from a Heltec V4 console (tools/heltec_v4_tx) instead: exact rates and deviations")
    ap.add_argument("--vectors", default=__file__.rsplit("/", 3)[0] + "/test/test_wxsensor/vectors.inc")
    a = ap.parse_args()
    rx = Companion(a.rx)
    if a.heltec:
        import serial
        h = serial.Serial(a.heltec, 115200, timeout=0.3)

        def send(kbps, dev, sync, pkt):
            h.reset_input_buffer()
            h.write(f"fskraw {a.mhz} {kbps} {dev} {sync.lstrip('a') or sync} {pkt}\n".encode())
            time.sleep(0.15)
            return "OK" in h.read(200).decode(errors="replace")
    else:
        tx = Companion(a.tx)

        def send(kbps, dev, sync, pkt):   # the XIAO sends at ±35 kHz
            r = tx.cli(f"wx tx {kbps} {a.mhz} {sync} {pkt}")
            return bool(r and r.startswith("OK"))
    vs = vectors(a.vectors)
    if a.only:
        vs = [v for v in vs if v[2] in a.only.split(",")]
    print("rx>", rx.cli(f"set wx.freq {a.mhz}"), "|", rx.cli("set wx.every 0"), "|", rx.cli("wx on"))
    rx.channel_posts(1.0)
    results = []
    kind = None
    for i, (name, proto, model, hx) in enumerate(vs):
        want = "ecowitt" if proto in (0, 6) else "lacrosse"
        if i % 8 == 0 or want != kind:   # a fresh sensor table (it holds 12), the brand's formats only
            print("rx>", rx.cli("wx off"), "|", rx.cli(f"set wx.kind {want}"), "|", rx.cli("wx on"), "|", rx.cli("wx scan on"))
            rx.channel_posts(1.0)
            kind = want
        kbps, dev, sync = AIR[proto]
        kbps = EDGE.get(name, kbps)
        pkt = hx[: (32 if proto in (0, 6) else 13) * 2]
        before = good(rx)
        # scanning all the time takes the brand's formats in turn, 5 s each: send for a whole round
        secs = 5 * (2 if want == "ecowitt" else 6) + 4
        sent, t0 = 0, time.time()
        while time.time() - t0 < secs:
            sent += send(kbps, dev, sync, pkt)
            time.sleep(a.gap)
        time.sleep(0.8)
        got = good(rx) - before
        posts = [t for _, t in rx.channel_posts(1.0)]
        mine = [t for t in posts if model.split("-")[0] in t]
        share = 5 / secs   # its format's turn
        results.append((name, model, sent, got, mine[:1], share))
        print(f"{name} [{model} {kbps}k {dev} kHz]: sent {sent} (about {int(sent * share)} in its format's turn), heard {got}; post: {mine[:1] or '-'}", flush=True)
    # a packet of a family the firmware doesn't know, with the checks every Fine Offset packet has
    print("rx>", rx.cli("set wx.kind ecowitt"), "|", rx.cli("wx scan on"))
    time.sleep(1.0)
    b = bytes([0x63, 0x12, 0x34, 0x56, 1, 2, 3, 4, 5, 6])
    b += bytes([crc8(b)])
    b += bytes([sum(b) & 0xFF])
    for _ in range(3):
        send(AIR[0][0], AIR[0][1], AIR[0][2], b.hex() + "aaaa")
        time.sleep(a.gap)
    time.sleep(0.8)
    print("unknown:", rx.cli("get wx.unknown"), "|", rx.cli("get wx.unknown 1"))
    print("sensors:", rx.cli("get wx.sensors"))
    print("stats:", rx.cli("get wx.stats"))
    print("rx>", rx.cli("wx scan off"), "|", rx.cli("set wx.kind both"))
    print("\nsummary:")
    for name, model, sent, got, post, share in results:
        print(f"  {model:10} heard {got:3}, about {int(sent * share):3} sent in its turn  {'posted' if post else 'NO POST'}  {name}")


if __name__ == "__main__":
    main()
