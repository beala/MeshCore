#!/usr/bin/env python3
"""Record raw cu8 samples from an rtl_tcp server (an RTL-SDR on another machine).

  rtltcp_rec.py HOST:PORT out.cu8 --mhz 978 --rate 2083334 --gain 49.6 --secs 120

Same file format as 'rtl_sdr', so uat_hunt.py and dump978 read it. Reports if the network
fell behind (fewer samples arrived than the time taken).
"""
import argparse
import socket
import struct
import time


def cmd(s, c, v):
    s.sendall(struct.pack(">BI", c, int(v) & 0xFFFFFFFF))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("addr")
    ap.add_argument("out")
    ap.add_argument("--mhz", type=float, default=978.0)
    ap.add_argument("--rate", type=int, default=2083334)
    ap.add_argument("--gain", type=float, default=49.6, help="dB; 0 = automatic")
    ap.add_argument("--secs", type=float, default=60)
    a = ap.parse_args()
    host, port = a.addr.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    hdr = s.recv(12)
    print("server:", hdr[:4], "tuner", struct.unpack(">I", hdr[4:8])[0])
    cmd(s, 0x02, a.rate)
    cmd(s, 0x01, a.mhz * 1e6)
    if a.gain > 0:
        cmd(s, 0x03, 1)            # manual gain
        cmd(s, 0x04, a.gain * 10)  # tenths of a dB
    else:
        cmd(s, 0x03, 0)
    cmd(s, 0x08, 0)                # chip AGC off
    time.sleep(0.3)
    # throw away the first half second (sampled before the settings took)
    skip = a.rate  # bytes: half a second of I/Q pairs
    while skip > 0:
        b = s.recv(min(1 << 20, skip))
        if not b:
            break
        skip -= len(b)
    want = int(a.rate * a.secs) * 2
    got = 0
    t0 = time.time()
    with open(a.out, "wb") as f:
        while got < want:
            b = s.recv(min(1 << 20, want - got))
            if not b:
                break
            f.write(b)
            got += len(b)
    dt = time.time() - t0
    print(f"{got / 2 / a.rate:.1f} s of samples in {dt:.1f} s ({got / dt / 2 / a.rate * 100:.0f}% of real time)")


if __name__ == "__main__":
    main()
