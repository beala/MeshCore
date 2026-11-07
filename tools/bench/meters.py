#!/usr/bin/env python3
"""Utility meters on 915 MHz: Neptune R900 (water) and Itron ERT SCM / SCM+ (gas, electric, water).

All send on-off keyed chips at 32.768 kchip/s (docs/utility_meters.md):
  R900   31 chips of 1010.., sync A9666965, then 168 chips: 42 groups of 4 chips, each one of six
         codes (a base-6 digit), two digits per 5 bits -> 104 bits. No CRC: the codes check it.
  SCM+   Manchester (data 1 = chips 10), 16 bytes: 16 A3, protocol 1E, endpoint type, id (4),
         consumption (4), tamper (2), CRC-16/CCITT (init 0x0971) of bytes 2-13
  SCM    Manchester, 96 bits: a 21-bit sync 1F2A60, the id's high bits, tamper, type, consumption
         (24), the id's low bits (24), CRC-16 poly 0x6F63 of bytes 2-11

  meters.py read rec.cu8 [--rate 2400000] [--vectors]   frames in an RTL-SDR recording (any rate)
  meters.py chips r900|scm|scmplus <id> <total> [...]   the chips a meter would send, as hex,
                                                         for the bench sender ('meter tx')
  meters.py selftest
"""
import argparse
import sys

CHIP_RATE = 32768.0

# ---- R900 ----
R900_SYNC = 0xA9666965
R900_CODES = [0b0011, 0b0101, 0b0110, 0b1100, 0b1010, 0b1001]   # base-6 digit -> 4 chips
R900_DIGIT = {c: d for d, c in enumerate(R900_CODES)}


def bits_to_int(bits):
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v


def int_to_bits(v, n):
    return [(v >> (n - 1 - i)) & 1 for i in range(n)]


def bits_to_bytes(bits):
    return bytes(bits_to_int(bits[i:i + 8]) for i in range(0, len(bits) - len(bits) % 8, 8))


def r900_decode(chips):
    """168 chips after the sync -> 13 bytes, or None"""
    if len(chips) < 168:
        return None
    bits = []
    for i in range(21):
        hi = R900_DIGIT.get(bits_to_int(chips[8 * i:8 * i + 4]))
        lo = R900_DIGIT.get(bits_to_int(chips[8 * i + 4:8 * i + 8]))
        if hi is None or lo is None:
            return None
        v = hi * 6 + lo
        if v > 31:
            return None
        bits += int_to_bits(v, 5)
    return bits_to_bytes(bits[:104])


def r900_fields(b):
    return dict(kind="R900", id=int.from_bytes(b[0:4], "big"), unkn1=b[4] >> 4, type=b[4] & 15,
                nouse=(b[5] >> 2) & 7, backflow=b[5] & 3,
                total=((b[9] >> 5) << 24) | int.from_bytes(b[6:9], "big"),
                leak=(b[9] >> 2) & 7, leaknow=b[9] & 3, extra=b[10:13].hex())


def r900_chips(meter_id, total, mtype=3, nouse=0, backflow=0, leak=0, leaknow=0, unkn1=10, extra=b"\0\0\0"):
    b = bytearray(13)
    b[0:4] = meter_id.to_bytes(4, "big")
    b[4] = (unkn1 << 4) | mtype
    b[5] = (nouse << 2) | backflow
    b[6:9] = (total & 0xFFFFFF).to_bytes(3, "big")
    b[9] = ((total >> 24) << 5) | (leak << 2) | leaknow
    b[10:13] = extra
    bits = []
    for x in b:
        bits += int_to_bits(x, 8)
    bits.append(0)   # 105 bits: 21 groups of 5
    chips = [1, 0] * 15 + [1] + int_to_bits(R900_SYNC, 32)
    for i in range(21):
        v = bits_to_int(bits[5 * i:5 * i + 5])
        chips += int_to_bits(R900_CODES[v // 6], 4) + int_to_bits(R900_CODES[v % 6], 4)
    return chips


# ---- Itron ERT ----
def crc16(data, poly, init):
    c = init
    for x in data:
        c ^= x << 8
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def manchester(bits, one=(1, 0)):
    out = []
    for b in bits:
        out += list(one) if b else list(one[::-1])
    return out


def unmanchester(chips, one=(1, 0)):
    bits = []
    for i in range(0, len(chips) - 1, 2):
        p = (chips[i], chips[i + 1])
        if p == one:
            bits.append(1)
        elif p == one[::-1]:
            bits.append(0)
        else:
            return None
    return bits


def scmplus_fields(b):
    if len(b) < 16 or b[0:2] != b"\x16\xa3" or crc16(b[2:14], 0x1021, 0x0971) != int.from_bytes(b[14:16], "big"):
        return None
    return dict(kind="SCM+", protocol=b[2], type=b[3], id=int.from_bytes(b[4:8], "big"),
                total=int.from_bytes(b[8:12], "big"), tamper=int.from_bytes(b[12:14], "big"))


def scmplus_bytes(meter_id, total, etype=0xFC, tamper=0x1208):
    b = bytearray(b"\x16\xa3\x1e") + bytes([etype]) + meter_id.to_bytes(4, "big") + total.to_bytes(4, "big") + tamper.to_bytes(2, "big")
    return bytes(b) + crc16(b[2:14], 0x1021, 0x0971).to_bytes(2, "big")


SCM_SYNC = 0x1F2A60   # 21 bits


def scm_fields(bits):
    """96 bits starting with the 21-bit sync"""
    if len(bits) < 96 or bits_to_int(bits[:21]) != SCM_SYNC:
        return None
    b = bits_to_bytes(bits[:96])
    if crc16(b[2:12], 0x6F63, 0) != 0 or not any(b[2:10]):
        return None
    return dict(kind="SCM", id=((b[2] & 6) << 23) | int.from_bytes(b[7:10], "big"), ptamper=b[3] >> 6,
                type=(b[3] >> 2) & 15, etamper=b[3] & 3, total=int.from_bytes(b[4:7], "big"))


def scm_bits(meter_id, total, etype=12, ptamper=0, etamper=0):
    bits = int_to_bits(SCM_SYNC, 21) + int_to_bits((meter_id >> 24) & 3, 2) + [0]
    bits += int_to_bits(ptamper, 2) + int_to_bits(etype, 4) + int_to_bits(etamper, 2)
    bits += int_to_bits(total, 24) + int_to_bits(meter_id & 0xFFFFFF, 24)
    b = bits_to_bytes(bits)   # 10 bytes
    c = crc16(b[2:10], 0x6F63, 0)
    return bits + int_to_bits(c, 16)


# ---- reading a recording ----
def find(chips, word, n):
    """positions just after each match of an n-bit word"""
    import numpy as np
    w = np.array(int_to_bits(word, n), dtype=np.int8)
    c = np.array(chips, dtype=np.int8)
    if len(c) < n:
        return []
    win = np.lib.stride_tricks.sliding_window_view(c, n)
    return [int(i) + n for i in np.flatnonzero((win == w).all(axis=1))]


def decode_chips(chips):
    """every meter frame in one burst's chips: (fields, chips after the sync, sync name)"""
    out = []
    for at in find(chips, R900_SYNC, 32):
        b = r900_decode(chips[at:at + 168])
        if b:
            out.append((r900_fields(b), chips[at:at + 168], "r900"))
    for one in ((1, 0), (0, 1)):
        name = "10" if one == (1, 0) else "01"
        # no preamble: the frame starts with the sync, whose first chip (a 0 bit's 'off') can't be seen
        sync = manchester(int_to_bits(0x16A3, 16), one)[1:]
        for at in find(chips, bits_to_int(sync), 31):
            bits = unmanchester(chips[at:at + 224], one)
            if bits and len(bits) == 112:
                f = scmplus_fields(b"\x16\xa3" + bits_to_bytes(bits))
                if f:
                    out.append((f, chips[at:at + 224], "scm+ one=" + name))
        # SCM: the sync's last 16 bits (2A60) as chips, then 75 bits
        sync = manchester(int_to_bits(0x2A60, 16), one)
        for at in find(chips, bits_to_int(sync), 32):
            bits = unmanchester(chips[at:at + 150], one)
            if bits and len(bits) == 75:
                f = scm_fields(int_to_bits(SCM_SYNC, 21) + bits)
                if f:
                    out.append((f, chips[at:at + 150], "scm one=" + name))
    return out


def read(path, rate, vectors):
    import numpy as np
    raw = np.memmap(path, dtype=np.uint8, mode="r")
    n = len(raw) // 2
    spc = rate / CHIP_RATE
    found = []
    stats = {}
    block = int(rate)
    for start in range(0, n, block):
        x = raw[2 * start:2 * min(n, start + block + int(rate * 0.06))].astype(np.float32) - 127.5
        z = x[0::2] + 1j * x[1::2]
        p = np.abs(z) ** 2
        sm = np.convolve(p, np.ones(int(spc)) / int(spc), mode="same")
        floor = np.median(sm)
        on = sm > floor * 10 ** 1.0
        edges = np.flatnonzero(np.diff(on.astype(np.int8)))
        # bursts: on-stretches closer than 4 chips joined (the chips themselves switch on and off)
        runs = []
        i = 0
        while i + 1 < len(edges):
            s, e = edges[i], edges[i + 1]
            i += 2
            while i + 1 < len(edges) and edges[i] - e < 4 * spc:
                e = edges[i + 1]
                i += 2
            if e - s > 100 * spc and s < block:
                runs.append((s, e))
        for s, e in runs:
            seg = z[max(0, s - int(8 * spc)):e + int(8 * spc)]
            # the burst's own frequency: mix it to 0 and keep about 100 kHz
            f = np.fft.fftfreq(len(seg), 1 / rate)
            pk = f[np.argmax(np.abs(np.fft.fft(seg)))]
            bb = seg * np.exp(-2j * np.pi * pk * np.arange(len(seg)) / rate)
            k = max(1, int(spc / 3))
            mag = np.abs(np.convolve(bb, np.ones(k) / k, mode="same"))
            hi, lo = np.percentile(mag, 90), np.percentile(mag, 10)
            b = mag > (hi + lo) / 2
            ed = np.flatnonzero(np.diff(b.astype(np.int8)))
            if len(ed) < 10:
                continue
            # chip timing from the edges, again every 32 chips (the clocks differ by a few ppm)
            chips = []
            t = float(ed[0]) + spc / 2
            while t < len(b) - 1:
                near = ed[(ed > t - 16 * spc) & (ed < t + 16 * spc)]
                if len(near):
                    ph = np.angle(np.mean(np.exp(2j * np.pi * (near - ed[0]) / spc))) / (2 * np.pi) * spc
                    base = ed[0] + ph + spc / 2
                    t = base + round((t - base) / spc) * spc
                if int(t) >= len(b):
                    break
                chips.append(int(b[int(t)]))
                t += spc
            res = decode_chips(chips)
            when = (start + s) / rate
            for fields, after, how in res:
                fields["freq_khz"] = round(pk / 1000, 1)
                fields["at_s"] = round(when, 3)
                fields["db"] = round(10 * np.log10(hi ** 2 / max(lo ** 2, 1e-3)), 1)
                found.append((fields, after, how))
                stats[how] = stats.get(how, 0) + 1
            if not res:
                stats["unknown burst"] = stats.get("unknown burst", 0) + 1
    seen = set()
    for fields, after, how in found:
        key = (fields["kind"], fields["id"], fields["at_s"])
        if key in seen:
            continue
        seen.add(key)
        print(fields, how)
        if vectors:
            print("   chips after sync:", bits_to_bytes(after + [0] * (-len(after) % 8)).hex())
    print("bursts:", stats)


def radio_chips(kind, meter_id, total, **kw):
    """the chips the radio hands over after its sync word (src/helpers/meters/Meters.h), as bytes"""
    if kind == "r900":
        c = r900_chips(meter_id, total, **kw)[31 + 32:]
    elif kind == "scmplus":
        c = manchester(int_to_bits(int.from_bytes(scmplus_bytes(meter_id, total, **kw), "big"), 128))[48:]
    else:
        c = manchester(scm_bits(meter_id, total, **kw))[40:]
    return bits_to_bytes(c + [0] * (-len(c) % 8))


def vectors():
    """C test data: made-up meters (never real ones: the readings are someone's)"""
    cases = [("r900", "R900_LEAK", 12345678, 1234567, dict(leak=3, leaknow=1, backflow=1, nouse=2)),
             ("r900", "R900_BIG", 3000000001, 0x7FFFFFF, {}),
             ("scmplus", "SCMPLUS_GAS", 87654321, 98765, dict(etype=0xFC, tamper=0x1208)),
             ("scmplus", "SCMPLUS_ELECTRIC", 55500011, 4000000, dict(etype=0x07)),
             ("scm", "SCM_GAS", 23456789, 345678, dict(etype=12)),
             ("scm", "SCM_ELECTRIC", 41234567, 16000000, dict(etype=7, ptamper=1, etamper=2))]
    print("// made by tools/bench/meters.py vectors")
    for kind, name, i, t, kw in cases:
        b = radio_chips(kind, i, t, **kw)
        print(f"static const uint8_t {name}[] = {{" + ", ".join(f"0x{x:02x}" for x in b) + "};")


def selftest():
    c = r900_chips(1234567890, 1200345, leak=6, leaknow=2, extra=bytes.fromhex("910173"))
    r = decode_chips(c)
    assert r and r[0][0]["id"] == 1234567890 and r[0][0]["total"] == 1200345 and r[0][0]["leaknow"] == 2, r
    for one in ((1, 0), (0, 1)):
        c = [1, 0] * 20 + manchester([int(x) for x in format(int.from_bytes(scmplus_bytes(87654321, 31337), "big"), "0128b")], one)
        r = decode_chips(c)
        assert r and r[0][0]["kind"] == "SCM+" and r[0][0]["id"] == 87654321 and r[0][0]["total"] == 31337, r
        c = [1, 0] * 10 + manchester(scm_bits(23456789, 485732), one)
        r = decode_chips(c)
        assert r and r[0][0]["kind"] == "SCM" and r[0][0]["id"] == 23456789 and r[0][0]["total"] == 485732, r
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("read")
    a.add_argument("file")
    a.add_argument("--rate", type=float, default=2400000)
    a.add_argument("--vectors", action="store_true")
    a = sub.add_parser("chips")
    a.add_argument("kind", choices=["r900", "scm", "scmplus"])
    a.add_argument("id", type=int)
    a.add_argument("total", type=int)
    a.add_argument("--leak", type=int, default=0)
    a.add_argument("--leaknow", type=int, default=0)
    a.add_argument("--one", default="10", help="Manchester: the chips for a data 1")
    sub.add_parser("selftest")
    sub.add_parser("vectors")
    a = ap.parse_args()
    if a.cmd == "read":
        read(a.file, a.rate, a.vectors)
    elif a.cmd == "chips":
        one = (1, 0) if a.one == "10" else (0, 1)
        if a.kind == "r900":
            c = r900_chips(a.id, a.total, leak=a.leak, leaknow=a.leaknow)
        elif a.kind == "scmplus":
            c = [1, 0] * 20 + manchester(int_to_bits(int.from_bytes(scmplus_bytes(a.id, a.total), "big"), 128), one)
        else:
            c = [1, 0] * 10 + manchester(scm_bits(a.id, a.total), one)
        print(bits_to_bytes(c + [0] * (-len(c) % 8)).hex(), len(c))
    elif a.cmd == "vectors":
        vectors()
    else:
        selftest()


if __name__ == "__main__":
    sys.exit(main())
