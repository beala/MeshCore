#!/usr/bin/env python3
"""FIS-B ground station frames (UAT uplink, 978 MHz): build and read them, for bench tests.

Real ground stations can't be heard from the bench, so this makes frames that look like theirs:
METAR text in DLAC, in a FIS-B APDU (product 413), in an information frame, after the 8-byte UAT
header; 432 bytes as 6 Reed-Solomon (92,72) blocks interleaved into 552. The format is as
documented by dump978 (mutability/dump978 uat_decode.c, fec.c); docs/airport_weather.md.

  fisb.py frame "METAR KLMO 052153Z 31012KT 10SM FEW080 12/M01 A3002" [...]   552 bytes, hex
  fisb.py iq out.cu8 "METAR ..." [...]     the frame on air as RTL-SDR samples (2.083333 MS/s,
                                           unsigned 8-bit IQ): 'dump978 < out.cu8 | uat2text'
  fisb.py read [file]                      dump978's "+..." lines (or 552-byte hex frames): the
                                           text reports in them
  fisb.py vectors sample-data.txt > test/test_fisb/vectors.inc   C test vectors: real frames
                                           from dump978's sample data, and made ones with errors
  fisb.py selftest

Nothing here transmits: bench_tx sends with the XIAO at 915 MHz. Never on 978 MHz.
"""
import math
import sys

UPLINK_SYNC = 0x153225B1D   # 36 bits
BLOCKS, BLOCK_DATA, BLOCK_LEN = 6, 72, 92
DATA_LEN = BLOCKS * BLOCK_DATA    # 432
FRAME_LEN = BLOCKS * BLOCK_LEN    # 552
PRODUCT_TEXT = 413                # generic text, DLAC (METAR, TAF, SIGMET, PIREP, ...)

# ---- GF(256), x^8 + x^7 + x^2 + x + 1; RS with first root 120, primitive element 1 ----
EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x187
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def gmul(a, b):
    return EXP[LOG[a] + LOG[b]] if a and b else 0


def rs_generator(nroots, fcr=120):
    g = [1]   # highest power first
    for i in range(nroots):
        root = EXP[(fcr + i) % 255]
        out = g + [0]
        for j in range(len(g)):
            out[j + 1] ^= gmul(g[j], root)
        g = out
    return g


GEN20 = rs_generator(20)


def rs_encode(data, nroots=20):
    """Systematic: data then nroots parity bytes (byte 0 the highest power of x)."""
    gen = GEN20 if nroots == 20 else rs_generator(nroots)
    rem = [0] * nroots
    for d in data:
        f = d ^ rem[0]
        rem = rem[1:] + [0]
        if f:
            for j in range(nroots):
                rem[j] ^= gmul(gen[j + 1], f)
    return bytes(data) + bytes(rem)


def rs_syndromes_ok(cw, nroots=20, fcr=120):
    for i in range(nroots):
        root = EXP[(fcr + i) % 255]
        s = 0
        for c in cw:
            s = gmul(s, root) ^ c
        if s:
            return False
    return True


def interleave(data432):
    assert len(data432) == DATA_LEN
    blocks = [rs_encode(data432[b * BLOCK_DATA:(b + 1) * BLOCK_DATA]) for b in range(BLOCKS)]
    out = bytearray(FRAME_LEN)
    for b in range(BLOCKS):
        for i in range(BLOCK_LEN):
            out[i * BLOCKS + b] = blocks[b][i]   # byte i of the frame is block i mod 6
    return bytes(out)


def deinterleave(frame552):
    """The 432 data bytes, or None if a block has errors (no correction here: the C code does that)."""
    data = bytearray()
    for b in range(BLOCKS):
        cw = bytes(frame552[i * BLOCKS + b] for i in range(BLOCK_LEN))
        if not rs_syndromes_ok(cw):
            return None
        data += cw[:BLOCK_DATA]
    return bytes(data)


# ---- DLAC: 6-bit characters, 4 in 3 bytes ----
DLAC = "\x03ABCDEFGHIJKLMNOPQRSTUVWXYZ\x1a\t\x1e\n| !\"#$%&'()*+,-./0123456789:;<=>?"


def dlac_encode(text):
    codes = []
    i = 0
    while i < len(text):
        c = text[i].upper()
        if c == " ":   # a run of 2+ spaces: tab and the count, as stations do for indents
            n = 1
            while i + n < len(text) and text[i + n] == " " and n < 63:
                n += 1
            if n >= 2:
                codes += [28, n]
                i += n
                continue
        if c == "\t":
            c = " "
        k = DLAC.find(c)
        codes.append(k if k >= 0 and k != 28 else DLAC.index("?"))
        i += 1
    while len(codes) % 4:
        codes.append(0)   # ETX pads the last 3 bytes
    out = bytearray()
    for j in range(0, len(codes), 4):
        a, b, c, d = codes[j:j + 4]
        out += bytes([(a << 2) | (b >> 4), ((b & 15) << 4) | (c >> 2), ((c & 3) << 6) | d])
    return bytes(out)


def dlac_decode(data):
    codes = []
    for j in range(0, len(data) - len(data) % 3, 3):
        x = (data[j] << 16) | (data[j + 1] << 8) | data[j + 2]
        codes += [(x >> 18) & 63, (x >> 12) & 63, (x >> 6) & 63, x & 63]
    rem = len(data) % 3   # dump978 reads a trailing 1 or 2 bytes too
    if rem:
        x = int.from_bytes(bytes(data[-rem:]) + bytes(3 - rem), "big")
        codes += [(x >> 18) & 63, (x >> 12) & 63, (x >> 6) & 63, x & 63][:rem + 1]
    out = []
    tab = False
    for c in codes:
        if tab:
            out.append(" " * c)
            tab = False
        elif c == 28:
            tab = True
        else:
            out.append(DLAC[c])
    return "".join(out)


# ---- APDU, information frame, UAT header ----
def apdu(payload, product=PRODUCT_TEXT, hours=0, minutes=0):
    """FIS-B APDU header, time option 0 (hours, minutes): flags a/g/p 0, product, s 0."""
    h = bytes([(product >> 6) & 0x1F, ((product & 0x3F) << 2) | 0,   # t_opt bit 1 = 0
               (0 << 7) | ((hours & 31) << 2) | (minutes >> 4), (minutes & 15) << 4])
    return h + payload


def info_frame(data, ftype=0):
    n = len(data)
    assert n < 512
    return bytes([n >> 1, ((n & 1) << 7) | (ftype & 15)]) + data


def uat_header(lat=40.164, lon=-105.163, slot=7, tisb=0):
    raw_lat = int(round(lat * 16777216 / 360)) % (1 << 23)   # 23 bits; south as 180+lat
    raw_lon = int(round(lon * 16777216 / 360)) % (1 << 24)
    pos_valid, utc, app_valid = 1, 1, 1
    b = bytearray(8)
    b[0] = raw_lat >> 15
    b[1] = (raw_lat >> 7) & 0xFF
    b[2] = ((raw_lat & 0x7F) << 1) | (raw_lon >> 23)
    b[3] = (raw_lon >> 15) & 0xFF
    b[4] = (raw_lon >> 7) & 0xFF
    b[5] = ((raw_lon & 0x7F) << 1) | pos_valid
    b[6] = (utc << 7) | (app_valid << 5) | (slot & 31)
    b[7] = (tisb & 15) << 4
    return bytes(b)


def build_data(reports, hours=21, minutes=53, **hdr):
    """432 data bytes: one text APDU per information frame, as many reports as fit."""
    body = bytearray()
    for r in reports:
        f = info_frame(apdu(dlac_encode(r.rstrip("\n") + "\n\x1e"), hours=hours, minutes=minutes))
        if len(body) + len(f) > DATA_LEN - 8:
            raise ValueError("too much text for one frame")
        body += f
    data = uat_header(**hdr) + bytes(body)
    return data + bytes(DATA_LEN - len(data))   # 0-length type-0 frame (zeros): no more frames


def build_frame(reports, **kw):
    return interleave(build_data(reports, **kw))


def read_data(data):
    """Text reports in 432 data bytes (as dump978's '+' lines carry them): list of (product, text)."""
    out = []
    if not data[6] & 0x20:   # application data not valid
        return out
    p = 8
    while p + 2 <= DATA_LEN:
        n = (data[p] << 1) | (data[p + 1] >> 7)
        ftype = data[p + 1] & 15
        if n == 0 and ftype == 0:
            break
        if p + 2 + n > DATA_LEN:
            break
        f = data[p + 2:p + 2 + n]
        p += 2 + n
        if ftype != 0 or n < 4:
            continue
        product = ((f[0] & 0x1F) << 6) | (f[1] >> 2)
        s_flag = f[1] & 2
        t_opt = ((f[1] & 1) << 1) | (f[2] >> 7)
        hdr = [4, 5, 5, 6][t_opt]
        if product != PRODUCT_TEXT or s_flag or n < hdr:
            continue
        text = dlac_decode(f[hdr:])
        for rec in text.replace("\x03", "\x1e").split("\x1e"):
            if rec.strip():
                out.append(rec)
    return out


# ---- on air: CPFSK, 1.041667 Mbit/s, +-312.5 kHz, 2 samples per bit ----
def frame_bits(frame):
    bits = [(UPLINK_SYNC >> (35 - i)) & 1 for i in range(36)]
    for b in frame:
        bits += [(b >> (7 - i)) & 1 for i in range(8)]
    return bits


def iq_cu8(frame, lead_bits=400, tail_bits=400, amp=60, noise=4, seed=1):
    import random
    rnd = random.Random(seed)
    bits = [rnd.getrandbits(1) for _ in range(lead_bits)] + frame_bits(frame) + [rnd.getrandbits(1) for _ in range(tail_bits)]
    sps = 2
    dphi = math.pi / 2   # +-312.5 kHz at 2.083333 MS/s: a quarter turn per sample
    out = bytearray()
    phase = 0.0
    on = lambda k: lead_bits // 2 <= k < len(bits) - tail_bits // 2   # quiet noise either side
    for k, b in enumerate(bits):
        for _ in range(sps):
            phase += dphi if b else -dphi
            a = amp if on(k) else 0
            i = 127.5 + a * math.cos(phase) + rnd.gauss(0, noise)
            q = 127.5 + a * math.sin(phase) + rnd.gauss(0, noise)
            out += bytes([max(0, min(255, int(i))), max(0, min(255, int(q)))])
    return bytes(out)


def selftest():
    reps = ["METAR KLMO 052153Z 31012KT 10SM FEW080 12/M01 A3002 RMK AO2 SLP163\n  T01171006=",
            "METAR KBJC 052150Z 30015G22KT 10SM SCT100 13/M03 A3001="]
    data = build_data(reps)
    frame = interleave(data)
    assert len(frame) == FRAME_LEN
    assert deinterleave(frame) == data
    got = read_data(data)
    assert got == [r + "\n" for r in reps], got
    assert dlac_decode(dlac_encode("ABC 123")) .rstrip("\x03") == "ABC 123"
    print("ok:", len(frame), "bytes;", got)


def c_str(s):
    out = ""
    for ch in s:
        if ch == "\n":
            out += "\\n"
        elif ch in "\\\"":
            out += "\\" + ch
        elif 32 <= ord(ch) < 127:
            out += ch
        else:
            out += "\\x%02x\"\"" % ord(ch)
    return '"' + out + '"'


def vectors(path, out=sys.stdout):
    import gzip, random
    lines = (gzip.open(path, "rt") if path.endswith(".gz") else open(path)).read().splitlines()
    real = []
    for line in lines:
        if not line.startswith("+"):
            continue
        d = bytes.fromhex(line[1:].split(";")[0])
        reps = read_data(d)
        kinds = {r.split(" ")[0] for r in reps}
        if reps and ("METAR" in kinds or "TAF" in kinds or "WINDS" in kinds) and len(real) < 6:
            if not any(k in {r.split(" ")[0] for x in real for r in x[1]} for k in kinds) or len(real) < 3:
                real.append((d, reps))
    w = out.write
    w("// Made by tools/bench/fisb.py vectors: real ground station frames (from dump978's sample data,\n")
    w("// already corrected: 432 data bytes) with the text reports in them, and made frames with errors.\n")
    w("struct RealFrame { const char* data_hex; int n; const char* reports[8]; };\n")
    w("static const RealFrame REAL[] = {\n")
    for d, reps in real:
        w("  { \"%s\", %d, {\n" % (d.hex(), len(reps)))
        for r in reps[:8]:
            w("    %s,\n" % c_str(r))
        w("  } },\n")
    w("};\n")
    reps = ["METAR KLMO 052153Z 31012KT 10SM FEW080 12/M01 A3002 RMK AO2 SLP163\n  T01171006=",
            "SPECI KBJC 052201Z 30025G35KT 3SM +TSRA BKN040CB 10/02 A2998="]
    clean = build_frame(reps)
    rnd = random.Random(5)
    ten = bytearray(clean)
    for b in range(BLOCKS):
        for i in rnd.sample(range(BLOCK_LEN), 10):
            ten[i * BLOCKS + b] ^= rnd.randrange(1, 256)
    eleven = bytearray(clean)
    for i in rnd.sample(range(BLOCK_LEN), 11):
        eleven[i * BLOCKS + 3] ^= rnd.randrange(1, 256)
    w("static const char* MADE_REPORTS[] = { %s, %s };\n" % (c_str(reps[0] + "\n"), c_str(reps[1] + "\n")))
    w("static const char* MADE_CLEAN = \"%s\";\n" % clean.hex())
    w("static const char* MADE_TEN_PER_BLOCK = \"%s\";\n" % bytes(ten).hex())
    w("static const char* MADE_ELEVEN_IN_ONE = \"%s\";\n" % bytes(eleven).hex())


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "selftest":
        selftest()
    elif cmd == "frame":
        print(build_frame(argv[2:]).hex())
    elif cmd == "iq":
        with open(argv[2], "wb") as f:
            f.write(iq_cu8(build_frame(argv[3:])))
    elif cmd == "vectors":
        vectors(argv[2])
    elif cmd == "read":
        src = open(argv[2]) if len(argv) > 2 else sys.stdin
        for line in src:
            line = line.strip()
            if line.startswith("+"):
                h = line[1:].split(";")[0]
            elif len(line) == 2 * FRAME_LEN:
                d = deinterleave(bytes.fromhex(line))
                if d is None:
                    print("(RS errors)")
                    continue
                h = d.hex()
            else:
                continue
            for r in read_data(bytes.fromhex(h)):
                print(repr(r))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
