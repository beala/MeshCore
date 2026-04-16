#!/usr/bin/env python3
"""Decode MeshCore RS232Bridge packets from a serial device."""

import argparse
import serial
import struct
import sys
from datetime import datetime

MAGIC = 0xC03E
BAUD = 115200

PAYLOAD_TYPES = {
    0x00: "REQ",
    0x01: "RESPONSE",
    0x02: "TXT_MSG",
    0x03: "ACK",
    0x04: "ADVERT",
    0x05: "GRP_TXT",
    0x06: "GRP_DATA",
    0x07: "ANON_REQ",
    0x08: "PATH",
    0x09: "TRACE",
    0x0A: "MULTIPART",
    0x0B: "CONTROL",
    0x0F: "RAW_CUSTOM",
}

ROUTE_TYPES = {
    0x00: "TRANSPORT_FLOOD",
    0x01: "FLOOD",
    0x02: "DIRECT",
    0x03: "TRANSPORT_DIRECT",
}


def fletcher16(data: bytes) -> int:
    s1, s2 = 0, 0
    for b in data:
        s1 = (s1 + b) % 255
        s2 = (s2 + s1) % 255
    return (s2 << 8) | s1


def decode_packet(payload: bytes) -> dict:
    if len(payload) < 2:
        return {"error": "payload too short"}

    i = 0
    header = payload[i]; i += 1

    route_type = header & 0x03
    payload_type = (header >> 2) & 0x0F
    payload_ver = (header >> 6) & 0x03
    has_transport = route_type in (0x00, 0x03)

    transport_codes = None
    if has_transport:
        if i + 4 > len(payload):
            return {"error": "truncated transport codes"}
        transport_codes = struct.unpack_from("<HH", payload, i)
        i += 4

    if i >= len(payload):
        return {"error": "missing path_len"}
    path_len_byte = payload[i]; i += 1

    hash_count = path_len_byte & 63
    hash_size = (path_len_byte >> 6) + 1
    if hash_size == 4:
        return {"error": "reserved hash_size"}
    path_byte_len = hash_count * hash_size

    if i + path_byte_len > len(payload):
        return {"error": "truncated path"}
    path_bytes = payload[i:i + path_byte_len]
    i += path_byte_len

    pkt_payload = payload[i:]

    result = {
        "route": ROUTE_TYPES.get(route_type, f"0x{route_type:02X}"),
        "type": PAYLOAD_TYPES.get(payload_type, f"0x{payload_type:02X}"),
        "ver": payload_ver,
        "path_hashes": [path_bytes[j*hash_size:(j+1)*hash_size].hex() for j in range(hash_count)],
        "payload_len": len(pkt_payload),
        "payload_hex": pkt_payload.hex(),
    }
    if transport_codes:
        result["transport_codes"] = [f"0x{c:04X}" for c in transport_codes]
    return result


def read_packets(port: str):
    ser = serial.Serial(port, BAUD, timeout=1)
    print(f"Listening on {port} at {BAUD} baud...\n")

    buf = bytearray()

    while True:
        chunk = ser.read(256)
        if chunk:
            buf.extend(chunk)

        while len(buf) >= 4:
            # Find magic
            if not (buf[0] == 0xC0 and buf[1] == 0x3E):
                buf.pop(0)
                continue

            if len(buf) < 4:
                break

            pkt_len = (buf[2] << 8) | buf[3]
            total = 4 + pkt_len + 2  # magic(2) + len(2) + payload(n) + checksum(2)

            if len(buf) < total:
                break  # wait for more data

            pkt_payload = bytes(buf[4:4 + pkt_len])
            recv_checksum = (buf[4 + pkt_len] << 8) | buf[5 + pkt_len]
            calc_checksum = fletcher16(pkt_payload)

            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            if recv_checksum != calc_checksum:
                print(f"[{ts}] CHECKSUM MISMATCH (got 0x{recv_checksum:04X}, expected 0x{calc_checksum:04X})")
            else:
                decoded = decode_packet(pkt_payload)
                print(f"[{ts}] len={pkt_len} crc=0x{recv_checksum:04X}")
                for k, v in decoded.items():
                    print(f"  {k}: {v}")
            print()

            del buf[:total]


def main():
    parser = argparse.ArgumentParser(description="Decode MeshCore RS232Bridge packets")
    parser.add_argument("device", help="Serial device path (e.g. /dev/ttyUSB0)")
    args = parser.parse_args()

    try:
        read_packets(args.device)
    except KeyboardInterrupt:
        print("\nStopped.")
    except serial.SerialException as e:
        print(f"Serial error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
