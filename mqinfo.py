#!/usr/bin/env python3

import argparse
import socket
import string
import sys
from typing import Iterable, List


DEFAULT_PORTS = [1414, 1415, 1416, 1417, 1418, 1419]
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 2.0
MAX_READ = 4096


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe a host for IBM MQ listeners and print any banner-like data."
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Probe only one TCP port instead of the default IBM MQ ports",
    )
    return parser.parse_args()


def printable_ascii(data: bytes) -> List[str]:
    text = "".join(chr(byte) if 32 <= byte <= 126 else " " for byte in data)
    parts = [" ".join(chunk.split()) for chunk in text.split("  ")]
    return [part for part in parts if part]


def printable_ebcdic(data: bytes) -> List[str]:
    try:
        decoded = data.decode("cp500", errors="ignore")
    except LookupError:
        return []

    allowed = set(string.ascii_letters + string.digits + "._-/")
    cleaned = "".join(char if char in allowed else " " for char in decoded)
    chunks = [" ".join(chunk.split()) for chunk in cleaned.split("  ")]
    return [chunk for chunk in chunks if len(chunk) >= 4]


def unique_strings(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def probe_port(host: str, port: int) -> int:
    print(f"[+] Probing {host}:{port}")
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(READ_TIMEOUT)
            try:
                data = sock.recv(MAX_READ)
            except socket.timeout:
                data = b""
    except ConnectionRefusedError:
        print("    closed")
        return 1
    except TimeoutError:
        print("    timeout")
        return 1
    except OSError as exc:
        print(f"    error: {exc}")
        return 1

    print("    open")
    if not data:
        print("    no immediate banner data returned")
        return 0

    print(f"    received {len(data)} bytes")
    print(f"    hex: {data.hex()}")

    ascii_hits = unique_strings(printable_ascii(data))
    ebcdic_hits = unique_strings(printable_ebcdic(data))

    if ascii_hits:
        print("    ascii strings:")
        for value in ascii_hits:
            print(f"      - {value}")

    if ebcdic_hits:
        print("    ebcdic(cp500) strings:")
        for value in ebcdic_hits:
            print(f"      - {value}")

    mq_indicators = [
        value for value in ascii_hits + ebcdic_hits if "MQ" in value or "SVRCONN" in value
    ]
    if mq_indicators:
        print("    likely IBM MQ response detected")
    else:
        print("    open port responded, but no clear IBM MQ marker was extracted")

    return 0


def main() -> int:
    args = parse_args()
    ports = [args.port] if args.port else DEFAULT_PORTS

    rc = 0
    for port in ports:
        if not 1 <= port <= 65535:
            print(f"invalid port: {port}", file=sys.stderr)
            return 2
        rc |= probe_port(args.host, port)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
