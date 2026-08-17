#!/usr/bin/env python3

import argparse
import re
import socket
import string
import sys
from typing import Dict, Iterable, List


DEFAULT_PORTS = [1414, 1415, 1416, 1417, 1418, 1419]
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 2.0
MAX_READ = 4096
SCRIPT_VERSION = "0.2.0"
IBM_MQ_PROBE = (
    b"TSH\x20\x00\x00\x00\xEC\x01\x01\x31\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x01\x11\x04\xB8\x00\x00\x49\x44\x20\x20\x0A\x26\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x7F\xF6\x06\x40\x00\x00\x00\x00\x00\x00"
    b"SYSTEM.ADMIN.SVRCONN\x51\x00\x04\xB8"
    b"nmap-probe\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    b"\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    b"\x20\x20\x20\x20\x20\x20\x20\x20"
    b"\x00\x00\x00\x01\x00\x6A\x00\x00\x00\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF"
    b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x02MQJB00000000CANNED_DATA\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    b"\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    b"\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
)
VERSION_PATTERN = re.compile(r"MQMV(\d{2})(\d{2})(\d{2})(\d{2})([A-Z0-9]{4})\.(\S+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe a host for IBM MQ listeners and print parsed listener metadata."
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Probe only one TCP port instead of the default IBM MQ ports",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Print raw response details in addition to parsed MQ metadata",
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


def decode_ebcdic_strip(data: bytes) -> str:
    return data.decode("cp500", errors="ignore").strip()


def parse_mq_version(raw_version: str) -> str:
    return ".".join(str(int(part)) for part in wrap_version(raw_version))


def wrap_version(raw_version: str) -> List[str]:
    return [raw_version[i : i + 2] for i in range(0, len(raw_version), 2)]


def extract_mq_metadata(data: bytes) -> Dict[str, str]:
    if len(data) < 0xD0:
        return {}

    metadata: Dict[str, str] = {}
    tsh = decode_ebcdic_strip(data[0:4])
    if tsh:
        metadata["header"] = tsh

    declared_length = int.from_bytes(data[4:8], byteorder="big", signed=False)
    if declared_length:
        metadata["declared_length"] = str(declared_length)

    channel = decode_ebcdic_strip(data[0x34:0x48])
    if channel:
        metadata["channel"] = channel

    queue_manager = decode_ebcdic_strip(data[0x4C:0x50])
    if queue_manager:
        metadata["queue_manager"] = queue_manager

    build_marker = decode_ebcdic_strip(data[0xB0:0xD8])
    if build_marker:
        metadata["build_marker"] = build_marker
        match = VERSION_PATTERN.search(build_marker)
        if match:
            metadata["version"] = parse_mq_version("".join(match.groups()[:4]))
            metadata["build_queue_manager"] = match.group(5)
            metadata["build_id"] = match.group(6)

    return metadata


def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            chunk = sock.recv(MAX_READ)
        except socket.timeout:
            break

        if not chunk:
            break
        chunks.append(chunk)
        if len(chunk) < MAX_READ:
            break

    return b"".join(chunks)


def print_parsed_metadata(metadata: Dict[str, str]) -> None:
    print("    parsed:")
    if "header" in metadata:
        print(f"      - header: {metadata['header']}")
    if "declared_length" in metadata:
        print(f"      - declared_length: {metadata['declared_length']}")
    if "channel" in metadata:
        print(f"      - channel: {metadata['channel']}")
    if "queue_manager" in metadata:
        print(f"      - queue_manager: {metadata['queue_manager']}")
    if "build_marker" in metadata:
        print(f"      - build_marker: {metadata['build_marker']}")
    if "version" in metadata:
        print(f"      - version: {metadata['version']}")
    if "build_id" in metadata:
        print(f"      - build_id: {metadata['build_id']}")


def probe_port(host: str, port: int, debug: bool) -> int:
    print(f"[+] Probing {host}:{port}")
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(READ_TIMEOUT)
            passive_data = recv_all(sock)
            if passive_data:
                data = passive_data
                response_mode = "passive banner"
            else:
                sock.sendall(IBM_MQ_PROBE)
                data = recv_all(sock)
                response_mode = "IBM MQ probe response"
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
        if debug:
            print("    no passive banner and no reply to IBM MQ probe")
        else:
            print("    no MQ metadata returned")
        return 0

    metadata = extract_mq_metadata(data)
    if metadata:
        print_parsed_metadata(metadata)
    else:
        print("    no MQ metadata parsed")

    if not debug:
        return 0

    print(f"    received {len(data)} bytes ({response_mode})")
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

    print(f"mqinfo.py v{SCRIPT_VERSION}")
    print()

    rc = 0
    for port in ports:
        if not 1 <= port <= 65535:
            print(f"invalid port: {port}", file=sys.stderr)
            return 2
        rc |= probe_port(args.host, port, args.debug)

    print()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
