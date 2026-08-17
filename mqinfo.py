#!/usr/bin/env python3

import argparse
import ipaddress
import re
import socket
import string
import sys
from typing import Dict, Iterable, List


DEFAULT_PORTS = [1414, 1415, 1416, 1417, 1418, 1419]
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 2.0
MAX_READ = 4096
SCRIPT_VERSION = "0.2.6"
BANNER_TITLE = "IBM MQ Info Tool"
TSH_HEADER_SIZE = 28
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


class BannerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        banner = f"\n{BANNER_TITLE} v{SCRIPT_VERSION}\n\n"
        return banner + super().format_help() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = BannerArgumentParser(
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
    parser.add_argument(
        "--socks",
        help="Connect through a SOCKS5 proxy specified as host:port or socks5://host:port",
    )
    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit(0)
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


def parse_socks_proxy(proxy: str) -> tuple[str, int]:
    value = proxy.strip()
    if "://" in value:
        scheme, value = value.split("://", 1)
        if scheme.lower() != "socks5":
            raise ValueError(f"unsupported proxy scheme: {scheme}")

    if ":" not in value:
        raise ValueError("proxy must be in host:port format")

    host, port_text = value.rsplit(":", 1)
    host = host.strip()
    if not host:
        raise ValueError("proxy host cannot be empty")

    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid proxy port: {port_text}") from exc

    if not 1 <= port <= 65535:
        raise ValueError(f"invalid proxy port: {port}")

    return host, port


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("connection closed while reading from SOCKS proxy")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def build_socks5_address(target_host: str, target_port: int) -> bytes:
    try:
        host_ip = ipaddress.ip_address(target_host)
    except ValueError:
        encoded_host = target_host.encode("idna")
        if len(encoded_host) > 255:
            raise ValueError("target hostname is too long for SOCKS5")
        return b"\x03" + bytes([len(encoded_host)]) + encoded_host + target_port.to_bytes(2, "big")

    if host_ip.version == 4:
        return b"\x01" + host_ip.packed + target_port.to_bytes(2, "big")
    return b"\x04" + host_ip.packed + target_port.to_bytes(2, "big")


def skip_socks5_bound_address(sock: socket.socket, atyp: int) -> None:
    if atyp == 0x01:
        recv_exact(sock, 4 + 2)
        return
    if atyp == 0x04:
        recv_exact(sock, 16 + 2)
        return
    if atyp == 0x03:
        host_length = recv_exact(sock, 1)[0]
        recv_exact(sock, host_length + 2)
        return
    raise OSError(f"unsupported SOCKS5 address type in reply: {atyp}")


def socks5_connect(sock: socket.socket, target_host: str, target_port: int) -> None:
    sock.sendall(b"\x05\x01\x00")
    method_reply = recv_exact(sock, 2)
    if method_reply[0] != 0x05:
        raise OSError("invalid SOCKS5 proxy response version")
    if method_reply[1] != 0x00:
        raise OSError("SOCKS5 proxy requires unsupported authentication")

    request = b"\x05\x01\x00" + build_socks5_address(target_host, target_port)
    sock.sendall(request)

    reply = recv_exact(sock, 4)
    if reply[0] != 0x05:
        raise OSError("invalid SOCKS5 proxy reply version")
    if reply[1] != 0x00:
        raise OSError(f"SOCKS5 proxy connect failed with status 0x{reply[1]:02x}")

    skip_socks5_bound_address(sock, reply[3])


def open_socket(target_host: str, target_port: int, socks_proxy: str | None) -> socket.socket:
    if not socks_proxy:
        return socket.create_connection((target_host, target_port), timeout=CONNECT_TIMEOUT)

    proxy_host, proxy_port = parse_socks_proxy(socks_proxy)
    sock = socket.create_connection((proxy_host, proxy_port), timeout=CONNECT_TIMEOUT)
    try:
        socks5_connect(sock, target_host, target_port)
        return sock
    except Exception:
        sock.close()
        raise


def extract_mq_metadata(data: bytes) -> Dict[str, str]:
    if len(data) < TSH_HEADER_SIZE:
        return {}

    metadata: Dict[str, str] = {}
    tsh = decode_ebcdic_strip(data[0:4])
    if tsh:
        metadata["header"] = tsh

    declared_length = int.from_bytes(data[4:8], byteorder="big", signed=False)
    if declared_length:
        metadata["declared_length"] = str(declared_length)

    id_base = TSH_HEADER_SIZE

    tsh_ccsid = int.from_bytes(data[24:26], byteorder="big", signed=False)
    if tsh_ccsid:
        metadata["tsh_ccsid"] = str(tsh_ccsid)

    channel = decode_ebcdic_strip(data[id_base + 24 : id_base + 44])
    if channel:
        metadata["channel"] = channel

    queue_manager = decode_ebcdic_strip(data[id_base + 48 : id_base + 96])
    if queue_manager:
        metadata["queue_manager"] = queue_manager

    if len(data) >= id_base + 48:
        ccsid = int.from_bytes(data[id_base + 46 : id_base + 48], byteorder="big", signed=False)
        if ccsid:
            metadata["ccsid"] = str(ccsid)

    if len(data) >= id_base + 100:
        heartbeat_interval = int.from_bytes(
            data[id_base + 96 : id_base + 100], byteorder="big", signed=False
        )
        metadata["heartbeat_interval"] = str(heartbeat_interval)

    product_id = decode_ebcdic_strip(data[id_base + 148 : id_base + 160])
    if product_id:
        metadata["product_id"] = product_id

    build_marker = decode_ebcdic_strip(data[id_base + 148 : id_base + 196])
    if build_marker:
        metadata["build_marker"] = build_marker
        match = VERSION_PATTERN.search(build_marker)
        if match:
            metadata["version"] = parse_mq_version("".join(match.groups()[:4]))
            metadata["build_queue_manager"] = match.group(5)
            metadata["build_id"] = match.group(6)

    queue_manager_id = decode_ebcdic_strip(data[id_base + 160 : id_base + 208])
    if queue_manager_id:
        metadata["queue_manager_id"] = queue_manager_id

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
    if "tsh_ccsid" in metadata:
        print(f"      - tsh_ccsid: {metadata['tsh_ccsid']}")
    if "channel" in metadata:
        print(f"      - channel: {metadata['channel']}")
    if "queue_manager" in metadata:
        print(f"      - queue_manager: {metadata['queue_manager']}")
    if "ccsid" in metadata:
        print(f"      - ccsid: {metadata['ccsid']}")
    if "heartbeat_interval" in metadata:
        print(f"      - heartbeat_interval: {metadata['heartbeat_interval']}")
    if "product_id" in metadata:
        print(f"      - product_id: {metadata['product_id']}")
    if "build_marker" in metadata:
        print(f"      - build_marker: {metadata['build_marker']}")
    if "version" in metadata:
        print(f"      - version: {metadata['version']}")
    if "build_id" in metadata:
        print(f"      - build_id: {metadata['build_id']}")
    if "queue_manager_id" in metadata:
        print(f"      - queue_manager_id: {metadata['queue_manager_id']}")


def probe_port(host: str, port: int, debug: bool, socks_proxy: str | None) -> int:
    print(f"[+] Probing {host}:{port}")
    try:
        with open_socket(host, port, socks_proxy) as sock:
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

    print()
    print(f"{BANNER_TITLE} v{SCRIPT_VERSION}")
    print()

    rc = 0
    for port in ports:
        if not 1 <= port <= 65535:
            print(f"invalid port: {port}", file=sys.stderr)
            return 2
        try:
            rc |= probe_port(args.host, port, args.debug, args.socks)
        except ValueError as exc:
            print(f"invalid SOCKS proxy: {exc}", file=sys.stderr)
            return 2

    print()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
