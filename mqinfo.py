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
SCRIPT_VERSION = "0.2.11"
BANNER_TITLE = "IBM MQ Info Tool"
BANNER_CREDIT = "by Michał Majchrowicz AFINE Team"
BANNER_LINE = f"{BANNER_TITLE} v{SCRIPT_VERSION} {BANNER_CREDIT}"
ANSI_RESET = "\033[0m"
STATUS_COLORS = {
    "open": "\033[32m",
    "closed": "\033[31m",
    "timeout": "\033[33m",
    "error": "\033[35m",
}
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
RFP_ICF_FLAGS = [
    (0x01, "MSG_SEQ_NO"),
    (0x02, "CONVERSION_CAPABLE"),
    (0x04, "SPLIT_MESSAGES"),
    (0x08, "REQUEST_INITIATION"),
    (0x10, "REQUEST_SECURITY"),
    (0x20, "MQREQUEST"),
    (0x40, "SVRCONN_SECURITY"),
    (0x80, "RUNTIME_APP"),
]
RFP_ICF2_FLAGS = [
    (0x01, "DIST_LIST_CAPABLE"),
    (0x02, "FAST_MESSAGES_REQUIRED"),
    (0x04, "RESPONDER_CONVERSION"),
    (0x08, "DUAL_UOW"),
    (0x10, "XAREQUEST"),
    (0x20, "XARUNTIME_APP"),
    (0x40, "SPIREQUEST"),
    (0x80, "TRACE_ROUTE_CAPABLE"),
]
RFP_ICF3_FLAGS = [
    (0x01, "MSG_PROP_CAPABLE"),
    (0x08, "MULTIPLEX_SYNCGET"),
    (0x10, "PWD_PROT_ALWAYS"),
    (0x20, "RET_CONTAG_CAPABLE"),
]
RFP_IEF_FLAGS = [
    (0x01, "CCSID_NOT_SUPPORTED"),
    (0x02, "ENCODING_INVALID"),
    (0x04, "MAX_TRANSMISSION_SIZE"),
    (0x08, "FAP_LEVEL"),
    (0x10, "MAX_MSG_SIZE"),
    (0x20, "MAX_MSG_PER_BATCH"),
    (0x40, "SEQ_WRAP_VALUE"),
    (0x80, "HEARTBEAT_INTERVAL"),
]
RFP_IEF2_FLAGS = [
    (0x01, "HDRCOMPLIST"),
    (0x02, "MSGCOMPLIST"),
    (0x04, "SSL_RESET"),
]
RFP_IEF3_FLAGS = [
    (0x01, "MSG_PROP_CAPABLE"),
    (0x02, "MULTICAST_CAPABLE"),
    (0x04, "MSG_PROP_INT_SEPARATE"),
    (0x08, "MULTIPLEX_SYNCGET"),
    (0x10, "PROT_ALGORITHMS"),
    (0x20, "RET_CONTAG_CAPABLE"),
]
RFP_ERR_CODES = {
    0: "NONE",
    1: "NO_CHANNEL",
    2: "CHANNEL_WRONG_TYPE",
    3: "QM_UNAVAILABLE",
    4: "MSG_SEQUENCE_ERROR",
    5: "QM_TERMINATING",
    6: "CAN_NOT_STORE",
    7: "USER_CLOSED",
    8: "TIMEOUT_EXPIRED",
    9: "TARGET_Q_UNKNOWN",
    10: "PROTOCOL_SEGMENT_TYPE",
    11: "PROTOCOL_LENGTH_ERROR",
    12: "PROTOCOL_INVALID_DATA",
    13: "PROTOCOL_SEGMENT_ERROR",
    14: "PROTOCOL_ID_ERROR",
    15: "PROTOCOL_MSH_ERROR",
    16: "PROTOCOL_GENERAL",
    17: "BATCH_FAILURE",
    18: "MESSAGE_LENGTH_ERROR",
    19: "SEGMENT_NUMBER_ERROR",
    20: "SECURITY_FAILURE",
    21: "WRAP_VALUE_ERROR",
    22: "CHANNEL_UNAVAILABLE",
    23: "CLOSED_BY_EXIT",
    24: "CIPHER_SPEC",
    25: "PEER_NAME",
    26: "SSL_CLIENT_CERTIFICATE",
    27: "RMT_RSRCS_IN_RECOVERY",
    28: "SSL_REFRESHING",
    29: "INVALID_HOBJ",
    30: "CONV_ID_ERROR",
    31: "SOCKET_ACTION_TYPE",
    32: "STANDBY_Q_MGR",
    36: "PASSWORD_PROTECTION",
    37: "MAX_CONNS_LIMIT_REACHED",
    38: "SSL_INVALID_RESET",
    39: "LUWID_MISMATCH",
    40: "CERT_NOT_SELECTED",
    255: "COMMIT_INTERVAL",
}


class BannerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        banner = f"\n{BANNER_LINE}\n\n"
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
    parser.add_argument(
        "--flags",
        action="store_true",
        help="Show raw MQ ID/IDE/error flag fields from the listener response",
    )
    parser.add_argument(
        "--color",
        "-c",
        action="store_true",
        help="Color key status lines to improve readability",
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


def decode_flag_bits(value: int, definitions: list[tuple[int, str]]) -> str:
    names = [name for mask, name in definitions if value & mask]
    return ",".join(names) if names else "none"


def decode_err_code(value: int) -> str:
    return RFP_ERR_CODES.get(value, "unknown")


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

    fap_level = data[id_base + 4]
    if fap_level:
        metadata["fap_level"] = str(fap_level)

    metadata["id_flags"] = f"0x{data[id_base + 5]:02x}"
    metadata["id_flags_decoded"] = decode_flag_bits(data[id_base + 5], RFP_ICF_FLAGS)
    metadata["ide_flags"] = f"0x{data[id_base + 6]:02x}"
    metadata["ide_flags_decoded"] = decode_flag_bits(data[id_base + 6], RFP_IEF_FLAGS)
    metadata["err_flags"] = f"0x{data[id_base + 7]:02x}"
    metadata["err_flags_decoded"] = decode_err_code(data[id_base + 7])

    max_messages_per_batch = int.from_bytes(
        data[id_base + 10 : id_base + 12], byteorder="big", signed=False
    )
    if max_messages_per_batch:
        metadata["max_messages_per_batch"] = str(max_messages_per_batch)

    max_transmission_size = int.from_bytes(
        data[id_base + 12 : id_base + 16], byteorder="big", signed=False
    )
    if max_transmission_size:
        metadata["max_transmission_size"] = str(max_transmission_size)

    max_message_size = int.from_bytes(
        data[id_base + 16 : id_base + 20], byteorder="big", signed=False
    )
    if max_message_size:
        metadata["max_message_size"] = str(max_message_size)

    message_sequence_wrap_value = int.from_bytes(
        data[id_base + 20 : id_base + 24], byteorder="big", signed=False
    )
    if message_sequence_wrap_value:
        metadata["message_sequence_wrap_value"] = str(message_sequence_wrap_value)

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
        metadata["id_flags_2"] = f"0x{data[id_base + 44]:02x}"
        metadata["id_flags_2_decoded"] = decode_flag_bits(data[id_base + 44], RFP_ICF2_FLAGS)
        metadata["ide_flags_2"] = f"0x{data[id_base + 45]:02x}"
        metadata["ide_flags_2_decoded"] = decode_flag_bits(data[id_base + 45], RFP_IEF2_FLAGS)

    if len(data) >= id_base + 100:
        heartbeat_interval = int.from_bytes(
            data[id_base + 96 : id_base + 100], byteorder="big", signed=False
        )
        metadata["heartbeat_interval"] = str(heartbeat_interval)

        efl_length = int.from_bytes(data[id_base + 100 : id_base + 102], byteorder="big", signed=False)
        if efl_length:
            metadata["efl_length"] = str(efl_length)
        metadata["err_flags_2"] = f"0x{data[id_base + 102]:02x}"

    if len(data) >= id_base + 124:
        header_compression = [value for value in data[id_base + 104 : id_base + 106] if value != 0xFF]
        if header_compression:
            metadata["header_compression"] = ",".join(str(value) for value in header_compression)

        message_compression = [
            value for value in data[id_base + 106 : id_base + 122] if value != 0xFF
        ]
        if message_compression:
            metadata["message_compression"] = ",".join(str(value) for value in message_compression)

    if len(data) >= id_base + 132:
        ssl_key_reset = int.from_bytes(
            data[id_base + 124 : id_base + 128], byteorder="big", signed=False
        )
        if ssl_key_reset:
            metadata["ssl_key_reset"] = str(ssl_key_reset)

        conversations_per_socket = int.from_bytes(
            data[id_base + 128 : id_base + 132], byteorder="big", signed=False
        )
        if conversations_per_socket:
            metadata["conversations_per_socket"] = str(conversations_per_socket)
        metadata["id_flags_3"] = f"0x{data[id_base + 132]:02x}"
        metadata["id_flags_3_decoded"] = decode_flag_bits(data[id_base + 132], RFP_ICF3_FLAGS)
        metadata["ide_flags_3"] = f"0x{data[id_base + 133]:02x}"
        metadata["ide_flags_3_decoded"] = decode_flag_bits(data[id_base + 133], RFP_IEF3_FLAGS)

    if len(data) >= id_base + 148:
        process_id = int.from_bytes(data[id_base + 136 : id_base + 140], byteorder="big", signed=False)
        if process_id:
            metadata["process_id"] = str(process_id)

        thread_id = int.from_bytes(data[id_base + 140 : id_base + 144], byteorder="big", signed=False)
        if thread_id:
            metadata["thread_id"] = str(thread_id)

        trace_id = int.from_bytes(data[id_base + 144 : id_base + 148], byteorder="big", signed=False)
        if trace_id:
            metadata["trace_id"] = str(trace_id)

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

    if len(data) >= id_base + 228:
        pal_values = []
        for offset in range(id_base + 208, id_base + 228, 2):
            value = int.from_bytes(data[offset : offset + 2], byteorder="big", signed=False)
            if value != 0xFFFF:
                pal_values.append(str(value))
        if pal_values:
            metadata["pal"] = ",".join(pal_values)

    if len(data) >= id_base + 240:
        r_bytes = data[id_base + 228 : id_base + 240]
        if any(byte != 0x00 for byte in r_bytes):
            metadata["r_hex"] = r_bytes.hex()

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


def print_parsed_metadata(metadata: Dict[str, str], debug: bool, show_flags: bool) -> None:
    print("    parsed:")
    if "header" in metadata:
        print(f"      - header: {metadata['header']}")
    if "declared_length" in metadata:
        print(f"      - declared_length: {metadata['declared_length']}")
    if "tsh_ccsid" in metadata:
        print(f"      - tsh_ccsid: {metadata['tsh_ccsid']}")
    if "fap_level" in metadata:
        print(f"      - fap_level: {metadata['fap_level']}")
    if "max_messages_per_batch" in metadata:
        print(f"      - max_messages_per_batch: {metadata['max_messages_per_batch']}")
    if "max_transmission_size" in metadata:
        print(f"      - max_transmission_size: {metadata['max_transmission_size']}")
    if "max_message_size" in metadata:
        print(f"      - max_message_size: {metadata['max_message_size']}")
    if "message_sequence_wrap_value" in metadata:
        print(
            f"      - message_sequence_wrap_value: {metadata['message_sequence_wrap_value']}"
        )
    if "channel" in metadata:
        print(f"      - channel: {metadata['channel']}")
    if "queue_manager" in metadata:
        print(f"      - queue_manager: {metadata['queue_manager']}")
    if "ccsid" in metadata:
        print(f"      - ccsid: {metadata['ccsid']}")
    if "heartbeat_interval" in metadata:
        print(f"      - heartbeat_interval: {metadata['heartbeat_interval']}")
    if "efl_length" in metadata:
        print(f"      - efl_length: {metadata['efl_length']}")
    if "header_compression" in metadata:
        print(f"      - header_compression: {metadata['header_compression']}")
    if "message_compression" in metadata:
        print(f"      - message_compression: {metadata['message_compression']}")
    if "ssl_key_reset" in metadata:
        print(f"      - ssl_key_reset: {metadata['ssl_key_reset']}")
    if "conversations_per_socket" in metadata:
        print(f"      - conversations_per_socket: {metadata['conversations_per_socket']}")
    if "process_id" in metadata:
        print(f"      - process_id: {metadata['process_id']}")
    if "thread_id" in metadata:
        print(f"      - thread_id: {metadata['thread_id']}")
    if "trace_id" in metadata:
        print(f"      - trace_id: {metadata['trace_id']}")
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
    if "pal" in metadata:
        print(f"      - pal: {metadata['pal']}")
    if show_flags:
        print("      - flags:")
        print(f"        id_flags: {metadata['id_flags']} ({metadata['id_flags_decoded']})")
        print(f"        ide_flags: {metadata['ide_flags']} ({metadata['ide_flags_decoded']})")
        print(f"        err_flags: {metadata['err_flags']} ({metadata['err_flags_decoded']})")
        if "id_flags_2" in metadata:
            print(
                f"        id_flags_2: {metadata['id_flags_2']} ({metadata['id_flags_2_decoded']})"
            )
        if "ide_flags_2" in metadata:
            print(
                f"        ide_flags_2: {metadata['ide_flags_2']} ({metadata['ide_flags_2_decoded']})"
            )
        if "err_flags_2" in metadata:
            print(f"        err_flags_2: {metadata['err_flags_2']}")
        if "id_flags_3" in metadata:
            print(
                f"        id_flags_3: {metadata['id_flags_3']} ({metadata['id_flags_3_decoded']})"
            )
        if "ide_flags_3" in metadata:
            print(
                f"        ide_flags_3: {metadata['ide_flags_3']} ({metadata['ide_flags_3_decoded']})"
            )
    if debug and "r_hex" in metadata:
        print(f"      - r_hex: {metadata['r_hex']}")


def colorize(text: str, color_name: str, enabled: bool) -> str:
    if not enabled:
        return text
    color_code = STATUS_COLORS.get(color_name)
    return f"{color_code}{text}{ANSI_RESET}" if color_code else text


def probe_port(
    host: str, port: int, debug: bool, socks_proxy: str | None, show_flags: bool, color: bool
) -> int:
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
        print(f"    {colorize('closed', 'closed', color)}")
        return 1
    except TimeoutError:
        print(f"    {colorize('timeout', 'timeout', color)}")
        return 1
    except OSError as exc:
        print(f"    {colorize('error', 'error', color)}: {exc}")
        return 1

    print(f"    {colorize('open', 'open', color)}")
    if not data:
        if debug:
            print("    no passive banner and no reply to IBM MQ probe")
        else:
            print("    no MQ metadata returned")
        return 0

    metadata = extract_mq_metadata(data)
    if metadata:
        print_parsed_metadata(metadata, debug, show_flags)
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
    print(BANNER_LINE)
    print()

    rc = 0
    for port in ports:
        if not 1 <= port <= 65535:
            print(f"invalid port: {port}", file=sys.stderr)
            return 2
        try:
            rc |= probe_port(args.host, port, args.debug, args.socks, args.flags, args.color)
        except ValueError as exc:
            print(f"invalid SOCKS proxy: {exc}", file=sys.stderr)
            return 2

    print()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
