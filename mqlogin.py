#!/usr/bin/env python3

import argparse
import codecs
import getpass
import ipaddress
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path


SCRIPT_VERSION = "0.2.5"
BANNER_TITLE = "IBM MQ Login Tool"
DEFAULT_CHANNEL = "SYSTEM.ADMIN.SVRCONN"
DEFAULT_PORT = 1414
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 3.0
MAX_READ = 4096
TSH_HEADER_SIZE = 28
MQAPI_HEADER_SIZE = 16

MQCD_VERSION_1 = 1
MQCNO_VERSION_5 = 5
MQCSP_VERSION_1 = 1
MQCSP_AUTH_USER_ID_AND_PWD = 1
RFP_FAP_LEVEL = 17
LOCAL_CCSID = 819
RFP_TST_INITIAL_INFO = 1
RFP_TST_STATUS_INFO = 5
RFP_TST_USERID_DATA = 8
RFP_TST_CONAUTH_INFO = 10
RFP_TST_MQCONN = 129
RFP_TST_MQCONN_REPLY = 145
RFP_TCF_FIRST = 0x10
RFP_TCF_LAST = 0x20
RFP_OPT_MQCONN = 0x01
RFP_OPT_MQCONNX = 0x02
RFP_CF_SPCAP_SUPPORTED = 0x01
RFP_CF_ACCEPT_QM_HINTS = 0x04
MQ_CHLTYPE_CLNTCONN = 6
MQ_TRPTYPE_TCP = 2

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

MQRC_NAMES = {
    0: "MQRC_NONE",
    2009: "MQRC_CONNECTION_BROKEN",
    2035: "MQRC_NOT_AUTHORIZED",
    2059: "MQRC_Q_MGR_NOT_AVAILABLE",
    2063: "MQRC_SECURITY_ERROR",
    2195: "MQRC_UNEXPECTED_ERROR",
    2278: "MQRC_CLIENT_CONN_ERROR",
    2291: "MQRC_USER_ID_NOT_AVAILABLE",
    2393: "MQRC_SSL_INITIALIZATION_ERROR",
    2537: "MQRC_CHANNEL_NOT_AVAILABLE",
    2538: "MQRC_HOST_NOT_AVAILABLE",
    2594: "MQRC_PASSWORD_PROTECTION_ERROR",
}


class BannerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        banner = f"\n{BANNER_TITLE} v{SCRIPT_VERSION}\n\n"
        return banner + super().format_help() + "\n"


@dataclass
class RawLoginResult:
    ok: bool
    comp_code: int | None = None
    reason_code: int | None = None
    handle: int | None = None
    queue_manager: str | None = None
    channel: str | None = None
    fap_level: int | None = None
    stage: str | None = None
    error_text: str | None = None


def format_mqrc(reason_code: int) -> str:
    name = MQRC_NAMES.get(reason_code)
    return f"{reason_code} ({name})" if name else str(reason_code)


def authorization_summary(result: RawLoginResult) -> str:
    if result.ok:
        return "succeeded (MQRC_NONE): the queue manager accepted the connection"
    if result.reason_code == 2035:
        return (
            "failed (MQRC_NOT_AUTHORIZED): the effective MQ identity is not permitted "
            "to connect to this queue manager"
        )
    if result.reason_code is not None:
        return f"not confirmed ({format_mqrc(result.reason_code)}): {result.error_text or 'MQCONN failed'}"
    return f"not confirmed: {result.error_text or 'MQCONN did not complete'}"


YFX = bytes(
    [
        0xDF,
        0x09,
        0x15,
        0x84,
        0x89,
        0x7B,
        0x7E,
        0xD6,
        0xB7,
        0x32,
        0xC1,
        0x17,
        0xB5,
        0xF8,
        0xAB,
        0xB8,
        0xD5,
        0x41,
        0xE3,
        0x1B,
        0xDB,
        0x54,
        0xAA,
        0x62,
    ]
)
PC_1C = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
PC_1D = [62, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC_2C = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2]
PC_2D = [41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
E_TABLE = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
P_TABLE = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
IP_TABLE = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
IP_INV_TABLE = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


def build_parser() -> argparse.ArgumentParser:
    parser = BannerArgumentParser(
        description="Test a single IBM MQ client login with an explicit username/password."
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=DEFAULT_PORT,
        help="Listener port to connect to",
    )
    parser.add_argument(
        "--channel",
        default=DEFAULT_CHANNEL,
        help=f"SVRCONN channel name (default: {DEFAULT_CHANNEL})",
    )
    parser.add_argument(
        "--qmgr",
        default="",
        help="Queue manager name; leave empty to let the client use the server default",
    )
    parser.add_argument(
        "--user",
        help="User name for MQ connection authentication",
    )
    parser.add_argument(
        "--creds",
        metavar="FILE",
        help="Check sequential username:password pairs from FILE instead of one --user",
    )
    parser.add_argument(
        "--password",
        help="Password for MQ connection authentication; if omitted, prompt securely",
    )
    parser.add_argument(
        "--password-env",
        default="MQ_PASSWORD",
        help="Environment variable to read the password from before prompting",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "raw", "ibmmq"),
        default="auto",
        help="Connection backend to use (default: auto)",
    )
    parser.add_argument(
        "--socks",
        help="Connect through a SOCKS5 proxy specified as host:port or socks5://host:port",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=CONNECT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print raw protocol metadata to stderr; passwords are never printed",
    )
    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit(0)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("timeout must be greater than 0")
    if bool(args.user) == bool(args.creds):
        parser.error("provide exactly one of --user or --creds")
    if args.creds and args.password is not None:
        parser.error("--password cannot be used with --creds")
    return args


def load_ibmmq():
    try:
        import ibmmq  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "ibmmq is not installed or IBM MQ client libraries are unavailable. "
            "Install the ibmmq package and the IBM MQ C client first."
        ) from exc
    return ibmmq


def resolve_password(args: argparse.Namespace) -> str:
    if args.password is not None:
        return args.password

    if args.password_env:
        value = os.environ.get(args.password_env)
        if value:
            return value

    return getpass.getpass("MQ password: ")


def read_credentials_file(filename: str) -> list[tuple[str, str]]:
    try:
        lines = Path(filename).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot read credentials file {filename!r}: {exc}") from exc

    credentials: list[tuple[str, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"credentials file line {line_number}: expected username:password")
        username, password = line.split(":", 1)
        username = username.strip()
        if not username:
            raise ValueError(f"credentials file line {line_number}: username is empty")
        credentials.append((username, password))
    if not credentials:
        raise ValueError("credentials file contains no credential pairs")
    return credentials


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
            raise OSError("connection closed while reading")
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
        recv_exact(sock, 6)
        return
    if atyp == 0x04:
        recv_exact(sock, 18)
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


def open_socket(
    target_host: str, target_port: int, socks_proxy: str | None, timeout: float
) -> socket.socket:
    if not socks_proxy:
        return socket.create_connection((target_host, target_port), timeout=timeout)

    proxy_host, proxy_port = parse_socks_proxy(socks_proxy)
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        socks5_connect(sock, target_host, target_port)
        return sock
    except Exception:
        sock.close()
        raise


def mq_codec(ccsid: int) -> str:
    if ccsid == 819:
        return "iso-8859-1"
    try:
        codecs.lookup(f"cp{ccsid}")
    except LookupError:
        if ccsid == 870:
            # CP870 is not included with every Python build. CP500 has the
            # same encoding for the ASCII subset used by MQ identifiers.
            return "cp500"
        raise ValueError(f"unsupported MQ CCSID: {ccsid}")
    return f"cp{ccsid}"


def encode_mq_bytes(value: str, ccsid: int) -> bytes:
    return value.encode(mq_codec(ccsid), errors="strict")


def decode_mq_field(data: bytes, ccsid: int) -> str:
    return data.decode(mq_codec(ccsid), errors="ignore").strip()


def encode_mq_field(value: str, size: int, ccsid: int = LOCAL_CCSID) -> bytes:
    # RemoteConnection defaults to CCSID 819, which is ISO-8859-1. Channel
    # names therefore travel as ASCII-compatible bytes, padded with spaces.
    raw = encode_mq_bytes(value, ccsid)[:size]
    return raw.ljust(size, encode_mq_bytes(" ", ccsid))


def encode_ascii_field(value: str, size: int) -> bytes:
    raw = value.encode("ascii", errors="ignore")[:size]
    return raw.ljust(size, b" ")


def align_to_grain(ptr_size: int, size: int) -> int:
    remainder = size % ptr_size
    return 0 if remainder == 0 else ptr_size - remainder


def write_u32(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 4] = value.to_bytes(4, "big", signed=False)


def write_u32_ordered(buffer: bytearray, offset: int, value: int, swap: bool) -> None:
    """Write RFP structure integers in the queue manager's negotiated order."""
    buffer[offset : offset + 4] = value.to_bytes(4, "little" if swap else "big", signed=False)


def read_u32(buffer: bytes | bytearray, offset: int) -> int:
    return int.from_bytes(buffer[offset : offset + 4], "big", signed=False)


def read_u32_ordered(buffer: bytes | bytearray, offset: int, swap: bool) -> int:
    return int.from_bytes(buffer[offset : offset + 4], "little" if swap else "big", signed=False)


def _bytes_to_bits(byte_data: bytes) -> list[int]:
    bits = [0] * (len(byte_data) * 8)
    for i, curr_byte in enumerate(byte_data):
        for j in range(8):
            bits[i * 8 + j] = (curr_byte >> (7 - j)) & 1
    return bits


def _bits_to_bytes(bit_data: list[int]) -> bytes:
    out = bytearray(len(bit_data) // 8)
    for i in range(len(out)):
        j = i * 8
        out[i] = (
            (bit_data[j] << 7)
            | (bit_data[j + 1] << 6)
            | (bit_data[j + 2] << 5)
            | (bit_data[j + 3] << 4)
            | (bit_data[j + 4] << 3)
            | (bit_data[j + 5] << 2)
            | (bit_data[j + 6] << 1)
            | bit_data[j + 7]
        )
    return bytes(out)


def _key_schedule(key: bytes) -> list[list[int]]:
    bit_key = _bytes_to_bits(key)
    c = [bit_key[index - 1] for index in PC_1C]
    d = [bit_key[index - 1] for index in PC_1D]
    schedules: list[list[int]] = []
    for shift in SHIFTS:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        ks = [0] * 48
        for j in range(24):
            ks[j] = c[PC_2C[j] - 1]
            ks[j + 24] = d[PC_2D[j] - 29]
        schedules.append(ks)
    return schedules


def _des_f(right: list[int], key_bits: list[int]) -> list[int]:
    input_s = [right[index - 1] ^ key_bits[i] for i, index in enumerate(E_TABLE)]
    output_s = [0] * 32
    for i in range(8):
        j = i * 6
        row = input_s[j] * 2 + input_s[j + 5]
        col = input_s[j + 1] * 8 + input_s[j + 2] * 4 + input_s[j + 3] * 2 + input_s[j + 4]
        val = S_BOXES[i][row][col]
        k = i * 4
        output_s[k] = (val >> 3) & 1
        output_s[k + 1] = (val >> 2) & 1
        output_s[k + 2] = (val >> 1) & 1
        output_s[k + 3] = val & 1
    return [output_s[index - 1] for index in P_TABLE]


def _des_encrypt_block(key: bytes, block: bytes) -> bytes:
    ks = _key_schedule(key)
    tmp = [_bytes_to_bits(block)[index - 1] for index in IP_TABLE]
    for round_index in range(16):
        left = tmp[:32]
        right = tmp[32:]
        f_out = _des_f(right, ks[round_index])
        if round_index < 15:
            tmp = right + [left[i] ^ f_out[i] for i in range(32)]
        else:
            tmp = [left[i] ^ f_out[i] for i in range(32)] + right
    output_bits = [tmp[index - 1] for index in IP_INV_TABLE]
    return _bits_to_bytes(output_bits)


def remote_ppa_finish_auth_flow(
    buffer: bytearray, length_offset: int, password_offset: int, r_state: bytes, ppa: int, swap: bool
) -> int:
    password_length = read_u32_ordered(buffer, length_offset, swap)
    if ppa == 0:
        return password_length
    if password_length == 0:
        return password_length
    if ppa != 1:
        return -1
    padded_length = password_length
    if padded_length % 8 != 0:
        padded_length += 8 - (padded_length % 8)
    working = bytearray(padded_length)
    working[:password_length] = buffer[password_offset : password_offset + password_length]
    ra = r_state[0:8]
    rb = r_state[8:16]
    rc = r_state[16:24]
    keys: list[bytes] = []
    for base, r_part in ((0, ra), (8, rb), (16, rc)):
        key = bytearray(8)
        for index in range(8):
            key[index] = YFX[base + index] ^ 0x08
            if index == 0:
                key[index] = (key[index] & 0xF0) | ((key[index] ^ r_part[index]) & 0x0F)
            else:
                key[index] ^= r_part[index]
        keys.append(bytes(key))
    for key in keys:
        for block in range(0, padded_length, 8):
            working[block : block + 8] = _des_encrypt_block(key, bytes(working[block : block + 8]))
    buffer[password_offset : password_offset + padded_length] = working
    return padded_length


def build_tsh(segment_type: int, payload_length: int, control_flags1: int, ccsid: int = LOCAL_CCSID) -> bytes:
    tsh = bytearray(TSH_HEADER_SIZE)
    tsh[0:4] = b"TSH "
    write_u32(tsh, 4, TSH_HEADER_SIZE + payload_length)
    tsh[8] = 1
    tsh[9] = segment_type & 0xFF
    tsh[10] = control_flags1 & 0xFF
    tsh[11] = 0
    write_u32(tsh, 20, 1)
    tsh[24:26] = ccsid.to_bytes(2, "big")
    return bytes(tsh)


def build_initial_id_packet(
    channel: str,
    qmgr: str,
    client_r: bytes,
    ccsid: int = LOCAL_CCSID,
    id_flags2: int = 0x51,
    id_flags3: int = 0x28,
) -> bytes:
    payload = bytearray(240)
    # RfpID uses a literal ASCII eyecatcher, unlike the MQ character fields.
    payload[0:4] = b"ID  "
    payload[4] = RFP_FAP_LEVEL
    payload[5] = 0x22  # conversion capable + MQ request
    payload[6] = 0
    payload[7] = 0
    payload[10:12] = (10).to_bytes(2, "big")
    write_u32(payload, 12, 0x400)
    write_u32(payload, 16, 0)
    write_u32(payload, 20, 0)
    payload[24:44] = encode_mq_field(channel, 20, ccsid)
    payload[44] = id_flags2
    payload[45] = 0
    payload[46:48] = ccsid.to_bytes(2, "big")
    payload[48:96] = encode_mq_field(qmgr, 48, ccsid)
    write_u32(payload, 96, 300)
    payload[100:102] = (138).to_bytes(2, "big")
    payload[102] = 0
    payload[104:106] = b"\x00\xFF"
    payload[106:122] = b"\xFF" * 16
    # This raw backend implements normal TSH flows only. Do not negotiate MSH
    # multiplexing, whose header uses different offsets.
    write_u32(payload, 128, 0)
    payload[132] = id_flags3
    payload[133] = 0
    payload[148:160] = encode_mq_field("MQJB00000000", 12, ccsid)
    payload[160:208] = encode_mq_field("PYMQLOGIN", 48, ccsid)
    # Offer no protection and DES. The queue manager selects DES when its
    # CONNAUTH policy requires protected passwords.
    payload[208:210] = (0).to_bytes(2, "big")
    payload[210:212] = (1).to_bytes(2, "big")
    for offset in range(212, 228, 2):
        payload[offset : offset + 2] = (0xFFFF).to_bytes(2, "big")
    payload[228:240] = client_r
    tsh = build_tsh(RFP_TST_INITIAL_INFO, len(payload), 0x01 | RFP_TCF_FIRST | RFP_TCF_LAST, ccsid)
    return tsh + payload


def build_mqcd(connection_name: str, channel: str, ccsid: int) -> bytes:
    size = 332
    payload = bytearray(size)
    payload[0:20] = encode_mq_field(channel, 20, ccsid)
    write_u32(payload, 20, MQCD_VERSION_1)
    write_u32(payload, 24, MQ_CHLTYPE_CLNTCONN)
    write_u32(payload, 28, MQ_TRPTYPE_TCP)
    payload[144:164] = encode_mq_field(connection_name, 20, ccsid)
    return bytes(payload)


def build_mqcsp(user: str, password: str, ccsid: int) -> bytes:
    ptr_size = 4
    base_size = 48
    user_bytes = encode_mq_bytes(user, ccsid)
    password_bytes = encode_mq_bytes(password, ccsid)
    total_size = base_size + align_to_grain(ptr_size, base_size) + len(user_bytes) + len(password_bytes)
    payload = bytearray(total_size)
    payload[0:4] = b"CSP "
    write_u32(payload, 4, MQCSP_VERSION_1)
    write_u32(payload, 8, MQCSP_AUTH_USER_ID_AND_PWD)
    pos = base_size + align_to_grain(ptr_size, base_size)
    write_u32(payload, 20, pos)
    write_u32(payload, 24, len(user_bytes))
    payload[pos : pos + len(user_bytes)] = user_bytes
    pos += len(user_bytes)
    write_u32(payload, 40, pos)
    write_u32(payload, 44, len(password_bytes))
    payload[pos : pos + len(password_bytes)] = password_bytes
    return bytes(payload)


def build_mqcno(mqcd: bytes, mqcsp: bytes) -> bytes:
    ptr_size = 4
    size = 188
    payload = bytearray(size + len(mqcd) + len(mqcsp))
    payload[0:4] = b"CNO "
    write_u32(payload, 4, MQCNO_VERSION_5)
    write_u32(payload, 8, 0)
    write_u32(payload, 12, size)
    write_u32(payload, 180, size + len(mqcd))
    payload[size : size + len(mqcd)] = mqcd
    payload[size + len(mqcd) : size + len(mqcd) + len(mqcsp)] = mqcsp
    return bytes(payload)


def build_fap_mqcno() -> bytes:
    payload = bytearray(280)
    payload[0:4] = b"FCNO"
    write_u32(payload, 4, 4)
    write_u32(payload, 8, RFP_CF_SPCAP_SUPPORTED | RFP_CF_ACCEPT_QM_HINTS)
    return bytes(payload)


def build_rfp_mqconn(qmgr: str, app_name: str, ccsid: int) -> bytes:
    payload = bytearray(120)
    payload[0:48] = encode_mq_field(qmgr, 48, ccsid)
    payload[48:76] = encode_mq_field(app_name, 28, ccsid)
    write_u32(payload, 76, 28)
    write_u32(payload, 112, RFP_OPT_MQCONN | RFP_OPT_MQCONNX)
    write_u32(payload, 116, 0)
    return bytes(payload)


def build_mqapi_header(transmission_length: int) -> bytes:
    payload = bytearray(MQAPI_HEADER_SIZE)
    # RfpMQAPI's call length includes the TSH and MQAPI headers.
    write_u32(payload, 0, transmission_length)
    return bytes(payload)


def build_mqconn_packet(qmgr: str, fap_level: int, ccsid: int) -> bytes:
    app_name = "PYMQLOGIN"
    fap_mqcno = build_fap_mqcno()
    rfp_mqconn = build_rfp_mqconn(qmgr, app_name, ccsid)
    reconnection_data = bytes(72) if fap_level >= 10 else b""
    call_body = rfp_mqconn + fap_mqcno + reconnection_data
    transmission_length = TSH_HEADER_SIZE + MQAPI_HEADER_SIZE + len(call_body)
    mqapi = build_mqapi_header(transmission_length)
    tsh = build_tsh(RFP_TST_MQCONN, len(mqapi) + len(call_body), RFP_TCF_FIRST | RFP_TCF_LAST, ccsid)
    return tsh + mqapi + call_body


def build_uid_packet(user: str, fap_level: int, ccsid: int) -> bytes:
    payload_size = 28 if fap_level < 5 else 132
    payload = bytearray(payload_size)
    payload[0:4] = b"UID "
    short_user = user.upper()[:12]
    payload[4:16] = encode_mq_field(short_user, 12, ccsid)
    payload[16:28] = encode_mq_field("", 12, ccsid)
    if fap_level >= 5:
        payload[28:92] = encode_mq_field(user, 64, ccsid)
    tsh = build_tsh(RFP_TST_USERID_DATA, len(payload), RFP_TCF_FIRST | RFP_TCF_LAST, ccsid)
    return tsh + payload


def build_caut_packet(user: str, password: str, fap_level: int, ppa: int, r_state: bytes, swap: bool, ccsid: int) -> bytes:
    user_bytes = encode_mq_bytes(user, ccsid)
    password_bytes = encode_mq_bytes(password, ccsid)
    user_id_offset = 32 if fap_level > 16 else 24
    payload = bytearray(user_id_offset + len(user_bytes) + len(password_bytes))
    payload[0:4] = b"CAUT"
    # RfpCAUT uses JmqiDC.writeI32(..., this.swap); swap is negotiated from
    # the received TSH encoding (1 = big-endian, 2 = little-endian).
    write_u32_ordered(payload, 4, MQCSP_AUTH_USER_ID_AND_PWD, swap)
    write_u32_ordered(payload, 8, len(user_bytes), swap)
    write_u32_ordered(payload, 12, len(password_bytes), swap)
    write_u32_ordered(payload, 16, len(user_bytes), swap)
    write_u32_ordered(payload, 20, len(password_bytes), swap)
    if fap_level > 16:
        write_u32_ordered(payload, 24, 0, swap)
        write_u32_ordered(payload, 28, 0, swap)
    payload[user_id_offset : user_id_offset + len(user_bytes)] = user_bytes
    password_offset = user_id_offset + len(user_bytes)
    payload[password_offset : password_offset + len(password_bytes)] = password_bytes
    new_password_len = remote_ppa_finish_auth_flow(payload, 20, password_offset, r_state, ppa, swap)
    if new_password_len < 0:
        raise ValueError(f"unsupported MQ password protection algorithm: {ppa}")
    write_u32_ordered(payload, 20, new_password_len, swap)
    tsh = build_tsh(RFP_TST_CONAUTH_INFO, len(payload), RFP_TCF_FIRST | RFP_TCF_LAST, ccsid)
    return tsh + payload


def recv_tsh_packet(sock: socket.socket) -> bytes:
    header = recv_exact(sock, TSH_HEADER_SIZE)
    declared_length = int.from_bytes(header[4:8], "big", signed=False)
    if declared_length < TSH_HEADER_SIZE:
        raise OSError(f"invalid MQ packet length: {declared_length}")
    body = recv_exact(sock, declared_length - TSH_HEADER_SIZE)
    return header + body


def debug_tsh(args: argparse.Namespace, direction: str, stage: str, packet: bytes) -> None:
    """Emit enough wire metadata to diagnose protocol negotiation safely."""
    if not args.debug:
        return
    if len(packet) < TSH_HEADER_SIZE:
        print(f"[debug] {direction} {stage}: {len(packet)} bytes (short TSH)", file=sys.stderr)
        return
    print(
        f"[debug] {direction} {stage}: bytes={len(packet)} segment={packet[9]} "
        f"flags=0x{packet[10]:02x} encoding={packet[8]} ccsid="
        f"{int.from_bytes(packet[24:26], 'big')}",
        file=sys.stderr,
    )


def debug_id_reply(args: argparse.Namespace, packet: bytes) -> None:
    if not args.debug or len(packet) < TSH_HEADER_SIZE + 134:
        return
    body = packet[TSH_HEADER_SIZE:]
    print(
        f"[debug] ID fields: id_flags=0x{body[5]:02x} ide_flags=0x{body[6]:02x} "
        f"err_flags=0x{body[7]:02x} id_flags2=0x{body[44]:02x} "
        f"ide_flags2=0x{body[45]:02x} err_flags2=0x{body[102]:02x} "
        f"id_flags3=0x{body[132]:02x} ide_flags3=0x{body[133]:02x} "
        f"max_xmit={read_u32(body, 12)}",
        file=sys.stderr,
    )


def parse_id_response(packet: bytes) -> tuple[int | None, str | None, str | None, int | None, int | None, bytes, bool, int]:
    if len(packet) < TSH_HEADER_SIZE + 8:
        return None, None, None, None, None, b"", False, LOCAL_CCSID
    base = TSH_HEADER_SIZE
    ccsid = int.from_bytes(packet[24:26], "big", signed=False)
    fap_level = packet[base + 4]
    err = packet[base + 7]
    channel = None
    if len(packet) >= base + 44:
        channel = decode_mq_field(packet[base + 24 : base + 44], ccsid) or None
    queue_manager = None
    if len(packet) >= base + 96:
        queue_manager = decode_mq_field(packet[base + 48 : base + 96], ccsid) or None
    ppa = None
    if len(packet) >= base + 210:
        ppa = int.from_bytes(packet[base + 208 : base + 210], "big", signed=False)
    server_r = packet[base + 228 : base + 240] if len(packet) >= base + 240 else b""
    return err, channel, queue_manager, fap_level, ppa, server_r, packet[8] == 2, ccsid


def parse_mqconn_reply(packet: bytes) -> RawLoginResult:
    if len(packet) < TSH_HEADER_SIZE:
        return RawLoginResult(ok=False, error_text="short MQCONN reply")
    segment_type = packet[9]
    if segment_type == RFP_TST_STATUS_INFO:
        return RawLoginResult(ok=False, error_text=f"MQCONN status error: {describe_error_status(packet)}")
    if len(packet) < TSH_HEADER_SIZE + MQAPI_HEADER_SIZE:
        return RawLoginResult(ok=False, error_text="short MQCONN reply")
    if segment_type != RFP_TST_MQCONN_REPLY:
        return RawLoginResult(
            ok=False,
            error_text=f"unexpected reply segment type {segment_type}",
        )
    comp_code = int.from_bytes(packet[TSH_HEADER_SIZE + 4 : TSH_HEADER_SIZE + 8], "big", signed=False)
    reason_code = int.from_bytes(packet[TSH_HEADER_SIZE + 8 : TSH_HEADER_SIZE + 12], "big", signed=False)
    handle = int.from_bytes(packet[TSH_HEADER_SIZE + 12 : TSH_HEADER_SIZE + 16], "big", signed=False)
    return RawLoginResult(
        ok=comp_code == 0,
        comp_code=comp_code,
        reason_code=reason_code,
        handle=handle,
    )


def parse_status_packet(packet: bytes) -> tuple[bool, str | None]:
    if len(packet) < TSH_HEADER_SIZE:
        return False, "short status reply"
    segment_type = packet[9]
    control_flags1 = packet[10]
    if segment_type != RFP_TST_STATUS_INFO:
        return False, f"unexpected reply segment type {segment_type}"
    if control_flags1 & 0x02:
        return False, "server returned error status flow"
    return True, None


def describe_error_status(packet: bytes) -> str:
    """Decode the RfpESH body used with an error/close status TSH."""
    if len(packet) < TSH_HEADER_SIZE + 8:
        return "short error status flow"
    swap = packet[8] == 2
    error_data_length = read_u32_ordered(packet, TSH_HEADER_SIZE, swap)
    return_code = read_u32_ordered(packet, TSH_HEADER_SIZE + 4, swap)
    return (
        f"{RFP_ERR_CODES.get(return_code, f'unknown error {return_code}')} "
        f"(return_code={return_code}, error_data_bytes={error_data_length})"
    )


def connect_with_raw(args: argparse.Namespace, password: str) -> RawLoginResult:
    stage = "connect"
    sock = open_socket(args.host, args.port, args.socks, args.timeout)
    try:
        sock.settimeout(READ_TIMEOUT)
        active_ccsid = LOCAL_CCSID
        id_flags2 = 0x51
        id_flags3 = 0x28
        for id_attempt in range(4):
            stage = "id-send"
            client_r = os.urandom(12)
            id_packet = build_initial_id_packet(
                args.channel, args.qmgr, client_r, active_ccsid, id_flags2, id_flags3
            )
            debug_tsh(args, "tx", stage, id_packet)
            sock.sendall(id_packet)
            stage = "id-recv"
            id_reply = recv_tsh_packet(sock)
            debug_tsh(args, "rx", stage, id_reply)
            if id_reply[9] != RFP_TST_INITIAL_INFO:
                status_detail = ""
                if id_reply[9] == RFP_TST_STATUS_INFO:
                    status_detail = f": {describe_error_status(id_reply)}"
                return RawLoginResult(
                    ok=False,
                    stage=stage,
                    error_text=f"expected INITIAL_INFO reply, received segment {id_reply[9]}{status_detail}",
                )
            err_flag, channel, queue_manager, fap_level, ppa, server_r, swap, remote_ccsid = parse_id_response(id_reply)
            debug_id_reply(args, id_reply)
            if args.debug:
                print(
                    f"[debug] negotiated: fap={fap_level} ppa={ppa} byte_order="
                    f"{'little' if swap else 'big'} remote_ccsid={remote_ccsid} "
                    f"server_r_bytes={len(server_r)} id_error={bool(id_reply[10] & 0x02)}",
                    file=sys.stderr,
                )
            if id_reply[10] & 0x02:
                body = id_reply[TSH_HEADER_SIZE:]
                next_ccsid = remote_ccsid
                next_flags2 = id_flags2 & ~body[45]
                next_flags3 = id_flags3 & ~body[133]
                if (next_ccsid, next_flags2, next_flags3) != (active_ccsid, id_flags2, id_flags3):
                    active_ccsid = next_ccsid
                    id_flags2 = next_flags2
                    id_flags3 = next_flags3
                    continue
                return RawLoginResult(
                    ok=False,
                    queue_manager=queue_manager,
                    channel=channel,
                    fap_level=fap_level,
                    stage=stage,
                    error_text="queue manager rejected initial negotiation without a supported retry change",
                )
            break
        else:
            raise AssertionError("initial negotiation did not complete")
        if err_flag not in (None, 0):
            return RawLoginResult(
                ok=False,
                queue_manager=queue_manager,
                channel=channel,
                fap_level=fap_level,
                stage=stage,
                error_text=f"listener rejected initial ID with {RFP_ERR_CODES.get(err_flag, err_flag)}",
            )
        # Older/shorter ID replies do not include PAL/R. IBM's client treats
        # that as the legacy, unprotected-password negotiation.
        if ppa is not None and ppa not in (0, 1):
            return RawLoginResult(
                ok=False,
                queue_manager=queue_manager,
                channel=channel,
                fap_level=fap_level,
                stage=stage,
                error_text=f"queue manager selected unsupported password protection algorithm: {ppa}",
            )
        if ppa == 1 and len(server_r) != 12:
            return RawLoginResult(
                ok=False,
                queue_manager=queue_manager,
                channel=channel,
                fap_level=fap_level,
                stage=stage,
                error_text="queue manager selected DES password protection without an R value",
            )

        stage = "uid-send"
        uid_user = getpass.getuser()
        uid_packet = build_uid_packet(uid_user, fap_level or RFP_FAP_LEVEL, active_ccsid)
        debug_tsh(args, "tx", stage, uid_packet)
        sock.sendall(uid_packet)

        stage = "caut-send"
        r_state = client_r + server_r
        caut_packet = build_caut_packet(args.user, password, fap_level or RFP_FAP_LEVEL, ppa or 0, r_state, swap, active_ccsid)
        debug_tsh(args, "tx", stage, caut_packet)
        if args.debug:
            print(
                f"[debug] CAUT: fap={fap_level or RFP_FAP_LEVEL} ppa={ppa or 0} "
                f"user_bytes={len(encode_mq_bytes(args.user, active_ccsid))} "
                f"password_bytes={len(encode_mq_bytes(password, active_ccsid))}",
                file=sys.stderr,
            )
        sock.sendall(caut_packet)
        stage = "caut-recv"
        caut_reply = recv_tsh_packet(sock)
        debug_tsh(args, "rx", stage, caut_reply)
        caut_ok, caut_error = parse_status_packet(caut_reply)
        if not caut_ok:
            return RawLoginResult(
                ok=False,
                queue_manager=queue_manager,
                channel=channel,
                fap_level=fap_level,
                stage=stage,
                error_text=caut_error,
            )

        stage = "mqconn-send"
        mqconn_packet = build_mqconn_packet(args.qmgr, fap_level or RFP_FAP_LEVEL, active_ccsid)
        debug_tsh(args, "tx", stage, mqconn_packet)
        sock.sendall(mqconn_packet)
        stage = "mqconn-recv"
        conn_reply = recv_tsh_packet(sock)
        debug_tsh(args, "rx", stage, conn_reply)
        result = parse_mqconn_reply(conn_reply)
        result.queue_manager = queue_manager
        result.channel = channel
        result.fap_level = fap_level
        result.stage = "mqconn"
        return result
    except Exception as exc:
        return RawLoginResult(ok=False, stage=stage, error_text=str(exc))
    finally:
        sock.close()


def connect_with_ibmmq(args: argparse.Namespace, password: str) -> RawLoginResult:
    ibmmq = load_ibmmq()
    conn_name = f"{args.host}({args.port})"
    queue_manager = None
    try:
        queue_manager = ibmmq.connect(args.qmgr, args.channel, conn_name, args.user, password)
        return RawLoginResult(
            ok=True,
            queue_manager=getattr(queue_manager, "name", None) or args.qmgr or None,
            channel=args.channel,
        )
    except Exception as exc:
        return RawLoginResult(
            ok=False,
            comp_code=getattr(exc, "comp", None),
            reason_code=getattr(exc, "reason", None),
            error_text=str(exc),
        )
    finally:
        if queue_manager is not None:
            try:
                queue_manager.disconnect()
            except Exception:
                pass


def choose_backend(args: argparse.Namespace) -> str:
    if args.backend != "auto":
        return args.backend
    try:
        import ibmmq  # type: ignore  # noqa: F401

        return "ibmmq"
    except ImportError:
        return "raw"


def connect_and_report(args: argparse.Namespace, password: str | None = None, show_banner: bool = True) -> int:
    if password is None:
        password = resolve_password(args)
    backend = choose_backend(args)
    conn_name = f"{args.host}({args.port})"

    if show_banner:
        print()
        print(f"{BANNER_TITLE} v{SCRIPT_VERSION}")
        print()
    print(f"[+] Connecting to {conn_name}")
    print(f"    channel: {args.channel}")
    print(f"    queue manager: {args.qmgr or '<default>'}")
    print(f"    user: {args.user}")
    print(f"    backend: {backend}")

    if backend == "raw":
        result = connect_with_raw(args, password)
    else:
        result = connect_with_ibmmq(args, password)

    if result.ok:
        print("    login: success")
        print(f"    authorization: {authorization_summary(result)}")
        if result.queue_manager:
            print(f"    connected queue manager: {result.queue_manager}")
        if result.channel:
            print(f"    negotiated channel: {result.channel}")
        if result.handle is not None:
            print(f"    handle: {result.handle}")
        print()
        return 0

    print("    login: failed")
    if result.comp_code is not None:
        print(f"    mqcc: {result.comp_code}")
    if result.reason_code is not None:
        print(f"    mqrc: {format_mqrc(result.reason_code)}")
    if result.fap_level is not None:
        print(f"    fap_level: {result.fap_level}")
    if result.stage:
        print(f"    stage: {result.stage}")
    if result.error_text:
        print(f"    error: {result.error_text}")
    print(f"    authorization: {authorization_summary(result)}")
    print()
    return 1


def check_credentials_file(args: argparse.Namespace) -> int:
    credentials = read_credentials_file(args.creds)
    print()
    print(f"{BANNER_TITLE} v{SCRIPT_VERSION}")
    print()
    print(f"[+] Checking {len(credentials)} credential pair(s) sequentially")

    successes = 0
    for index, (username, password) in enumerate(credentials, start=1):
        print(f"\n[{index}/{len(credentials)}]")
        args.user = username
        if connect_and_report(args, password, show_banner=False) == 0:
            successes += 1

    failures = len(credentials) - successes
    print(f"[+] Summary: {successes} authorized, {failures} not authorized or not confirmed")
    return 0 if failures == 0 else 1


def main() -> int:
    args = parse_args()
    if args.creds:
        return check_credentials_file(args)
    return connect_and_report(args)


if __name__ == "__main__":
    raise SystemExit(main())
