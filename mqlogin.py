#!/usr/bin/env python3

import argparse
import getpass
import ipaddress
import os
import socket
import sys
from dataclasses import dataclass


SCRIPT_VERSION = "0.2.0"
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
RFP_TST_INITIAL_INFO = 1
RFP_TST_MQCONN = 129
RFP_TST_MQCONN_REPLY = 145
RFP_TCF_FIRST = 0x10
RFP_TCF_LAST = 0x20
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
    error_text: str | None = None


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
        required=True,
        help="User name for MQ connection authentication",
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


def decode_ebcdic_strip(data: bytes) -> str:
    return data.decode("cp500", errors="ignore").strip()


def encode_mq_field(value: str, size: int) -> bytes:
    raw = value.encode("cp500", errors="ignore")[:size]
    return raw.ljust(size, b"\x40")


def encode_ascii_field(value: str, size: int) -> bytes:
    raw = value.encode("ascii", errors="ignore")[:size]
    return raw.ljust(size, b" ")


def align_to_grain(ptr_size: int, size: int) -> int:
    remainder = size % ptr_size
    return 0 if remainder == 0 else ptr_size - remainder


def write_u32(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 4] = value.to_bytes(4, "big", signed=False)


def build_tsh(segment_type: int, payload_length: int, control_flags1: int) -> bytes:
    tsh = bytearray(TSH_HEADER_SIZE)
    tsh[0:4] = b"TSH "
    write_u32(tsh, 4, TSH_HEADER_SIZE + payload_length)
    tsh[8] = 1
    tsh[9] = segment_type & 0xFF
    tsh[10] = control_flags1 & 0xFF
    tsh[11] = 0
    write_u32(tsh, 20, 1)
    tsh[24:26] = (1208).to_bytes(2, "big")
    return bytes(tsh)


def build_initial_id_packet(channel: str, qmgr: str) -> bytes:
    payload = bytearray(240)
    payload[0:4] = encode_mq_field("ID  ", 4)
    payload[4] = RFP_FAP_LEVEL
    payload[5] = 0x7F
    payload[6] = 0xF6
    payload[7] = 0x06
    payload[10:12] = (10).to_bytes(2, "big")
    write_u32(payload, 12, 0x400)
    write_u32(payload, 16, 0)
    write_u32(payload, 20, 0)
    payload[24:44] = encode_mq_field(channel, 20)
    payload[44] = 0x00
    payload[45] = 0x6A
    payload[46:48] = (1208).to_bytes(2, "big")
    payload[48:96] = encode_mq_field(qmgr, 48)
    write_u32(payload, 96, 300)
    payload[100:102] = (138).to_bytes(2, "big")
    payload[102] = 0
    payload[104:106] = b"\x00\xFF"
    payload[106:122] = b"\xFF" * 16
    write_u32(payload, 128, 1)
    payload[132] = 0x10
    payload[133] = 0x20
    payload[148:160] = encode_mq_field("MQJB00000000", 12)
    payload[160:208] = encode_mq_field("PYMQLOGIN", 48)
    for offset in range(208, 228, 2):
        payload[offset : offset + 2] = (0xFFFF).to_bytes(2, "big")
    tsh = build_tsh(RFP_TST_INITIAL_INFO, len(payload), RFP_TCF_FIRST | RFP_TCF_LAST)
    return tsh + payload


def build_mqcd(connection_name: str, channel: str) -> bytes:
    size = 332
    payload = bytearray(size)
    payload[0:20] = encode_mq_field(channel, 20)
    write_u32(payload, 20, MQCD_VERSION_1)
    write_u32(payload, 24, MQ_CHLTYPE_CLNTCONN)
    write_u32(payload, 28, MQ_TRPTYPE_TCP)
    payload[144:164] = encode_ascii_field(connection_name, 20)
    return bytes(payload)


def build_mqcsp(user: str, password: str) -> bytes:
    ptr_size = 4
    base_size = 48
    total_size = base_size + align_to_grain(ptr_size, base_size) + len(user.encode()) + len(password.encode())
    payload = bytearray(total_size)
    payload[0:4] = b"CSP "
    write_u32(payload, 4, MQCSP_VERSION_1)
    write_u32(payload, 8, MQCSP_AUTH_USER_ID_AND_PWD)
    pos = base_size + align_to_grain(ptr_size, base_size)
    user_bytes = user.encode("ascii", errors="ignore")
    password_bytes = password.encode("ascii", errors="ignore")
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


def build_rfp_mqconn(qmgr: str, app_name: str) -> bytes:
    payload = bytearray(120)
    payload[0:48] = encode_mq_field(qmgr, 48)
    payload[48:76] = encode_mq_field(app_name, 28)
    write_u32(payload, 76, 0)
    write_u32(payload, 112, RFP_OPT_MQCONNX)
    write_u32(payload, 116, 0)
    return bytes(payload)


def build_mqapi_header(call_length: int) -> bytes:
    payload = bytearray(MQAPI_HEADER_SIZE)
    write_u32(payload, 0, call_length)
    return bytes(payload)


def build_mqconn_packet(host: str, port: int, qmgr: str, channel: str, user: str, password: str) -> bytes:
    connection_name = f"{host}({port})"
    app_name = "PYMQLOGIN"
    mqcd = build_mqcd(connection_name, channel)
    mqcsp = build_mqcsp(user, password)
    mqcno = build_mqcno(mqcd, mqcsp)
    fap_mqcno = build_fap_mqcno()
    rfp_mqconn = build_rfp_mqconn(qmgr, app_name)
    call_body = rfp_mqconn + fap_mqcno + mqcno
    mqapi = build_mqapi_header(len(call_body))
    tsh = build_tsh(RFP_TST_MQCONN, len(mqapi) + len(call_body), RFP_TCF_FIRST | RFP_TCF_LAST)
    return tsh + mqapi + call_body


def recv_tsh_packet(sock: socket.socket) -> bytes:
    header = recv_exact(sock, TSH_HEADER_SIZE)
    declared_length = int.from_bytes(header[4:8], "big", signed=False)
    if declared_length < TSH_HEADER_SIZE:
        raise OSError(f"invalid MQ packet length: {declared_length}")
    body = recv_exact(sock, declared_length - TSH_HEADER_SIZE)
    return header + body


def parse_id_response(packet: bytes) -> tuple[int | None, str | None, str | None, int | None]:
    if len(packet) < TSH_HEADER_SIZE + 104:
        return None, None, None, None
    base = TSH_HEADER_SIZE
    fap_level = packet[base + 4]
    err = packet[base + 7]
    channel = decode_ebcdic_strip(packet[base + 24 : base + 44]) or None
    queue_manager = decode_ebcdic_strip(packet[base + 48 : base + 96]) or None
    return err, channel, queue_manager, fap_level


def parse_mqconn_reply(packet: bytes) -> RawLoginResult:
    if len(packet) < TSH_HEADER_SIZE + MQAPI_HEADER_SIZE:
        return RawLoginResult(ok=False, error_text="short MQCONN reply")
    segment_type = packet[9]
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


def connect_with_raw(args: argparse.Namespace, password: str) -> RawLoginResult:
    sock = open_socket(args.host, args.port, args.socks, args.timeout)
    try:
        sock.settimeout(READ_TIMEOUT)
        sock.sendall(build_initial_id_packet(args.channel, args.qmgr))
        id_reply = recv_tsh_packet(sock)
        err_flag, channel, queue_manager, fap_level = parse_id_response(id_reply)
        if err_flag not in (None, 0):
            return RawLoginResult(
                ok=False,
                queue_manager=queue_manager,
                channel=channel,
                fap_level=fap_level,
                error_text=f"listener rejected initial ID with {RFP_ERR_CODES.get(err_flag, err_flag)}",
            )

        sock.sendall(build_mqconn_packet(args.host, args.port, args.qmgr, args.channel, args.user, password))
        conn_reply = recv_tsh_packet(sock)
        result = parse_mqconn_reply(conn_reply)
        result.queue_manager = queue_manager
        result.channel = channel
        result.fap_level = fap_level
        return result
    except Exception as exc:
        return RawLoginResult(ok=False, error_text=str(exc))
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


def connect_and_report(args: argparse.Namespace) -> int:
    password = resolve_password(args)
    backend = choose_backend(args)
    conn_name = f"{args.host}({args.port})"

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
        print(f"    mqrc: {result.reason_code}")
    if result.fap_level is not None:
        print(f"    fap_level: {result.fap_level}")
    if result.error_text:
        print(f"    error: {result.error_text}")
    print()
    return 1


def main() -> int:
    args = parse_args()
    return connect_and_report(args)


if __name__ == "__main__":
    raise SystemExit(main())
