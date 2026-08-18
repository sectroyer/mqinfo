#!/usr/bin/env python3

"""Authenticate to IBM MQ and list SPI functions available on the session."""

import argparse
import sys
from dataclasses import dataclass

import mqlogin


SCRIPT_VERSION = "0.1.0"
BANNER_TITLE = "IBM MQ Functions Tool"
BANNER_CREDIT = "by Michał Majchrowicz AFINE Team"
BANNER_LINE = f"{BANNER_TITLE} v{SCRIPT_VERSION} {BANNER_CREDIT}"

RFP_TST_API_CALL = 140
RFP_TST_API_REPLY = 156
SPI_QUERY_VERB_ID = 1
SPI_QUERY_VERB_VERSION = 1
SPI_INSPI_SIZE = 12
SPI_QUERY_INOUT_SIZE = 12
SPI_QUERY_IN_SIZE = 12
SPI_QUERY_OUT_HEADER_SIZE = 16
SPI_VERB_ARRAY_SIZE = 20
SPI_QUERY_BUFFERED_VERBS = 12
SPI_QUERY_OUT_OFFSET = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE + SPI_INSPI_SIZE + SPI_QUERY_INOUT_SIZE
SPI_VERB_NAMES = {
    1: "QUERY",
    2: "PUT",
    3: "GET",
    4: "ACTIVATE",
    5: "SYNCPOINT",
    7: "SUBSCRIBE",
    8: "UNSUBSCRIBE",
    11: "NOTIFY",
    12: "OPEN",
}


class BannerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        banner = f"\n{BANNER_LINE}\n\n"
        return banner + super().format_help() + "\n"


@dataclass
class SessionContext:
    sock: object
    queue_manager: str | None
    channel: str | None
    fap_level: int
    password_protection: int
    handle: int
    swap: bool
    ccsid: int


@dataclass
class SpiVerb:
    verb_id: int
    max_inout_version: int
    max_in_version: int
    max_out_version: int
    flags: int


@dataclass
class QueryResult:
    queue_manager: str | None = None
    channel: str | None = None
    handle: int | None = None
    fap_level: int | None = None
    password_protection: int | None = None
    comp_code: int | None = None
    reason_code: int | None = None
    verbs: list[SpiVerb] | None = None
    error_text: str | None = None
    stage: str | None = None


def format_spi_verb(verb: SpiVerb) -> str:
    """Format a non-empty SPI capability entry returned by SPI QUERY."""
    return (
        f"verb_id={verb.verb_id} ({SPI_VERB_NAMES.get(verb.verb_id, 'UNKNOWN')}) "
        f"max_inout={verb.max_inout_version} "
        f"max_in={verb.max_in_version} "
        f"max_out={verb.max_out_version} "
        f"flags=0x{verb.flags:08x}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = BannerArgumentParser(
        description=(
            "Log in to IBM MQ with the raw RFP flow and list SPI functions "
            "available on the live session. The numeric MQCONN handle alone is "
            "not sufficient; the query must run on the same socket."
        )
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=mqlogin.DEFAULT_PORT,
        help=f"Listener port to connect to (default: {mqlogin.DEFAULT_PORT})",
    )
    parser.add_argument(
        "--channel",
        default=mqlogin.DEFAULT_CHANNEL,
        help=f"SVRCONN channel name (default: {mqlogin.DEFAULT_CHANNEL})",
    )
    parser.add_argument(
        "--qmgr",
        default="",
        help="Queue manager name; leave empty to let the client use the server default",
    )
    parser.add_argument("--user", required=True, help="User name for MQ connection authentication")
    parser.add_argument("--password", help="Password for MQ connection authentication; if omitted, prompt securely")
    parser.add_argument(
        "--password-env",
        default="MQ_PASSWORD",
        help="Environment variable to read the password from before prompting",
    )
    parser.add_argument(
        "--socks",
        help="Connect through a SOCKS5 proxy specified as host:port or socks5://host:port",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=mqlogin.CONNECT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {mqlogin.CONNECT_TIMEOUT})",
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
    return args


def build_spi_query_packet(swap: bool, ccsid: int) -> bytes:
    out_buffer_length = SPI_QUERY_BUFFERED_VERBS * SPI_VERB_ARRAY_SIZE
    trans_length = (
        mqlogin.TSH_HEADER_SIZE
        + mqlogin.MQAPI_HEADER_SIZE
        + SPI_INSPI_SIZE
        + SPI_QUERY_INOUT_SIZE
        + SPI_QUERY_IN_SIZE
    )
    payload = bytearray(trans_length - mqlogin.TSH_HEADER_SIZE)

    mqlogin.write_u32(payload, 0, trans_length + out_buffer_length)
    mqlogin.write_u32_ordered(payload, 12, 0, swap)

    in_spi_offset = mqlogin.MQAPI_HEADER_SIZE
    mqlogin.write_u32_ordered(payload, in_spi_offset + 0, SPI_QUERY_VERB_ID, swap)
    mqlogin.write_u32_ordered(payload, in_spi_offset + 4, SPI_QUERY_VERB_VERSION, swap)
    mqlogin.write_u32_ordered(payload, in_spi_offset + 8, SPI_QUERY_OUT_HEADER_SIZE + out_buffer_length, swap)

    inout_offset = in_spi_offset + SPI_INSPI_SIZE
    payload[inout_offset : inout_offset + 4] = b"SPQU"
    mqlogin.write_u32_ordered(payload, inout_offset + 4, SPI_QUERY_VERB_VERSION, swap)
    mqlogin.write_u32_ordered(payload, inout_offset + 8, SPI_QUERY_INOUT_SIZE, swap)

    in_offset = inout_offset + SPI_QUERY_INOUT_SIZE
    payload[in_offset : in_offset + 4] = b"SPQI"
    mqlogin.write_u32_ordered(payload, in_offset + 4, SPI_QUERY_VERB_VERSION, swap)
    mqlogin.write_u32_ordered(payload, in_offset + 8, SPI_QUERY_IN_SIZE, swap)

    tsh = mqlogin.build_tsh(
        RFP_TST_API_CALL,
        len(payload),
        mqlogin.RFP_TCF_FIRST | mqlogin.RFP_TCF_LAST,
        ccsid,
    )
    return tsh + payload


def parse_spi_query_reply(packet: bytes, swap: bool) -> tuple[int, int, list[SpiVerb]]:
    if len(packet) < mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE:
        raise ValueError("short SPI reply")

    comp_code = mqlogin.read_u32_ordered(packet, mqlogin.TSH_HEADER_SIZE + 4, swap)
    reason_code = mqlogin.read_u32_ordered(packet, mqlogin.TSH_HEADER_SIZE + 8, swap)

    if comp_code == 2:
        return comp_code, reason_code, []

    if len(packet) < SPI_QUERY_OUT_OFFSET + SPI_QUERY_OUT_HEADER_SIZE:
        raise ValueError("short SPI query output")

    out_struct = packet[SPI_QUERY_OUT_OFFSET : SPI_QUERY_OUT_OFFSET + 4]
    if out_struct not in (b"SPQO", bytes((0xE2, 0xD7, 0xD8, 0xD6))):
        raise ValueError("unexpected SPI query output eyecatcher")

    array_size = mqlogin.read_u32_ordered(packet, SPI_QUERY_OUT_OFFSET + 12, swap)
    array_offset = SPI_QUERY_OUT_OFFSET + SPI_QUERY_OUT_HEADER_SIZE
    verbs: list[SpiVerb] = []
    for _ in range(array_size):
        if len(packet) < array_offset + SPI_VERB_ARRAY_SIZE:
            raise ValueError("truncated SPI verb array")
        verbs.append(
            SpiVerb(
                verb_id=mqlogin.read_u32_ordered(packet, array_offset + 0, swap),
                max_inout_version=mqlogin.read_u32_ordered(packet, array_offset + 4, swap),
                max_in_version=mqlogin.read_u32_ordered(packet, array_offset + 8, swap),
                max_out_version=mqlogin.read_u32_ordered(packet, array_offset + 12, swap),
                flags=mqlogin.read_u32_ordered(packet, array_offset + 16, swap),
            )
        )
        array_offset += SPI_VERB_ARRAY_SIZE

    # Some queue managers report fixed-capacity empty entries in the returned
    # array.  Verb ID 0 is reserved, so it is not an available SPI function.
    return comp_code, reason_code, [verb for verb in verbs if verb.verb_id != 0]


def establish_session(args: argparse.Namespace, password: str) -> SessionContext:
    stage = "connect"
    sock = mqlogin.open_socket(args.host, args.port, args.socks, args.timeout)
    try:
        sock.settimeout(mqlogin.READ_TIMEOUT)
        active_ccsid = mqlogin.LOCAL_CCSID
        id_flags2 = 0x51
        id_flags3 = 0x28
        client_r = mqlogin.os.urandom(12)

        for _ in range(4):
            stage = "id-send"
            id_packet = mqlogin.build_initial_id_packet(args.channel, args.qmgr, client_r, active_ccsid, id_flags2, id_flags3)
            mqlogin.debug_tsh(args, "tx", stage, id_packet)
            sock.sendall(id_packet)

            stage = "id-recv"
            id_reply = mqlogin.recv_tsh_packet(sock)
            mqlogin.debug_tsh(args, "rx", stage, id_reply)
            if id_reply[9] != mqlogin.RFP_TST_INITIAL_INFO:
                status_detail = ""
                if id_reply[9] == mqlogin.RFP_TST_STATUS_INFO:
                    status_detail = f": {mqlogin.describe_error_status(id_reply)}"
                raise RuntimeError(f"expected INITIAL_INFO reply, received segment {id_reply[9]}{status_detail}")

            err_flag, channel, queue_manager, fap_level, ppa, server_r, swap, remote_ccsid = mqlogin.parse_id_response(id_reply)
            mqlogin.debug_id_reply(args, id_reply)

            if id_reply[10] & 0x02:
                body = id_reply[mqlogin.TSH_HEADER_SIZE :]
                next_ccsid = remote_ccsid
                next_flags2 = id_flags2 & ~body[45]
                next_flags3 = id_flags3 & ~body[133]
                if (next_ccsid, next_flags2, next_flags3) != (active_ccsid, id_flags2, id_flags3):
                    active_ccsid = next_ccsid
                    id_flags2 = next_flags2
                    id_flags3 = next_flags3
                    continue
                raise RuntimeError("queue manager rejected initial negotiation without a supported retry change")
            break
        else:
            raise AssertionError("initial negotiation did not complete")

        if err_flag not in (None, 0):
            raise RuntimeError(f"listener rejected initial ID with {mqlogin.RFP_ERR_CODES.get(err_flag, err_flag)}")

        if ppa is not None and ppa not in (0, 1):
            raise RuntimeError(f"queue manager selected unsupported password protection algorithm: {ppa}")
        if ppa == 1 and len(server_r) != 12:
            raise RuntimeError("queue manager selected DES password protection without an R value")

        stage = "uid-send"
        uid_packet = mqlogin.build_uid_packet(mqlogin.getpass.getuser(), fap_level or mqlogin.RFP_FAP_LEVEL, active_ccsid)
        mqlogin.debug_tsh(args, "tx", stage, uid_packet)
        sock.sendall(uid_packet)

        stage = "caut-send"
        r_state = client_r + server_r
        caut_packet = mqlogin.build_caut_packet(
            args.user,
            password,
            fap_level or mqlogin.RFP_FAP_LEVEL,
            ppa or 0,
            r_state,
            swap,
            active_ccsid,
        )
        mqlogin.debug_tsh(args, "tx", stage, caut_packet)
        sock.sendall(caut_packet)

        stage = "caut-recv"
        caut_reply = mqlogin.recv_tsh_packet(sock)
        mqlogin.debug_tsh(args, "rx", stage, caut_reply)
        caut_ok, caut_error = mqlogin.parse_status_packet(caut_reply)
        if not caut_ok:
            raise RuntimeError(caut_error or "queue manager rejected authentication")

        stage = "mqconn-send"
        mqconn_packet = mqlogin.build_mqconn_packet(args.qmgr, fap_level or mqlogin.RFP_FAP_LEVEL, active_ccsid)
        mqlogin.debug_tsh(args, "tx", stage, mqconn_packet)
        sock.sendall(mqconn_packet)

        stage = "mqconn-recv"
        conn_reply = mqlogin.recv_tsh_packet(sock)
        mqlogin.debug_tsh(args, "rx", stage, conn_reply)
        result = mqlogin.parse_mqconn_reply(conn_reply)
        if not result.ok:
            detail = result.error_text or "MQCONN failed"
            if result.reason_code is not None:
                detail = f"{detail} ({mqlogin.format_mqrc(result.reason_code)})"
            raise RuntimeError(detail)

        return SessionContext(
            sock=sock,
            queue_manager=queue_manager,
            channel=channel,
            fap_level=fap_level or mqlogin.RFP_FAP_LEVEL,
            password_protection=ppa or 0,
            handle=result.handle or 0,
            swap=swap,
            ccsid=active_ccsid,
        )
    except Exception:
        sock.close()
        raise


def query_spi_functions(args: argparse.Namespace, password: str) -> QueryResult:
    session: SessionContext | None = None
    try:
        session = establish_session(args, password)
        result = QueryResult(
            queue_manager=session.queue_manager,
            channel=session.channel,
            handle=session.handle,
            fap_level=session.fap_level,
            password_protection=session.password_protection,
            stage="spi-query",
        )

        packet = build_spi_query_packet(session.swap, session.ccsid)
        mqlogin.debug_tsh(args, "tx", "spi-query-send", packet)
        session.sock.sendall(packet)

        reply = mqlogin.recv_tsh_packet(session.sock)
        mqlogin.debug_tsh(args, "rx", "spi-query-recv", reply)
        if len(reply) < mqlogin.TSH_HEADER_SIZE:
            result.error_text = "short SPI reply"
            return result
        if reply[9] == mqlogin.RFP_TST_STATUS_INFO:
            result.error_text = mqlogin.describe_error_status(reply)
            return result
        if reply[9] != RFP_TST_API_REPLY:
            result.error_text = f"unexpected SPI reply segment {reply[9]}"
            return result

        comp_code, reason_code, verbs = parse_spi_query_reply(reply, session.swap)
        result.comp_code = comp_code
        result.reason_code = reason_code
        result.verbs = verbs
        return result
    except Exception as exc:
        return QueryResult(error_text=str(exc))
    finally:
        if session is not None:
            session.sock.close()


def print_result(args: argparse.Namespace, result: QueryResult) -> int:
    print()
    print(BANNER_LINE)
    print()
    print(f"[+] Connecting to {args.host}({args.port})")
    print(f"    channel: {args.channel}")
    print(f"    queue manager: {args.qmgr or '<default>'}")
    print(f"    user: {args.user}")
    print("    backend: raw")

    if result.error_text:
        print("    login/query: failed")
        if result.stage:
            print(f"    stage: {result.stage}")
        print(f"    error: {result.error_text}")
        print()
        return 1

    print("    login/query: success")
    if result.queue_manager:
        print(f"    connected queue manager: {result.queue_manager}")
    if result.channel:
        print(f"    negotiated channel: {result.channel}")
    if result.handle is not None:
        print(f"    handle: {result.handle}")
    if result.fap_level is not None:
        print(f"    fap_level: {result.fap_level}")
    if result.password_protection is not None:
        print(f"    password protection: {mqlogin.format_password_protection(result.password_protection)}")
    if result.comp_code is not None:
        print(f"    spi mqcc: {result.comp_code}")
    if result.reason_code is not None:
        print(f"    spi mqrc: {mqlogin.format_mqrc(result.reason_code)}")

    verbs = result.verbs or []
    print(f"    spi functions: {len(verbs)}")
    print()
    for verb in verbs:
        print(format_spi_verb(verb))
    if not verbs:
        print("no SPI functions returned")
    print()
    return 0 if (result.comp_code in (0, 1, None)) else 1


def main() -> int:
    args = parse_args()
    password = mqlogin.resolve_password(args)
    result = query_spi_functions(args, password)
    return print_result(args, result)


if __name__ == "__main__":
    raise SystemExit(main())
