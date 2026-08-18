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

# Raw MQI flow types and a deliberately small set of read-only inquiry values.
RFP_TST_MQOPEN = 131
RFP_TST_MQCLOSE = 132
RFP_TST_MQINQ = 137
RFP_TST_MQOPEN_REPLY = 147
RFP_TST_MQCLOSE_REPLY = 148
RFP_TST_MQINQ_REPLY = 153
RFP_TST_MQGET = 133
RFP_TST_MQGET_REPLY = 149
MQOD_V1_SIZE = 168
MQOPEN_PRIV_V1_SIZE = 28
MQOO_INQUIRE = 0x00000020
MQOO_BROWSE = 0x00000008
MQCO_NONE = 0
MQOT_Q = 1
MQOT_Q_MGR = 5
MQGMO_BROWSE_FIRST = 0x00000010
MQGMO_BROWSE_NEXT = 0x00000020
MQGMO_ACCEPT_TRUNCATED_MSG = 0x00000040
MQMD_V1_SIZE = 324
MQGMO_V1_SIZE = 72
MQIA_CODED_CHAR_SET_ID = 2
MQIA_MAX_MSG_LENGTH = 13
MQIA_MAX_PRIORITY = 14
MQIA_COMMAND_LEVEL = 31
MQIA_PLATFORM = 32
MQCA_Q_MGR_NAME = 2015
MQIA_CURRENT_Q_DEPTH = 3
MQIA_DEF_PERSISTENCE = 5
MQIA_INHIBIT_GET = 9
MQIA_INHIBIT_PUT = 10
MQIA_MAX_Q_DEPTH = 15
MQIA_Q_TYPE = 20
MQCA_Q_NAME = 2016
QMGR_INFO_SELECTORS = (
    ("coded_char_set_id", MQIA_CODED_CHAR_SET_ID),
    ("max_message_length", MQIA_MAX_MSG_LENGTH),
    ("max_priority", MQIA_MAX_PRIORITY),
    ("command_level", MQIA_COMMAND_LEVEL),
    ("platform", MQIA_PLATFORM),
)
MQ_PLATFORM_NAMES = {
    1: "z/OS (MVS/OS390)",
    2: "OS/2",
    3: "AIX/UNIX",
    4: "IBM i (OS/400)",
    5: "Windows",
    11: "Windows NT",
    12: "OpenVMS",
    13: "NonStop (NSK/NSS)",
    15: "Open TP1",
    18: "z/VM",
    23: "z/TPF",
    27: "z/VSE",
    28: "IBM MQ Appliance",
}
MQ_CCSID_NAMES = {
    37: "EBCDIC US/Canada",
    500: "EBCDIC International",
    819: "ISO-8859-1 (Latin-1)",
    870: "EBCDIC Multilingual Latin-2",
    1200: "UTF-16",
    1208: "UTF-8",
}
MQ_QUEUE_TYPE_NAMES = {1: "local", 2: "model", 3: "alias", 6: "remote"}
MQ_PERSISTENCE_NAMES = {0: "not persistent", 1: "persistent", 2: "as queue default"}
MQ_INHIBIT_NAMES = {0: "allowed", 1: "inhibited"}


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


@dataclass
class MqiInquireResult:
    comp_code: int
    reason_code: int
    int_attributes: list[int] | None = None
    char_attributes: bytes = b""
    error_text: str | None = None


@dataclass
class BrowseResult:
    comp_code: int
    reason_code: int
    data: bytes = b""
    data_length: int | None = None
    ccsid: int | None = None
    format_name: str | None = None
    message_id: bytes | None = None
    error_text: str | None = None


def format_spi_verb(verb: SpiVerb) -> str:
    """Format a non-empty SPI capability entry returned by SPI QUERY."""
    return (
        f"verb_id={verb.verb_id} ({SPI_VERB_NAMES.get(verb.verb_id, 'UNKNOWN')}) "
        f"max_inout={verb.max_inout_version} "
        f"max_in={verb.max_in_version} "
        f"max_out={verb.max_out_version} "
        f"flags=0x{verb.flags:08x}"
    )


def format_mq_platform(platform: int) -> str:
    return f"{platform} ({MQ_PLATFORM_NAMES.get(platform, 'unknown platform')})"


def format_mq_ccsid(ccsid: int) -> str:
    return f"{ccsid} ({MQ_CCSID_NAMES.get(ccsid, 'unknown CCSID')})"


def format_command_level(command_level: int) -> str:
    if 900 <= command_level <= 999:
        return f"{command_level} (IBM MQ {command_level // 100}.{(command_level // 10) % 10}.{command_level % 10})"
    return str(command_level)


def format_queue_attribute(name: str, value: int | str) -> int | str:
    if not isinstance(value, int):
        return value
    if name == "queue_type":
        return f"{value} ({MQ_QUEUE_TYPE_NAMES.get(value, 'unknown type')})"
    if name == "default_persistence":
        return f"{value} ({MQ_PERSISTENCE_NAMES.get(value, 'unknown persistence')})"
    if name in ("get", "put"):
        return f"{value} ({MQ_INHIBIT_NAMES.get(value, 'unknown state')})"
    return value


def format_queue_manager_attribute(name: str, value: int | str) -> int | str:
    if name == "coded_char_set_id" and isinstance(value, int):
        return format_mq_ccsid(value)
    if name == "command_level" and isinstance(value, int):
        return format_command_level(value)
    if name == "platform" and isinstance(value, int):
        return format_mq_platform(value)
    if name == "max_message_length" and value == 0:
        return "0 (not reported)"
    return value


def _build_mqi_packet(
    segment_type: int,
    handle: int,
    body: bytes,
    swap: bool,
    ccsid: int,
    expected_reply_bytes: int = 0,
) -> bytes:
    payload = bytearray(mqlogin.MQAPI_HEADER_SIZE + len(body))
    # RfpMQAPI CallLength includes the request and the caller-provided output
    # buffer.  TransLength (the TSH length) covers the request only.
    mqlogin.write_u32(payload, 0, len(payload) + mqlogin.TSH_HEADER_SIZE + expected_reply_bytes)
    mqlogin.write_u32_ordered(payload, 12, handle, swap)
    payload[mqlogin.MQAPI_HEADER_SIZE :] = body
    return mqlogin.build_tsh(segment_type, len(payload), mqlogin.RFP_TCF_FIRST | mqlogin.RFP_TCF_LAST, ccsid) + payload


def _parse_mqi_reply(packet: bytes, expected_segment: int, swap: bool) -> tuple[int, int]:
    if len(packet) >= mqlogin.TSH_HEADER_SIZE and packet[9] == mqlogin.RFP_TST_STATUS_INFO:
        raise ValueError(mqlogin.describe_error_status(packet))
    if len(packet) < mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE:
        raise ValueError("short MQI reply")
    if packet[9] != expected_segment:
        raise ValueError(f"unexpected MQI reply segment {packet[9]}")
    base = mqlogin.TSH_HEADER_SIZE
    return (
        mqlogin.read_u32_ordered(packet, base + 4, swap),
        mqlogin.read_u32_ordered(packet, base + 8, swap),
    )


def _recv_spanned_mqi_reply(session_sock: object) -> bytes:
    """Receive an MQI reply and append any RFP continuation payloads.

    MQGET replies can be segmented before the fixed MQMD/MQGMO portion as well
    as within message data.  The first TSH supplies the reply type and all
    continuations contribute only their payload.
    """
    packet = mqlogin.recv_tsh_packet(session_sock)
    combined = bytearray(packet)
    segments = 1
    while len(packet) >= mqlogin.TSH_HEADER_SIZE and not (packet[10] & mqlogin.RFP_TCF_LAST):
        if segments >= 1024:
            raise ValueError("too many MQI reply continuation segments")
        packet = mqlogin.recv_tsh_packet(session_sock)
        if len(packet) < mqlogin.TSH_HEADER_SIZE:
            raise ValueError("short MQI reply continuation")
        combined.extend(packet[mqlogin.TSH_HEADER_SIZE :])
        segments += 1
    return bytes(combined)


def build_mqinq_packet(handle: int, selectors: list[int], char_attr_length: int, swap: bool, ccsid: int) -> bytes:
    int_attr_count = sum(selector <= 2000 for selector in selectors)
    body = bytearray(12 + 4 * len(selectors))
    mqlogin.write_u32_ordered(body, 0, len(selectors), swap)
    mqlogin.write_u32_ordered(body, 4, int_attr_count, swap)
    mqlogin.write_u32_ordered(body, 8, char_attr_length, swap)
    for index, selector in enumerate(selectors):
        mqlogin.write_u32_ordered(body, 12 + index * 4, selector, swap)
    expected_reply_bytes = int_attr_count * 4 + char_attr_length + 1
    return _build_mqi_packet(RFP_TST_MQINQ, handle, body, swap, ccsid, expected_reply_bytes)


def inquire(session_sock: object, handle: int, selectors: list[int], char_attr_length: int, swap: bool, ccsid: int) -> MqiInquireResult:
    """Perform a read-only MQINQ on an existing MQCONN/MQOPEN handle."""
    try:
        packet = build_mqinq_packet(handle, selectors, char_attr_length, swap, ccsid)
        session_sock.sendall(packet)
        reply = _recv_spanned_mqi_reply(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQINQ_REPLY, swap)
        if comp_code == 2:
            return MqiInquireResult(comp_code, reason_code)
        int_count = sum(selector <= 2000 for selector in selectors)
        offset = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE + 12 + 4 * len(selectors)
        required = offset + int_count * 4 + char_attr_length
        if len(reply) < required:
            return MqiInquireResult(comp_code, reason_code, error_text="truncated MQINQ reply")
        # MQI integer attributes are signed MQLONG values.  In particular, MQ
        # uses -1 (0xffffffff on the wire) for values that are not applicable.
        int_attributes = []
        for index in range(int_count):
            value = mqlogin.read_u32_ordered(reply, offset + 4 * index, swap)
            int_attributes.append(value - 0x100000000 if value >= 0x80000000 else value)
        char_offset = offset + int_count * 4
        return MqiInquireResult(comp_code, reason_code, int_attributes, reply[char_offset : char_offset + char_attr_length])
    except Exception as exc:
        return MqiInquireResult(2, 2195, error_text=str(exc))


def build_mqopen_packet(
    object_name: str | None,
    object_type: int,
    swap: bool,
    ccsid: int,
    fap_level: int,
    open_options: int = MQOO_INQUIRE,
) -> bytes:
    name = mqlogin.encode_mq_bytes(object_name or "", ccsid)
    if object_name is not None and (not name or len(name) > 48):
        raise ValueError("object name must contain 1 to 48 encoded bytes")
    # MQOD V1 fields are fixed-width MQ character fields.  The IBM client
    # writes empty fields as CCSID-specific spaces and defaults DynamicQName
    # to AMQ.*; NUL-filled fields are rejected as MQRC_OD_ERROR (2044).
    space = mqlogin.encode_mq_bytes(" ", ccsid)
    def mq_field(value: bytes, length: int) -> bytes:
        return value[:length].ljust(length, space)

    od = bytearray(MQOD_V1_SIZE)
    od[0:4] = mq_field(mqlogin.encode_mq_bytes("OD  ", ccsid), 4)
    mqlogin.write_u32_ordered(od, 4, 1, swap)
    mqlogin.write_u32_ordered(od, 8, object_type, swap)
    od[12:60] = mq_field(name, 48)
    od[60:108] = mq_field(b"", 48)
    od[108:156] = mq_field(mqlogin.encode_mq_bytes("AMQ.*", ccsid), 48)
    od[156:168] = mq_field(b"", 12)
    body = od + open_options.to_bytes(4, "little" if swap else "big")
    if fap_level >= 9:
        private = bytearray(b"FOPA" + b"\x00" * (MQOPEN_PRIV_V1_SIZE - 4))
        for offset in (4, 8):
            mqlogin.write_u32_ordered(private, offset, 1 if offset == 4 else MQOPEN_PRIV_V1_SIZE, swap)
        mqlogin.write_u32_ordered(private, 12, 0xFFFFFFFF, swap)
        mqlogin.write_u32_ordered(private, 16, 0xFFFFFFFF, swap)
        body += private
    return _build_mqi_packet(RFP_TST_MQOPEN, 0, body, swap, ccsid)


def open_for_inquire(
    session_sock: object,
    object_name: str | None,
    object_type: int,
    swap: bool,
    ccsid: int,
    fap_level: int,
    open_options: int = MQOO_INQUIRE,
) -> tuple[int | None, MqiInquireResult]:
    try:
        session_sock.sendall(build_mqopen_packet(object_name, object_type, swap, ccsid, fap_level, open_options))
        reply = mqlogin.recv_tsh_packet(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQOPEN_REPLY, swap)
        if comp_code == 2:
            return None, MqiInquireResult(comp_code, reason_code)
        handle = mqlogin.read_u32_ordered(reply, mqlogin.TSH_HEADER_SIZE + 12, swap)
        return handle, MqiInquireResult(comp_code, reason_code)
    except Exception as exc:
        return None, MqiInquireResult(2, 2195, error_text=str(exc))


def close_object(session_sock: object, handle: int, swap: bool, ccsid: int) -> None:
    session_sock.sendall(
        _build_mqi_packet(
            RFP_TST_MQCLOSE,
            handle,
            MQCO_NONE.to_bytes(4, "little" if swap else "big"),
            swap,
            ccsid,
        )
    )
    _parse_mqi_reply(mqlogin.recv_tsh_packet(session_sock), RFP_TST_MQCLOSE_REPLY, swap)


def inquire_queue_manager(session_sock: object, swap: bool, ccsid: int) -> tuple[dict[str, int | str], MqiInquireResult]:
    selectors = [selector for _, selector in QMGR_INFO_SELECTORS] + [MQCA_Q_MGR_NAME]
    handle, open_result = open_for_inquire(session_sock, None, MQOT_Q_MGR, swap, ccsid, 9)
    if handle is None:
        return {}, open_result
    try:
        result = inquire(session_sock, handle, selectors, 48, swap, ccsid)
        if result.error_text or result.comp_code == 2 or result.int_attributes is None:
            return {}, result
        values: dict[str, int | str] = {
            name: value for (name, _), value in zip(QMGR_INFO_SELECTORS, result.int_attributes)
        }
        values["queue_manager_name"] = mqlogin.decode_mq_field(result.char_attributes, ccsid)
        return values, result
    finally:
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def inquire_queue(session_sock: object, object_name: str, swap: bool, ccsid: int, fap_level: int) -> tuple[dict[str, int | str], MqiInquireResult]:
    """Open a queue with MQOO_INQUIRE only, return attributes, then close it."""
    handle, open_result = open_for_inquire(session_sock, object_name, MQOT_Q, swap, ccsid, fap_level)
    if handle is None:
        return {}, open_result
    try:
        selectors = [
            MQIA_CURRENT_Q_DEPTH,
            MQIA_MAX_Q_DEPTH,
            MQIA_Q_TYPE,
            MQIA_DEF_PERSISTENCE,
            MQIA_INHIBIT_GET,
            MQIA_INHIBIT_PUT,
            MQCA_Q_NAME,
        ]
        result = inquire(session_sock, handle, selectors, 48, swap, ccsid)
        if result.error_text or result.comp_code == 2 or result.int_attributes is None:
            return {}, result
        return {
            "current_depth": result.int_attributes[0],
            "max_depth": result.int_attributes[1],
            "queue_type": result.int_attributes[2],
            "default_persistence": result.int_attributes[3],
            "get": result.int_attributes[4],
            "put": result.int_attributes[5],
            "queue_name": mqlogin.decode_mq_field(result.char_attributes, ccsid),
        }, result
    finally:
        # A failed MQINQ can cause the queue manager to close the socket. Do
        # not hide the inquiry result with a secondary best-effort close error.
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def build_mqget_browse_packet(
    handle: int, max_bytes: int, swap: bool, ccsid: int, browse_option: int = MQGMO_BROWSE_FIRST
) -> bytes:
    if not 1 <= max_bytes <= 1024 * 1024:
        raise ValueError("browse byte limit must be between 1 and 1048576")
    md = bytearray(MQMD_V1_SIZE)
    md[0:4] = mqlogin.encode_mq_bytes("MD  ", ccsid)
    mqlogin.write_u32_ordered(md, 4, 1, swap)
    gmo = bytearray(MQGMO_V1_SIZE)
    gmo[0:4] = mqlogin.encode_mq_bytes("GMO ", ccsid)
    mqlogin.write_u32_ordered(gmo, 4, 1, swap)
    if browse_option not in (MQGMO_BROWSE_FIRST, MQGMO_BROWSE_NEXT):
        raise ValueError("invalid non-destructive browse option")
    mqlogin.write_u32_ordered(gmo, 8, browse_option | MQGMO_ACCEPT_TRUNCATED_MSG, swap)
    body = md + gmo + max_bytes.to_bytes(4, "little" if swap else "big")
    return _build_mqi_packet(RFP_TST_MQGET, handle, body, swap, ccsid, max_bytes)


def browse_message(
    session_sock: object, handle: int, max_bytes: int, swap: bool, ccsid: int, browse_option: int
) -> BrowseResult:
    """Browse, never consume, at most ``max_bytes`` from the current cursor position."""
    try:
        session_sock.sendall(build_mqget_browse_packet(handle, max_bytes, swap, ccsid, browse_option))
        reply = _recv_spanned_mqi_reply(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQGET_REPLY, swap)
        if comp_code == 2:
            return BrowseResult(comp_code, reason_code)
        base = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE
        data_offset = base + MQMD_V1_SIZE + MQGMO_V1_SIZE
        if len(reply) < data_offset + 4:
            return BrowseResult(
                comp_code,
                reason_code,
                error_text=(
                    f"truncated MQGET reply (received {len(reply)} bytes; "
                    f"need at least {data_offset + 4} bytes for MQMD/MQGMO/data length)"
                ),
            )
        data_length = mqlogin.read_u32_ordered(reply, data_offset, swap)
        body_start = data_offset + 4
        data = reply[body_start : body_start + min(max_bytes, data_length)]
        return BrowseResult(
            comp_code,
            reason_code,
            data=data,
            data_length=data_length,
            ccsid=mqlogin.read_u32_ordered(reply, base + 28, swap),
            format_name=mqlogin.decode_mq_field(reply[base + 32 : base + 40], ccsid),
            message_id=reply[base + 48 : base + 72],
        )
    except Exception as exc:
        return BrowseResult(2, 2195, error_text=str(exc))


def browse_queue(
    session_sock: object, object_name: str, max_bytes: int, swap: bool, ccsid: int, fap_level: int
) -> BrowseResult:
    handle, open_result = open_for_inquire(
        session_sock, object_name, MQOT_Q, swap, ccsid, fap_level, MQOO_INQUIRE | MQOO_BROWSE
    )
    if handle is None:
        return BrowseResult(open_result.comp_code, open_result.reason_code, error_text=open_result.error_text)
    try:
        return browse_message(session_sock, handle, max_bytes, swap, ccsid, MQGMO_BROWSE_FIRST)
    finally:
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def browse_queue_messages(
    session_sock: object, object_name: str, max_bytes: int, count: int, swap: bool, ccsid: int, fap_level: int
) -> list[BrowseResult]:
    """Browse up to ``count`` messages using BROWSE_FIRST then BROWSE_NEXT."""
    if count < 1:
        raise ValueError("browse count must be at least 1")
    handle, open_result = open_for_inquire(
        session_sock, object_name, MQOT_Q, swap, ccsid, fap_level, MQOO_INQUIRE | MQOO_BROWSE
    )
    if handle is None:
        return [BrowseResult(open_result.comp_code, open_result.reason_code, error_text=open_result.error_text)]
    results: list[BrowseResult] = []
    try:
        for index in range(count):
            result = browse_message(
                session_sock, handle, max_bytes, swap, ccsid,
                MQGMO_BROWSE_FIRST if index == 0 else MQGMO_BROWSE_NEXT,
            )
            if result.reason_code == 2033:
                if not results:
                    results.append(result)
                break
            results.append(result)
            if result.error_text or result.comp_code == 2:
                break
        return results
    finally:
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


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
