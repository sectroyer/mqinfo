#!/usr/bin/env python3

"""Authenticated IBM MQ diagnostics using the raw RFP protocol.

Provides SPI capability discovery, read-only PCF inquiries, optional
dead-letter-queue inspection, and MQSC diagnostics.
"""

import argparse
import getpass
import os
import struct
import sys
from dataclasses import dataclass

import mqlogin
# IBM MQ protocol constants (segment types, structure sizes/offsets,
# option flags, attribute selectors, MQDLH layout).
from mqrc_codes import *  # noqa: F403


SCRIPT_VERSION = "0.1.0"
BANNER_TITLE = "IBM MQ Functions Tool"
BANNER_CREDIT = "by Michał Majchrowicz AFINE Team"
BANNER_LINE = f"{BANNER_TITLE} v{SCRIPT_VERSION} {BANNER_CREDIT}"

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
PCF_REPLY_MODEL_QUEUE = "SYSTEM.DEFAULT.MODEL.QUEUE"
# On z/OS the command server replies to a queue derived from the command
# reply model. SYSTEM.DEFAULT.MODEL.QUEUE is normally DEFTYPE(TEMPDYN),
# which is not a suitable reply target for the command server's address
# space, so the command reply model is preferred on that platform.
PCF_REPLY_MODEL_QUEUE_ZOS = "SYSTEM.COMMAND.REPLY.MODEL"
PCF_COMMAND_QUEUE = "SYSTEM.ADMIN.COMMAND.QUEUE"
PCF_REQUEST_EXPIRY = 300
# Longer expiry (5 min) for requests whose replies may need to be collected
# from the dead-letter queue instead of the reply queue. See
# recover_pcf_replies_via_dlq for when that applies.
PCF_DLQ_RECOVERY_EXPIRY = 3000
QMGR_EVENT_QUEUE = "SYSTEM.ADMIN.QMGR.EVENT"
MQCMD_ESCAPE = 38
MQIACF_ESCAPE_TYPE = 1017
MQCACF_ESCAPE_TEXT = 3014
MQET_MQSC = 1
# MQDLH (dead-letter header) layout, big-endian. The original undelivered
# message follows immediately at MQDLH_SIZE.
PCF_QUEUE_LIST_SELECTORS = (
    MQCA_Q_NAME,
    MQIA_CURRENT_Q_DEPTH,
    MQIA_MAX_Q_DEPTH,
    MQIA_Q_TYPE,
)
QMGR_INFO_SELECTORS = (
    ("coded_char_set_id", MQIA_CODED_CHAR_SET_ID),
    ("max_message_length", MQIA_MAX_MSG_LENGTH),
    ("max_priority", MQIA_MAX_PRIORITY),
    ("command_level", MQIA_COMMAND_LEVEL),
    ("platform", MQIA_PLATFORM),
)


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
class DynamicReplyQueue:
    handle: int | None
    name: str | None
    result: MqiInquireResult


@dataclass
class MqiPutResult:
    comp_code: int
    reason_code: int
    correlation_id: bytes | None = None
    error_text: str | None = None


@dataclass(frozen=True)
class PcfQueueRecord:
    name: str
    current_depth: int | None
    max_depth: int | None
    queue_type: int | None


@dataclass
class PcfQueueListResult:
    records: list[PcfQueueRecord]
    comp_code: int
    reason_code: int
    error_text: str | None = None
    reply_queue_name: str | None = None


@dataclass
class PcfQmgrProbeResult:
    responses: list[object]
    comp_code: int
    reason_code: int
    error_text: str | None = None
    reply_queue_name: str | None = None


@dataclass(frozen=True)
class DeadLetterRecord:
    """One browsed dead-letter message: its DLH fields and the original payload."""
    reason_code: int
    dest_queue: str
    dest_qmgr: str
    ccsid: int
    format_name: str
    payload: bytes


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


class SessionError(RuntimeError):
    """Attach the failing protocol stage to a session setup error."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage


def mqenc_native(swap: bool) -> int:
    """Return MQENC_NATIVE for the queue manager's negotiated byte order."""
    return 546 if swap else MQENC_NATIVE


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
    dynamic_queue_name: str = "AMQ.*",
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
    dynamic_name = mqlogin.encode_mq_bytes(dynamic_queue_name, ccsid)
    if not dynamic_name or len(dynamic_name) > 48:
        raise ValueError("dynamic queue name must contain 1 to 48 encoded bytes")
    od[108:156] = mq_field(dynamic_name, 48)
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


def build_dynamic_reply_mqopen_packet(
    swap: bool,
    ccsid: int,
    fap_level: int,
    model_queue: str = PCF_REPLY_MODEL_QUEUE,
    dynamic_prefix: str = "AMQ.PCF.*",
) -> bytes:
    """Build an MQOPEN for a dynamic PCF reply queue.

    The queue manager derives a unique name from ``model_queue`` and
    ``dynamic_prefix``.  This helper only constructs bytes; it performs no I/O.
    """
    return build_mqopen_packet(
        model_queue,
        MQOT_Q,
        swap,
        ccsid,
        fap_level,
        # PCFAgent uses an exclusive input handle for its private reply queue
        # (8196). This prevents another consumer from stealing a reply.
        MQOO_INPUT_EXCLUSIVE | MQOO_FAIL_IF_QUIESCING,
        dynamic_prefix,
    )


def build_pcf_command_queue_mqopen_packet(swap: bool, ccsid: int, fap_level: int) -> bytes:
    """Build an MQOPEN for the PCF command queue with output authority only."""
    return build_mqopen_packet(
        PCF_COMMAND_QUEUE,
        MQOT_Q,
        swap,
        ccsid,
        fap_level,
        # PCFAgent opens the command queue with output and inquire (8240).
        MQOO_OUTPUT | MQOO_INQUIRE | MQOO_FAIL_IF_QUIESCING,
    )


def open_pcf_command_queue(
    session_sock: object, swap: bool, ccsid: int, fap_level: int
) -> tuple[int | None, MqiInquireResult]:
    """Open the PCF command queue for output and return its live MQ object handle."""
    try:
        session_sock.sendall(build_pcf_command_queue_mqopen_packet(swap, ccsid, fap_level))
        reply = _recv_spanned_mqi_reply(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQOPEN_REPLY, swap)
        result = MqiInquireResult(comp_code, reason_code)
        if comp_code == 2:
            return None, result
        if len(reply) < mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE:
            return None, MqiInquireResult(2, 2195, error_text="truncated command-queue MQOPEN reply")
        return mqlogin.read_u32_ordered(reply, mqlogin.TSH_HEADER_SIZE + 12, swap), result
    except Exception as exc:
        return None, MqiInquireResult(2, 2195, error_text=str(exc))


def open_dynamic_reply_queue(
    session_sock: object,
    swap: bool,
    ccsid: int,
    fap_level: int,
    model_queue: str = PCF_REPLY_MODEL_QUEUE,
    dynamic_prefix: str = "AMQ.PCF.*",
) -> DynamicReplyQueue:
    """Create/open a dynamic reply queue and return its resolved name.

    MQOPEN returns an MQOD in its reply; its ObjectName field contains the
    queue manager-generated dynamic name. The caller owns the returned handle
    and must close it when finished.
    """
    try:
        session_sock.sendall(
            build_dynamic_reply_mqopen_packet(swap, ccsid, fap_level, model_queue, dynamic_prefix)
        )
        reply = _recv_spanned_mqi_reply(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQOPEN_REPLY, swap)
        result = MqiInquireResult(comp_code, reason_code)
        if comp_code == 2:
            return DynamicReplyQueue(None, None, result)
        api_offset = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE
        required = api_offset + MQOD_V1_SIZE
        if len(reply) < required:
            return DynamicReplyQueue(None, None, MqiInquireResult(2, 2195, error_text="truncated dynamic MQOPEN reply"))
        handle = mqlogin.read_u32_ordered(reply, mqlogin.TSH_HEADER_SIZE + 12, swap)
        name = mqlogin.decode_mq_field(reply[api_offset + 12 : api_offset + 60], ccsid)
        if not name:
            return DynamicReplyQueue(None, None, MqiInquireResult(2, 2195, error_text="dynamic MQOPEN returned no queue name"))
        return DynamicReplyQueue(handle, name, result)
    except Exception as exc:
        return DynamicReplyQueue(None, None, MqiInquireResult(2, 2195, error_text=str(exc)))


def open_pcf_reply_queue(
    session_sock: object, swap: bool, ccsid: int, fap_level: int, platform: int | None, debug: bool = False
) -> DynamicReplyQueue:
    """Open a dynamic PCF reply queue using the model appropriate to the platform.

    On z/OS (platform 1) the command server replies to a queue derived from
    SYSTEM.COMMAND.REPLY.MODEL. SYSTEM.DEFAULT.MODEL.QUEUE is normally
    DEFTYPE(TEMPDYN), which is not a usable reply target for the command
    server's own address space, and a reply put there can be discarded
    silently. Falls back to the default model if the z/OS model is
    unavailable, so non-z/OS and unusual z/OS setups still work.
    """
    candidates: list[tuple[str, str]] = []
    if platform == 1:
        candidates.append((PCF_REPLY_MODEL_QUEUE_ZOS, "SYSTEM.COMMAND.REPLY.*"))
    candidates.append((PCF_REPLY_MODEL_QUEUE, "AMQ.PCF.*"))

    last = DynamicReplyQueue(None, None, MqiInquireResult(2, 2195, error_text="no reply model queue tried"))
    for model_queue, dynamic_prefix in candidates:
        reply_queue = open_dynamic_reply_queue(
            session_sock, swap, ccsid, fap_level, model_queue, dynamic_prefix
        )
        if debug:
            status = reply_queue.name if reply_queue.handle is not None else (
                reply_queue.result.error_text or mqlogin.format_mqrc(reply_queue.result.reason_code)
            )
            print(f"[debug] reply-queue model {model_queue!r} -> {status}", file=sys.stderr)
        if reply_queue.handle is not None:
            return reply_queue
        last = reply_queue
    return last


def build_pcf_request_mqmd(reply_to_queue: str, ccsid: int, reply_to_qmgr: str = "", swap: bool = False, expiry: int = PCF_REQUEST_EXPIRY) -> bytes:
    """Build an MQMD V1 for a PCF command request; no message is sent."""
    space = mqlogin.encode_mq_bytes(" ", ccsid)
    def field(value: str, length: int) -> bytes:
        raw = mqlogin.encode_mq_bytes(value, ccsid)
        if len(raw) > length:
            raise ValueError("MQMD character field exceeds its fixed width")
        return raw.ljust(length, space)

    # RemoteFAP's PCF request path uses MQMD V1. Keeping this descriptor V1
    # avoids shifting MQPMO for z/OS servers that parse PCF MQPUT requests
    # with the V1 fixed offset rather than reading Version dynamically.
    md = bytearray(MQMD_V1_SIZE)
    md[0:4] = field("MD  ", 4)
    mqlogin.write_u32_ordered(md, 4, 1, swap)
    # PCFAgent sets MQRO_PASS_CORREL_ID so the command server propagates the
    # generated request CorrelId to each reply on the dynamic reply queue.
    mqlogin.write_u32_ordered(md, MQMD_REPORT_OFFSET, MQRO_PASS_CORREL_ID, swap)
    mqlogin.write_u32_ordered(md, MQMD_MSG_TYPE_OFFSET, MQMT_REQUEST, swap)
    # PCFAgent's default request expiry is 30 seconds, represented as 300
    # tenths of a second in MQMD.Expiry.
    mqlogin.write_u32_ordered(md, MQMD_EXPIRY_OFFSET, expiry, swap)
    mqlogin.write_u32_ordered(md, MQMD_ENCODING_OFFSET, mqenc_native(swap), swap)
    mqlogin.write_u32_ordered(md, 28, ccsid, swap)
    md[MQMD_FORMAT_OFFSET : MQMD_FORMAT_OFFSET + 8] = field("MQADMIN", 8)
    mqlogin.write_u32_ordered(md, MQMD_PRIORITY_OFFSET, MQPRI_AS_Q_DEF & 0xFFFFFFFF, swap)
    mqlogin.write_u32_ordered(md, MQMD_PERSISTENCE_OFFSET, MQPER_NOT_PERSISTENT, swap)
    md[MQMD_REPLY_TO_Q_OFFSET : MQMD_REPLY_TO_Q_OFFSET + 48] = field(reply_to_queue, 48)
    md[MQMD_REPLY_TO_Q_MGR_OFFSET : MQMD_REPLY_TO_Q_MGR_OFFSET + 48] = field(reply_to_qmgr, 48)
    # z/OS validates character fields as blank; binary fields (AccountingToken,
    # PutApplType) remain at their zero defaults.
    for off, size in ((196, 12), (240, 32), (276, 28), (304, 8), (312, 8), (320, 4)):
        md[off : off + size] = space * size
    return bytes(md)


def build_pcf_inquire_q_mqmd(reply_queue: DynamicReplyQueue, ccsid: int, swap: bool, reply_to_qmgr: str = "", expiry: int = PCF_REQUEST_EXPIRY) -> bytes:
    """Build the PCF request MQMD using a live dynamic reply-queue context."""
    if reply_queue.handle is None or not reply_queue.name:
        raise ValueError("a successfully opened dynamic reply queue is required")
    return build_pcf_request_mqmd(reply_queue.name, ccsid, reply_to_qmgr=reply_to_qmgr, swap=swap, expiry=expiry)


def build_mqput_packet(handle: int, mqmd: bytes, message: bytes, swap: bool, ccsid: int, fap_level: int = 9) -> bytes:
    """Build an MQPUT request for a non-persistent PCF command message.

    This function only serializes a packet. Callers must not send it until the
    PCF request/reply flow has passed the remaining offline validation steps.
    """
    if len(mqmd) not in (MQMD_V1_SIZE, MQMD_V2_SIZE):
        raise ValueError("MQPUT requires an MQMD V1 or V2 structure")
    pmo = bytearray(MQPMO_V1_SIZE)
    pmo[0:4] = mqlogin.encode_mq_bytes("PMO ", ccsid)
    mqlogin.write_u32_ordered(pmo, 4, 1, swap)
    # NO_SYNCPOINT avoids RRS unit-of-work setup on z/OS.
    # NEW_CORREL_ID asks the QMgr to generate a CorrelId we can match on MQGET.
    mqlogin.write_u32_ordered(pmo, 8, MQPMO_NO_SYNCPOINT | MQPMO_NEW_CORREL_ID | MQPMO_FAIL_IF_QUIESCING, swap)
    space = mqlogin.encode_mq_bytes(" ", ccsid)
    pmo[32:80] = space * 48
    pmo[80:128] = space * 48

    fixed_body = mqmd + bytes(pmo) + len(message).to_bytes(4, "little" if swap else "big")
    # RemoteFAP CallLength includes the serialized structures AND the message data.
    # z/OS uses this value to determine how many bytes constitute the full MQPUT call.
    call_length = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE + len(fixed_body) + len(message)

    api_header = bytearray(mqlogin.MQAPI_HEADER_SIZE)
    mqlogin.write_u32(api_header, 0, call_length)
    mqlogin.write_u32_ordered(api_header, 12, handle, swap)

    full_payload = bytes(api_header) + fixed_body + message
    tsh = mqlogin.build_tsh(RFP_TST_MQPUT, len(full_payload), mqlogin.RFP_TCF_FIRST | mqlogin.RFP_TCF_LAST, ccsid)
    return tsh + full_payload


def put_pcf_command(
    session_sock: object,
    command_handle: int,
    mqmd: bytes,
    pcf_message: bytes,
    swap: bool,
    ccsid: int,
    debug: bool = False,
    fap_level: int = 9,
) -> MqiPutResult:
    """Send one PCF command message and return its assigned correlation ID."""
    try:
        if debug:
            reply_to_q = mqlogin.decode_mq_field(
                mqmd[MQMD_REPLY_TO_Q_OFFSET : MQMD_REPLY_TO_Q_OFFSET + 48], ccsid
            )
            reply_to_qmgr = mqlogin.decode_mq_field(
                mqmd[MQMD_REPLY_TO_Q_MGR_OFFSET : MQMD_REPLY_TO_Q_MGR_OFFSET + 48], ccsid
            )
            format_name = mqlogin.decode_mq_field(
                mqmd[MQMD_FORMAT_OFFSET : MQMD_FORMAT_OFFSET + 8], ccsid
            )
            print(
                f"[debug] PCF MQPUT: hobj={command_handle} pcf_bytes={len(pcf_message)} "
                f"mqmd_version={mqlogin.read_u32_ordered(mqmd, 4, swap)} "
                f"report=0x{mqlogin.read_u32_ordered(mqmd, MQMD_REPORT_OFFSET, swap):08x} "
                f"msg_type={mqlogin.read_u32_ordered(mqmd, MQMD_MSG_TYPE_OFFSET, swap)} "
                f"expiry={mqlogin.read_u32_ordered(mqmd, MQMD_EXPIRY_OFFSET, swap)} "
                f"encoding={mqlogin.read_u32_ordered(mqmd, MQMD_ENCODING_OFFSET, swap)} "
                f"ccsid={mqlogin.read_u32_ordered(mqmd, 28, swap)} format={format_name!r} "
                f"reply_to_q={reply_to_q!r} reply_to_qmgr={reply_to_qmgr!r}",
                file=sys.stderr,
            )
        mqput_packet = build_mqput_packet(command_handle, mqmd, pcf_message, swap, ccsid, fap_level)
        if debug:
            tsh_len = int.from_bytes(mqput_packet[4:8], "big")
            call_len = int.from_bytes(mqput_packet[mqlogin.TSH_HEADER_SIZE:mqlogin.TSH_HEADER_SIZE + 4], "big")
            pmo_base = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE + len(mqmd)
            pmo_version = mqlogin.read_u32_ordered(mqput_packet, pmo_base + 4, swap)
            pmo_options = mqlogin.read_u32_ordered(mqput_packet, pmo_base + 8, swap)
            pmo_size = MQPMO_V2_SIZE if pmo_version == 2 else MQPMO_V1_SIZE
            print(
                f"[debug] MQPUT packet: total={len(mqput_packet)} tsh_len={tsh_len} call_len={call_len} "
                f"pmo_version={pmo_version} pmo_size={pmo_size} pmo_options=0x{pmo_options:08x} pcf_hex={pcf_message.hex()}",
                file=sys.stderr,
            )
            print(f"[debug] MQPUT full packet hex: {mqput_packet.hex()}", file=sys.stderr)
        session_sock.sendall(mqput_packet)
        try:
            reply = _recv_spanned_mqi_reply(session_sock)
        except Exception as recv_exc:
            if debug:
                print(f"[debug] MQPUT recv failed: {recv_exc!r}", file=sys.stderr)
                try:
                    session_sock.settimeout(1.0)
                    leftover = session_sock.recv(4096)
                    print(f"[debug] MQPUT socket leftover: {leftover.hex() if leftover else '(empty)'}", file=sys.stderr)
                except Exception as le:
                    print(f"[debug] MQPUT no leftover: {le!r}", file=sys.stderr)
            raise
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQPUT_REPLY, swap)
        if debug:
            print(
                f"[debug] PCF MQPUT reply: mqcc={mqlogin.format_mqcc(comp_code)} mqrc={mqlogin.format_mqrc(reason_code)}",
                file=sys.stderr,
            )
            if comp_code == 2:
                print(f"[debug] PCF MQPUT reply raw: {reply.hex()}", file=sys.stderr)
        if comp_code == 2:
            return MqiPutResult(comp_code, reason_code)
        md_offset = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE
        if len(reply) < md_offset + MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE:
            return MqiPutResult(comp_code, reason_code, error_text="truncated MQPUT reply MQMD")
        result = MqiPutResult(
            comp_code,
            reason_code,
            correlation_id=reply[md_offset + MQMD_CORREL_ID_OFFSET : md_offset + MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE],
        )
        if debug:
            all_zero = not any(result.correlation_id)
            print(
                f"[debug] PCF request CorrelId={result.correlation_id.hex()}"
                + (" (WARNING: all-zero CorrelId — MQGET will never match)" if all_zero else ""),
                file=sys.stderr,
            )
        return result
    except Exception as exc:
        return MqiPutResult(2, 2195, error_text=str(exc))
def response_matches_request(response_mqmd: bytes, request_correlation_id: bytes) -> bool:
    """Return whether a reply MQMD matches the PCF request correlation ID."""
    return (
        len(response_mqmd) >= MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE
        and len(request_correlation_id) == MQMD_ID_SIZE
        and response_mqmd[MQMD_CORREL_ID_OFFSET : MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE] == request_correlation_id
    )


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
        reply = _recv_spanned_mqi_reply(session_sock)
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


def inquire_queue_manager(session_sock: object, swap: bool, ccsid: int, fap_level: int = 9) -> tuple[dict[str, int | str], MqiInquireResult]:
    selectors = [selector for _, selector in QMGR_INFO_SELECTORS] + [MQCA_Q_MGR_NAME]
    handle, open_result = open_for_inquire(session_sock, None, MQOT_Q_MGR, swap, ccsid, fap_level)
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


def parse_dead_letter_message(data: bytes, ccsid: int) -> DeadLetterRecord | None:
    """Split a browsed MQDEAD message into its DLH fields and original payload.

    Returns None when the buffer does not start with a DLH eyecatcher.
    """
    if len(data) < MQDLH_SIZE or data[0:4] not in (b"DLH ", mqlogin.encode_mq_bytes("DLH ", ccsid)):
        return None
    return DeadLetterRecord(
        reason_code=int.from_bytes(data[MQDLH_REASON_OFFSET : MQDLH_REASON_OFFSET + 4], "big"),
        dest_queue=mqlogin.decode_mq_field(data[MQDLH_DEST_Q_NAME_OFFSET : MQDLH_DEST_Q_NAME_OFFSET + 48], ccsid),
        dest_qmgr=mqlogin.decode_mq_field(data[MQDLH_DEST_Q_MGR_OFFSET : MQDLH_DEST_Q_MGR_OFFSET + 48], ccsid),
        ccsid=int.from_bytes(data[MQDLH_CCSID_OFFSET : MQDLH_CCSID_OFFSET + 4], "big"),
        format_name=mqlogin.decode_mq_field(data[MQDLH_FORMAT_OFFSET : MQDLH_FORMAT_OFFSET + 8], ccsid),
        payload=data[MQDLH_SIZE:],
    )


def recover_pcf_replies_via_dlq(
    session_sock: object,
    reply_queue_name: str,
    swap: bool,
    ccsid: int,
    fap_level: int,
    debug: bool = False,
) -> list[object]:
    """Resolve the DLQ and pull back any PCF replies addressed to one queue."""
    dlq_name, _ = inquire_dead_letter_queue_name(session_sock, swap, ccsid, fap_level)
    if not dlq_name:
        return []
    pairs = recover_dead_lettered_pcf_pairs(
        session_sock, dlq_name, {reply_queue_name}, swap, ccsid, fap_level, debug=debug
    )
    if debug:
        print(
            f"[debug] DLQ fallback for {reply_queue_name}: {len(pairs)} reply/replies",
            file=sys.stderr,
        )
    return [response for _, response in pairs if response is not None]


def recover_dead_lettered_pcf_pairs(
    session_sock: object,
    dlq_name: str,
    reply_queue_names: set[str],
    swap: bool,
    ccsid: int,
    fap_level: int,
    max_messages: int = 200,
    max_bytes: int = 4096,
    debug: bool = False,
) -> list[tuple[DeadLetterRecord, object | None]]:
    """Recover dead-lettered PCF replies as (dlh_record, parsed_response) pairs.

    Pairing matters: a single command can produce several replies (a detail
    response carrying the real reason, then a summary response), and a payload
    that fails to parse must not shift the alignment of everything after it.
    Callers that need to attribute a reason to a specific request must use
    these pairs rather than two parallel lists.
    """
    import mqpcf

    pairs: list[tuple[DeadLetterRecord, object | None]] = []
    for browse in browse_queue_messages(
        session_sock, dlq_name, max_bytes, max_messages, swap, ccsid, fap_level
    ):
        if browse.error_text or browse.comp_code == 2 or not browse.data:
            continue
        record = parse_dead_letter_message(browse.data, ccsid)
        if record is None or (reply_queue_names and record.dest_queue not in reply_queue_names):
            continue
        try:
            pairs.append((record, mqpcf.parse_response(record.payload)))
        except Exception as exc:
            if debug:
                print(
                    f"[debug] DLQ reply for {record.dest_queue} not parseable as PCF: {exc}",
                    file=sys.stderr,
                )
            pairs.append((record, None))
    return pairs


def recover_dead_lettered_pcf_replies(
    session_sock: object,
    dlq_name: str,
    reply_queue_names: set[str],
    swap: bool,
    ccsid: int,
    fap_level: int,
    max_messages: int = 200,
    max_bytes: int = 4096,
    debug: bool = False,
) -> tuple[list[object], list[DeadLetterRecord]]:
    """Browse the dead-letter queue and recover PCF replies addressed to us.

    A command server reply is not always deliverable to the requester's reply
    queue -- the queue may be full, put-inhibited, or refused for the
    requesting identity. In those cases the queue manager routes the reply to
    the dead-letter queue instead, where the original message survives intact
    behind the MQDLH. This reads such replies back from the DLQ.

    Browsing only; nothing is consumed.
    """
    pairs = recover_dead_lettered_pcf_pairs(
        session_sock, dlq_name, reply_queue_names, swap, ccsid, fap_level,
        max_messages, max_bytes, debug,
    )
    matched = [record for record, _ in pairs]
    parsed = [response for _, response in pairs if response is not None]
    if debug:
        print(
            f"[debug] DLQ recovery: matched={len(matched)} parsed={len(parsed)}",
            file=sys.stderr,
        )
    return parsed, matched


def enumerate_dead_letter_queue(
    session_sock: object,
    dlq_name: str,
    swap: bool,
    ccsid: int,
    fap_level: int,
    max_messages: int = 200,
    max_bytes: int = 4096,
) -> tuple[list[DeadLetterRecord], list[BrowseResult]]:
    """Browse the whole dead-letter queue and decode every DLH.

    Read-only (MQOO_BROWSE); nothing is consumed. The DLH DestQName fields
    are a queue-name discovery channel that does not depend on PCF being
    authorized, and the payloads show what data is exposed to a client that
    can browse the DLQ.
    """
    records: list[DeadLetterRecord] = []
    others: list[BrowseResult] = []
    for browse in browse_queue_messages(
        session_sock, dlq_name, max_bytes, max_messages, swap, ccsid, fap_level
    ):
        if browse.error_text or browse.comp_code == 2 or not browse.data:
            continue
        record = parse_dead_letter_message(browse.data, ccsid)
        if record is None:
            others.append(browse)
        else:
            records.append(record)
    return records, others


def summarize_dead_letter_queue(records: list[DeadLetterRecord]) -> dict[str, dict[str, int]]:
    """Group dead-letter records by destination queue and DLH reason."""
    summary: dict[str, dict[str, int]] = {}
    for record in records:
        by_reason = summary.setdefault(record.dest_queue, {})
        key = mqlogin.format_mqrc(record.reason_code)
        by_reason[key] = by_reason.get(key, 0) + 1
    return summary


def inquire_dead_letter_queue_name(
    session_sock: object, swap: bool, ccsid: int, fap_level: int
) -> tuple[str, MqiInquireResult]:
    """Read-only MQINQ for the queue manager's dead-letter queue name."""
    handle, open_result = open_for_inquire(session_sock, None, MQOT_Q_MGR, swap, ccsid, fap_level)
    if handle is None:
        return "", open_result
    try:
        result = inquire(session_sock, handle, [MQCA_DEAD_LETTER_Q_NAME], 48, swap, ccsid)
        if result.error_text or result.comp_code == 2:
            return "", result
        return mqlogin.decode_mq_field(result.char_attributes, ccsid), result
    finally:
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def inquire_model_queue(
    session_sock: object, object_name: str, swap: bool, ccsid: int, fap_level: int
) -> tuple[dict[str, int | str], MqiInquireResult]:
    """Read-only MQINQ of a model queue's definition type and queue type.

    Used to confirm whether a reply model queue is TEMPDYN or PERMDYN, which
    determines whether the z/OS command server can use queues derived from it
    as a reply target.
    """
    handle, open_result = open_for_inquire(session_sock, object_name, MQOT_Q, swap, ccsid, fap_level)
    if handle is None:
        return {}, open_result
    try:
        result = inquire(session_sock, handle, [MQIA_Q_TYPE, MQIA_DEFINITION_TYPE, MQCA_Q_NAME], 48, swap, ccsid)
        if result.error_text or result.comp_code == 2 or result.int_attributes is None:
            return {}, result
        return {
            "queue_type": result.int_attributes[0],
            "definition_type": result.int_attributes[1],
            "queue_name": mqlogin.decode_mq_field(result.char_attributes, ccsid),
        }, result
    finally:
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def inquire_command_queue_target(
    session_sock: object, swap: bool, ccsid: int, fap_level: int
) -> tuple[dict[str, int | str], MqiInquireResult]:
    """Resolve the PCF command-queue alias and inspect its local target.

    This is limited to MQOO_INQUIRE and MQINQ: it neither puts a command nor
    reads an application message.
    """
    alias_handle, open_result = open_for_inquire(
        session_sock, PCF_COMMAND_QUEUE, MQOT_Q, swap, ccsid, fap_level
    )
    if alias_handle is None:
        return {}, open_result
    try:
        alias_result = inquire(
            session_sock,
            alias_handle,
            [MQIA_Q_TYPE, MQCA_Q_NAME, MQCA_BASE_Q_NAME],
            96,
            swap,
            ccsid,
        )
    finally:
        try:
            close_object(session_sock, alias_handle, swap, ccsid)
        except (OSError, ValueError):
            pass

    if alias_result.error_text or alias_result.comp_code == 2 or alias_result.int_attributes is None:
        return {}, alias_result
    alias_name = mqlogin.decode_mq_field(alias_result.char_attributes[:48], ccsid)
    target_name = mqlogin.decode_mq_field(alias_result.char_attributes[48:96], ccsid)
    values: dict[str, int | str] = {
        "command_queue_name": alias_name,
        "command_queue_type": alias_result.int_attributes[0],
        "command_queue_target": target_name,
    }
    if not target_name:
        return values, alias_result

    target_handle, target_open_result = open_for_inquire(
        session_sock, target_name, MQOT_Q, swap, ccsid, fap_level
    )
    if target_handle is None:
        return values, target_open_result
    try:
        target_result = inquire(
            session_sock,
            target_handle,
            [
                MQIA_Q_TYPE,
                MQIA_CURRENT_Q_DEPTH,
                MQIA_MAX_Q_DEPTH,
                MQIA_OPEN_INPUT_COUNT,
                MQIA_OPEN_OUTPUT_COUNT,
                MQCA_Q_NAME,
            ],
            48,
            swap,
            ccsid,
        )
    finally:
        try:
            close_object(session_sock, target_handle, swap, ccsid)
        except (OSError, ValueError):
            pass
    if target_result.error_text or target_result.comp_code == 2 or target_result.int_attributes is None:
        return values, target_result
    values.update(
        {
            "target_queue_name": mqlogin.decode_mq_field(target_result.char_attributes, ccsid),
            "target_queue_type": target_result.int_attributes[0],
            "target_current_depth": target_result.int_attributes[1],
            "target_max_depth": target_result.int_attributes[2],
            "target_open_input_count": target_result.int_attributes[3],
            "target_open_output_count": target_result.int_attributes[4],
        }
    )
    return values, target_result


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


def build_pcf_reply_mqget_packet(
    handle: int,
    request_correlation_id: bytes,
    max_bytes: int,
    swap: bool,
    ccsid: int,
    wait_interval_ms: int = 30000,
) -> bytes:
    """Build a correlated MQGET for one PCF reply on the temporary queue."""
    if len(request_correlation_id) != MQMD_ID_SIZE:
        raise ValueError("PCF request correlation ID must be 24 bytes")
    if not 1 <= max_bytes <= 1024 * 1024:
        raise ValueError("PCF reply byte limit must be between 1 and 1048576")
    if not 0 <= wait_interval_ms <= 2_147_483_647:
        raise ValueError("PCF reply wait interval must be between 0 and 2147483647 ms")
    md = bytearray(MQMD_V1_SIZE)
    md[0:4] = mqlogin.encode_mq_bytes("MD  ", ccsid)
    mqlogin.write_u32_ordered(md, 4, 1, swap)
    md[MQMD_CORREL_ID_OFFSET : MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE] = request_correlation_id
    gmo = bytearray(MQGMO_V2_SIZE)
    gmo[0:4] = mqlogin.encode_mq_bytes("GMO ", ccsid)
    mqlogin.write_u32_ordered(gmo, 4, 2, swap)
    # PCFAgent defaults to MQGMO_WAIT | MQGMO_FAIL_IF_QUIESCING |
    # MQGMO_CONVERT (24577).
    mqlogin.write_u32_ordered(gmo, 8, MQGMO_WAIT | MQGMO_FAIL_IF_QUIESCING | MQGMO_CONVERT, swap)
    mqlogin.write_u32_ordered(gmo, 12, wait_interval_ms, swap)
    mqlogin.write_u32_ordered(gmo, 72, MQMO_MATCH_CORREL_ID, swap)
    body = md + gmo + max_bytes.to_bytes(4, "little" if swap else "big")
    return _build_mqi_packet(RFP_TST_MQGET, handle, body, swap, ccsid, max_bytes)


def build_any_message_mqget_packet(
    handle: int,
    max_bytes: int,
    swap: bool,
    ccsid: int,
    wait_interval_ms: int = 2000,
) -> bytes:
    """Build an uncorrelated MQGET that accepts any message on the queue.

    Diagnostic only: used to check whether a PCF reply queue is truly empty
    or holds a message whose CorrelId did not match what we expected.
    """
    if not 1 <= max_bytes <= 1024 * 1024:
        raise ValueError("reply byte limit must be between 1 and 1048576")
    md = bytearray(MQMD_V1_SIZE)
    md[0:4] = mqlogin.encode_mq_bytes("MD  ", ccsid)
    mqlogin.write_u32_ordered(md, 4, 1, swap)
    gmo = bytearray(MQGMO_V2_SIZE)
    gmo[0:4] = mqlogin.encode_mq_bytes("GMO ", ccsid)
    mqlogin.write_u32_ordered(gmo, 4, 2, swap)
    mqlogin.write_u32_ordered(gmo, 8, MQGMO_WAIT | MQGMO_FAIL_IF_QUIESCING | MQGMO_CONVERT | MQGMO_ACCEPT_TRUNCATED_MSG, swap)
    mqlogin.write_u32_ordered(gmo, 12, wait_interval_ms, swap)
    body = md + gmo + max_bytes.to_bytes(4, "little" if swap else "big")
    return _build_mqi_packet(RFP_TST_MQGET, handle, body, swap, ccsid, max_bytes)


def probe_any_message(
    session_sock: object,
    reply_handle: int,
    max_bytes: int,
    swap: bool,
    ccsid: int,
    wait_interval_ms: int = 2000,
) -> MqiInquireResult:
    """Diagnostic: attempt an uncorrelated MQGET to see if anything at all is queued.

    This destructively consumes a message if one is present. It exists only to
    distinguish "reply queue truly empty" (server never replied) from
    "a reply exists but its CorrelId did not match" (our own bug).
    """
    try:
        session_sock.sendall(build_any_message_mqget_packet(reply_handle, max_bytes, swap, ccsid, wait_interval_ms))
        reply = _recv_spanned_mqi_reply(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQGET_REPLY, swap)
        if comp_code == 2:
            return MqiInquireResult(comp_code, reason_code)
        base = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE
        data_offset = base + MQMD_V1_SIZE + MQGMO_V2_SIZE
        if len(reply) < data_offset + 4:
            return MqiInquireResult(2, 2195, error_text="truncated uncorrelated MQGET reply")
        found_correl_id = reply[base + MQMD_CORREL_ID_OFFSET : base + MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE]
        data_length = mqlogin.read_u32_ordered(reply, data_offset, swap)
        return MqiInquireResult(
            comp_code,
            reason_code,
            error_text=f"found unmatched message: correl_id={found_correl_id.hex()} data_length={data_length}",
        )
    except Exception as exc:
        return MqiInquireResult(2, 2195, error_text=str(exc))


def build_self_test_mqmd(ccsid: int, swap: bool) -> bytes:
    """Build a minimal, fully valid MQMD V1 for the self-test loopback message.

    Unlike build_pcf_request_mqmd, this sets no Report options, so no
    ReplyToQ is required (avoids MQRC_MISSING_REPLY_TO_Q) — the loopback test
    already gets its own CorrelId via MQPMO_NEW_CORREL_ID on the PUT.
    """
    space = mqlogin.encode_mq_bytes(" ", ccsid)
    def field(value: str, length: int) -> bytes:
        return mqlogin.encode_mq_bytes(value, ccsid).ljust(length, space)

    md = bytearray(MQMD_V1_SIZE)
    md[0:4] = field("MD  ", 4)
    mqlogin.write_u32_ordered(md, 4, 1, swap)
    mqlogin.write_u32_ordered(md, MQMD_MSG_TYPE_OFFSET, MQMT_DATAGRAM, swap)
    mqlogin.write_u32_ordered(md, MQMD_EXPIRY_OFFSET, PCF_REQUEST_EXPIRY, swap)
    mqlogin.write_u32_ordered(md, MQMD_ENCODING_OFFSET, mqenc_native(swap), swap)
    mqlogin.write_u32_ordered(md, 28, ccsid, swap)
    md[MQMD_FORMAT_OFFSET : MQMD_FORMAT_OFFSET + 8] = field("MQSTR", 8)
    mqlogin.write_u32_ordered(md, MQMD_PRIORITY_OFFSET, MQPRI_AS_Q_DEF & 0xFFFFFFFF, swap)
    mqlogin.write_u32_ordered(md, MQMD_PERSISTENCE_OFFSET, MQPER_NOT_PERSISTENT, swap)
    md[MQMD_REPLY_TO_Q_OFFSET : MQMD_REPLY_TO_Q_OFFSET + 48] = field("", 48)
    md[MQMD_REPLY_TO_Q_MGR_OFFSET : MQMD_REPLY_TO_Q_MGR_OFFSET + 48] = field("", 48)
    for off, size in ((196, 12), (240, 32), (276, 28), (304, 8), (312, 8), (320, 4)):
        md[off : off + size] = space * size
    return bytes(md)


def self_test_loopback(
    session_sock: object, swap: bool, ccsid: int, fap_level: int, wait_ms: int = 5000
) -> MqiPutResult:
    """Control test: PUT a plain message to a private dynamic queue and MQGET
    it back by CorrelId, entirely independent of the PCF command server and
    SYSTEM.ADMIN.COMMAND.QUEUE.

    This isolates whether basic MQPUT/MQGET/correlation plumbing works on
    this session at all, so a stuck PCF flow can be attributed to the command
    server specifically rather than a general PUT/GET problem.
    """
    handle, open_result = open_for_inquire(
        session_sock,
        PCF_REPLY_MODEL_QUEUE,
        MQOT_Q,
        swap,
        ccsid,
        fap_level,
        MQOO_INPUT_EXCLUSIVE | MQOO_OUTPUT | MQOO_FAIL_IF_QUIESCING,
    )
    if handle is None:
        return MqiPutResult(
            open_result.comp_code, open_result.reason_code,
            error_text=open_result.error_text or "self-test dynamic MQOPEN failed",
        )
    try:
        md = build_self_test_mqmd(ccsid, swap)
        message = mqlogin.encode_mq_bytes("MQ-SELFTEST-MESSAGE", ccsid)
        put_result = put_pcf_command(session_sock, handle, md, message, swap, ccsid, False, fap_level)
        if put_result.comp_code == 2 or put_result.correlation_id is None:
            return put_result
        session_sock.sendall(
            build_pcf_reply_mqget_packet(handle, put_result.correlation_id, 256, swap, ccsid, wait_ms)
        )
        reply = _recv_spanned_mqi_reply(session_sock)
        comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQGET_REPLY, swap)
        if comp_code == 2:
            return MqiPutResult(comp_code, reason_code, correlation_id=put_result.correlation_id)
        base = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE
        data_offset = base + MQMD_V1_SIZE + MQGMO_V2_SIZE
        if len(reply) < data_offset + 4:
            return MqiPutResult(2, 2195, error_text="truncated self-test MQGET reply")
        data_length = mqlogin.read_u32_ordered(reply, data_offset, swap)
        data = reply[data_offset + 4 : data_offset + 4 + data_length]
        return MqiPutResult(
            comp_code, reason_code, correlation_id=put_result.correlation_id,
            error_text=f"round-trip succeeded: {data!r}",
        )
    except Exception as exc:
        return MqiPutResult(2, 2195, error_text=str(exc))
    finally:
        try:
            close_object(session_sock, handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def get_pcf_responses(
    session_sock: object,
    reply_handle: int,
    request_correlation_id: bytes,
    max_bytes: int,
    swap: bool,
    ccsid: int,
    wait_interval_ms: int = 30000,
    debug: bool = False,
) -> tuple[list[object], MqiInquireResult]:
    """Receive correlated PCF replies until the PCF response marks LAST."""
    import mqpcf

    responses: list[object] = []
    try:
        for _ in range(1024):
            if debug:
                print(
                    f"[debug] PCF MQGET: hobj={reply_handle} match_correl_id={request_correlation_id.hex()} "
                    f"wait_ms={wait_interval_ms} max_bytes={max_bytes}",
                    file=sys.stderr,
                )
            session_sock.sendall(
                build_pcf_reply_mqget_packet(
                    reply_handle, request_correlation_id, max_bytes, swap, ccsid, wait_interval_ms
                )
            )
            reply = _recv_spanned_mqi_reply(session_sock)
            comp_code, reason_code = _parse_mqi_reply(reply, RFP_TST_MQGET_REPLY, swap)
            result = MqiInquireResult(comp_code, reason_code)
            if debug:
                print(
                    f"[debug] PCF MQGET reply: mqcc={mqlogin.format_mqcc(comp_code)} mqrc={mqlogin.format_mqrc(reason_code)}",
                    file=sys.stderr,
                )
            if comp_code == 2:
                return responses, result
            base = mqlogin.TSH_HEADER_SIZE + mqlogin.MQAPI_HEADER_SIZE
            data_offset = base + MQMD_V1_SIZE + MQGMO_V2_SIZE
            if len(reply) < data_offset + 4:
                return responses, MqiInquireResult(2, 2195, error_text="truncated correlated MQGET reply")
            if not response_matches_request(reply[base : base + MQMD_V1_SIZE], request_correlation_id):
                return responses, MqiInquireResult(2, 2195, error_text="PCF reply correlation ID mismatch")
            data_length = mqlogin.read_u32_ordered(reply, data_offset, swap)
            data = reply[data_offset + 4 : data_offset + 4 + min(data_length, max_bytes)]
            if len(data) != min(data_length, max_bytes):
                return responses, MqiInquireResult(2, 2195, error_text="truncated PCF response data")
            parsed = mqpcf.parse_response(data)
            if debug:
                response_correlation_id = reply[
                    base + MQMD_CORREL_ID_OFFSET : base + MQMD_CORREL_ID_OFFSET + MQMD_ID_SIZE
                ]
                print(
                    f"[debug] PCF response: bytes={data_length} correl_id={response_correlation_id.hex()} "
                    f"pcf_mqcc={mqlogin.format_mqcc(parsed.comp_code)} pcf_mqrc={mqlogin.format_mqrc(parsed.reason_code)} "
                    f"last={parsed.is_last}",
                    file=sys.stderr,
                )
            responses.append(parsed)
            if parsed.is_last:
                return responses, result
        return responses, MqiInquireResult(2, 2195, error_text="too many PCF response messages")
    except Exception as exc:
        return responses, MqiInquireResult(2, 2195, error_text=str(exc))


def pcf_queue_records(responses: list[object]) -> list[PcfQueueRecord]:
    """Convert parsed MQCMD_INQUIRE_Q PCF responses to queue records."""
    records: list[PcfQueueRecord] = []
    for response in responses:
        parameters = getattr(response, "parameters", {})
        name = parameters.get(MQCA_Q_NAME)
        if not isinstance(name, str) or not name:
            continue
        def integer(selector: int) -> int | None:
            value = parameters.get(selector)
            return value if isinstance(value, int) else None
        records.append(
            PcfQueueRecord(name, integer(MQIA_CURRENT_Q_DEPTH), integer(MQIA_MAX_Q_DEPTH), integer(MQIA_Q_TYPE))
        )
    return records


def list_queues(
    session_sock: object,
    pattern: str,
    swap: bool,
    ccsid: int,
    fap_level: int,
    max_reply_bytes: int = 1024,
    reply_wait_seconds: float = 15.0,
    selector_count: int = len(PCF_QUEUE_LIST_SELECTORS),
    debug: bool = False,
) -> PcfQueueListResult:
    """Run the authorized, read-only PCF Inquire Queue flow on one session."""
    import mqpcf

    if reply_wait_seconds <= 0:
        return PcfQueueListResult([], 2, 2195, "PCF reply wait must be greater than zero")
    if not 1 <= selector_count <= len(PCF_QUEUE_LIST_SELECTORS):
        return PcfQueueListResult([], 2, 2195, "PCF selector count must be between 1 and 4")
    reply_wait_ms = min(max(1, int(reply_wait_seconds * 1000)), 2_147_483_647)
    selectors = PCF_QUEUE_LIST_SELECTORS[:selector_count]

    qmgr_values, qmgr_result = inquire_queue_manager(session_sock, swap, ccsid, fap_level)
    if qmgr_result.error_text or qmgr_result.comp_code == 2:
        return PcfQueueListResult([], qmgr_result.comp_code, qmgr_result.reason_code, qmgr_result.error_text or "queue-manager inquiry failed")
    pcf_header_type = 16 if qmgr_values.get("platform") == 1 else mqpcf.MQCFT_COMMAND

    reply_queue = open_pcf_reply_queue(
        session_sock, swap, ccsid, fap_level, qmgr_values.get("platform"), debug
    )
    if reply_queue.handle is None:
        return PcfQueueListResult([], reply_queue.result.comp_code, reply_queue.result.reason_code, reply_queue.result.error_text or "temporary reply-queue MQOPEN failed")
    command_handle: int | None = None
    # PCF command processing on z/OS is slow; bump socket timeout to cover the
    # full GMO WaitInterval plus a small margin before entering the PCF phase.
    _orig_timeout = session_sock.gettimeout()
    session_sock.settimeout(reply_wait_seconds + 10)
    try:
        command_handle, open_result = open_pcf_command_queue(session_sock, swap, ccsid, fap_level)
        if command_handle is None:
            return PcfQueueListResult([], open_result.comp_code, open_result.reason_code, open_result.error_text or "command-queue MQOPEN failed")
        md = build_pcf_inquire_q_mqmd(
            reply_queue, ccsid, swap,
            reply_to_qmgr=str(qmgr_values.get("queue_manager_name", "")),
            # If the reply cannot be delivered to the reply queue it is
            # dead-lettered instead, and the default 30s expiry would let it
            # lapse before it could be collected. Keep it alive long enough
            # for the DLQ fallback below.
            expiry=PCF_DLQ_RECOVERY_EXPIRY,
        )
        # PCF string parameters must be tagged with the character set actually
        # used to encode them. MQMD.CodedCharSetId advertises the queue
        # manager's CCSID, so encode the pattern the same way rather than
        # hardcoding UTF-8.
        string_ccsid = ccsid if ccsid in (819, 870, 1208) else mqpcf.MQCCSI_UTF8
        request = mqpcf.build_inquire_q_request(pattern, list(selectors), pcf_header_type, string_ccsid)
        if debug:
            print(
                f"[debug] PCF queues: reply_queue={reply_queue.name} reply_hobj={reply_queue.handle} "
                f"command_hobj={command_handle} header_type={pcf_header_type} string_ccsid={string_ccsid} "
                f"selectors={list(selectors)}",
                file=sys.stderr,
            )
        put_result = put_pcf_command(session_sock, command_handle, md, request, swap, ccsid, debug, fap_level)
        if put_result.comp_code == 2 or put_result.correlation_id is None:
            detail = put_result.error_text or mqlogin.format_mqrc(put_result.reason_code)
            packet = build_mqput_packet(command_handle, md, request, swap, ccsid, fap_level)
            tsh_length = int.from_bytes(packet[4:8], "big")
            call_length = int.from_bytes(packet[mqlogin.TSH_HEADER_SIZE : mqlogin.TSH_HEADER_SIZE + 4], "big")
            return PcfQueueListResult(
                [],
                put_result.comp_code,
                put_result.reason_code,
                (
                    f"PCF MQPUT failed: {detail}; header_type={pcf_header_type} "
                    f"pcf_bytes={len(request)} frame_bytes={len(packet)} "
                    f"tsh_length={tsh_length} call_length={call_length}"
                ),
            )
        responses, get_result = get_pcf_responses(
            session_sock,
            reply_queue.handle,
            put_result.correlation_id,
            max_reply_bytes,
            swap,
            ccsid,
            reply_wait_ms,
            debug,
        )
        if get_result.comp_code == 2:
            detail = get_result.error_text or mqlogin.format_mqrc(get_result.reason_code)
            if debug and get_result.reason_code == 2033:
                probe = probe_any_message(session_sock, reply_queue.handle, max_reply_bytes, swap, ccsid)
                print(
                    f"[debug] uncorrelated reply-queue probe: mqcc={mqlogin.format_mqcc(probe.comp_code)} "
                    f"mqrc={mqlogin.format_mqrc(probe.reason_code)} {probe.error_text or ''}",
                    file=sys.stderr,
                )
            # No reply arrived on the reply queue. If it was dead-lettered
            # instead, it can still be recovered from the DLQ.
            recovered = recover_pcf_replies_via_dlq(
                session_sock, reply_queue.name, swap, ccsid, fap_level, debug
            )
            for response in recovered:
                reason = getattr(response, "reason_code", 0)
                if getattr(response, "comp_code", 0) == 2 and reason not in (0, 3008):
                    return PcfQueueListResult(
                        [], response.comp_code, reason,
                        f"PCF Inquire Queue refused: {mqlogin.format_pcf_reason(reason)}",
                        reply_queue_name=reply_queue.name,
                    )
            records = pcf_queue_records(recovered)
            if records:
                return PcfQueueListResult(records, 0, 0, reply_queue_name=reply_queue.name)
            return PcfQueueListResult(
                [], get_result.comp_code, get_result.reason_code,
                f"correlated PCF MQGET failed: {detail}",
                reply_queue_name=reply_queue.name,
            )
        for response in responses:
            if getattr(response, "comp_code", 0) == 2:
                return PcfQueueListResult([], response.comp_code, response.reason_code, "PCF Inquire Queue failed")
        return PcfQueueListResult(pcf_queue_records(responses), get_result.comp_code, get_result.reason_code)
    finally:
        session_sock.settimeout(_orig_timeout)
        if command_handle is not None:
            try:
                close_object(session_sock, command_handle, swap, ccsid)
            except (OSError, ValueError):
                pass
        try:
            close_object(session_sock, reply_queue.handle, swap, ccsid)
        except (OSError, ValueError):
            pass


# MQSC verbs that only read state. The escape path hands raw MQSC to the
# command server, so anything outside this set is refused by default.
MQSC_READONLY_VERBS = ("DISPLAY", "DIS")


def is_readonly_mqsc(command: str) -> bool:
    """Return whether an MQSC command string is a read-only DISPLAY command."""
    first = command.strip().split(None, 1)[0].upper() if command.strip() else ""
    return first in MQSC_READONLY_VERBS


def build_escape_request(mqsc_command: str, header_type: int, string_ccsid: int) -> bytes:
    """Build an MQCMD_ESCAPE request carrying one MQSC command string."""
    import mqpcf

    codec = {819: "iso-8859-1", 870: "cp500", 1208: "utf-8"}.get(string_ccsid)
    if codec is None:
        raise ValueError(f"unsupported escape string CCSID {string_ccsid}")
    if header_type not in (mqpcf.MQCFT_COMMAND, 16):
        raise ValueError("unsupported PCF command header type")
    text = mqsc_command.strip()
    if not text:
        raise ValueError("MQSC command text must not be empty")
    encoded = text.encode(codec)
    if len(encoded) > 32768:
        raise ValueError("MQSC command text is too long")
    padded = encoded + b"\x00" * ((-len(encoded)) % 4)

    escape_type = struct.pack(
        ">IIII", mqpcf.MQCFT_INTEGER, 16, MQIACF_ESCAPE_TYPE, MQET_MQSC
    )
    escape_text = struct.pack(
        ">IIIII", mqpcf.MQCFT_STRING, 20 + len(padded), MQCACF_ESCAPE_TEXT, string_ccsid, len(encoded)
    ) + padded
    header = struct.pack(
        ">IIIIIIIII", header_type, mqpcf.MQCFH_SIZE, 3, MQCMD_ESCAPE, 1, mqpcf.MQCFC_LAST, 0, 0, 2
    )
    return header + escape_type + escape_text


def send_mqsc_escape(
    session_sock: object,
    mqsc_command: str,
    swap: bool,
    ccsid: int,
    fap_level: int,
    reply_wait_seconds: float = 15.0,
    allow_unsafe: bool = False,
    debug: bool = False,
) -> PcfQmgrProbeResult:
    """Send one MQSC command through the PCF escape path (MQCMD_ESCAPE).

    The escape route is a different command path from native PCF and may be
    authorized separately. Replies that the command server cannot deliver are
    recovered from the dead-letter queue, as with native PCF.

    Refuses anything that is not a DISPLAY command unless allow_unsafe is set,
    because escape text is executed verbatim by the command server.
    """
    import mqpcf

    if not allow_unsafe and not is_readonly_mqsc(mqsc_command):
        return PcfQmgrProbeResult(
            [], 2, 2195,
            f"refused: {mqsc_command.strip()!r} is not a read-only DISPLAY command "
            "(pass allow_unsafe=True to override)",
        )

    qmgr_values, qmgr_result = inquire_queue_manager(session_sock, swap, ccsid, fap_level)
    if qmgr_result.error_text or qmgr_result.comp_code == 2:
        return PcfQmgrProbeResult([], qmgr_result.comp_code, qmgr_result.reason_code, "queue-manager inquiry failed")
    platform = qmgr_values.get("platform")
    header_type = 16 if platform == 1 else mqpcf.MQCFT_COMMAND
    string_ccsid = ccsid if ccsid in (819, 870, 1208) else mqpcf.MQCCSI_UTF8

    reply_queue = open_pcf_reply_queue(session_sock, swap, ccsid, fap_level, platform, debug)
    if reply_queue.handle is None:
        return PcfQmgrProbeResult([], reply_queue.result.comp_code, reply_queue.result.reason_code, "reply-queue MQOPEN failed")
    command_handle: int | None = None
    _orig_timeout = session_sock.gettimeout()
    session_sock.settimeout(reply_wait_seconds + 10)
    try:
        command_handle, open_result = open_pcf_command_queue(session_sock, swap, ccsid, fap_level)
        if command_handle is None:
            return PcfQmgrProbeResult([], open_result.comp_code, open_result.reason_code, "command-queue MQOPEN failed")
        request = build_escape_request(mqsc_command, header_type, string_ccsid)
        if debug:
            print(
                f"[debug] MQSC escape: {mqsc_command!r} reply_queue={reply_queue.name} "
                f"header_type={header_type} string_ccsid={string_ccsid} pcf_bytes={len(request)}",
                file=sys.stderr,
            )
        md = build_pcf_inquire_q_mqmd(
            reply_queue, ccsid, swap, reply_to_qmgr=str(qmgr_values.get("queue_manager_name", ""))
        )
        put_result = put_pcf_command(session_sock, command_handle, md, request, swap, ccsid, debug, fap_level)
        if put_result.comp_code == 2 or put_result.correlation_id is None:
            return PcfQmgrProbeResult(
                [], put_result.comp_code, put_result.reason_code,
                put_result.error_text or "escape MQPUT failed",
                reply_queue_name=reply_queue.name,
            )
        responses, get_result = get_pcf_responses(
            session_sock, reply_queue.handle, put_result.correlation_id, 8192, swap, ccsid,
            min(max(1, int(reply_wait_seconds * 1000)), 2_147_483_647), debug,
        )
        if responses:
            return PcfQmgrProbeResult(responses, get_result.comp_code, get_result.reason_code,
                                      reply_queue_name=reply_queue.name)
        return PcfQmgrProbeResult(
            [], get_result.comp_code, get_result.reason_code,
            get_result.error_text or mqlogin.format_mqrc(get_result.reason_code),
            reply_queue_name=reply_queue.name,
        )
    finally:
        session_sock.settimeout(_orig_timeout)
        if command_handle is not None:
            try:
                close_object(session_sock, command_handle, swap, ccsid)
            except (OSError, ValueError):
                pass
        try:
            close_object(session_sock, reply_queue.handle, swap, ccsid)
        except (OSError, ValueError):
            pass


def probe_queue_manager_pcf(
    session_sock: object, swap: bool, ccsid: int, fap_level: int, reply_wait_seconds: float = 15.0, debug: bool = False
) -> PcfQmgrProbeResult:
    """Issue IBM's small, read-only PCF Inquire Queue Manager probe."""
    import mqpcf

    if reply_wait_seconds <= 0:
        return PcfQmgrProbeResult([], 2, 2195, "PCF reply wait must be greater than zero")
    qmgr_values, qmgr_result = inquire_queue_manager(session_sock, swap, ccsid, fap_level)
    if qmgr_result.error_text or qmgr_result.comp_code == 2:
        return PcfQmgrProbeResult([], qmgr_result.comp_code, qmgr_result.reason_code, qmgr_result.error_text or "queue-manager inquiry failed")
    # z/OS expects MQCFT_COMMAND_XR (16) rather than MQCFT_COMMAND (1); the
    # queue-list path already did this, so keep the probe consistent.
    header_type = 16 if qmgr_values.get("platform") == 1 else mqpcf.MQCFT_COMMAND
    reply_queue = open_pcf_reply_queue(
        session_sock, swap, ccsid, fap_level, qmgr_values.get("platform"), debug
    )
    if reply_queue.handle is None:
        return PcfQmgrProbeResult([], reply_queue.result.comp_code, reply_queue.result.reason_code, reply_queue.result.error_text or "temporary reply-queue MQOPEN failed")
    command_handle: int | None = None
    _orig_timeout = session_sock.gettimeout()
    session_sock.settimeout(reply_wait_seconds + 10)
    try:
        command_handle, open_result = open_pcf_command_queue(session_sock, swap, ccsid, fap_level)
        if command_handle is None:
            return PcfQmgrProbeResult([], open_result.comp_code, open_result.reason_code, open_result.error_text or "command-queue MQOPEN failed")
        selectors = [MQIA_PLATFORM, MQCA_Q_MGR_NAME, MQIA_CODED_CHAR_SET_ID, MQIA_COMMAND_LEVEL]
        request = mqpcf.build_inquire_qmgr_request(selectors, header_type)
        if debug:
            print(
                f"[debug] PCF qmgr probe: reply_queue={reply_queue.name} reply_hobj={reply_queue.handle} "
                f"command_hobj={command_handle} header_type={header_type} pcf_bytes={len(request)} selectors={selectors}",
                file=sys.stderr,
            )
        md = build_pcf_inquire_q_mqmd(reply_queue, ccsid, swap, reply_to_qmgr=str(qmgr_values.get("queue_manager_name", "")))
        put_result = put_pcf_command(session_sock, command_handle, md, request, swap, ccsid, debug, fap_level)
        if put_result.comp_code == 2 or put_result.correlation_id is None:
            return PcfQmgrProbeResult([], put_result.comp_code, put_result.reason_code, put_result.error_text or "PCF probe MQPUT failed")
        responses, get_result = get_pcf_responses(
            session_sock,
            reply_queue.handle,
            put_result.correlation_id,
            1024,
            swap,
            ccsid,
            min(max(1, int(reply_wait_seconds * 1000)), 2_147_483_647),
            debug,
        )
        if get_result.comp_code == 2:
            if debug and get_result.reason_code == 2033:
                probe = probe_any_message(session_sock, reply_queue.handle, 1024, swap, ccsid)
                print(
                    f"[debug] uncorrelated reply-queue probe: mqcc={mqlogin.format_mqcc(probe.comp_code)} "
                    f"mqrc={mqlogin.format_mqrc(probe.reason_code)} {probe.error_text or ''}",
                    file=sys.stderr,
                )
            return PcfQmgrProbeResult(
                responses, get_result.comp_code, get_result.reason_code, get_result.error_text,
                reply_queue_name=reply_queue.name,
            )
        for response in responses:
            if getattr(response, "comp_code", 0) == 2:
                return PcfQmgrProbeResult(responses, response.comp_code, response.reason_code, "PCF Inquire Queue Manager failed")
        return PcfQmgrProbeResult(responses, get_result.comp_code, get_result.reason_code)
    finally:
        session_sock.settimeout(_orig_timeout)
        if command_handle is not None:
            try:
                close_object(session_sock, command_handle, swap, ccsid)
            except (OSError, ValueError):
                pass
        try:
            close_object(session_sock, reply_queue.handle, swap, ccsid)
        except (OSError, ValueError):
            pass


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
        max_message_size = mqlogin.MQCD_DEFAULT_MAX_MSG_LENGTH
        client_r = os.urandom(12)

        for _ in range(4):
            stage = "id-send"
            id_packet = mqlogin.build_initial_id_packet(
                args.channel, args.qmgr, client_r, active_ccsid, id_flags2, id_flags3, max_message_size
            )
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
                if len(body) < 134:
                    raise RuntimeError("short initial-negotiation retry reply")
                next_ccsid = remote_ccsid
                next_flags2 = id_flags2 & ~body[45]
                next_flags3 = id_flags3 & ~body[133]
                next_max_message_size = max_message_size
                if body[7] & 0x10:
                    next_max_message_size = mqlogin.read_u32_ordered(body, 16, swap)
                    if next_max_message_size <= 0:
                        raise RuntimeError("queue manager negotiated an invalid maximum message size")
                if (next_ccsid, next_flags2, next_flags3, next_max_message_size) != (
                    active_ccsid,
                    id_flags2,
                    id_flags3,
                    max_message_size,
                ):
                    active_ccsid = next_ccsid
                    id_flags2 = next_flags2
                    id_flags3 = next_flags3
                    max_message_size = next_max_message_size
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
        uid_packet = mqlogin.build_uid_packet(getpass.getuser(), fap_level or mqlogin.RFP_FAP_LEVEL, active_ccsid)
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
    except Exception as exc:
        sock.close()
        raise SessionError(stage, str(exc)) from exc


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

        reply = _recv_spanned_mqi_reply(session.sock)
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
        return QueryResult(error_text=str(exc), stage=getattr(exc, "stage", None))
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

    if result.comp_code == 2:
        print("    login/query: failed")
        if result.stage:
            print(f"    stage: {result.stage}")
        print(f"    spi mqcc: {mqlogin.format_mqcc(result.comp_code)}")
        print(f"    spi mqrc: {mqlogin.format_mqrc(result.reason_code or 0)}")
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
