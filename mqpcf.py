"""Minimal IBM MQ PCF encoding-independent response parsing helpers.

These functions only parse bytes supplied by a caller.  They do not create
connections or send administrative commands.
"""

from dataclasses import dataclass
import struct


MQCFT_COMMAND = 1
MQCFT_RESPONSE = 2
MQCFT_INTEGER = 3
MQCFT_STRING = 4
MQCFT_INTEGER_LIST = 5
MQCFC_LAST = 1
MQCFC_NOT_LAST = 0
MQCFH_SIZE = 36
MQCMD_INQUIRE_Q = 13
MQCA_Q_NAME = 2016
MQIACF_Q_ATTRS = 1002
MQCCSI_UTF8 = 1208


@dataclass(frozen=True)
class PcfResponse:
    command: int
    sequence: int
    is_last: bool
    comp_code: int
    reason_code: int
    parameters: dict[int, int | str | list[int]]


def _signed(value: int) -> int:
    return value - 0x100000000 if value >= 0x80000000 else value


def _pad4(value: bytes) -> bytes:
    return value + b"\x00" * ((-len(value)) % 4)


def build_inquire_q_request(pattern: str, attributes: list[int]) -> bytes:
    """Build a read-only PCF MQCMD_INQUIRE_Q request payload."""
    encoded = pattern.encode("utf-8")
    if not encoded or len(encoded) > 48:
        raise ValueError("queue pattern must contain 1 to 48 UTF-8 bytes")
    if not attributes:
        raise ValueError("at least one queue attribute selector is required")
    name = _pad4(encoded)
    name_parameter = struct.pack(
        ">IIIII", MQCFT_STRING, 20 + len(name), MQCA_Q_NAME, MQCCSI_UTF8, len(encoded)
    ) + name
    attributes_parameter = struct.pack(
        ">IIII", MQCFT_INTEGER_LIST, 16 + 4 * len(attributes), MQIACF_Q_ATTRS, len(attributes)
    ) + struct.pack(f">{len(attributes)}I", *attributes)
    header = struct.pack(
        ">IIIIIIIII", MQCFT_COMMAND, MQCFH_SIZE, 3, MQCMD_INQUIRE_Q, 1, MQCFC_LAST, 0, 0, 2
    )
    return header + name_parameter + attributes_parameter


def _decode_string(value: bytes, ccsid: int) -> str:
    # PCF object names are normally ASCII-compatible.  Preserve undecodable
    # bytes rather than rejecting a response with an unfamiliar CCSID.
    codec = {819: "iso-8859-1", 1208: "utf-8", 1200: "utf-16-be", 870: "cp500"}.get(ccsid, "utf-8")
    return value.decode(codec, errors="replace")


def parse_response(packet: bytes) -> PcfResponse:
    """Parse one complete MQCFH response and its scalar/list parameters."""
    if len(packet) < MQCFH_SIZE:
        raise ValueError("short MQCFH response")
    ptype, length, version, command, sequence, control, comp, reason, count = struct.unpack(
        ">IIIIIIIII", packet[:MQCFH_SIZE]
    )
    if ptype != MQCFT_RESPONSE or length != MQCFH_SIZE or version not in (1, 2, 3):
        raise ValueError("invalid MQCFH response")
    if control not in (MQCFC_NOT_LAST, MQCFC_LAST):
        raise ValueError("unsupported MQCFH control value")
    offset = MQCFH_SIZE
    parameters: dict[int, int | str | list[int]] = {}
    for _ in range(count):
        if offset + 12 > len(packet):
            raise ValueError("truncated PCF parameter")
        parameter_type, parameter_length, selector = struct.unpack(">III", packet[offset : offset + 12])
        if parameter_length < 16 or parameter_length % 4 or offset + parameter_length > len(packet):
            raise ValueError("invalid PCF parameter length")
        if parameter_type == MQCFT_INTEGER:
            if parameter_length != 16:
                raise ValueError("invalid PCF integer parameter length")
            parameters[selector] = _signed(struct.unpack(">I", packet[offset + 12 : offset + 16])[0])
        elif parameter_type == MQCFT_STRING:
            if parameter_length < 20:
                raise ValueError("short PCF string parameter")
            ccsid, string_length = struct.unpack(">II", packet[offset + 12 : offset + 20])
            if string_length > parameter_length - 20:
                raise ValueError("invalid PCF string length")
            parameters[selector] = _decode_string(packet[offset + 20 : offset + 20 + string_length], ccsid)
        elif parameter_type == MQCFT_INTEGER_LIST:
            if parameter_length < 16:
                raise ValueError("short PCF integer-list parameter")
            item_count = struct.unpack(">I", packet[offset + 12 : offset + 16])[0]
            if parameter_length != 16 + item_count * 4:
                raise ValueError("invalid PCF integer-list length")
            parameters[selector] = [
                _signed(struct.unpack(">I", packet[offset + 16 + item * 4 : offset + 20 + item * 4])[0])
                for item in range(item_count)
            ]
        else:
            raise ValueError(f"unsupported PCF parameter type {parameter_type}")
        offset += parameter_length
    if offset != len(packet):
        raise ValueError("unexpected trailing PCF response bytes")
    return PcfResponse(command, sequence, control == MQCFC_LAST, _signed(comp), _signed(reason), parameters)


def parse_response_sequence(packets: list[bytes], expected_command: int) -> list[PcfResponse]:
    """Parse a complete ordered PCF response sequence for one command."""
    if not packets:
        raise ValueError("PCF response sequence is empty")
    responses = [parse_response(packet) for packet in packets]
    for index, response in enumerate(responses, start=1):
        if response.command != expected_command:
            raise ValueError("PCF response command does not match request")
        if response.sequence != index:
            raise ValueError("PCF response sequence number is not contiguous")
        if response.is_last != (index == len(responses)):
            raise ValueError("PCF LAST control does not match response sequence")
    return responses
