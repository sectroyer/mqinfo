#!/usr/bin/env python3

"""Check explicitly supplied IBM MQ channel names without authenticating."""

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import mqlogin


SCRIPT_VERSION = "0.1.1"
BANNER_TITLE = "IBM MQ Channel Check Tool"
ANSI_RESET = "\033[0m"
RESULT_COLORS = {
    ("exists", "client-connectable"): "\033[32m",
    ("exists", "non-client"): "\033[36m",
    ("absent", None): "\033[31m",
    ("not confirmed", None): "\033[33m",
}


class BannerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        banner = f"\n{BANNER_TITLE} v{SCRIPT_VERSION}\n\n"
        return banner + super().format_help() + "\n"


@dataclass
class ChannelResult:
    name: str
    status: str
    detail: str
    channel_type: str | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = BannerArgumentParser(
        description="Check supplied IBM MQ SVRCONN channel names using only the initial ID flow."
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument("channels", metavar="CHANNELS_FILE", help="UTF-8 file containing one channel name per line")
    parser.add_argument("--port", "-p", type=int, default=mqlogin.DEFAULT_PORT, help="Listener port to connect to")
    parser.add_argument(
        "--qmgr",
        default="",
        help="Queue manager name; leave empty to let the listener use its default",
    )
    parser.add_argument("--socks", help="SOCKS5 proxy as host:port or socks5://host:port")
    parser.add_argument(
        "--timeout",
        type=float,
        default=mqlogin.CONNECT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {mqlogin.CONNECT_TIMEOUT})",
    )
    parser.add_argument("--debug", action="store_true", help="Print initial-flow packet metadata to stderr")
    parser.add_argument("--color", "-c", action="store_true", help="Color result status by outcome")
    return parser


def read_channels(path: str) -> list[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"could not read channel file: {exc}") from exc

    channels = []
    for line_number, raw_line in enumerate(lines, start=1):
        channel = raw_line.strip()
        if not channel or channel.startswith("#"):
            continue
        try:
            encoded_length = len(mqlogin.encode_mq_bytes(channel, mqlogin.LOCAL_CCSID))
        except ValueError as exc:
            raise ValueError(f"line {line_number}: {exc}") from exc
        if encoded_length > 20:
            raise ValueError(f"line {line_number}: channel name exceeds the 20-byte MQ limit")
        channels.append(channel)

    if not channels:
        raise ValueError("channel file contains no channel names")
    return channels


def classify_reply(channel: str, packet: bytes) -> ChannelResult:
    if len(packet) < mqlogin.TSH_HEADER_SIZE:
        return ChannelResult(channel, "not confirmed", "short MQ reply")

    segment_type = packet[9]
    if segment_type == mqlogin.RFP_TST_INITIAL_INFO:
        # An INITIAL_INFO response proves the listener recognized the supplied
        # channel. It may still request negotiation changes, which are unrelated
        # to channel-name existence.
        return ChannelResult(
            channel,
            "exists",
            "listener returned INITIAL_INFO",
            "client-connectable",
        )
    if segment_type == mqlogin.RFP_TST_STATUS_INFO:
        swap = packet[8] == 2
        return_code = None
        if len(packet) >= mqlogin.TSH_HEADER_SIZE + 8:
            return_code = mqlogin.read_u32_ordered(packet, mqlogin.TSH_HEADER_SIZE + 4, swap)
        detail = mqlogin.describe_error_status(packet)
        if return_code == 1:
            return ChannelResult(channel, "absent", detail)
        if return_code == 2:
            return ChannelResult(
                channel,
                "exists",
                "CHANNEL_WRONG_TYPE; exact MQ channel type is not disclosed",
                "non-client",
            )
        return ChannelResult(channel, "not confirmed", detail)
    return ChannelResult(channel, "not confirmed", f"unexpected reply segment {segment_type}")


def check_channel(args: argparse.Namespace, channel: str) -> ChannelResult:
    sock = None
    try:
        sock = mqlogin.open_socket(args.host, args.port, args.socks, args.timeout)
        sock.settimeout(mqlogin.READ_TIMEOUT)
        packet = mqlogin.build_initial_id_packet(channel, args.qmgr, os.urandom(12))
        mqlogin.debug_tsh(args, "tx", "id-send", packet)
        sock.sendall(packet)
        reply = mqlogin.recv_tsh_packet(sock)
        mqlogin.debug_tsh(args, "rx", "id-recv", reply)
        return classify_reply(channel, reply)
    except Exception as exc:
        return ChannelResult(channel, "not confirmed", str(exc))
    finally:
        if sock is not None:
            sock.close()


def format_result(result: ChannelResult, color: bool) -> str:
    type_label = f" [{result.channel_type}]" if result.channel_type else ""
    status = result.status
    if color:
        color_code = RESULT_COLORS.get((result.status, result.channel_type))
        if color_code:
            status = f"{color_code}{status}{ANSI_RESET}"
    return f"{result.name}: {status}{type_label} ({result.detail})"


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    args = parser.parse_args()
    try:
        channels = read_channels(args.channels)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"{BANNER_TITLE} v{SCRIPT_VERSION}\n")
    print(f"[+] Checking {len(channels)} channel name(s) on {args.host}:{args.port}")
    results = [check_channel(args, channel) for channel in channels]
    for result in results:
        print(format_result(result, args.color))

    existing = sum(result.status == "exists" for result in results)
    absent = sum(result.status == "absent" for result in results)
    unconfirmed = len(results) - existing - absent
    print(f"\n[+] Summary: {existing} exists, {absent} absent, {unconfirmed} not confirmed")
    return 1 if unconfirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
