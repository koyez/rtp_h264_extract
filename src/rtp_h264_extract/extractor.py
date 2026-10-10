#!/usr/bin/env python3
"""Extract H.264 from RTP in a pcap/pcapng file.

The extractor uses tshark's RTP dissection, reads H.264 sprop-parameter-sets
from RTSP SDP when present, depacketizes RFC 6184 Single NAL/FU-A/STAP-A, and
writes Annex-B NAL units.  The output starts at the first IDR so a capture
that begins in the middle of a GOP does not leave undecodable P pictures at
its beginning.
"""
from __future__ import annotations

import argparse
import base64
import csv
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


START_CODE = b"\x00\x00\x00\x01"


class ExtractError(RuntimeError):
    pass


@dataclass
class RtpPacket:
    frame: int
    src: str
    sport: int
    dst: str
    dport: int
    ssrc: int
    pt: int
    seq: int
    timestamp: int
    marker: bool
    payload: bytes


@dataclass
class NalUnit:
    seq: int
    timestamp: int
    pt: int
    payload: bytes

    @property
    def nal_type(self) -> int:
        return self.payload[0] & 0x1F if self.payload else -1


def run_tshark(tshark: str, args: list[str]) -> str:
    cmd = [tshark, *args]
    try:
        proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        raise ExtractError(f"cannot run tshark ({tshark!r}): {exc}") from exc
    if proc.returncode:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise ExtractError(f"tshark failed ({proc.returncode}): {detail}")
    return proc.stdout


def _decode_hex(value: str) -> bytes:
    # tshark normally emits contiguous hex; accept colon-separated output too.
    value = value.replace(":", "").replace(" ", "").strip()
    if not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def load_rtp_packets(tshark: str, pcap: Path, display_filter: str) -> list[RtpPacket]:
    expr = "rtp"
    if display_filter:
        expr += f" && ({display_filter})"
    fields = [
        "frame.number", "ip.src", "udp.srcport", "ip.dst", "udp.dstport",
        "rtp.ssrc", "rtp.p_type", "rtp.seq", "rtp.timestamp", "rtp.marker",
        "rtp.payload",
    ]
    out = run_tshark(tshark, [
        "-r", str(pcap), "-Y", expr, "-T", "fields", *sum((["-e", f] for f in fields), []),
        "-E", "header=n", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f",
    ])
    packets: list[RtpPacket] = []
    for line_no, row in enumerate(csv.reader(out.splitlines(), delimiter="\t"), 1):
        if len(row) != len(fields) or not row[-1]:
            continue
        try:
            packets.append(RtpPacket(
                frame=int(row[0]), src=row[1], sport=int(row[2]), dst=row[3],
                dport=int(row[4]), ssrc=int(row[5], 0), pt=int(row[6]),
                seq=int(row[7]), timestamp=int(row[8]), marker=row[9].lower() == "true",
                payload=_decode_hex(row[10]),
            ))
        except (ValueError, IndexError) as exc:
            raise ExtractError(f"invalid RTP row {line_no}: {row!r}") from exc
    packets.sort(key=lambda p: p.frame)
    return packets


def read_sdp_parameter_sets(tshark: str, pcap: Path) -> dict[int, tuple[bytes, bytes]]:
    """Return {RTP payload type: (SPS, PPS)} from RTSP SDP responses.

    tcp.payload is used instead of rtsp.data because Wireshark exposes the SDP
    body as TCP data on some versions. Reassembled TCP data is also queried.
    Searching every RTSP segment makes this work with both one-packet and
    segmented SDP responses.
    """
    fields = ["frame.number", "tcp.payload", "tcp.reassembled.data"]
    out = run_tshark(tshark, [
        "-r", str(pcap), "-Y", "rtsp", "-T", "fields",
        *sum((["-e", f] for f in fields), []), "-E", "header=n",
        "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a",
    ])
    blobs: list[bytes] = []
    for row in csv.reader(out.splitlines(), delimiter="\t"):
        for value in row[1:]:
            data = _decode_hex(value)
            if data:
                blobs.append(data)
    # A response may be split across TCP segments. Joining all RTSP bytes also
    # handles a line split between segments; the regex is deliberately narrow.
    text = b"\n".join(blobs).decode("latin1", errors="ignore")
    candidates: dict[int, set[tuple[bytes, bytes]]] = defaultdict(set)
    for match in re.finditer(r"a=fmtp:\s*(\d+)\s+([^\r\n]*)", text,
                             flags=re.IGNORECASE):
        pt = int(match.group(1))
        params = match.group(2)
        sm = re.search(r"sprop-parameter-sets\s*=\s*([^;\s]+)", params,
                       flags=re.IGNORECASE)
        if not sm:
            continue
        pieces = [piece.strip() for piece in sm.group(1).split(",")]
        if len(pieces) < 2:
            continue
        try:
            sps, pps = base64.b64decode(pieces[0]), base64.b64decode(pieces[1])
        except Exception:
            continue
        if sps and pps and (sps[0] & 0x1F) == 7 and (pps[0] & 0x1F) == 8:
            candidates[pt].add((sps, pps))
    # A dynamic payload type can be reused by different RTSP sessions. Only
    # use a parameter set automatically when all SDP occurrences for that PT
    # agree; otherwise the caller must provide --sps/--pps.
    return {pt: next(iter(values)) for pt, values in candidates.items()
            if len(values) == 1}


def depacketize(packets: Iterable[RtpPacket]) -> tuple[list[NalUnit], Counter, list[tuple[int, int]]]:
    """Depacketize Single NAL, STAP-A and FU-A packets.

    Returns NAL units, packet/NAL counters, and sequence gaps. A FU chain is
    dropped when a sequence discontinuity or timestamp change is observed.
    """
    nals: list[NalUnit] = []
    stats: Counter = Counter()
    gaps: list[tuple[int, int]] = []
    fu: bytearray | None = None
    fu_seq: int | None = None
    fu_timestamp: int | None = None
    fu_start_seq: int | None = None
    previous_seq: int | None = None

    def drop_fu(reason: str) -> None:
        nonlocal fu, fu_seq, fu_timestamp, fu_start_seq
        if fu is not None:
            stats[f"fu_drop_{reason}"] += 1
        fu = fu_seq = fu_timestamp = fu_start_seq = None

    def emit(seq: int, timestamp: int, payload: bytes, pt: int) -> None:
        if payload:
            nals.append(NalUnit(seq, timestamp, pt, payload))

    for packet in packets:
        stats["rtp_packets"] += 1
        if previous_seq is not None:
            delta = (packet.seq - previous_seq) & 0xFFFF
            if delta == 0:
                stats["duplicate_packets"] += 1
                continue
            if delta != 1:
                gaps.append((previous_seq, packet.seq))
                drop_fu("sequence_gap")
        previous_seq = packet.seq
        payload = packet.payload
        if not payload:
            stats["empty_payload"] += 1
            continue
        nal_type = payload[0] & 0x1F
        if nal_type == 24:  # STAP-A
            stats["stap_a_packets"] += 1
            if fu is not None:
                drop_fu("interrupted")
            offset = 1
            while offset + 2 <= len(payload):
                size = int.from_bytes(payload[offset:offset + 2], "big")
                offset += 2
                if size == 0 or offset + size > len(payload):
                    stats["bad_stap"] += 1
                    break
                emit(packet.seq, packet.timestamp, payload[offset:offset + size], packet.pt)
                offset += size
            if offset != len(payload):
                stats["bad_stap"] += 1
        elif nal_type == 28:  # FU-A
            stats["fu_a_packets"] += 1
            if len(payload) < 3:
                stats["bad_fu"] += 1
                drop_fu("short")
                continue
            fu_indicator, fu_header = payload[0], payload[1]
            start, end = bool(fu_header & 0x80), bool(fu_header & 0x40)
            original_type = fu_header & 0x1F
            if start:
                drop_fu("nested")
                fu = bytearray(bytes([(fu_indicator & 0xE0) | original_type]) + payload[2:])
                fu_seq = packet.seq
                fu_timestamp = packet.timestamp
                fu_start_seq = packet.seq
                if end:
                    emit(packet.seq, packet.timestamp, bytes(fu), packet.pt)
                    drop_fu("complete")
            elif fu is None or fu_seq is None or fu_timestamp != packet.timestamp or packet.seq != ((fu_seq + 1) & 0xFFFF):
                stats["bad_fu"] += 1
                drop_fu("continuation")
            else:
                fu.extend(payload[2:])
                fu_seq = packet.seq
                if end:
                    emit(fu_start_seq if fu_start_seq is not None else packet.seq,
                         packet.timestamp, bytes(fu), packet.pt)
                    drop_fu("complete")
        elif 1 <= nal_type <= 23:
            if fu is not None:
                drop_fu("interrupted")
            stats["single_nal_packets"] += 1
            emit(packet.seq, packet.timestamp, payload, packet.pt)
        else:
            stats[f"unsupported_type_{nal_type}"] += 1
            drop_fu("unsupported")
    drop_fu("eof")
    stats["nal_units"] = len(nals)
    return nals, stats, gaps


def pick_parameter_sets(sprop: dict[int, tuple[bytes, bytes]], pt: int) -> tuple[bytes, bytes] | None:
    if pt in sprop:
        return sprop[pt]
    if len(sprop) == 1:
        return next(iter(sprop.values()))
    return None


def write_annexb(nals: Iterable[NalUnit], out_path: Path,
                 sprop: dict[int, tuple[bytes, bytes]]) -> tuple[Counter, bool]:
    stats: Counter = Counter()
    started = False
    external_written = False
    cached: dict[int, bytes] = {}
    with out_path.open("wb") as out:
        def write_nal(payload: bytes) -> None:
            out.write(START_CODE)
            out.write(payload)
            stats["written_nals"] += 1

        def begin(pt: int) -> None:
            nonlocal started, external_written
            if started:
                return
            params = pick_parameter_sets(sprop, pt)
            if params is not None:
                write_nal(params[0])
                write_nal(params[1])
                external_written = True
            else:
                # In-band SPS/PPS may have arrived in a STAP-A before the IDR.
                for nal_type in (7, 8):
                    if nal_type in cached:
                        write_nal(cached[nal_type])
            started = True
            stats["started_at_idr"] += 1

        for nal in nals:
            typ = nal.nal_type
            if typ in (7, 8):
                cached[typ] = nal.payload
                if started:
                    write_nal(nal.payload)
                else:
                    stats["parameter_nals_cached"] += 1
                continue
            if not started:
                if typ == 5:
                    begin(nal.pt)
                    write_nal(nal.payload)
                else:
                    stats["pre_idr_nals_dropped"] += 1
                continue
            write_nal(nal.payload)

    return stats, external_written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("-Y", "--filter", default="",
                        help="Wireshark display filter selecting one RTP video stream, e.g. 'udp.stream==140 && rtp.ssrc==0xd4c1700a'")
    parser.add_argument("--tshark", default=shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark")
    parser.add_argument("--sps", help="base64 or hex SPS override when SDP is absent")
    parser.add_argument("--pps", help="base64 or hex PPS override when SDP is absent")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not args.pcap.is_file():
        raise ExtractError(f"pcap does not exist: {args.pcap}")

    packets = load_rtp_packets(args.tshark, args.pcap, args.filter)
    if not packets:
        raise ExtractError("no RTP packets matched; check Decode As RTP/H264 and --filter")
    keys = {(p.src, p.sport, p.dst, p.dport, p.ssrc, p.pt) for p in packets}
    if len(keys) > 1:
        raise ExtractError(f"filter selected {len(keys)} RTP streams; add IP/port/SSRC to --filter")

    if bool(args.sps) != bool(args.pps):
        raise ExtractError("--sps and --pps must be provided together")
    sprop = read_sdp_parameter_sets(args.tshark, args.pcap)
    if args.sps and args.pps:
        def parse_param(value: str) -> bytes:
            value = value.strip()
            try:
                if re.fullmatch(r"[0-9a-fA-F: ]+", value):
                    return _decode_hex(value)
                return base64.b64decode(value)
            except Exception as exc:
                raise ExtractError(f"invalid parameter set: {value!r}") from exc
        sprop[packets[0].pt] = (parse_param(args.sps), parse_param(args.pps))

    nals, packet_stats, gaps = depacketize(packets)
    # NALs do not need the PT for the selected-stream case. Reduce SDP to one
    # entry so a capture containing several RTSP sessions cannot pick the wrong one.
    selected_sprop = {}
    if packets[0].pt in sprop:
        selected_sprop[packets[0].pt] = sprop[packets[0].pt]
    elif len(sprop) == 1:
        selected_sprop[packets[0].pt] = next(iter(sprop.values()))
    write_stats, external = write_annexb(nals, args.output, selected_sprop)

    print(f"RTP packets: {packet_stats['rtp_packets']}; NAL units: {len(nals)}")
    print(f"stream: {packets[0].src}:{packets[0].sport} -> {packets[0].dst}:{packets[0].dport}, "
          f"SSRC=0x{packets[0].ssrc:08x}, PT={packets[0].pt}")
    print(f"sequence gaps: {len(gaps)}; FU-A packets: {packet_stats['fu_a_packets']}; "
          f"STAP-A packets: {packet_stats['stap_a_packets']}")
    parameter_source = "SDP" if external else (
        "in-band RTP" if write_stats["parameter_nals_cached"] else "none"
    )
    print(f"parameter sets: {parameter_source}; "
          f"pre-IDR NALs dropped: {write_stats['pre_idr_nals_dropped']}; "
          f"written NALs: {write_stats['written_nals']}")
    if gaps:
        print(f"first sequence gap: {gaps[0][0]} -> {gaps[0][1]}", file=sys.stderr)
    if not external and not any(n.nal_type == 7 for n in nals):
        print("warning: no SPS/PPS found in SDP or RTP; decoder may reject the output", file=sys.stderr)
    if not write_stats['started_at_idr']:
        print("warning: no IDR was found; output may not be independently decodable", file=sys.stderr)
    return 0


def cli(argv: list[str] | None = None) -> int:
    """CLI entry point with concise user-facing error handling."""
    try:
        return main(argv)
    except ExtractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
