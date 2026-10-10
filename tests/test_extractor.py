from pathlib import Path

from rtp_h264_extract.extractor import RtpPacket, depacketize, write_annexb


def packet(seq: int, payload: bytes, timestamp: int = 1000, marker: bool = False) -> RtpPacket:
    return RtpPacket(
        frame=seq, src="192.0.2.1", sport=5004, dst="192.0.2.2", dport=6000,
        ssrc=0x12345678, pt=97, seq=seq, timestamp=timestamp,
        marker=marker, payload=payload,
    )


def test_depacketize_single_stap_and_fu_a(tmp_path: Path) -> None:
    # A P slice before the first IDR must be dropped by the Annex-B writer.
    p_slice = packet(1, b"\x41\x01", timestamp=900)
    sps, pps = b"\x67\x42\x00", b"\x68\xce"
    stap = b"\x78" + len(sps).to_bytes(2, "big") + sps + len(pps).to_bytes(2, "big") + pps
    fu_start = packet(3, b"\x7c\x85\xaa", timestamp=1000)
    fu_end = packet(4, b"\x7c\x45\xbb", timestamp=1000, marker=True)

    nals, stats, gaps = depacketize([p_slice, packet(2, stap, timestamp=1000), fu_start, fu_end])
    assert not gaps
    assert [nal.nal_type for nal in nals] == [1, 7, 8, 5]
    assert stats["stap_a_packets"] == 1
    assert stats["fu_a_packets"] == 2

    output = tmp_path / "video.264"
    write_stats, external = write_annexb(nals, output, {})
    assert not external
    assert write_stats["pre_idr_nals_dropped"] == 1
    assert output.read_bytes() == (
        b"\x00\x00\x00\x01" + sps +
        b"\x00\x00\x00\x01" + pps +
        b"\x00\x00\x00\x01\x65\xaa\xbb"
    )


def test_sdp_parameter_sets_are_written_before_idr(tmp_path: Path) -> None:
    sps, pps = b"\x67\x42\xc0", b"\x68\xce"
    nals, _, _ = depacketize([
        packet(1, b"\x41\x01"),
        packet(2, b"\x65\x99", marker=True),
    ])
    output = tmp_path / "video.264"
    stats, external = write_annexb(nals, output, {97: (sps, pps)})
    assert external
    assert stats["started_at_idr"] == 1
    assert output.read_bytes() == (
        b"\x00\x00\x00\x01" + sps +
        b"\x00\x00\x00\x01" + pps +
        b"\x00\x00\x00\x01\x65\x99"
    )


def test_sequence_gap_drops_incomplete_fu() -> None:
    nals, stats, gaps = depacketize([
        packet(10, b"\x7c\x85\xaa"),
        packet(12, b"\x7c\x45\xbb", marker=True),
    ])
    assert nals == []
    assert gaps == [(10, 12)]
    assert stats["fu_drop_sequence_gap"] == 1
