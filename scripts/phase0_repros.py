#!/usr/bin/env python3
"""Generate the synthetic inputs used by the Phase 0 baseline investigation."""

import argparse
import hashlib
import ipaddress
import struct
from pathlib import Path


ETHERNET = bytes.fromhex("ffffffffffff0011223344550800")
BASE_TIME = 1_700_000_000


def tcp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    *,
    ident: int = 1,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x02,
    tcp_bytes: int = 20,
) -> bytes:
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + tcp_bytes,
        ident,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    return ETHERNET + ip + tcp[:tcp_bytes]


def write_pcap(path: Path, frames: list[bytes], *, spread_ten_seconds: bool = False) -> None:
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            if spread_ten_seconds:
                seconds = BASE_TIME + index // 10
                micros = (index % 10) * 100_000
            else:
                seconds = BASE_TIME + index // 1000
                micros = (index % 1000) * 1000
            output.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            output.write(frame)


def block(kind: int, body: bytes) -> bytes:
    length = 12 + len(body)
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    syn = tcp_frame("10.0.0.1", "10.0.0.2", 12345, 443)
    syn_ack = tcp_frame("10.0.0.2", "10.0.0.1", 443, 12345, ack=2, flags=0x12)
    write_pcap(output_dir / "known-two-packet.pcap", [syn, syn_ack])
    write_pcap(
        output_dir / "malformed-tcp.pcap",
        [tcp_frame("10.0.0.1", "10.0.0.2", 12345, 443, tcp_bytes=10)],
    )
    write_pcap(output_dir / "backpressure-10000.pcap", [syn] * 10_000)

    sources = [
        tcp_frame(
            f"10.{(index // 254) + 2}.{(index % 254) + 1}.1",
            "10.0.0.100",
            20_000 + index,
            443,
        )
        for index in range(32)
    ]
    write_pcap(output_dir / "syn-flood-32-sources.pcap", sources)

    flows = [
        tcp_frame(
            f"10.{(index // 254) + 2}.{(index % 254) + 1}.1",
            "10.1.0.1",
            10_000 + index,
            80,
            ident=index + 1,
        )
        for index in range(100)
    ]
    write_pcap(output_dir / "many-flows-spread.pcap", flows, spread_ten_seconds=True)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    timestamp = BASE_TIME * 1_000_000
    padding = b"\x00" * ((4 - len(syn) % 4) % 4)
    epb = block(
        6,
        struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(syn), len(syn))
        + syn
        + padding,
    )
    (output_dir / "one-packet.pcapng").write_bytes(shb + idb + epb)

    (output_dir / "capacity-1.toml").write_text(
        "[pipeline]\nchannel_capacity = 1\n", encoding="utf-8"
    )
    (output_dir / "syn-flood.toml").write_text(
        "[analysis.anomalies]\n"
        "enabled = true\n"
        "[analysis.anomalies.syn_flood]\n"
        "enabled = true\n"
        "window_secs = 5.0\n"
        "syn_threshold = 32\n"
        "unique_src_threshold = 32\n"
        "cooldown_secs = 0.0\n"
        "[analysis.anomalies.port_scan]\n"
        "enabled = false\n",
        encoding="utf-8",
    )

    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            print(f"{digest}  {path.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="directory for generated traces and configs")
    generate(parser.parse_args().output_dir)
