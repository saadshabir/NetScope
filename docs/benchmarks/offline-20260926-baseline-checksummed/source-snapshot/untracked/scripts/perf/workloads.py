#!/usr/bin/env python3
"""Generate deterministic, streamed classic-PCAP benchmark workloads."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
import struct
from collections import Counter
from pathlib import Path
from typing import BinaryIO


ROOT = Path(__file__).resolve().parents[2]
SEED = 0x4E455453434F5045
BASE_TIMESTAMP = 1_800_000_000
PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
DEST_MAC = bytes.fromhex("020000000001")
SRC_MAC = bytes.fromhex("020000000002")
DESTINATION = ipaddress.IPv4Address("203.0.113.1")

WORKLOADS = {
    "steady-flow": "Small TCP packets repeatedly update one established flow.",
    "high-cardinality": "Small TCP SYN packets create distinct flows.",
    "mixed": "Deterministic TCP, UDP, and ICMP traffic with mixed frame sizes.",
    "analysis-heavy": "TCP SYN traffic with repeated sources for flow and anomaly analysis.",
}


def _checksum(data: bytes) -> int:
    """Return the Internet checksum for an IP header or transport segment."""
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _transport_checksum(
    source: ipaddress.IPv4Address, protocol: int, segment: bytes
) -> int:
    pseudo_header = (
        source.packed
        + DESTINATION.packed
        + struct.pack("!BBH", 0, protocol, len(segment))
    )
    checksum = _checksum(pseudo_header + segment)
    # A computed UDP checksum of zero is transmitted as all ones.
    return checksum or 0xFFFF


def _ipv4_frame(
    source: ipaddress.IPv4Address,
    protocol: int,
    transport: bytes,
    ident: int,
) -> bytes:
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        ident & 0xFFFF,
        0,
        64,
        protocol,
        0,
        source.packed,
        DESTINATION.packed,
    )
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    return DEST_MAC + SRC_MAC + struct.pack("!H", 0x0800) + ip_header + transport


def _tcp_frame(
    source: ipaddress.IPv4Address,
    source_port: int,
    destination_port: int,
    ident: int,
    *,
    sequence: int,
    flags: int,
    payload_length: int = 0,
) -> bytes:
    payload = bytes((ident + offset) & 0xFF for offset in range(payload_length))
    tcp_header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence & 0xFFFFFFFF,
        0,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    segment = tcp_header + payload
    tcp_header = tcp_header[:16] + struct.pack(
        "!H", _transport_checksum(source, 6, segment)
    ) + tcp_header[18:]
    return _ipv4_frame(source, 6, tcp_header + payload, ident)


def _udp_frame(
    source: ipaddress.IPv4Address,
    source_port: int,
    destination_port: int,
    ident: int,
    frame_length: int,
) -> bytes:
    payload_length = max(0, frame_length - 14 - 20 - 8)
    payload = bytes((ident + offset) & 0xFF for offset in range(payload_length))
    udp_header = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    segment = udp_header + payload
    udp_header = udp_header[:6] + struct.pack(
        "!H", _transport_checksum(source, 17, segment)
    )
    return _ipv4_frame(source, 17, udp_header + payload, ident)


def _icmp_frame(
    source: ipaddress.IPv4Address,
    ident: int,
    frame_length: int,
) -> bytes:
    payload_length = max(0, frame_length - 14 - 20 - 8)
    payload = bytes((ident + offset) & 0xFF for offset in range(payload_length))
    icmp_header = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, 1)
    icmp_header = icmp_header[:2] + struct.pack(
        "!H", _checksum(icmp_header + payload)
    ) + icmp_header[4:]
    return _ipv4_frame(source, 1, icmp_header + payload, ident)


def _source_for(index: int) -> ipaddress.IPv4Address:
    # 198.18.0.0/15 is reserved for network-device benchmarks.
    return ipaddress.IPv4Address(0xC6120000 + (index % 131_070))


def _make_packet(
    name: str,
    index: int,
    packet_count: int,
    rng: random.Random,
) -> tuple[bytes, str, tuple[int, int, int, int, int] | None]:
    if name == "steady-flow":
        frame = _tcp_frame(
            ipaddress.IPv4Address("198.18.0.1"),
            51000,
            443,
            index,
            sequence=index * 2,
            flags=0x10,
        )
        return frame, "tcp", (6, 0xC6120001, 51000, int(DESTINATION), 443)

    if name == "high-cardinality":
        flow_id = index
        frame = _tcp_frame(
            _source_for(flow_id),
            10000 + flow_id % 50000,
            443,
            index,
            sequence=index,
            flags=0x02,
        )
        source = int(_source_for(flow_id))
        source_port = 10000 + flow_id % 50000
        return frame, "tcp", (6, source, source_port, int(DESTINATION), 443)

    if name == "analysis-heavy":
        source_id = index % 20_000
        source = _source_for(source_id)
        source_port = 30000 + source_id
        frame = _tcp_frame(
            source,
            source_port,
            443,
            index,
            sequence=index,
            flags=0x02,
        )
        return frame, "tcp", (6, int(source), source_port, int(DESTINATION), 443)

    if name != "mixed":
        raise ValueError(f"unknown workload: {name}")

    # Keep the input distribution deterministic across machines while using a
    # fixed seed to avoid making packet type or length periodic with flow IDs.
    protocol_choice = rng.randrange(100)
    packet_choice = rng.randrange(100)
    flow_capacity = min(max(128, packet_count // 4), 25_000)
    flow_id = index % flow_capacity
    source = _source_for(flow_id)
    if packet_choice < 40:
        frame_length = 54
    elif packet_choice < 70:
        frame_length = 128
    elif packet_choice < 90:
        frame_length = 512
    else:
        frame_length = 1514

    if protocol_choice < 70:
        source_port = 10000 + flow_id % 50000
        frame = _tcp_frame(
            source,
            source_port,
            443,
            index,
            sequence=index,
            flags=0x10,
            payload_length=max(0, frame_length - 54),
        )
        key = (6, int(source), source_port, int(DESTINATION), 443)
        return frame, "tcp", key
    if protocol_choice < 95:
        source_port = 20000 + flow_id % 40000
        frame = _udp_frame(source, source_port, 53, index, frame_length)
        key = (17, int(source), source_port, int(DESTINATION), 53)
        return frame, "udp", key

    return _icmp_frame(source, index, frame_length), "icmp", None


def _write_packet(file: BinaryIO, frame: bytes, index: int, spacing_us: int) -> None:
    timestamp_offset_us = index * spacing_us
    seconds = BASE_TIMESTAMP + timestamp_offset_us // 1_000_000
    microseconds = timestamp_offset_us % 1_000_000
    file.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
    file.write(frame)


def generate_workload(name: str, packet_count: int, output: Path) -> dict:
    if name not in WORKLOADS:
        raise ValueError(f"unknown workload {name!r}; choose from {', '.join(WORKLOADS)}")
    if packet_count < 1:
        raise ValueError("packet count must be positive")

    seed = SEED ^ (sum(name.encode("ascii")) << 32) ^ packet_count
    rng = random.Random(seed)
    packet_sizes: Counter[int] = Counter()
    protocols: Counter[str] = Counter()
    flow_keys: set[tuple[int, int, int, int, int]] = set()
    wire_bytes = 0
    digest = hashlib.sha256()
    digest.update(PCAP_GLOBAL_HEADER)
    spacing_us = 1 if name in {"high-cardinality", "analysis-heavy"} else 10

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("wb") as trace:
        trace.write(PCAP_GLOBAL_HEADER)
        for index in range(packet_count):
            frame, protocol, flow_key = _make_packet(name, index, packet_count, rng)
            record_header = struct.pack(
                "<IIII",
                BASE_TIMESTAMP + (index * spacing_us) // 1_000_000,
                (index * spacing_us) % 1_000_000,
                len(frame),
                len(frame),
            )
            trace.write(record_header)
            trace.write(frame)
            digest.update(record_header)
            digest.update(frame)
            packet_sizes[len(frame)] += 1
            protocols[protocol] += 1
            wire_bytes += len(frame)
            if name == "mixed" and flow_key is not None:
                flow_keys.add(flow_key)
    temporary.replace(output)

    if name == "steady-flow":
        flow_cardinality = 1
    elif name == "high-cardinality":
        # A source/port pair repeats after lcm(131070, 50000) packets.
        flow_cardinality = min(packet_count, 655_350_000)
    elif name == "analysis-heavy":
        flow_cardinality = min(packet_count, 20_000)
    else:
        flow_cardinality = len(flow_keys)

    manifest = {
        "schema_version": 2,
        "generator": "scripts/perf/workloads.py",
        "workload": name,
        "description": WORKLOADS[name],
        "synthetic": True,
        "provenance": "Generated locally from fixed seeds; contains no captured user or network traffic.",
        "seed": f"0x{seed:016x}",
        "packet_count": packet_count,
        "pcap_file": output.name,
        "pcap_sha256": digest.hexdigest(),
        "pcap_bytes": output.stat().st_size,
        "wire_bytes": wire_bytes,
        "link_type": "Ethernet (DLT_EN10MB, 1)",
        "captured_length_equals_wire_length": True,
        "checksums": "valid IPv4, TCP, UDP, and ICMP Internet checksums",
        "packet_size_distribution_bytes": {
            str(size): packet_sizes[size] for size in sorted(packet_sizes)
        },
        "protocol_mix_packets": dict(sorted(protocols.items())),
        "flow_cardinality": flow_cardinality,
        "flow_cardinality_definition": "Distinct IPv4 five-tuples for TCP and UDP packets; ICMP does not create tracked flows.",
        "timestamp_spacing_microseconds": spacing_us,
        "timestamp_start_unix_seconds": BASE_TIMESTAMP,
        "timestamp_end_unix_seconds": BASE_TIMESTAMP
        + ((packet_count - 1) * spacing_us) / 1_000_000,
    }
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workload", choices=["all", *WORKLOADS], default="all")
    parser.add_argument("--packets", type=int, default=100_000)
    parser.add_argument(
        "--counts",
        help="comma-separated packet counts, for example 10000,100000,1000000,5000000",
    )
    args = parser.parse_args()

    names = list(WORKLOADS) if args.workload == "all" else [args.workload]
    try:
        counts = (
            sorted({int(value.strip()) for value in args.counts.split(",") if value.strip()})
            if args.counts
            else [args.packets]
        )
    except ValueError:
        parser.error("--counts must be a comma-separated list of positive integers")
    if not counts or any(count < 1 for count in counts):
        parser.error("packet counts must be positive")

    for name in names:
        for packet_count in counts:
            trace = args.output_dir / f"{name}-{packet_count}.pcap"
            manifest = generate_workload(name, packet_count, trace)
            print(
                f"{name}: {manifest['packet_count']:,} packets, "
                f"{manifest['wire_bytes']:,} wire bytes, sha256={manifest['pcap_sha256']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
