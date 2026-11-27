"""Verify benchmark packet checksums and reproducibility of the smoke PCAPs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

from workloads import ROOT, _make_packet, generate_workload


def checksum_valid(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


class WorkloadChecksumTests(unittest.TestCase):
    def test_generated_protocol_checksums(self) -> None:
        seen: set[int] = set()
        for workload, count in (("steady-flow", 1), ("high-cardinality", 1), ("analysis-heavy", 1), ("mixed", 300)):
            rng = random.Random(123)
            for index in range(count):
                frame, _, _ = _make_packet(workload, index, count, rng)
                ip = frame[14:]
                header_len = (ip[0] & 0x0F) * 4
                self.assertTrue(checksum_valid(ip[:header_len]))
                segment = ip[header_len:]
                protocol = ip[9]
                if protocol == 1:
                    self.assertTrue(checksum_valid(segment))
                else:
                    pseudo_header = (
                        ipaddress.IPv4Address(ip[12:16]).packed
                        + ipaddress.IPv4Address(ip[16:20]).packed
                        + struct.pack("!BBH", 0, protocol, len(segment))
                    )
                    self.assertTrue(checksum_valid(pseudo_header + segment))
                seen.add(protocol)
        self.assertEqual(seen, {1, 6, 17})


class SmokeWorkloadTests(unittest.TestCase):
    def test_smoke_workloads_match_tracked_manifests(self) -> None:
        reference_dir = ROOT / "docs" / "benchmarks" / "workloads-10k-smoke"
        packet_count = 10_000
        with tempfile.TemporaryDirectory() as directory:
            for workload in ("steady-flow", "high-cardinality", "mixed", "analysis-heavy"):
                with self.subTest(workload=workload):
                    trace = Path(directory) / f"{workload}-{packet_count}.pcap"
                    manifest_name = f"{trace.name}.manifest.json"
                    expected = json.loads((reference_dir / manifest_name).read_text())
                    generate_workload(workload, packet_count, trace)
                    self.assertEqual(
                        hashlib.sha256(trace.read_bytes()).hexdigest(),
                        expected["pcap_sha256"],
                    )
                    self.assertEqual(
                        json.loads(trace.with_name(manifest_name).read_text()),
                        expected,
                    )


if __name__ == "__main__":
    unittest.main()
