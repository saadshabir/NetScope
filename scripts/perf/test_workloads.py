"""Verify generated packets are usable beyond NetScope's checksum-blind parser."""

from __future__ import annotations

import ipaddress
import random
import struct
import unittest

from workloads import _make_packet


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


if __name__ == "__main__":
    unittest.main()
