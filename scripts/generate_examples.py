#!/usr/bin/env python3
"""Generate NetScope's small, deterministic synthetic investigation PCAPs."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
import struct
import tempfile
from collections.abc import Iterable
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "examples" / "pcaps"
MANIFEST_NAME = "manifest.json"
BASE_TIMESTAMP = 1_700_000_000
SYNTHETIC_SEED = 0x4E455453434F5045
DEST_MAC = bytes.fromhex("020000000001")
SRC_MAC = bytes.fromhex("020000000002")
ETHERNET_TYPE_IPV4 = 0x0800
ETHERNET_TYPE_IPV6 = 0x86DD


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(
    payload: bytes,
    ethertype: int,
    *,
    vlan_tags: tuple[tuple[int, int], ...] = (),
) -> bytes:
    header_type = ethertype
    tagged_payload = payload
    for tag_type, vlan_id in reversed(vlan_tags):
        tagged_payload = struct.pack("!HH", vlan_id & 0x0FFF, header_type) + tagged_payload
        header_type = tag_type
    return DEST_MAC + SRC_MAC + struct.pack("!H", header_type) + tagged_payload


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ident: int) -> bytes:
    src_bytes = ipaddress.IPv4Address(src).packed
    dst_bytes = ipaddress.IPv4Address(dst).packed
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident & 0xFFFF,
        0,
        64,
        protocol,
        0,
        src_bytes,
        dst_bytes,
    )
    checksum = internet_checksum(header_without_checksum)
    header = bytearray(header_without_checksum)
    header[10:12] = checksum.to_bytes(2, "big")
    return bytes(header) + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    ) + payload


def transport_checksum(src: str, dst: str, protocol: int, segment: bytes) -> int:
    source = ipaddress.ip_address(src)
    destination = ipaddress.ip_address(dst)
    if source.version != destination.version:
        raise ValueError("transport checksum endpoints must use the same IP version")
    if source.version == 4:
        pseudo_header = struct.pack(
            "!4s4sBBH",
            source.packed,
            destination.packed,
            0,
            protocol,
            len(segment),
        )
    else:
        pseudo_header = struct.pack(
            "!16s16sI3xB",
            source.packed,
            destination.packed,
            len(segment),
            protocol,
        )
    return internet_checksum(pseudo_header + segment)


def tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x02,
    payload: bytes = b"",
) -> bytes:
    segment = bytearray(struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        (5 << 12) | flags,
        65535,
        0,
        0,
    ) + payload)
    checksum = transport_checksum(src_ip, dst_ip, 6, bytes(segment))
    segment[16:18] = checksum.to_bytes(2, "big")
    return bytes(segment)


def udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    segment = bytearray(struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload)
    checksum = transport_checksum(src_ip, dst_ip, 17, bytes(segment))
    segment[6:8] = (checksum or 0xFFFF).to_bytes(2, "big")
    return bytes(segment)


def ipv4_tcp_frame(
    src: str,
    dst: str,
    src_port: int,
    dst_port: int,
    *,
    ident: int,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x02,
    payload: bytes = b"",
) -> bytes:
    segment = tcp(src, dst, src_port, dst_port, seq=seq, ack=ack, flags=flags, payload=payload)
    return ethernet(ipv4(src, dst, 6, segment, ident), ETHERNET_TYPE_IPV4)


def ipv4_udp_frame(
    src: str,
    dst: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    *,
    ident: int,
    vlan_tags: tuple[tuple[int, int], ...] = (),
) -> bytes:
    segment = udp(src, dst, src_port, dst_port, payload)
    packet = ipv4(src, dst, 17, segment, ident)
    return ethernet(packet, ETHERNET_TYPE_IPV4, vlan_tags=vlan_tags)


def dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    encoded_labels = (label.encode("ascii") for label in labels)
    return b"".join(bytes((len(label),)) + label for label in encoded_labels) + b"\x00"


def dns_query(name: str, transaction_id: int) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question


def dns_response(name: str, transaction_id: int, address: str) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xC0\x0C" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address(address).packed
    return struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0) + question + answer


def tls_client_hello(server_name: str, rng: random.Random) -> bytes:
    hostname = server_name.encode("ascii")
    server_name_entry = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    server_name_list = struct.pack("!H", len(server_name_entry)) + server_name_entry
    sni_extension = struct.pack("!HH", 0, len(server_name_list)) + server_name_list
    extensions = sni_extension
    body = (
        b"\x03\x03"
        + bytes(rng.getrandbits(8) for _ in range(32))
        + b"\x00"
        + b"\x00\x02\x00\x2F"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_hello(rng: random.Random) -> bytes:
    body = (
        b"\x03\x03"
        + bytes(rng.getrandbits(8) for _ in range(32))
        + b"\x00"
        + b"\x00\x2F"
        + b"\x00"
        + b"\x00\x00"
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def normal_packets(rng: random.Random) -> Iterable[bytes]:
    client = "192.0.2.10"
    server = "203.0.113.10"
    client_port = 51000
    server_port = 443
    client_seq = 1000
    server_seq = 9000
    hello = tls_client_hello("api.example.test", rng)
    server_hello = tls_server_hello(rng)
    yield ipv4_tcp_frame(
        client, server, client_port, server_port, ident=1, seq=client_seq, flags=0x02
    )
    yield ipv4_tcp_frame(
        server,
        client,
        server_port,
        client_port,
        ident=2,
        seq=server_seq,
        ack=client_seq + 1,
        flags=0x12,
    )
    yield ipv4_tcp_frame(
        client,
        server,
        client_port,
        server_port,
        ident=3,
        seq=client_seq + 1,
        ack=server_seq + 1,
        flags=0x10,
    )
    yield ipv4_tcp_frame(
        client,
        server,
        client_port,
        server_port,
        ident=4,
        seq=client_seq + 1,
        ack=server_seq + 1,
        flags=0x18,
        payload=hello,
    )
    yield ipv4_tcp_frame(
        server,
        client,
        server_port,
        client_port,
        ident=5,
        seq=server_seq + 1,
        ack=client_seq + 1 + len(hello),
        flags=0x18,
        payload=server_hello,
    )
    yield ipv4_tcp_frame(
        client,
        server,
        client_port,
        server_port,
        ident=6,
        seq=client_seq + 1 + len(hello),
        ack=server_seq + 1 + len(server_hello),
        flags=0x10,
    )

    query = dns_query("www.example.test", 0x4242)
    response = dns_response("www.example.test", 0x4242, "198.51.100.80")
    yield ipv4_udp_frame("192.0.2.10", "203.0.113.53", 53000, 53, query, ident=7)
    yield ipv4_udp_frame("203.0.113.53", "192.0.2.10", 53, 53000, response, ident=8)


def port_scan_packets() -> Iterable[bytes]:
    ports = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 5432, 8080)
    for index, port in enumerate(ports, start=1):
        yield ipv4_tcp_frame(
            "192.0.2.50",
            "198.51.100.20",
            45000,
            port,
            ident=index,
            seq=1000 + index,
            flags=0x02,
        )


def syn_flood_packets() -> Iterable[bytes]:
    for index in range(64):
        source = f"198.18.{index // 254}.{(index % 254) + 1}"
        yield ipv4_tcp_frame(
            source,
            "203.0.113.200",
            30000 + index,
            443,
            ident=index + 1,
            seq=10000 + index,
            flags=0x02,
        )


def icmpv4_frame() -> bytes:
    echo = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"netscope")
    echo[2:4] = internet_checksum(bytes(echo)).to_bytes(2, "big")
    return ethernet(ipv4("192.0.2.60", "198.51.100.60", 1, bytes(echo), 30), ETHERNET_TYPE_IPV4)


def icmpv6_frame() -> bytes:
    src = "2001:db8::60"
    dst = "2001:db8::61"
    echo = bytearray(struct.pack("!BBHHH", 128, 0, 0, 0x5678, 2) + b"v6demo")
    pseudo_header = struct.pack(
        "!16s16sI3xB",
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
        len(echo),
        58,
    )
    echo[2:4] = internet_checksum(pseudo_header + bytes(echo)).to_bytes(2, "big")
    packet = ipv6(src, dst, 58, bytes(echo))
    return ethernet(packet, ETHERNET_TYPE_IPV6)


def protocol_edge_packets() -> Iterable[bytes]:
    v6_tcp = tcp("2001:db8::1", "2001:db8::2", 54000, 443, seq=1, flags=0x02)
    yield ethernet(
        ipv6("2001:db8::1", "2001:db8::2", 6, v6_tcp),
        ETHERNET_TYPE_IPV6,
    )
    yield ipv4_udp_frame(
        "192.0.2.70",
        "198.51.100.70",
        53001,
        5353,
        b"qinq-demo",
        ident=31,
        vlan_tags=((0x88A8, 100), (0x8100, 200)),
    )
    yield icmpv4_frame()
    yield icmpv6_frame()

    truncated_tcp = b"\xD4\x31\x01\xBB\x00\x00\x00\x01\x00\x00"
    yield ethernet(
        ipv4("192.0.2.80", "198.51.100.80", 6, truncated_tcp, 32),
        ETHERNET_TYPE_IPV4,
    )
    yield ethernet(b"synthetic-unsupported-payload", 0x88B5)


FIXTURES = (
    (
        "normal.pcap",
        "TCP and partial TLS handshake, DNS query and response, and visible ClientHello SNI",
        normal_packets,
        250_000,
    ),
    (
        "port-scan.pcap",
        "One source sends TCP SYN probes to sixteen destination ports",
        port_scan_packets,
        100_000,
    ),
    (
        "syn-flood.pcap",
        "Sixty-four synthetic sources send initial SYNs to one destination and port",
        syn_flood_packets,
        50_000,
    ),
    (
        "protocol-edges.pcap",
        "IPv6, QinQ, ICMP, truncated TCP, and an unsupported EtherType",
        protocol_edge_packets,
        250_000,
    ),
)

EXPECTED_PACKET_ACCOUNTING = {
    "normal.pcap": {
        "packets_with_transport_header": 8,
        "malformed_or_unsupported_packets": 0,
    },
    "port-scan.pcap": {
        "packets_with_transport_header": 16,
        "malformed_or_unsupported_packets": 0,
    },
    "syn-flood.pcap": {
        "packets_with_transport_header": 64,
        "malformed_or_unsupported_packets": 0,
    },
    "protocol-edges.pcap": {
        "packets_with_transport_header": 4,
        "malformed_or_unsupported_packets": 2,
    },
}


def write_pcap(path: Path, packets: Iterable[bytes], interval_us: int) -> dict[str, int | str]:
    digest = hashlib.sha256()
    packet_count = 0
    wire_bytes = 0
    pcap_bytes = 24
    with path.open("wb") as output:
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        output.write(global_header)
        digest.update(global_header)
        for packet_count, packet in enumerate(packets, start=1):
            timestamp_us = (BASE_TIMESTAMP * 1_000_000) + (packet_count - 1) * interval_us
            timestamp_seconds, timestamp_fraction = divmod(timestamp_us, 1_000_000)
            record = struct.pack(
                "<IIII",
                timestamp_seconds,
                timestamp_fraction,
                len(packet),
                len(packet),
            )
            output.write(record)
            output.write(packet)
            digest.update(record)
            digest.update(packet)
            wire_bytes += len(packet)
            pcap_bytes += len(record) + len(packet)
    return {
        "packet_count": packet_count,
        "wire_bytes": wire_bytes,
        "pcap_bytes": pcap_bytes,
        "sha256": digest.hexdigest(),
    }


def generate(output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SYNTHETIC_SEED)
    fixtures = []
    for filename, description, packet_factory, interval_us in FIXTURES:
        packet_source = (
            packet_factory(rng) if filename == "normal.pcap" else packet_factory()
        )
        metadata = write_pcap(output_dir / filename, packet_source, interval_us=interval_us)
        fixtures.append(
            {
                "file": filename,
                "description": description,
                **metadata,
                "expected_packet_accounting": EXPECTED_PACKET_ACCOUNTING[filename],
            }
        )
    manifest = {
        "schema_version": 1,
        "synthetic": True,
        "provenance": (
            "All packets are generated locally by scripts/generate_examples.py; no traffic "
            "was captured from real users or networks."
        ),
        "generator": "scripts/generate_examples.py",
        "base_timestamp_utc_seconds": BASE_TIMESTAMP,
        "synthetic_seed": f"0x{SYNTHETIC_SEED:016x}",
        "fixtures": fixtures,
    }
    (output_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return manifest


def check(output_dir: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="netscope-example-pcaps-") as temp_dir:
        expected_dir = Path(temp_dir)
        expected_manifest = generate(expected_dir)
        expected_manifest_bytes = (expected_dir / MANIFEST_NAME).read_bytes()
        manifest_path = output_dir / MANIFEST_NAME
        if not manifest_path.is_file() or manifest_path.read_bytes() != expected_manifest_bytes:
            print(f"out of date or missing: {manifest_path}")
            return False
        okay = True
        expected_names = {str(item["file"]) for item in expected_manifest["fixtures"]}
        actual_names = {path.name for path in output_dir.glob("*.pcap")}
        for filename in sorted(actual_names - expected_names):
            print(f"unlisted fixture: {output_dir / filename}")
            okay = False
        for item in expected_manifest["fixtures"]:
            filename = str(item["file"])
            expected_path = expected_dir / filename
            actual_path = output_dir / filename
            if not actual_path.is_file():
                print(f"missing fixture: {actual_path}")
                okay = False
                continue
            if actual_path.stat().st_size != expected_path.stat().st_size:
                print(f"size mismatch: {actual_path}")
                okay = False
                continue
            actual_hash = hashlib.sha256(actual_path.read_bytes()).digest()
            expected_hash = hashlib.sha256(expected_path.read_bytes()).digest()
            if actual_hash != expected_hash:
                print(f"SHA-256 mismatch: {actual_path}")
                okay = False
        if okay:
            print(
                f"verified {len(expected_manifest['fixtures'])} synthetic PCAP fixtures "
                "and their manifest"
            )
        return okay


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in fixtures against deterministic generator output",
    )
    args = parser.parse_args()
    if args.check:
        return 0 if check(args.output_dir) else 1
    manifest = generate(args.output_dir)
    for fixture in manifest["fixtures"]:
        print(f"{fixture['sha256']}  {fixture['file']} ({fixture['packet_count']} packets)")
    print(f"wrote {args.output_dir / MANIFEST_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
