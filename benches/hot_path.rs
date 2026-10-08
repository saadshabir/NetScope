//! Criterion benchmarks for the NetScope hot path:
//! - `protocol::parse_packet` (zero-copy protocol parsing)
//! - `FlowTracker::observe` (flow table update)
//! - `pipeline::router::shard_for_packet` (shard routing)
//! - `handshake_sequence` (SYN → SYN-ACK → ACK end-to-end hot path)

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::time::Duration;

// We can't import private modules from the binary crate directly.
// Instead we build representative packet bytes inline and test the
// public API surface.

/// Build a realistic TCP/IPv4 SYN packet (Ethernet + IPv4 + TCP, 54 bytes).
fn make_tcp_syn_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 54]; // 14 eth + 20 ipv4 + 20 tcp

    // Ethernet header
    // dst mac
    pkt[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // src mac
    pkt[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // ethertype = IPv4
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4 header (20 bytes, no options)
    let ip = &mut pkt[14..34];
    ip[0] = 0x45; // version=4, ihl=5
    ip[1] = 0x00; // DSCP/ECN
    let total_len: u16 = 40; // 20 ip + 20 tcp
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&[0x00, 0x01]); // identification
    ip[6] = 0x40; // flags: DF
    ip[7] = 0x00; // fragment offset
    ip[8] = 64; // TTL
    ip[9] = 6; // protocol = TCP
    ip[10..12].copy_from_slice(&[0x00, 0x00]); // checksum (skip)
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);

    // TCP header (20 bytes, no options)
    let tcp = &mut pkt[34..54];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&1000u32.to_be_bytes()); // seq
    tcp[8..12].copy_from_slice(&0u32.to_be_bytes()); // ack
    tcp[12] = 0x50; // data offset = 5 (20 bytes)
    tcp[13] = 0x02; // SYN flag
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    tcp[16..18].copy_from_slice(&[0x00, 0x00]); // checksum
    tcp[18..20].copy_from_slice(&[0x00, 0x00]); // urgent ptr

    pkt
}

/// Build a TCP data packet with payload.
fn make_tcp_data_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload_len: usize,
) -> Vec<u8> {
    let total_pkt_len = 14 + 20 + 20 + payload_len;
    let mut pkt = vec![0u8; total_pkt_len];

    // Ethernet header
    pkt[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pkt[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4 header
    let ip_total: u16 = (20 + 20 + payload_len) as u16;
    let ip = &mut pkt[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);

    // TCP header
    let tcp = &mut pkt[34..54];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // data offset = 5
    tcp[13] = 0x10; // ACK flag
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());

    // Fill payload with arbitrary data
    for (i, byte) in pkt[54..].iter_mut().enumerate() {
        *byte = (i & 0xFF) as u8;
    }

    pkt
}

/// Build a TCP packet with arbitrary flags, seq, ack, and zero payload.
/// `flags` byte: SYN=0x02, SYN-ACK=0x12, ACK=0x10.
fn make_tcp_flagged_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 54]; // 14 eth + 20 ipv4 + 20 tcp

    // Ethernet header
    pkt[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pkt[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4 header (20 bytes)
    let ip = &mut pkt[14..34];
    ip[0] = 0x45;
    ip[1] = 0x00;
    let total_len: u16 = 40;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&[0x00, 0x01]);
    ip[6] = 0x40;
    ip[7] = 0x00;
    ip[8] = 64;
    ip[9] = 6; // TCP
    ip[10..12].copy_from_slice(&[0x00, 0x00]);
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);

    // TCP header (20 bytes)
    let tcp = &mut pkt[34..54];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // data offset = 5
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    tcp[16..18].copy_from_slice(&[0x00, 0x00]); // checksum
    tcp[18..20].copy_from_slice(&[0x00, 0x00]); // urgent ptr

    pkt
}

fn bench_parse_packet(c: &mut Criterion) {
    let syn_pkt = make_tcp_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
    let data_pkt = make_tcp_data_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 1000, 1, 1400);

    let mut group = c.benchmark_group("parse_packet");
    group.throughput(Throughput::Elements(1));

    group.bench_function("tcp_syn_54B", |b| {
        b.iter(|| {
            let _ = netscope::protocol::parse_packet(black_box(&syn_pkt));
        })
    });

    group.bench_function("tcp_data_1454B", |b| {
        b.iter(|| {
            let _ = netscope::protocol::parse_packet(black_box(&data_pkt));
        })
    });

    group.finish();
}

fn bench_flow_observe(c: &mut Criterion) {
    // Pre-parse a packet so we can benchmark just the flow tracker update.
    let data_pkt = make_tcp_data_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 1000, 1, 100);
    let parsed = netscope::protocol::parse_packet(&data_pkt).unwrap();

    let mut group = c.benchmark_group("flow_observe");
    group.throughput(Throughput::Elements(1));

    group.bench_function("existing_flow", |b| {
        let mut tracker = netscope::flow::FlowTracker::new(60.0, 100_000, true, true, true);
        // Seed the flow so observe hits the existing-flow fast path.
        tracker.observe(1.0, 100, &parsed);

        let mut ts = 2.0;
        b.iter(|| {
            tracker.observe(black_box(ts), 100, &parsed);
            ts += 0.001;
        })
    });

    for (name, limit) in [
        ("existing_flow_scale", 100_000),
        ("existing_flow_unlimited", 0),
    ] {
        group.bench_function(name, |b| {
            let mut tracker = netscope::flow::FlowTracker::new(60.0, limit, false, false, false);
            tracker.observe(1.0, 100, &parsed);
            b.iter(|| tracker.observe(black_box(2.0), 100, black_box(&parsed)))
        });
    }

    // Parse fixtures and allocate each table outside the timed region. Measure
    // a batch of distinct insertions into one table, rather than table setup.
    const BATCH: usize = 1024;
    let packets: Vec<_> = (0..BATCH)
        .map(|i| {
            make_tcp_data_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1024 + i as u16,
                80,
                1000,
                1,
                100,
            )
        })
        .collect();
    let parsed: Vec<_> = packets
        .iter()
        .map(|packet| netscope::protocol::parse_packet(packet).unwrap())
        .collect();
    group.throughput(Throughput::Elements(BATCH as u64));
    for (mode, deep) in [("full", true), ("scale", false)] {
        group.bench_function(format!("new_flows_{mode}"), |b| {
            b.iter_batched_ref(
                || netscope::flow::FlowTracker::new(60.0, BATCH, deep, deep, deep),
                |tracker| {
                    for packet in &parsed {
                        tracker.observe(black_box(1.0), 100, black_box(packet));
                    }
                    black_box(tracker.len());
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("capacity_churn_{mode}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut tracker = netscope::flow::FlowTracker::new(60.0, 256, deep, deep, deep);
                    for packet in &parsed[..256] {
                        tracker.observe(1.0, 100, packet);
                    }
                    tracker
                },
                |tracker| {
                    for packet in &parsed {
                        tracker.observe(black_box(2.0), 100, black_box(packet));
                    }
                    black_box(tracker.len());
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn bench_flow_expire(c: &mut Criterion) {
    const BATCH: usize = 1024;
    let packets: Vec<_> = (0..BATCH)
        .map(|i| make_tcp_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 1024 + i as u16, 80))
        .collect();
    let parsed: Vec<_> = packets
        .iter()
        .map(|packet| netscope::protocol::parse_packet(packet).unwrap())
        .collect();
    let mut group = c.benchmark_group("flow_expire");
    group.throughput(Throughput::Elements(BATCH as u64));
    for (mode, deep) in [("full", true), ("scale", false)] {
        for (name, now) in [("active", 2.0), ("expired", 120.0)] {
            group.bench_function(format!("{name}_{mode}"), |b| {
                b.iter_batched_ref(
                    || {
                        let mut tracker =
                            netscope::flow::FlowTracker::new(60.0, BATCH, deep, deep, deep);
                        for packet in &parsed {
                            tracker.observe(1.0, 54, packet);
                        }
                        tracker
                    },
                    |tracker| black_box(tracker.maybe_expire(black_box(now))),
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn bench_shard_routing(c: &mut Criterion) {
    let pkt = make_tcp_data_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 1000, 1, 100);

    let mut group = c.benchmark_group("shard_routing");
    group.throughput(Throughput::Elements(1));

    group.bench_function("shard_for_packet_4", |b| {
        b.iter(|| netscope::pipeline::router::shard_for_packet(black_box(&pkt), 4))
    });

    group.finish();
}

/// Benchmark the combined hot path for a full TCP 3-way handshake.
///
/// Each iteration processes three packets in sequence on a fresh flow:
///   1. SYN      (client → server)
///   2. SYN-ACK  (server → client)
///   3. ACK      (client → server)
///
/// Both `protocol::parse_packet` and `FlowTracker::observe` are measured.
/// Flow table setup is excluded from the timed region via `iter_custom`.
/// Throughput is expressed as packets (3 per iteration).
fn bench_handshake_sequence(c: &mut Criterion) {
    // Build the three packets once; they are re-used across iterations.
    let client_ip: [u8; 4] = [10, 0, 0, 1];
    let server_ip: [u8; 4] = [10, 0, 0, 2];
    let client_port: u16 = 54321;
    let server_port: u16 = 443;

    // SYN: client → server, seq=1000, ack=0, flags=SYN(0x02)
    let syn_pkt = make_tcp_flagged_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        1000,
        0,
        0x02,
    );
    // SYN-ACK: server → client, seq=5000, ack=1001, flags=SYN+ACK(0x12)
    let synack_pkt = make_tcp_flagged_packet(
        server_ip,
        client_ip,
        server_port,
        client_port,
        5000,
        1001,
        0x12,
    );
    // ACK: client → server, seq=1001, ack=5001, flags=ACK(0x10)
    let ack_pkt = make_tcp_flagged_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        1001,
        5001,
        0x10,
    );

    let mut group = c.benchmark_group("handshake_sequence");
    // Three packets per iteration.
    group.throughput(Throughput::Elements(3));

    group.bench_function("syn_synack_ack", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;

            for _ in 0..iters {
                // Fresh tracker per iteration — outside the timed region.
                let mut tracker = netscope::flow::FlowTracker::new(60.0, 100_000, true, true, true);

                let start = std::time::Instant::now();

                // SYN
                let parsed = netscope::protocol::parse_packet(black_box(&syn_pkt)).unwrap();
                tracker.observe(black_box(1.0), 54, &parsed);

                // SYN-ACK
                let parsed = netscope::protocol::parse_packet(black_box(&synack_pkt)).unwrap();
                tracker.observe(black_box(1.001), 54, &parsed);

                // ACK
                let parsed = netscope::protocol::parse_packet(black_box(&ack_pkt)).unwrap();
                tracker.observe(black_box(1.002), 54, &parsed);

                total += start.elapsed();
            }

            total
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_packet,
    bench_flow_observe,
    bench_flow_expire,
    bench_shard_routing,
    bench_handshake_sequence,
);
criterion_main!(benches);
