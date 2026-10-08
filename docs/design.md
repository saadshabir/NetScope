# Design

NetScope reads a PCAP or a live libpcap source, parses supported headers, updates bidirectional TCP/UDP flows, and emits summaries and optional views. Inline processing is the default. Worker sharding is an opt-in live/throughput path with explicit limits.

## Processing modes

```mermaid
flowchart LR
    SRC[PCAP or libpcap] --> CAP[Capture reader]
    CAP --> INLINE[Inline parser and flow table]
    CAP --> ROUTE[Canonical flow tuple router]
    ROUTE --> QUEUES[Bounded worker queues]
    QUEUES --> WORKERS[Worker-owned parser and flow tables]
    WORKERS --> AGG[Aggregator]
    INLINE --> OUT[Summary and exports]
    AGG --> OUT
    INLINE --> WEB[Optional dashboard and metrics]
    AGG --> WEB
```

Inline mode owns one flow table and one global anomaly detector. Pipeline mode routes both directions of a flow to the same worker, then merges worker summaries at shutdown. Offline reads block when queues fill, so file input is processed with backpressure. Live capture dispatch remains nonblocking; queue-full frames are counted as application dispatch drops. A capture PCAP is written before pipeline dispatch and can therefore contain frames absent from worker-side flows.

Pooled packet buffers initially reserve at most 2 KiB each, grow for larger frames, and retain grown capacity within the pool's return limit. This changes allocation rather than capture snaplen or packet contents. Workers always send shutdown accounting; full retained-flow snapshots are collected only for requested final JSON/CSV exports.

`flow.max_flows` is a total pipeline budget split among workers. A busy shard may evict flows while another has spare quota, and capacity is enforced before every new-flow insertion. A bounded second-chance clock evicts flows when a shard fills; timeout cleanup is separate and runs at most once per capture-time second. If the budget is below the requested worker count, NetScope reduces the active worker count so each shard receives a positive quota.

The clock stores reference bits in the flow entries. Timeout cleanup removes entries in place and builds removal snapshots only for enabled sinks. A conservative lower bound on retained last-seen timestamps lets cleanup return without scanning when no flow can have timed out; admitting a new flow with an older timestamp lowers that bound.

Both inline and pipeline offline expiry use a monotonic capture-time watermark. Idle worker ticks keep that watermark and do not compare historical packets with today's wall clock. Flow timestamps retain the earliest and latest observations, including out-of-order packets and captures spanning more than 50 days. Live workers also expire idle flows against wall time. To disable timeout removal in either mode, use `--flow-timeout-s 0`; the flow budget still applies.

Pipeline mode rejects enabled anomaly detection before opening the source. The router hashes the full canonical flow tuple, so sources targeting one destination may reach different shards; per-worker thresholds would change the detector's meaning.

## Decode and tracking scope

| Input layer | Recognized data | Flow or payload behavior |
| --- | --- | --- |
| Ethernet, Linux SLL v1, NULL/LOOP loopback, raw IP | Link type and supported inner network headers; Ethernet supports up to four 802.1Q/802.1ad tags. | Other link types, including SLL2, are reported unsupported. |
| ARP | Address and operation fields. | Decoded, but no flow is created. |
| IPv4 / IPv6 | Address, lengths, and network fields; IPv6 walks at most 16 common extension headers. | Non-initial fragments are skipped. There is no fragment reassembly. |
| TCP / UDP | Transport header fields and ports. | Bidirectional flows with directional counts. Malformed supported headers are classified separately. |
| ICMP / ICMPv6 | Type/code and echo identifier/sequence when present. | Decoded, but no flow is created. |
| DNS | UDP involving port 53; first query question and response section counts. | Packet-level decode only; no DNS-over-TCP or encrypted DNS inspection. |
| TLS | Best-effort SNI from a complete ClientHello in one TCP payload. | No TCP stream reassembly; split ClientHello messages can be missed and ECH can conceal SNI. |

TCP state, client direction, RTT, retransmission, and out-of-order fields are inferred from captured packets. They do not reconstruct a TCP byte stream. Capture-file support is limited by libpcap plus the link types above; classic PCAP is the checked-in and reproducible baseline. PCAPNG support is broader but has only a minimal single-interface Ethernet verification in the current evidence.

The final run summary distinguishes frames read, packets parsed, network and transport headers recognized, parse errors, malformed transports, unsupported packets, flows, alerts, worker accounting, and drop sources. Unavailable counters are `null`, not zero. See [Reference](reference.md) for output contracts.

## Anomaly semantics

The two detectors are configurable heuristics, not signature-based intrusion detection:

- **SYN flood:** counts initial TCP SYN observations in a sliding time window and requires both the configured SYN count and unique-source threshold for a target.
- **Port scan:** counts distinct destination ports and hosts observed from a source within its configured window; either positive unique-target threshold can fire the alert. Setting one threshold to zero disables that criterion.

SYN counts update incrementally; repeated SYNs with the same timestamp and source share one counted record. Scan targets keep only their latest timestamp. Each detector admits at most 4,096 keys and 65,536 records, with at most 4,096 timestamp/source records per SYN target or 4,096 distinct values per scan dimension. Full per-key windows discard their oldest evidence; global saturation blocks new records or keys until expiry frees space. Saturation can miss alerts, so thresholds above the retained evidence limit should be avoided.

Each detector has a per-key cooldown. Expired observations and cooldowns are pruned even when a key becomes inactive. Out-of-order capture timestamps use a monotonic event-time watermark so state does not move backward. A benign scanner, inventory check, or traffic burst may meet a threshold; a PCAP alone cannot establish intent, service impact, or whether a handshake completed.

## Dashboard and security

The optional dashboard runs in a dedicated server thread and consumes inline updates or aggregated pipeline frames. It offers `/`, `/ws`, `/api/health`, and `/metrics`. Packet samples are capture-wide, while detail data is kept in a bounded ring buffer. `sample_rate = 0` disables packet samples without disabling stats or alerts. Chart.js is vendored so the dashboard works offline; keep its license alongside the asset.

The server defaults to `127.0.0.1`. Host headers and browser origins must match configured dashboard endpoints, preventing foreign-origin WebSocket upgrades and DNS rebinding. Loopback names and the configured bind address are trusted by default; wildcard binds require explicit `web.allowed_origins` for remote hostnames or addresses. Native clients may omit Origin but still need a trusted Host. For remote access, enable TLS and authentication as shown in [Reference](reference.md#remote-dashboard). Basic auth covers every dashboard endpoint, including `/metrics` and the WebSocket handshake; without TLS, credentials travel over cleartext HTTP.

## Development checks

The focused project gates are:

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
python3 scripts/generate_examples.py --check
python3 scripts/perf/test_workloads.py
python3 scripts/perf/test_live_capture.py
```

Add coverage for observable behavior or a concrete regression risk. Keep long performance runs and privileged live replay outside ordinary CI.
