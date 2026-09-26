# Performance

NetScope is designed for high-throughput packet processing. This page covers benchmark results, how to run benchmarks, and tuning guidance.

For authoritative defaults referenced by the tuning examples here, see [Configuration](configuration.md) and `src/config.rs`.

## Optimizations

NetScope uses several performance-focused design choices on the hot path:

- **Zero-copy parsing** -- protocol headers are parsed as views over the original byte slice, with no allocations or copies.
- **Fast hashing** -- hot-path flow/anomaly maps use `ahash` (`AHashMap`/`AHashSet`) to reduce per-lookup hashing cost.
- **Partial top-N selection** -- uses `select_nth_unstable_by` to partition the top-N elements in O(F) time, then sorts only that slice.
- **Pipeline sharding (optional)** -- in `--pipeline` mode, each worker owns its own `FlowTracker`, avoiding shared hot-path contention. Anomaly detection is inline-only because worker-local thresholds would not match global thresholds.
- **Web tick batching** -- the web server ships one merged frame per tick (stats + sampled packets + alerts) and resyncs lagged clients by sending only the latest frame.
- **Pipeline top-flows fast path** -- workers use a fixed-size SpaceSaving-style tracker to choose a bounded candidate set, then recompute exact deltas for those candidates before building the dashboard payload.
- **Scale-mode flow storage** -- when `analysis.rtt = false`, `analysis.retrans = false`, and `analysis.out_of_order = false`, flow tracking switches to compact split IPv4/IPv6 tables (`ScaleFlowEntry`) to reduce per-flow memory overhead.

## Benchmark Results

Criterion benchmarks measured on Apple M-series (`cargo bench`):

| Benchmark                                  | Latency     | Throughput  |
| ------------------------------------------ | ----------- | ----------- |
| `parse_packet` (54B TCP SYN)               | ~5.8 ns     | ~172M pkt/s |
| `parse_packet` (1454B TCP data)            | ~5.8 ns     | ~173M pkt/s |
| `flow_observe` (existing flow)             | ~25 ns      | ~40M pkt/s  |
| `flow_observe` (new flow, cold setup)      | ~7.7 us     | ~130k pkt/s |
| `shard_routing` (4 shards)                 | ~4.1 ns     | ~246M pkt/s |
| `handshake_sequence` (SYN → SYN-ACK → ACK) | ~105 ns/pkt | ~9.6M pkt/s |

These numbers reflect isolated function-level performance measured by Criterion and will vary by CPU, compiler version, and background load.
The `flow_observe (new flow, cold setup)` benchmark includes flow tracker setup and is intended to represent a cold-path baseline rather than steady-state capture.
Actual capture throughput depends on the OS, NIC driver, libpcap configuration, and workload.

## Running Benchmarks

```bash
cargo bench
```

This runs the Criterion benchmarks defined in `benches/hot_path.rs`. Results are written to `target/criterion/` with HTML reports.

For repeatable end-to-end checks (pcap replay throughput, web dashboard fps/latency, etc.), see `scripts/perf/`.

Note: replay-based perf checks (`scripts/perf/validate-throughput.sh`, `scripts/perf/validate-web.sh`) require `tcpreplay`.
On macOS: `brew install tcpreplay`. On Debian/Ubuntu: `sudo apt-get install tcpreplay`.

For a single command that captures a small set of representative local checks (release build, one hot-path benchmark, and synthetic-flow memory validation), run:

```bash
scripts/perf/validate.sh
```

Logs are written under `tmp/perf/`.

To run a specific benchmark:

```bash
cargo bench --bench hot_path -- parse_packet
cargo bench --bench hot_path -- flow_observe
cargo bench --bench hot_path -- shard_routing
cargo bench --bench hot_path -- handshake_sequence
```

## Tuning Checklist

### Reducing kernel drops

- Use a BPF filter (`-f "..."`) to reduce the volume of traffic entering the capture pipeline.
- Reduce `--snaplen` when you only need headers (smaller packets = less copy/parse work and less memory bandwidth used per packet copied to userspace).
- Increase libpcap buffer size via config: `capture.buffer_size_mb = 8` (or higher for bursty traffic).
- Consider `capture.immediate_mode = true` (best-effort; depends on libpcap support).
- Enable pipeline mode (`--pipeline`) to parallelize processing.

Example perf-oriented capture config:

```toml
[capture]
timeout_ms = 1
buffer_size_mb = 8
immediate_mode = true
```

### Reducing dispatch drops (pipeline mode)

- Increase `channel_capacity` in the `[pipeline]` config section (default: 4096). Higher values use more memory.
- Add more workers (`--workers N`).
- Apply a BPF filter to reduce packet volume.

### Reducing web dashboard load

- Increase `sample_rate` (e.g., `sample_rate = 10` sends every 10th packet).
- Set `sample_rate = 0` to disable the live packet feed.
- `sample_rate` is capture-wide in both inline and pipeline modes, so increasing it reduces total packet samples rather than samples per shard.
- Reduce `top_n` (fewer flows per tick).
- Increase `tick_ms` (less frequent stats updates). Use `33` for roughly 30fps when you want smooth live updates.
- Reduce `payload_bytes` (smaller hex dumps per packet).
- Use `?perf=1` in the dashboard URL to inspect fps, latency p50/p95/p99, dropped frames, and client/server clock offset while tuning.

### Reducing memory usage

- Lower `max_flows` to cap the flow table size.
- Reduce `flow.timeout_secs` to expire flows sooner.
- Lower `packet_buffer` to keep fewer packets in the web dashboard ring buffer.
- In pipeline mode, `max_flows` is a total budget split among worker shards. A busy shard can evict flows while another still has unused quota; pruning runs at most once per second.
- For large flow-count runs, disable deep TCP analysis (`analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`) to activate scale-mode flow storage.

### Memory validation

Use the synthetic flow path to quickly validate scale-mode memory usage:

```bash
cargo run --release -- --synthetic-flows 1000000
```

This prints insertion time, estimated RSS, and a pass/fail check against the 500MB budget.

### CPU usage

- Pipeline mode with auto-detected workers uses half the available CPU cores (clamped 1..8).
- Disable analysis features you don't need: `analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`.
- Disable anomaly detection if not needed: `analysis.anomalies.enabled = false`.
