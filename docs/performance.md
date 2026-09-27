# Performance

This page documents NetScope's offline benchmark system and its first profile-guided change. The saved reports are the source for measured numbers; Criterion measurements remain useful for isolated parser, flow, and routing regressions, but they do not represent PCAP replay throughput.

## Results

The current [baseline](benchmarks/offline-20260926-baseline-checksummed/report.md) and [optimized](benchmarks/offline-20260926-checksummed/report.md) reports use the same checksummed PCAP hashes and configs across all 12 scenarios. Both save exact source patches and untracked scripts alongside raw runs. All runs reconciled their inputs and had zero offline dispatch drops. Supplemental repetitions retain noisy ranges rather than selecting the fastest run.

The earlier baseline and optimized suites ran on the same Apple M4 host (10 logical CPUs, 16 GiB RAM, macOS 27, Rust 1.93.1). The environment probe could not identify the libpcap version and records it as unavailable. These suites used synthetic packets with zero checksums. Their application source is recoverable from the recorded commit and the saved [optimized application patch](benchmarks/offline-20260926-after/source-snapshot/application.patch), but the original dirty runner revisions were not retained. Treat these reports as historical measurements with incomplete harness provenance.

- [Checksummed baseline report and raw records](benchmarks/offline-20260926-baseline-checksummed/report.md)
- [Checksummed optimized report and raw records](benchmarks/offline-20260926-checksummed/report.md)
- [Historical zero-checksum baseline report](benchmarks/offline-20260926-first/report.md)
- [Historical zero-checksum optimized report](benchmarks/offline-20260926-after/report.md)
- [Checksummed 10,000-packet smoke PCAPs and manifests](benchmarks/workloads-10k-smoke/)
- [Historical zero-checksum generator](benchmarks/legacy-workloads-v1.py) for regenerating the original report inputs

Profile sampling found frequent hash-map iterator folding while each pipeline worker selected top-flow candidates, including when both stats and dashboard output were disabled. Pipeline setup now disables heavy-hitter collection unless one of those consumers is enabled. The follow-up profile no longer samples that iterator-fold path; insertion and growth of the actual flow table remain visible. See the [baseline profile](benchmarks/offline-20260926-first/profiling/baseline-high-cardinality-5m-pipeline-w4/profile.json) and [follow-up profile](benchmarks/offline-20260926-after/profiling/high-cardinality-5m-pipeline-w4/profile.json).

The table compares matching checksummed 100,000-packet runs on the same host. Ranges overlap, so these results do not support a reliable throughput-gain claim.

| Scenario | Baseline packets/s median [range] | After packets/s median [range] | Median change |
| --- | ---: | ---: | ---: |
| High-cardinality, pipeline, 2 workers | 1,294,230 [1,288,413–1,345,313] | 1,315,012 [1,293,467–1,348,446] | +1.6% |
| High-cardinality, pipeline, 4 workers | 1,322,388 [1,291,487–1,353,950] | 1,336,575 [1,289,040–2,471,513] | +1.1% |
| Mixed, pipeline, 2 workers | 1,319,880 [1,290,299–1,449,431] | 1,294,928 [1,292,356–1,343,547] | -1.9% |

All offline runs reconciled generated input counts with the final summary and recorded zero pipeline dispatch drops and worker failures. These file-replay results say nothing about packets dropped before a PCAP was created. The dashboard probe measures server-to-local-WebSocket delivery, frame cadence, and sequence gaps; it does not measure browser rendering or paint latency. Several repeat batches showed wide run-to-run or batch-to-batch variation. Both reports retain every run and mark pooled spreads above 10% as provisional; neither selects the fastest repetition.

## Recreating workloads

`scripts/perf/workloads.py` streams deterministic synthetic classic-PCAP records to disk and writes a sidecar manifest with the seed, SHA-256, count, byte totals, packet-size distribution, protocol mix, distinct flow cardinality, and timestamp spacing. Version 2 generates valid IPv4, TCP, UDP, and ICMP checksums. It supports `steady-flow`, `high-cardinality`, `mixed`, and `analysis-heavy` traffic. The steady-flow trace starts midstream with ACK packets; it does not model a TCP handshake.

Generate a short smoke trace for each workload:

```bash
python3 scripts/perf/workloads.py \
  --output-dir tmp/perf/workloads-10k \
  --workload all \
  --counts 10000
```

Generate larger high-cardinality inputs when profiling or checking scale:

```bash
python3 scripts/perf/workloads.py \
  --output-dir tmp/perf/high-cardinality \
  --workload high-cardinality \
  --counts 100000,1000000,5000000
```

The runner creates its input traces in a temporary directory and records their manifest and hash in `results.json`; it removes the large PCAPs after each suite.

## Running the offline suite

The release runner builds with `cargo build --locked --release`, records the source commit, dirty state and source fingerprint, and saves the exact tracked patch and untracked files in `source-snapshot/`. It refuses to publish if source files change during the build or measurement. Each scenario gets a warm-up and at least five measured repetitions. A record includes the command, copied config, stdout, stderr, exit code, final summary, resource readings, and validation result. `scripts/perf/result.schema.json` documents the versioned JSON envelope. To rebuild a dirty-tree run, start from its recorded commit in a clean checkout and follow the saved `source-snapshot/README.md`.

Run all four workload families inline and the three pipeline-supported families with explicit worker counts. `analysis-heavy` enables anomaly detection, which Phase 3 intentionally restricts to inline mode:

```bash
python3 scripts/perf/run_offline.py \
  --output-dir tmp/perf/offline-100k \
  --packets 100000 \
  --repetitions 5 \
  --warmups 1 \
  --workers 2,4
```

Measure the dashboard in a separate high-cardinality pipeline scenario with a local WebSocket client:

```bash
python3 scripts/perf/run_offline.py \
  --output-dir tmp/perf/dashboard-1m \
  --packets 100000 \
  --repetitions 5 \
  --warmups 1 \
  --workers 2,4 \
  --dashboard \
  --dashboard-packets 1000000
```

The runner reports medians and min–max ranges for packet throughput, decimal Mbps, process CPU, CPU seconds per million packets, and peak RSS. Timing begins at process launch and includes PCAP open/read, processing, summary output, and shutdown; it excludes compilation and trace generation. CPU and memory measurements are collected outside NetScope's packet-processing path. macOS uses `/usr/bin/time -l`; Linux uses `/usr/bin/time` and `perf` adapters. The Linux adapter is implemented but has not been exercised on this macOS host.

To collect a separate CPU profile without mixing profiler overhead into timed repetitions:

```bash
python3 scripts/perf/profile_offline.py \
  --output-dir tmp/perf/profile-high-cardinality-5m \
  --workload high-cardinality \
  --packets 5000000 \
  --mode pipeline \
  --workers 4 \
  --duration-seconds 1
```

When a pooled throughput range exceeds 10% of its median, repeat selected scenario IDs with the same saved binary and regenerated PCAP hashes. Supplemental batches collect their own host, power state, and load readings:

```bash
python3 scripts/perf/repeat_scenarios.py \
  --baseline tmp/perf/offline-100k \
  --output-dir tmp/perf/offline-100k-repeat \
  --scenario-id high-cardinality-pipeline-w4-n100000 \
  --repetitions 5 \
  --warmups 1
```

The benchmark scripts are separate from the live-capture/drop validation. A PCAP run cannot measure kernel or interface loss.

## Tuning

### Reducing kernel drops

- Use a BPF filter (`-f "..."`) to reduce traffic entering the capture pipeline.
- Reduce `--snaplen` when only headers are needed.
- Increase `capture.buffer_size_mb` for bursty live traffic.
- Consider `capture.immediate_mode = true` where libpcap supports it.
- Use `--pipeline` to parallelize processing, then measure under a controlled live setup.

### Reducing live dispatch drops

- Increase `pipeline.channel_capacity`; larger queues use more memory.
- Add workers with `--workers N`.
- Reduce the live packet rate entering the application with a BPF filter.
- Offline PCAP processing applies backpressure and does not drop input frames silently.

### Reducing dashboard load

- Increase `sample_rate`; set it to `0` to disable live packet samples.
- Reduce `top_n` or increase `tick_ms` to reduce dashboard work.
- Reduce `payload_bytes` to limit packet hex dumps.
- Use `?perf=1` for frontend diagnostics, while keeping in mind that this is separate from the offline runner's server-to-client frame probe.

### Reducing memory use

- Lower `max_flows` to cap the flow table. In pipeline mode, the configured budget is divided among worker shards.
- Reduce `flow.timeout_secs` to expire flows sooner.
- Lower `packet_buffer` to retain fewer dashboard packets.
- For large flow-count runs, disable deep TCP analysis (`analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`) to use scale-mode flow storage.

The developer-only `--synthetic-flows` option measures flow-table insertion without PCAP parsing. It is not used for the process RSS or replay-throughput results above.
