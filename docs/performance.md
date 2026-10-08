# Performance

This page documents NetScope's offline benchmark system and measured optimization passes. The saved reports are the source for measured numbers; Criterion measurements remain useful for isolated parser, flow, and routing regressions, but they do not represent PCAP replay throughput.

- [Results and evidence](#results)
- [Recreating workloads](#recreating-workloads)
- [Running the offline suite](#running-the-offline-suite)
- [Live capture and packet loss](#live-capture-and-packet-loss)
- [Tuning](#tuning)

## Results

The latest [2026-10-08 performance pass](benchmarks/optimization-20261008/report.md) reduces flow bookkeeping, skips expiry scans when no flow can expire, grows pooled packet buffers on demand, and avoids full shutdown snapshots when exports are disabled. In an alternating comparison of the original and final binaries over the same one-million-packet high-cardinality trace, median pipeline throughput increased by 29.4% with two workers and 31.7% with four. Median peak RSS fell from 653.36 to 348.66 MiB and from 577.53 to 365.86 MiB respectively. These are local unlimited-flow, scale-mode observations on the Apple M4 host; all runs processed every frame with zero dispatch drops. The report retains ranges, source reconstruction, individual measurements, microbenchmarks, and correctness checks. Full-suite comparisons with wider ranges remain provisional.

The earlier checksummed [baseline](benchmarks/offline-20260926-baseline-checksummed/report.md) and [optimized](benchmarks/offline-20260926-checksummed/report.md) reports use the same PCAP hashes and configs across all 12 scenarios. Both save application source patches and harness copies alongside raw runs. Their reconstruction guides disclose omitted documentation, normalized diagnostic text, and published-file hashes; original source and binary fingerprints remain recorded. All runs reconciled their inputs and had zero offline dispatch drops. Supplemental repetitions retain noisy ranges rather than selecting the fastest run.

The earlier baseline and optimized suites ran on the same Apple M4 host (10 logical CPUs, 16 GiB RAM, macOS 27, Rust 1.93.1). The environment probe could not identify the libpcap version and records it as unavailable. These suites used synthetic packets with zero checksums. Their application source is recoverable from the recorded commit and the saved [optimized application patch](benchmarks/offline-20260926-after/source-snapshot/application.patch), but the original dirty runner revisions were not retained. Treat these reports as historical measurements with incomplete harness provenance.

- [Checksummed baseline report and raw records](benchmarks/offline-20260926-baseline-checksummed/report.md)
- [Checksummed optimized report and raw records](benchmarks/offline-20260926-checksummed/report.md)
- [Historical zero-checksum baseline report](benchmarks/offline-20260926-first/report.md)
- [Historical zero-checksum optimized report](benchmarks/offline-20260926-after/report.md)
- [Checksummed 10,000-packet smoke PCAPs and manifests](benchmarks/workloads-10k-smoke/)
- [Historical zero-checksum generator](benchmarks/legacy-workloads-v1.py) for regenerating the original report inputs

Profile sampling found frequent hash-map iterator folding while each pipeline worker selected top-flow candidates, including when both stats and dashboard output were disabled. Pipeline setup now disables heavy-hitter collection unless one of those consumers is enabled. The follow-up profile no longer samples that iterator-fold path; insertion and growth of the actual flow table remain visible. See the [baseline profile](benchmarks/offline-20260926-first/profiling/baseline-high-cardinality-5m-pipeline-w4/profile.json) and [follow-up profile](benchmarks/offline-20260926-after/profiling/high-cardinality-5m-pipeline-w4/profile.json).

The following historical table compares matching checksummed 100,000-packet runs on the same host. Ranges overlap, so those results do not support a reliable throughput-gain claim.

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

Run all four workload families inline and the three pipeline-supported families with explicit worker counts. `analysis-heavy` enables anomaly detection, which is supported only in inline mode:

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

If the saved binary has moved, add `--binary <PATH>` to the repeat command. Its SHA-256 must match the recorded binary; otherwise run a new suite. Historical build paths in the published reports are normalized labels, not guaranteed local locations.

The benchmark scripts are separate from the live-capture/drop validation. A PCAP run cannot measure kernel or interface loss.

## Live capture and packet loss

Use the isolated Linux procedure in [`scripts/perf/live_capture.py`](../scripts/perf/live_capture.py). It creates one deterministic, finite `steady-flow` trace, sets up capture on the receiver end of a named `veth` pair, and runs each offered rate three times. The sender transmits only after NetScope emits `NETSCOPE_READY`; the event includes the selected interface, BPF filter, snaplen, requested capture buffer, promiscuous/immediate modes, worker count, and per-worker queue capacity.

Create the isolated pair. The runner builds the release binary with `cargo build --locked --release` and saves the exact source inputs and build output before measuring:

```bash
sudo -v
sudo scripts/perf/live-veth.sh up
```

Run the default matrix (at least five seconds of offered traffic per rate, five rates, three repetitions; one million packets is the per-run minimum):

```bash
python3 scripts/perf/live_capture.py \
  --output-dir "tmp/perf/live-capture/$(date +%Y%m%d-%H%M%S)"
```

The default run retains the generated trace and every captured PCAP, about 3.2 GB of packet data before logs and JSON. Lower the rate list or `--duration-seconds` when less storage is available; each setting change belongs in the saved run record.

The runner requires Linux, `iproute2`, `tcpreplay`, GNU `/usr/bin/time`, Rust/Cargo, and a cached `sudo` authorization. It verifies the veth kind, UP state, reciprocal peer indexes, names, and fixed MAC addresses before running. The BPF filter is fixed to the generated trace; a preflight scan rejects a trace if any packet fails to match. Each trial has a finite `tcpreplay --limit`, scales its replay timeout to the requested rate, and gives NetScope up to 15 seconds to finish capture and worker shutdown after replay; process groups receive SIGINT and escalate to TERM/KILL if needed. A rate trial contributes to the bracket only when `tcpreplay` exits successfully, reports the full requested packet count, and achieves at least 99.5% of the requested rate. The report labels the bracket by requested rate and lists each achieved rate, so it does not claim an exact achieved rate. Larger rate shortfalls or incomplete replays remain inconclusive for sender/capture reconciliation unless separate drop counters or captured-versus-processed accounting prove a drop. The readiness event confirms the buffer size requested from libpcap; the OS does not provide a portable readback of the actual allocated capture buffer. The veth pair adds no IP addresses or routes. When finished, remove only this named pair:

```bash
sudo scripts/perf/live-veth.sh status
sudo scripts/perf/live-veth.sh down
```

Each suite saves `source.json`, a reconstructible `source-snapshot/` (including dirty tracked and untracked files), and release-build logs alongside the trace and results. The runner rejects a source change during the build and marks the suite invalid if the source or binary changes during measurement. Each run retains full NetScope and tcpreplay output, exact commands and config, the versioned NetScope summary, GNU time CPU/RSS output, veth counters before and after, and a captured PCAP. The runner compares the captured TCP sequence identifiers with the generated trace, then creates `suite.json` and `report.md`. PCAP writing is enabled for that reconciliation, so its disk I/O is part of the measured configuration. The report keeps `tcpreplay` send-path counts, NetScope frames read and worker-processed frames, libpcap kernel/interface drops, veth RX/TX drops, dispatch drops, wall time, CPU, and RSS as separate fields. Missing counters are unknown, not zero.

The tested requested rates form a bracket, not an exact maximum. The report names the highest qualified target with zero observed loss in every repetition and the first qualified target where any repetition showed loss. A loss observation from an under-rate or incomplete replay remains in the raw record but does not set a target-rate bracket endpoint. If no qualified loss appears, the report says no onset was established. Incomplete matrix coverage is shown separately. To narrow an observed bracket, rerun with additional rates between its endpoints and retain the same trace, host, settings, and repetition count. Review raw records as well as the generated summary.

The veth runner is Linux-only. macOS does not provide an equivalent isolated sender/receiver pair through `lo0`; do not use loopback replay to make a loss claim. A manual macOS trial is appropriate only with a second host connected over a dedicated, otherwise unused point-to-point link. Start NetScope on the receiver and wait for `NETSCOPE_READY` before starting finite `tcpreplay` on the sender. Save both command outputs, the NetScope summary, interface-counter readings, and the trace hash. Report unavailable drop counters as unavailable; the Linux runner's automated rate bracketing does not apply to that manual setup.

Controlled Linux live measurements are excluded from the current release scope. The checked-in [live-capture report](benchmarks/live-capture/report.md) records no measured live rate or loss number. Run the procedure above on Linux before publishing such results.

## Tuning

Change one setting at a time and retain the run summary's `effective_config` alongside the measurement. Worker count, TCP analysis, flow retention, packet sampling, and output files all affect the work being measured. See [output behavior](reference.md#output-behavior) before lowering retention limits.

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

- Lower `flow.max_flows` (CLI: `--max-flows`) to reduce retained flows. Pipeline divides the budget among workers and enforces it before admitting new flows. `0` means unlimited.
- Reduce `flow.timeout_secs` to expire flows sooner; `0` disables timeout removal. Removed flows require an expired-flow sink if they must remain in the investigation record.
- Lower `packet_buffer` to retain fewer dashboard packets.
- For large flow-count runs, disable deep TCP analysis (`analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`) to use scale-mode flow storage.
- Pipeline packet buffers start at at most 2 KiB and grow for larger captured frames. Requested final JSON/CSV exports still require materializing retained flow snapshots at shutdown; runs without those exports skip that work.

The published peak-RSS measurements come from whole-process runs over deterministic PCAP workloads. They include parsing and the configured flow workload; they should not be read as isolated per-flow storage cost. Use high-cardinality manifests when comparing memory behavior, and retain the host and raw-run records.
