# Performance

This page documents NetScope's offline benchmark system and summarizes optimization measurements. Raw benchmark artifacts are excluded from version control; the older published bundles were removed. Criterion measurements remain useful for isolated parser, flow, and routing regressions, but they do not represent PCAP replay throughput.

- [Historical results](#results)
- [Recreating workloads](#recreating-workloads)
- [Running the offline suite](#running-the-offline-suite)
- [Live capture and packet loss](#live-capture-and-packet-loss)
- [Tuning](#tuning)

## Results

### 2026-10-10 build and reporting pass

The [optimization plan](optimization-plan.md) ships a first phase: narrower dependency features, an optional dashboard enabled by default, fewer inline clock reads when stats are disabled, deferred scale-mode IPv6 reservation, and bounded exact top-N reporting. The headless command is `cargo build --locked --release --no-default-features`. A headless dashboard request fails before capture or output files are opened.

On the same Apple M4/macOS host, the fresh audit baseline was commit `0ffcb38`. Build-footprint measurements below use `5e478c4`, after the feature boundary and test isolation fix, before the packet-loop/reporting changes. Counts are unique resolved normal packages including NetScope on this platform, not the lockfile count or development dependencies.

| Build | Release bytes | MiB | Normal packages |
| --- | ---: | ---: | ---: |
| Audit baseline | 8,624,496 | 8.22 | 150 |
| Dashboard enabled | 8,601,936 | 8.20 | 141 |
| Headless | 2,613,472 | 2.49 | 65 |

After the reporting change (`133d735`), final release builds measured 8,488,464 bytes (8.10 MiB) with the dashboard and 2,611,088 bytes (2.49 MiB) headless. Binary sizes are specific to this host and toolchain.

The headless normal graph excludes Tokio, Axum, and Rustls. Separate sequential clean release builds with cached dependencies took 35.41 seconds for the dashboard and 16.59 seconds for headless. These are single build observations; they do not establish a repeatable build-time speedup. The automatic worker policy still uses half the estimated available CPUs, clamped to 1–8. The two CPU APIs agreed on this host; container/affinity behavior has not been exercised on Linux.

For the isolated inline clock change (`4ab995c`), baseline and candidate binaries alternated over five-million-packet traces, with one warm-up and five measured repetitions each. Stats, dashboard, and exports were disabled.

| Inline workload | CPU seconds / million packets before median [range] | After median [range] |
| --- | ---: | ---: |
| Steady flow | 0.128 [0.112–0.142] | 0.106 [0.096–0.110] |
| Mixed | 0.174 [0.172–0.208] | 0.154 [0.154–0.180] |
| Analysis heavy | 0.192 [0.190–0.202] | 0.192 [0.188–0.200] |

Peak RSS stayed approximately 8.1, 18.3, and 96.9 MiB respectively. Packet accounting reconciled without dispatch drops or worker failures. Throughput ranges were too variable for a general throughput claim; the analysis-heavy case showed essentially unchanged CPU cost.

Exact top-N selection (`133d735`, compared with `b80b2c6`) retains at most N candidates during each table scan and clones only selected full-mode keys. A focused harness populated 100,000 retained flows from the checksummed high-cardinality trace, then timed 1,000 rounds of CLI top-10 and dashboard top-10 snapshot reporting. Both APIs kept independent delta watermarks. Each storage mode used one warm-up and five measured runs with alternating binaries.

| Storage | Reporting seconds before median [range] | After median [range] | Whole-process peak RSS MiB before → after (median) |
| --- | ---: | ---: | ---: |
| Scale | 2.076 [2.061–2.229] | 0.523 [0.508–0.825] | 443.22 → 94.69 |
| Full | 4.927 [4.735–5.862] | 0.656 [0.535–0.959] | 503.12 → 152.84 |

These are repeated reporting costs, not packet replay throughput or isolated flow-storage size. The reporting timer excludes setup; process RSS includes the input buffer, table population, and allocator behavior across repeated reports. The harness, binary/workload hashes, raw readings, and candidate source snapshot are saved locally in `tmp/perf/heap-report-comparison`.

Worker batching at 32 and 64 packets was rejected because CPU changes were inconsistent across workloads and worker counts. Capping initial flow allocation reduced memory for tiny traces but increased one-million-packet burst peak RSS from 35.34 to 55.38 MiB in inline scale mode and 93.44 to 159.03 MiB in inline full mode. The original IPv4 preallocation remains. IPv6 reservation is deferred until first use, then uses the original reservation size; the IPv6 expiry/churn comparison did not establish a CPU improvement.

Default/headless export and accounting checks covered 80 combinations of storage mode, worker count, retention, and export settings. For bounded pipeline runs, random flow-to-worker hashing can change which flows survive each worker's quota across processes; those cases compare accounting, retention bounds, and lifecycle reconciliation rather than requiring identical retained flow IDs. These observations are offline measurements and do not establish Linux live-capture loss bounds. Local raw measurements and exact source snapshots are retained under ignored `tmp/perf/optimization-*`, `tmp/perf/inline-clock-5m`, and the focused comparison directories.

Final local validation passed formatting, locked offline Clippy with warnings denied, 193 default-build Rust tests, 170 headless Rust tests, both release builds, all four synthetic fixtures, and seven Python benchmark/live-classification tests. A final clean-source offline/dashboard suite passed all 72 runs across 12 scenarios, including local WebSocket delivery; its raw results are in `tmp/perf/optimization-final/offline`. Linux-only live shutdown tests were not run on macOS.

### 2026-10-08 optimization pass

This pass reduces flow bookkeeping and expiry scans, grows pooled packet buffers on demand, and collects full shutdown snapshots only for requested exports. The same checksummed one-million-packet high-cardinality trace was replayed on an Apple M4 with unlimited scale-mode flow storage and exports, stats, and dashboard disabled. Original and optimized binaries alternated within each repetition: one warm-up and seven measured runs per binary and worker count.

| Workers | Before packets/s median [range] | After packets/s median [range] | Peak RSS MiB before → after (median) |
| --- | ---: | ---: | ---: |
| 2 | 4,172,555 [4,121,598–4,231,286] | 5,400,804 [5,335,073–5,485,181] | 653.36 → 348.66 |
| 4 | 4,155,383 [4,126,331–4,404,437] | 5,473,383 [5,352,320–5,679,895] | 577.53 → 365.86 |

All frames reconciled with zero dispatch drops or worker failures. All 183 Rust tests passed, and eight comparisons across full/scale storage and four workloads produced identical retained exports and accounting. These are local offline observations; they do not establish live-capture throughput or loss bounds. Wider full-suite timing ranges remain provisional.

Baseline code is commit `99fb924`; optimized code is `dc4181c`. Use the [offline runner](#running-the-offline-suite) with `--packets 1000000` to repeat the workload. The original raw measurements, source snapshots, and comparison scripts have been removed; rerun the suite to collect evidence for a new comparison.

### Earlier measurements

The September benchmark bundles and profiling output have been removed because they included local filesystem paths. Generate fresh runs with the commands below. [Checksummed 10,000-packet smoke PCAPs and manifests](benchmarks/workloads-10k-smoke/) remain available as synthetic inputs.

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

If the saved binary has moved, add `--binary <PATH>` to the repeat command. Its SHA-256 must match the recorded binary; otherwise run a new suite.

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

The historical peak-RSS measurements above came from whole-process runs over deterministic PCAP workloads. They include parsing and the configured flow workload; they should not be read as isolated per-flow storage cost. Use high-cardinality manifests when comparing memory behavior, and retain the host and raw-run records for new measurements.
