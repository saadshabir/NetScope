# Offline benchmark report

Generated: `2026-09-26T21:33:27Z`
Source commit: `f85891b6a61f611bac90535082f75d88838d27e5`; dirty worktree: **true**; source fingerprint: `29c2dc9e5f06c74484333a75cd8d18ede5589ae5af41fab6c42d0643ae11df8c`.
Binary SHA-256: `73daa40f6fdd5563c2fb74a2163efd331062485ada8c814aeed0ce385384282f`.
Historical source limitation: this dirty-tree run saved hashes but not a complete source snapshot, so the recorded fingerprint alone cannot reconstruct the build.
Host: macOS-27.0-arm64-arm-64bit; CPU Apple M4; 10 logical / 10 physical CPUs; memory 16,384 MiB.
Rust: `rustc 1.93.1 (01f6ddf75 2026-02-11)`; libpcap: `unavailable`; power/governor: `Now drawing from 'AC Power' -InternalBattery-0 (id=23003235) 80%; AC attached; not charging present: true`.

## Method

Command: `python3 scripts/perf/run_offline.py --output-dir docs/benchmarks/offline-20260926-after --packets 100000 --repetitions 5 --warmups 1 --workers 2,4 --dashboard --dashboard-packets 1000000 --background-load-notes 'After profile-guided gating of heavy-hitter tracking; measured in a separate batch on the same host.'`.
The initial suite used 1 unreported warm-up run(s) and 5 measured repetitions per scenario. Supplemental batches, when present, are listed separately below; the results table pools all measured repetitions. NetScope was built with `cargo build --locked --release` for the initial suite; supplemental batches reuse its recorded binary.
Wall time starts immediately before launching the timed NetScope process and ends after exit; it includes PCAP open/read, processing, summary output, and shutdown. It excludes workload generation and compilation.
Throughput uses worker-processed packets (inline uses frames read) divided by wall seconds. Mbps is decimal and uses original wire bytes from the run summary. CPU is process user+system time; utilization can exceed 100% in pipeline mode. RSS is process peak resident set size.
Offline reconciliation compares generated manifest counts/bytes with NetScope's final summary and requires zero pipeline dispatch drops and worker failures. These PCAP results say nothing about packets lost before the files were created.
System load averages were [1.95849609375, 2.6064453125, 2.56298828125] at collection start and [3.59912109375, 2.96142578125, 2.69140625] at collection end. Background-load notes: After profile-guided gating of heavy-hitter tracking; measured in a separate batch on the same host.

## Results

Medians are shown with the observed min–max range. Aggregates and run metadata are in `results.json`; raw stdout, stderr, summaries, timer output, and copied configs are stored in each run directory.

| Workload | Mode | Workers | Features | Measured reps | Packets/s median [range] | Mbps median [range] | CPU % median [range] | CPU s / M packets median [range] | Peak RSS MiB median [range] | Input / processed |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| analysis-heavy | inline | — | anomalies | 5 | 2,473,286 [2,457,941–2,487,085] | 1,068.46 [1,061.83–1,074.42] | 24.73 [24.58–24.87] | 0.10 [0.10–0.10] | 30.02 [29.98–30.05] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 10 | 4,032,874 [3,406,535–4,317,963] | 1,742.20 [1,471.62–1,865.36] | 377.32 [334.31–404.39] | 0.93 [0.86–1.03] | 532.52 [510.42–591.80] | 1,000,000 / 1,000,000 |
| high-cardinality | pipeline | 4 | dashboard | 5 | 4,334,922 [4,224,005–4,429,031] | 1,872.69 [1,824.77–1,913.34] | 443.52 [438.67–450.58] | 1.03 [1.00–1.05] | 565.08 [560.19–577.31] | 1,000,000 / 1,000,000 |
| high-cardinality | inline | — | — | 10 | 3,479,836 [2,460,637–4,205,097] | 1,503.29 [1,063.00–1,816.60] | 34.80 [24.61–42.05] | 0.10 [0.10–0.10] | 26.36 [26.34–26.41] | 100,000 / 100,000 |
| high-cardinality | pipeline | 2 | — | 5 | 1,373,622 [1,290,062–1,402,089] | 593.40 [557.31–605.70] | 108.03 [96.87–112.17] | 0.80 [0.70–0.80] | 175.86 [175.41–176.42] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 5 | 1,352,880 [1,289,442–1,418,952] | 584.44 [557.04–612.99] | 162.35 [154.73–170.27] | 1.20 [1.20–1.20] | 175.00 [174.53–176.12] | 100,000 / 100,000 |
| mixed | inline | — | — | 5 | 2,484,482 [2,461,617–2,541,092] | 6,268.28 [6,210.59–6,411.10] | 24.84 [24.62–25.41] | 0.10 [0.10–0.10] | 17.22 [17.19–17.25] | 100,000 / 100,000 |
| mixed | pipeline | 2 | — | 5 | 1,351,786 [1,335,020–1,353,946] | 3,410.52 [3,368.22–3,415.97] | 148.70 [146.85–148.93] | 1.10 [1.10–1.10] | 162.88 [162.59–164.02] | 100,000 / 100,000 |
| mixed | pipeline | 4 | — | 5 | 1,351,243 [1,288,588–1,420,947] | 3,409.15 [3,251.07–3,585.01] | 198.17 [193.29–213.14] | 1.50 [1.40–1.50] | 162.23 [161.92–162.62] | 100,000 / 100,000 |
| steady-flow | inline | — | — | 5 | 4,950,230 [4,883,359–4,994,839] | 2,138.50 [2,109.61–2,157.77] | 49.50 [48.83–49.95] | 0.10 [0.10–0.10] | 7.94 [7.94–7.95] | 100,000 / 100,000 |
| steady-flow | pipeline | 2 | — | 10 | 2,421,847 [1,420,249–2,482,909] | 1,046.24 [613.55–1,072.62] | 97.22 [71.01–124.15] | 0.45 [0.40–0.50] | 138.84 [138.81–138.86] | 100,000 / 100,000 |
| steady-flow | pipeline | 4 | — | 5 | 2,478,893 [2,475,250–2,561,932] | 1,070.88 [1,069.31–1,106.75] | 99.16 [99.01–128.10] | 0.40 [0.40–0.50] | 139.28 [139.27–139.30] | 100,000 / 100,000 |

Throughput spread exceeded 10% of the median for: `high-cardinality-dashboard-control-pipeline-w4-n1000000`, `high-cardinality-inline-n100000`, `steady-flow-pipeline-w2-n100000`. The pooled ranges include every measured run; treat these comparisons as provisional and do not select the fastest run.

Supplemental batches use the same saved release binary and regenerated PCAP hashes. Their warm-ups and measured repetitions are separate from the initial suite; every run remains in `results.json`.

| Repeated scenario | Warm-ups / measured reps | Repeat-batch packets/s median [range] | Repeat spread | Load average start → end |
| --- | ---: | ---: | ---: | --- |
| high-cardinality-dashboard-control-pipeline-w4-n1000000 | 1 / 5 | 3,998,563 [3,714,774–4,041,952] | 8.18% | [2.96337890625, 3.029296875, 2.75390625] → [3.28662109375, 3.09521484375, 2.7783203125] |
| high-cardinality-inline-n100000 | 1 / 5 | 4,168,338 [4,152,680–4,205,097] | 1.26% | [2.96337890625, 3.029296875, 2.75390625] → [3.28662109375, 3.09521484375, 2.7783203125] |
| steady-flow-pipeline-w2-n100000 | 1 / 5 | 2,366,299 [2,081,768–2,457,211] | 15.87% | [2.96337890625, 3.029296875, 2.75390625] → [3.28662109375, 3.09521484375, 2.7783203125] |

Repeat batch `2026-09-26T21:12:29Z`: host and power state were not captured at repeat time; its load averages are shown above.

## Dashboard delivery

The dashboard scenario used a local WebSocket client and records server-to-client frame cadence, sequence gaps, and payload volume. It does not measure browser rendering FPS or frontend paint latency.

| Scenario | Frames/run median | Server frames/s median | Interval p50 | Interval p95 | Sequence gaps |
| --- | ---: | ---: | ---: | ---: | ---: |
| high-cardinality-dashboard-websocket-pipeline-w4-n1000000 | 7 | 30.57 | 32.95 ms | 33.08 ms | 0 |

The latest repeat batch still had more than 10% throughput spread for: `steady-flow-pipeline-w2-n100000`. Those results remain provisional.

## Reproduction

The exact invocation, source fingerprint, binary hash, and per-run commands are recorded in `metadata.json` and `results.json`. The historical generator in `source-snapshot/untracked/scripts/perf/workloads.py` recreates each zero-checksum trace. Each manifest records the deterministic seed, traffic profile, SHA-256, packet count, wire bytes, and flow cardinality.

A spread over 10% of a scenario median is flagged for a quieter repeat; the report does not select the fastest repetition. See `results.json` for exact per-run spread and validation state.
