# Offline benchmark report

Generated: `2026-09-26T21:51:03Z`
Source commit: `f85891b6a61f611bac90535082f75d88838d27e5`; dirty worktree: **true**; source fingerprint: `60d7b6ce1113d8f8760b81ddd6f690e596bc8a57c122b02fe0e5d619becb2a1d`.
Binary SHA-256: `73daa40f6fdd5563c2fb74a2163efd331062485ada8c814aeed0ce385384282f`.
The exact source inputs are saved in `source-snapshot/`; see its `README.md` for reconstruction.
Host: macOS-27.0-arm64-arm-64bit; CPU Apple M4; 10 logical / 10 physical CPUs; memory 16,384 MiB.
Rust: `rustc 1.93.1 (01f6ddf75 2026-02-11)`; libpcap: `unavailable`; power/governor: `Now drawing from 'AC Power' -InternalBattery-0 (id=23003235) 80%; AC attached; not charging present: true`.

## Method

Command: `python3 scripts/perf/run_offline.py --output-dir docs/benchmarks/offline-20260926-checksummed --packets 100000 --repetitions 5 --warmups 1 --workers 2,4 --dashboard --dashboard-packets 1000000 --background-load-notes 'Checksummed workload and complete source snapshot verification run; routine desktop background load.'`.
The initial suite used 1 unreported warm-up run(s) and 5 measured repetitions per scenario. Supplemental batches, when present, are listed separately below; the results table pools all measured repetitions. NetScope was built with `cargo build --locked --release` for the initial suite; supplemental batches reuse its recorded binary.
Wall time starts immediately before launching the timed NetScope process and ends after exit; it includes PCAP open/read, processing, summary output, and shutdown. It excludes workload generation and compilation.
Throughput uses worker-processed packets (inline uses frames read) divided by wall seconds. Mbps is decimal and uses original wire bytes from the run summary. CPU is process user+system time; utilization can exceed 100% in pipeline mode. RSS is process peak resident set size.
Offline reconciliation compares generated manifest counts/bytes with NetScope's final summary and requires zero pipeline dispatch drops and worker failures. These PCAP results say nothing about packets lost before the files were created.
System load averages were [3.3662109375, 2.86474609375, 2.64794921875] at collection start and [3.61669921875, 2.93798828125, 2.67724609375] at collection end. Background-load notes: Checksummed workload and complete source snapshot verification run; routine desktop background load.

## Results

Medians are shown with the observed min–max range. Aggregates and run metadata are in `results.json`; raw stdout, stderr, summaries, timer output, and copied configs are stored in each run directory.

| Workload | Mode | Workers | Features | Measured reps | Packets/s median [range] | Mbps median [range] | CPU % median [range] | CPU s / M packets median [range] | Peak RSS MiB median [range] | Input / processed |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| analysis-heavy | inline | — | anomalies | 5 | 2,532,570 [2,482,344–2,609,223] | 1,094.07 [1,072.37–1,127.18] | 25.84 [24.82–50.65] | 0.10 [0.10–0.20] | 30.02 [29.97–30.02] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 10 | 3,501,054 [3,403,876–4,214,808] | 1,512.46 [1,470.47–1,820.80] | 376.61 [333.83–404.62] | 1.00 [0.86–1.10] | 538.73 [513.94–560.36] | 1,000,000 / 1,000,000 |
| high-cardinality | pipeline | 4 | dashboard | 5 | 4,382,837 [4,329,435–4,486,422] | 1,893.39 [1,870.32–1,938.13] | 447.05 [437.27–450.99] | 1.02 [0.99–1.04] | 578.23 [572.22–660.66] | 1,000,000 / 1,000,000 |
| high-cardinality | inline | — | — | 10 | 2,480,917 [1,367,436–2,791,788] | 1,071.76 [590.73–1,206.05] | 25.05 [24.49–27.92] | 0.10 [0.10–0.20] | 26.36 [26.34–26.42] | 100,000 / 100,000 |
| high-cardinality | pipeline | 2 | — | 5 | 1,315,012 [1,293,467–1,348,446] | 568.09 [558.78–582.53] | 103.82 [93.04–107.88] | 0.80 [0.70–0.80] | 176.45 [174.86–176.45] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 10 | 1,336,575 [1,289,040–2,471,513] | 577.40 [556.87–1,067.69] | 157.44 [142.66–247.15] | 1.20 [1.00–1.20] | 175.66 [173.70–176.14] | 100,000 / 100,000 |
| mixed | inline | — | — | 5 | 2,476,259 [2,470,412–2,700,337] | 6,247.53 [6,232.78–6,812.87] | 24.76 [24.70–27.00] | 0.10 [0.10–0.10] | 17.20 [17.19–17.23] | 100,000 / 100,000 |
| mixed | pipeline | 2 | — | 5 | 1,294,928 [1,292,356–1,343,547] | 3,267.07 [3,260.58–3,389.73] | 142.44 [142.16–147.79] | 1.10 [1.10–1.10] | 163.53 [162.50–163.59] | 100,000 / 100,000 |
| mixed | pipeline | 4 | — | 5 | 1,302,695 [1,288,990–1,416,953] | 3,286.66 [3,252.08–3,574.93] | 182.38 [180.46–198.37] | 1.40 [1.40–1.40] | 162.00 [161.00–162.42] | 100,000 / 100,000 |
| steady-flow | inline | — | — | 10 | 4,942,453 [4,885,267–5,474,827] | 2,135.14 [2,110.44–2,365.13] | 49.42 [48.85–54.75] | 0.10 [0.10–0.10] | 7.98 [7.95–8.00] | 100,000 / 100,000 |
| steady-flow | pipeline | 2 | — | 10 | 1,423,043 [1,291,332–2,617,387] | 614.75 [557.86–1,130.71] | 81.26 [58.65–123.63] | 0.50 [0.40–0.60] | 138.86 [138.84–138.89] | 100,000 / 100,000 |
| steady-flow | pipeline | 4 | — | 5 | 2,477,765 [2,470,356–2,489,818] | 1,070.39 [1,067.19–1,075.60] | 123.87 [99.11–124.49] | 0.50 [0.40–0.50] | 139.30 [139.23–139.33] | 100,000 / 100,000 |

Throughput spread exceeded 10% of the median for: `high-cardinality-dashboard-control-pipeline-w4-n1000000`, `high-cardinality-inline-n100000`, `high-cardinality-pipeline-w4-n100000`, `steady-flow-inline-n100000`, `steady-flow-pipeline-w2-n100000`. The pooled ranges include every measured run; treat these comparisons as provisional and do not select the fastest run.

Supplemental batches use the same saved release binary and regenerated PCAP hashes. Their warm-ups and measured repetitions are separate from the initial suite; every run remains in `results.json`.

| Repeated scenario | Warm-ups / measured reps | Repeat-batch packets/s median [range] | Repeat spread | Load average start → end |
| --- | ---: | ---: | ---: | --- |
| high-cardinality-dashboard-control-pipeline-w4-n1000000 | 1 / 5 | 3,464,788 [3,403,876–3,526,925] | 3.55% | [3.50927734375, 3.04296875, 2.736328125] → [3.91748046875, 3.14111328125, 2.7744140625] |
| high-cardinality-inline-n100000 | 1 / 5 | 2,494,294 [2,448,985–2,791,788] | 13.74% | [3.50927734375, 3.04296875, 2.736328125] → [3.91748046875, 3.14111328125, 2.7744140625] |
| high-cardinality-pipeline-w4-n100000 | 1 / 5 | 1,300,013 [1,289,040–1,354,193] | 5.01% | [3.50927734375, 3.04296875, 2.736328125] → [3.91748046875, 3.14111328125, 2.7744140625] |
| steady-flow-inline-n100000 | 1 / 5 | 4,915,404 [4,885,267–5,005,892] | 2.45% | [3.50927734375, 3.04296875, 2.736328125] → [3.91748046875, 3.14111328125, 2.7744140625] |
| steady-flow-pipeline-w2-n100000 | 1 / 5 | 1,351,438 [1,291,332–1,379,796] | 6.55% | [3.50927734375, 3.04296875, 2.736328125] → [3.91748046875, 3.14111328125, 2.7744140625] |

Repeat batch `2026-09-26T21:50:55Z`: macOS-27.0-arm64-arm-64bit; CPU Apple M4; power/governor Now drawing from 'AC Power' -InternalBattery-0 (id=23003235) 80%; AC attached; not charging present: true; background notes: Repeat of five wide-spread checksummed scenarios under routine desktop load.

## Dashboard delivery

The dashboard scenario used a local WebSocket client and records server-to-client frame cadence, sequence gaps, and payload volume. It does not measure browser rendering FPS or frontend paint latency.

| Scenario | Frames/run median | Server frames/s median | Interval p50 | Interval p95 | Sequence gaps |
| --- | ---: | ---: | ---: | ---: | ---: |
| high-cardinality-dashboard-websocket-pipeline-w4-n1000000 | 6 | 27.36 | 33.01 ms | 38.17 ms | 0 |

The latest repeat batch still had more than 10% throughput spread for: `high-cardinality-inline-n100000`. Those results remain provisional.

## Reproduction

The exact invocation, source fingerprint, binary hash, and per-run commands are recorded in `metadata.json` and `results.json`. `scripts/perf/workloads.py` recreates each checksummed trace. Each manifest records the deterministic seed, traffic profile, SHA-256, packet count, wire bytes, and flow cardinality.

A spread over 10% of a scenario median is flagged for a quieter repeat; the report does not select the fastest repetition. See `results.json` for exact per-run spread and validation state.
