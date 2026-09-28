# Offline benchmark report

Generated: `2026-09-26T21:57:27Z`
Source commit: `f85891b6a61f611bac90535082f75d88838d27e5`; dirty worktree: **true**; source fingerprint: `f1f7310577a1e90aa36e5815f3541eb64e2df6972f6ec5e762eb2922fe9b686c`.
Binary SHA-256: `5034670c954182c4b31e5a5d92466f0a364bc418b8fd058c1397423a9930b510`.
The measured application source and published harness copies are saved in `source-snapshot/`; its `README.md` explains reconstruction, publication edits, and original versus published hashes.
Host: macOS-27.0-arm64-arm-64bit; CPU Apple M4; 10 logical / 10 physical CPUs; memory 16,384 MiB.
Rust: `rustc 1.93.1 (01f6ddf75 2026-02-11)`; libpcap: `unavailable`; power/governor: `Now drawing from 'AC Power' -InternalBattery-0 (id=23003235) 80%; AC attached; not charging present: true`.

## Method

Command: `python3 scripts/perf/run_offline.py --output-dir /Users/saad/Desktop/Main/Personal/Projects/NetScope/docs/benchmarks/offline-20260926-baseline-checksummed --packets 100000 --repetitions 5 --warmups 1 --workers 2,4 --dashboard --dashboard-packets 1000000 --background-load-notes 'Pre-optimization commit on the same Apple M4 host, with the same checksummed generator and runner; routine desktop background load.'`.
The initial suite used 1 unreported warm-up run(s) and 5 measured repetitions per scenario. Supplemental batches, when present, are listed separately below; the results table pools all measured repetitions. NetScope was built with `cargo build --locked --release` for the initial suite; supplemental batches reuse its recorded binary.
Wall time starts immediately before launching the timed NetScope process and ends after exit; it includes PCAP open/read, processing, summary output, and shutdown. It excludes workload generation and compilation.
Throughput uses worker-processed packets (inline uses frames read) divided by wall seconds. Mbps is decimal and uses original wire bytes from the run summary. CPU is process user+system time; utilization can exceed 100% in pipeline mode. RSS is process peak resident set size.
Offline reconciliation compares generated manifest counts/bytes with NetScope's final summary and requires zero pipeline dispatch drops and worker failures. These PCAP results say nothing about packets lost before the files were created.
System load averages were [3.48681640625, 3.3076171875, 2.9482421875] at collection start and [5.31005859375, 3.9375, 3.20703125] at collection end. Background-load notes: Pre-optimization commit on the same Apple M4 host, with the same checksummed generator and runner; routine desktop background load.

## Results

Medians are shown with the observed min–max range. Aggregates and run metadata are in `results.json`; raw stdout, stderr, summaries, timer output, and copied configs are stored in each run directory.

| Workload | Mode | Workers | Features | Measured reps | Packets/s median [range] | Mbps median [range] | CPU % median [range] | CPU s / M packets median [range] | Peak RSS MiB median [range] | Input / processed |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| analysis-heavy | inline | — | anomalies | 5 | 2,553,977 [2,506,760–2,699,544] | 1,103.32 [1,082.92–1,166.20] | 25.54 [25.07–27.00] | 0.10 [0.10–0.10] | 29.98 [29.91–30.06] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 10 | 4,201,263 [3,421,504–4,350,244] | 1,814.95 [1,478.09–1,879.31] | 421.89 [355.84–430.01] | 1.00 [0.97–1.04] | 590.67 [568.84–594.52] | 1,000,000 / 1,000,000 |
| high-cardinality | pipeline | 4 | dashboard | 5 | 4,312,919 [4,033,229–4,412,038] | 1,863.18 [1,742.35–1,906.00] | 445.59 [428.38–454.44] | 1.04 [1.03–1.10] | 582.08 [574.45–648.94] | 1,000,000 / 1,000,000 |
| high-cardinality | inline | — | — | 5 | 2,463,896 [2,460,928–2,472,623] | 1,064.40 [1,063.12–1,068.17] | 24.64 [24.61–24.73] | 0.10 [0.10–0.10] | 26.36 [26.34–26.38] | 100,000 / 100,000 |
| high-cardinality | pipeline | 2 | — | 5 | 1,294,230 [1,288,413–1,345,313] | 559.11 [556.59–581.18] | 116.48 [115.96–121.08] | 0.90 [0.90–0.90] | 175.70 [174.95–176.28] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 5 | 1,322,388 [1,291,487–1,353,950] | 571.27 [557.92–584.91] | 158.69 [142.06–162.47] | 1.20 [1.10–1.20] | 175.88 [174.31–177.95] | 100,000 / 100,000 |
| mixed | inline | — | — | 10 | 2,561,559 [2,456,784–2,762,679] | 6,462.74 [6,198.39–6,970.16] | 25.62 [24.57–27.63] | 0.10 [0.10–0.10] | 17.20 [17.17–17.22] | 100,000 / 100,000 |
| mixed | pipeline | 2 | — | 10 | 1,319,880 [1,290,299–1,449,431] | 3,330.02 [3,255.39–3,656.87] | 142.04 [130.63–148.86] | 1.10 [1.00–1.10] | 163.67 [163.56–164.20] | 100,000 / 100,000 |
| mixed | pipeline | 4 | — | 5 | 1,330,330 [1,291,476–1,394,305] | 3,356.39 [3,258.36–3,517.79] | 195.39 [193.72–204.32] | 1.50 [1.40–1.50] | 161.61 [161.38–161.73] | 100,000 / 100,000 |
| steady-flow | inline | — | — | 5 | 4,985,511 [4,925,057–5,046,141] | 2,153.74 [2,127.62–2,179.93] | 49.86 [49.25–50.46] | 0.10 [0.10–0.10] | 7.95 [7.91–7.98] | 100,000 / 100,000 |
| steady-flow | pipeline | 2 | — | 5 | 2,474,334 [2,465,843–2,628,484] | 1,068.91 [1,065.24–1,135.50] | 123.81 [123.60–147.95] | 0.50 [0.50–0.60] | 138.89 [138.86–138.91] | 100,000 / 100,000 |
| steady-flow | pipeline | 4 | — | 10 | 2,462,633 [1,348,512–2,484,915] | 1,063.86 [582.56–1,073.48] | 123.13 [67.43–124.25] | 0.50 [0.50–0.60] | 139.34 [139.30–139.38] | 100,000 / 100,000 |

Throughput spread exceeded 10% of the median for: `high-cardinality-dashboard-control-pipeline-w4-n1000000`, `mixed-inline-n100000`, `mixed-pipeline-w2-n100000`, `steady-flow-pipeline-w4-n100000`. The pooled ranges include every measured run; treat these comparisons as provisional and do not select the fastest run.

Supplemental batches use the same saved release binary and regenerated PCAP hashes. Their warm-ups and measured repetitions are separate from the initial suite; every run remains in `results.json`.

| Repeated scenario | Warm-ups / measured reps | Repeat-batch packets/s median [range] | Repeat spread | Load average start → end |
| --- | ---: | ---: | ---: | --- |
| high-cardinality-dashboard-control-pipeline-w4-n1000000 | 1 / 5 | 4,257,554 [4,180,842–4,350,244] | 3.98% | [4.77978515625, 3.89013671875, 3.20263671875] → [5.1279296875, 4.00927734375, 3.25634765625] |
| mixed-inline-n100000 | 1 / 5 | 2,598,705 [2,477,688–2,676,782] | 7.66% | [4.77978515625, 3.89013671875, 3.20263671875] → [5.1279296875, 4.00927734375, 3.25634765625] |
| mixed-pipeline-w2-n100000 | 1 / 5 | 1,306,268 [1,290,928–1,353,313] | 4.78% | [4.77978515625, 3.89013671875, 3.20263671875] → [5.1279296875, 4.00927734375, 3.25634765625] |
| steady-flow-pipeline-w4-n100000 | 1 / 5 | 2,474,053 [1,452,357–2,476,014] | 41.38% | [4.77978515625, 3.89013671875, 3.20263671875] → [5.1279296875, 4.00927734375, 3.25634765625] |

Repeat batch `2026-09-26T21:57:16Z`: macOS-27.0-arm64-arm-64bit; CPU Apple M4; power/governor Now drawing from 'AC Power' -InternalBattery-0 (id=23003235) 80%; AC attached; not charging present: true; background notes: Repeat of four wide-spread baseline scenarios under routine desktop load.

## Dashboard delivery

The dashboard scenario used a local WebSocket client and records server-to-client frame cadence, sequence gaps, and payload volume. It does not measure browser rendering FPS or frontend paint latency.

| Scenario | Frames/run median | Server frames/s median | Interval p50 | Interval p95 | Sequence gaps |
| --- | ---: | ---: | ---: | ---: | ---: |
| high-cardinality-dashboard-websocket-pipeline-w4-n1000000 | 7 | 29.57 | 32.95 ms | 35.32 ms | 0 |

The latest repeat batch still had more than 10% throughput spread for: `steady-flow-pipeline-w4-n100000`. Those results remain provisional.

## Reproduction

The exact invocation, source fingerprint, binary hash, and per-run commands are recorded in `metadata.json` and `results.json`. `scripts/perf/workloads.py` recreates each checksummed trace. Each manifest records the deterministic seed, traffic profile, SHA-256, packet count, wire bytes, and flow cardinality.

A spread over 10% of a scenario median is flagged for a quieter repeat; the report does not select the fastest repetition. See `results.json` for exact per-run spread and validation state.

## Publication notes

Unrelated documentation was omitted from the public source snapshot, harness diagnostic labels were normalized, and report/schema support for publication metadata was added. Historical build-directory labels were normalized in archived paths and build output. Measurement values, validation results, PCAP hashes, and original source and binary fingerprints were retained. See `source-snapshot/published-manifest.json` for hashes of the public copies.
