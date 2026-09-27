# Offline benchmark report

Generated: `2026-09-26T21:33:27Z`
Source commit: `f85891b6a61f611bac90535082f75d88838d27e5`; dirty worktree: **true**; source fingerprint: `e9b97be473c65a8174fe55c5504df95b4351b8666b9646caa57c5dc476f58c4d`.
Binary SHA-256: `4f57e8b18a0eb99b0e395b12bb8a819ccd947244986bdae2ef4080de02bdd870`.
Historical source limitation: this dirty-tree run saved hashes but not a complete source snapshot, so the recorded fingerprint alone cannot reconstruct the build.
Host: macOS-27.0-arm64-arm-64bit; CPU Apple M4; 10 logical / 10 physical CPUs; memory 16,384 MiB.
Rust: `rustc 1.93.1 (01f6ddf75 2026-02-11)`; libpcap: `unavailable`; power/governor: `Now drawing from 'AC Power' -InternalBattery-0 (id=23003235) 80%; AC attached; not charging present: true`.

## Method

Command: `python3 scripts/perf/run_offline.py --output-dir docs/benchmarks/offline-20260926-first --packets 100000 --repetitions 5 --warmups 1 --workers 2,4 --dashboard --dashboard-packets 1000000 --background-load-notes 'First reproducible local baseline; no manual load audit recorded.'`.
The initial suite used 1 unreported warm-up run(s) and 5 measured repetitions per scenario. Supplemental batches, when present, are listed separately below; the results table pools all measured repetitions. NetScope was built with `cargo build --locked --release` for the initial suite; supplemental batches reuse its recorded binary.
Wall time starts immediately before launching the timed NetScope process and ends after exit; it includes PCAP open/read, processing, summary output, and shutdown. It excludes workload generation and compilation.
Throughput uses worker-processed packets (inline uses frames read) divided by wall seconds. Mbps is decimal and uses original wire bytes from the run summary. CPU is process user+system time; utilization can exceed 100% in pipeline mode. RSS is process peak resident set size.
Offline reconciliation compares generated manifest counts/bytes with NetScope's final summary and requires zero pipeline dispatch drops and worker failures. These PCAP results say nothing about packets lost before the files were created.
System load averages were [2.89794921875, 2.92529296875, 2.43408203125] at collection start and [3.15966796875, 2.9775390625, 2.45751953125] at collection end. Background-load notes: First reproducible local baseline; no manual load audit recorded.

## Results

Medians are shown with the observed min–max range. Aggregates and run metadata are in `results.json`; raw stdout, stderr, summaries, timer output, and copied configs are stored in each run directory.

| Workload | Mode | Workers | Features | Measured reps | Packets/s median [range] | Mbps median [range] | CPU % median [range] | CPU s / M packets median [range] | Peak RSS MiB median [range] | Input / processed |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| analysis-heavy | inline | — | anomalies | 5 | 2,471,653 [2,463,669–2,550,953] | 1,067.75 [1,064.30–1,102.01] | 24.72 [24.64–51.02] | 0.10 [0.10–0.20] | 30.06 [29.98–30.06] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 10 | 4,124,390 [3,423,820–4,254,149] | 1,781.74 [1,479.09–1,837.79] | 412.64 [345.81–425.41] | 1.00 [0.99–1.03] | 581.36 [564.91–658.16] | 1,000,000 / 1,000,000 |
| high-cardinality | pipeline | 4 | dashboard | 10 | 4,282,519 [3,582,606–4,444,814] | 1,850.05 [1,547.69–1,920.16] | 446.82 [379.76–453.37] | 1.04 [1.02–1.09] | 580.90 [557.81–640.80] | 1,000,000 / 1,000,000 |
| high-cardinality | inline | — | — | 10 | 2,478,983 [2,467,204–2,828,228] | 1,070.92 [1,065.83–1,221.79] | 24.79 [24.67–28.28] | 0.10 [0.10–0.10] | 26.38 [26.36–26.41] | 100,000 / 100,000 |
| high-cardinality | pipeline | 2 | — | 5 | 1,291,539 [1,289,962–1,353,549] | 557.94 [557.26–584.73] | 116.24 [116.10–121.82] | 0.90 [0.90–0.90] | 175.92 [175.33–176.33] | 100,000 / 100,000 |
| high-cardinality | pipeline | 4 | — | 5 | 1,327,128 [1,288,656–1,355,362] | 573.32 [556.70–585.52] | 154.64 [142.02–172.53] | 1.20 [1.10–1.30] | 174.45 [174.20–175.39] | 100,000 / 100,000 |
| mixed | inline | — | — | 5 | 2,467,298 [2,455,173–2,489,327] | 6,224.92 [6,194.33–6,280.50] | 24.67 [24.55–24.89] | 0.10 [0.10–0.10] | 17.22 [17.20–17.23] | 100,000 / 100,000 |
| mixed | pipeline | 2 | — | 5 | 1,309,804 [1,289,200–1,365,359] | 3,304.60 [3,252.62–3,444.76] | 136.54 [128.92–145.38] | 1.00 [1.00–1.10] | 163.02 [162.59–163.67] | 100,000 / 100,000 |
| mixed | pipeline | 4 | — | 5 | 1,351,867 [1,349,790–1,355,019] | 3,410.72 [3,405.48–3,418.67] | 202.47 [189.21–203.25] | 1.50 [1.40–1.50] | 162.61 [161.89–162.98] | 100,000 / 100,000 |
| steady-flow | inline | — | — | 5 | 5,024,452 [4,924,047–5,276,790] | 2,170.56 [2,127.19–2,279.57] | 50.24 [49.24–52.77] | 0.10 [0.10–0.10] | 7.97 [7.97–7.98] | 100,000 / 100,000 |
| steady-flow | pipeline | 2 | — | 10 | 2,481,092 [1,447,264–2,574,433] | 1,071.83 [625.22–1,112.16] | 123.99 [72.36–128.72] | 0.50 [0.40–0.50] | 138.91 [138.88–138.92] | 100,000 / 100,000 |
| steady-flow | pipeline | 4 | — | 5 | 2,484,930 [2,474,525–2,714,757] | 1,073.49 [1,068.99–1,172.78] | 123.76 [108.59–129.82] | 0.50 [0.40–0.50] | 139.38 [139.36–139.41] | 100,000 / 100,000 |

Throughput spread exceeded 10% of the median for: `high-cardinality-dashboard-control-pipeline-w4-n1000000`, `high-cardinality-dashboard-websocket-pipeline-w4-n1000000`, `high-cardinality-inline-n100000`, `steady-flow-pipeline-w2-n100000`. The pooled ranges include every measured run; treat these comparisons as provisional and do not select the fastest run.

Supplemental batches use the same saved release binary and regenerated PCAP hashes. Their warm-ups and measured repetitions are separate from the initial suite; every run remains in `results.json`.

| Repeated scenario | Warm-ups / measured reps | Repeat-batch packets/s median [range] | Repeat spread | Load average start → end |
| --- | ---: | ---: | ---: | --- |
| high-cardinality-dashboard-control-pipeline-w4-n1000000 | 1 / 5 | 4,118,294 [3,460,039–4,196,643] | 17.89% | [2.7685546875, 2.77978515625, 2.59912109375] → [3.02685546875, 2.8330078125, 2.61865234375] |
| high-cardinality-dashboard-websocket-pipeline-w4-n1000000 | 1 / 5 | 4,294,001 [4,101,458–4,444,814] | 8.00% | [2.7685546875, 2.77978515625, 2.59912109375] → [3.02685546875, 2.8330078125, 2.61865234375] |
| high-cardinality-inline-n100000 | 1 / 5 | 2,490,084 [2,470,455–2,792,939] | 12.95% | [2.7685546875, 2.77978515625, 2.59912109375] → [3.02685546875, 2.8330078125, 2.61865234375] |
| steady-flow-pipeline-w2-n100000 | 1 / 5 | 2,532,581 [2,478,010–2,570,813] | 3.66% | [2.7685546875, 2.77978515625, 2.59912109375] → [3.02685546875, 2.8330078125, 2.61865234375] |

Repeat batch `2026-09-26T21:08:07Z`: host and power state were not captured at repeat time; its load averages are shown above.

## Dashboard delivery

The dashboard scenario used a local WebSocket client and records server-to-client frame cadence, sequence gaps, and payload volume. It does not measure browser rendering FPS or frontend paint latency.

| Scenario | Frames/run median | Server frames/s median | Interval p50 | Interval p95 | Sequence gaps |
| --- | ---: | ---: | ---: | ---: | ---: |
| high-cardinality-dashboard-websocket-pipeline-w4-n1000000 | 7 | 30.94 | 32.92 ms | 33.87 ms | 0 |

The latest repeat batch still had more than 10% throughput spread for: `high-cardinality-dashboard-control-pipeline-w4-n1000000`, `high-cardinality-inline-n100000`. Those results remain provisional.

## Reproduction

The exact invocation, source fingerprint, binary hash, and per-run commands are recorded in `metadata.json` and `results.json`. The historical generator in `source-snapshot/untracked/scripts/perf/workloads.py` recreates each zero-checksum trace. Each manifest records the deterministic seed, traffic profile, SHA-256, packet count, wire bytes, and flow cardinality.

A spread over 10% of a scenario median is flagged for a quieter repeat; the report does not select the fastest repetition. See `results.json` for exact per-run spread and validation state.
