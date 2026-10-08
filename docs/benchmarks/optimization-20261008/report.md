# Performance pass: 2026-10-08

This pass reduces flow bookkeeping and pipeline memory overhead without changing configured analysis, flow budgets, or output formats. All measurements below use synthetic offline PCAPs on one Apple M4 host; they do not establish a live-capture rate or loss bound.

## Changes

- Canonicalize each flow tuple once and use the flow-map entry lookup for admission below capacity and in unlimited mode.
- Keep second-chance reference bits in flow entries instead of a separate per-packet hash set. Scale entries remain 64 bytes.
- Remove timed-out flows in place and construct removed-flow snapshots only when a sink consumes them. A conservative oldest-last-seen bound skips cleanup when no flow can expire; old timestamps on new flows lower the bound.
- Start pooled packet buffers at at most 2 KiB, grow them for larger captured frames, and reuse grown buffers. The capture snaplen and packet contents are preserved.
- Collect full shutdown flow snapshots only for requested JSON/CSV exports. Workers always deliver shutdown accounting.
- Replace the new-flow microbenchmark that allocated a fresh 100,000-flow table per packet with pre-parsed batches and untimed setup. Add scale, capacity-churn, and expiry cases.

## Alternating binary comparison

The headline cases were repeated with the saved original binary and final binary alternated within each repetition. Each worker count has one warm-up per binary and seven measured repetitions per binary. The same checksummed 1,000,000-packet high-cardinality trace and unlimited scale-mode configuration are used in both variants. Exports, stats, dashboard, and anomaly detection are disabled. Timing includes process startup, PCAP read, processing, summary output, and shutdown. Peak RSS is measured by macOS `/usr/bin/time -l`.

| Workers | Before packets/s median [range] | After packets/s median [range] | Median change | Before RSS MiB median [range] | After RSS MiB median [range] | RSS change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 4,172,555 [4,121,598–4,231,286] | 5,400,804 [5,335,073–5,485,181] | +29.4% | 653.36 [652.58–654.03] | 348.66 [347.58–349.41] | -46.6% |
| 4 | 4,155,383 [4,126,331–4,404,437] | 5,473,383 [5,352,320–5,679,895] | +31.7% | 577.53 [564.73–609.83] | 365.86 [363.53–373.09] | -36.7% |

Every measured and warm-up run reconciled input frames and bytes, processed every dispatched frame, and recorded zero dispatch drops and worker failures. These are local observations, not a universal speedup guarantee. The larger four-worker baseline RSS range is retained.

## Full workload coverage

The original suite covered 10 scenarios; the final suite covered the same 10 plus a dashboard/control pair. Each used one warm-up and five measured repetitions per scenario. Host load differed between these sequential suites, and several ranges exceed 10% of their median. Use the alternating comparison above for the headline throughput comparison; the full-suite table retains all results for coverage and regression inspection.

| Scenario | Before packets/s median [range] | After packets/s median [range] | Before RSS MiB | After RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| `analysis-heavy-inline-n1000000` | 5,487,727 [5,332,015–5,643,983] | 5,384,970 [5,331,971–5,585,929] | 59.94 | 60.00 |
| `high-cardinality-dashboard-control-pipeline-w4-n1000000` | — | 5,397,852 [5,337,723–5,514,165] | — | 366.17 |
| `high-cardinality-dashboard-websocket-pipeline-w4-n1000000` | — | 6,319,909 [6,078,949–6,433,192] | — | 365.33 |
| `high-cardinality-inline-n1000000` | 3,432,867 [3,383,647–3,514,036] | 3,503,589 [3,410,121–4,156,097] | 332.31 | 332.38 |
| `high-cardinality-pipeline-w2-n1000000` | 4,196,883 [4,130,227–4,344,064] | 5,484,132 [5,375,359–5,588,251] | 653.42 | 348.17 |
| `high-cardinality-pipeline-w4-n1000000` | 4,217,035 [4,121,786–4,252,923] | 5,397,526 [5,330,611–5,480,657] | 577.92 | 362.19 |
| `mixed-inline-n1000000` | 4,216,092 [4,128,509–4,247,454] | 5,333,420 [4,252,757–5,423,779] | 18.28 | 18.34 |
| `mixed-pipeline-w2-n1000000` | 2,899,591 [2,865,431–2,905,808] | 3,392,275 [2,859,594–3,500,213] | 168.20 | 35.11 |
| `mixed-pipeline-w4-n1000000` | 2,881,708 [2,865,650–2,907,813] | 3,414,591 [3,402,367–3,442,548] | 166.78 | 32.53 |
| `steady-flow-inline-n1000000` | 7,852,226 [5,532,584–8,064,242] | 7,677,202 [7,544,731–7,850,434] | 8.03 | 8.09 |
| `steady-flow-pipeline-w2-n1000000` | 4,156,951 [3,502,389–4,213,832] | 5,374,640 [4,371,346–5,485,777] | 138.95 | 25.14 |
| `steady-flow-pipeline-w4-n1000000` | 4,183,746 [3,504,854–4,254,084] | 5,342,086 [4,270,937–5,488,983] | 139.41 | 25.55 |

The final WebSocket probe received the hello message and recorded zero sequence gaps in every measured repetition. It measures server-to-local-client delivery, not browser rendering. Its roughly 0.2-second replay is too short to characterize sustained dashboard latency.

## Flow microbenchmarks

Criterion uses 30 samples, one second of warm-up, and two seconds of measurement. Values are arithmetic mean time estimates with setup and fixture parsing excluded. Insertion and churn process 1,024 observations per timed batch; churn starts with 256 flows already in a 256-slot table. Expiry cases check a 1,024-flow table. Active-table checks can now return without scanning it, so their timings are per check, not packet-processing throughput.

| Benchmark | Before time ns | After time ns | Mean time change |
| --- | ---: | ---: | ---: |
| `flow_observe/capacity_churn_full` | 115,637.93 | 97,875.62 | -15.4% |
| `flow_observe/capacity_churn_scale` | 91,536.96 | 66,221.88 | -27.7% |
| `flow_observe/existing_flow` | 29.62 | 19.35 | -34.7% |
| `flow_observe/existing_flow_scale` | 25.85 | 18.21 | -29.6% |
| `flow_observe/existing_flow_unlimited` | 20.15 | 17.95 | -10.9% |
| `flow_observe/new_flows_full` | 102,904.22 | 74,479.51 | -27.6% |
| `flow_observe/new_flows_scale` | 58,655.13 | 30,580.05 | -47.9% |
| `flow_expire/active_full` | 3,170.53 | 8.88 | -99.7% |
| `flow_expire/active_scale` | 2,857.52 | 5.84 | -99.8% |
| `flow_expire/expired_full` | 45,232.45 | 29,720.72 | -34.3% |
| `flow_expire/expired_scale` | 20,026.43 | 6,025.54 | -69.9% |

These isolated results do not directly predict PCAP replay throughput. Confidence intervals and raw Criterion samples are retained in [microbenchmarks.json](microbenchmarks.json).

## Correctness and evidence

- 183 Rust tests passed, including new IPv4/IPv6 clock, bidirectional admission, expiry-boundary, full-frame buffer reuse, and optional-export accounting checks.
- Formatting, Clippy with warnings denied across all targets, release build, fixture verification, and benchmark-generator/live-classification tests passed.
- Retained exports and flow accounting matched the original binary in eight comparisons: four generated 5,000-packet workload families, both full and scale storage, a 128-flow budget, and timeout removal disabled.
- [measurements.json](measurements.json) retains complete alternating-run records, all full-suite timing/memory observations and validation results, workload hashes, environment readings, source fingerprints, and binary hashes.
- Raw stdout, stderr, copied configs, summary JSON, source snapshots, and resource output remain locally under `tmp/perf/optimization-20261008-{baseline,final,paired,export-equivalence}`. They are ignored by Git; the compact published evidence does not include every raw log.

## Reproduction

Baseline commit: `99fb92473839839ccb3007164d802eae61d2ecbd`. Apply [source.patch](source.patch) to that commit in a separate clean checkout to reconstruct the measured candidate. Documentation added after measurement is omitted from this patch. The patch SHA-256 is `cffff0ed441a9fe0af694b6cc739cbc14e7ad79fc114ddbe64efbe9c4379a92b`.

Original binary SHA-256: `3a12bd0856eeadc25537f9e86d8133805e60eb6674d2b1ff69419bc93e44a66b`. Final binary SHA-256: `3094edc24c9758456a933e11350b33f83219ed45bc2cd48b3b61551f1fe8b268`. A rebuild may differ because of paths and environment; retain its own hash when repeating measurements.

Run the standard suites from the matching source checkout:

```sh
python3 scripts/perf/run_offline.py --output-dir tmp/perf/baseline-repeat --packets 1000000 --repetitions 5 --warmups 1 --workers 2,4
python3 scripts/perf/run_offline.py --output-dir tmp/perf/candidate-repeat --packets 1000000 --repetitions 5 --warmups 1 --workers 2,4 --dashboard --dashboard-packets 1000000
```

For the isolated before/after comparison, apply only the benchmark-file portion of `source.patch` to the baseline, then run:

```sh
cargo bench --locked --bench hot_path -- 'flow_' --warm-up-time 1 --measurement-time 2 --sample-size 30 --save-baseline before-20261008
# Apply the remaining source changes, then compare with the same fixtures:
cargo bench --locked --bench hot_path -- 'flow_' --warm-up-time 1 --measurement-time 2 --sample-size 30 --baseline before-20261008
```

The exact alternating and export-validation scripts are saved as [compare_pipeline.py](compare_pipeline.py) and [verify_flow_exports.py](verify_flow_exports.py). These are evidence snapshots, not general CLI tools: copy them to `tmp/perf/` before running, preserve the recorded baseline binary at the path they use, build the candidate at `target/release/netscope`, and choose fresh output-directory names inside the scripts.

Before the next performance pass, profile the remaining capture-to-worker path and compare default bounded flow retention as well as unlimited tables. Large-frame traffic and controlled Linux live capture still need throughput/loss measurements.
