# NetScope streamlining plan

- **Status:** Phases 0, 1, and 2 complete. Phase 1 adds versioned run accounting, lossless offline pipeline dispatch, partial-parse classification, and a pipeline-wide flow budget. Phase 2 adds deterministic synthetic PCAP investigations and regression coverage.
- **Change type:** Focused cleanup with explicit behavior changes where current behavior is misleading.
- **Baseline inspected:** 2026-09-24, `main` at `6355f8c`.
- **Target:** A dependable Rust packet and flow investigation tool with reproducible correctness and performance evidence.
- **Consolidated record:** This plan includes the detailed Phase 0 baseline, full CLI reference, and complete change history formerly kept in separate documents.

This document is the execution plan for simplifying and strengthening NetScope. It is intentionally specific enough to turn each phase into reviewable changes. Checkboxes track work only after its acceptance checks pass; they do not indicate that a feature already works.

## Executive summary

NetScope already has a useful core, but the repository presents more surface than its evidence supports: many overlapping guides, old isolated benchmark numbers, replay scripts that cannot prove packet loss, and pipeline behavior that can silently weaken offline processing or anomaly thresholds. The cleanup should reduce the amount a maintainer must understand while making the important path easier to reproduce.

The streamlined project will do one job:

> Analyze a live capture or a supplied PCAP into trustworthy packet, flow, and narrowly defined anomaly results, while reporting exactly what it processed and how much CPU, memory, and time it used.

The first release of this cleanup should have one clear offline demo, a compact documentation set, synthetic investigation PCAPs, a measured benchmark suite, and an honest comparison with established tools. Performance tuning follows correctness and measurement. The dashboard remains an optional view of the same capture results, rather than a second product to expand independently.

## Product boundary and priorities

NetScope should make one path excellent: read a PCAP or capture live traffic, parse supported packets safely, track bidirectional flows, detect a small number of well-defined anomalies, and produce useful results with bounded resource use. Offline investigation is the reproducible default. Live capture, the dashboard, and the sharded pipeline extend that core.

Priorities, in order:

1. **Correctness and observability:** A run must finish, account for every packet it read, explain errors and drops, and produce deterministic investigation results.
2. **Reproducibility:** A clean checkout must include small example PCAPs, exact commands, expected outcomes, and repeatable benchmark inputs.
3. **Measured performance:** CPU, throughput, memory, and loss claims must come from saved runs with enough metadata to reproduce them.
4. **A focused interface:** Keep the useful capture, flow, alert, export, and dashboard workflows. Remove stale scripts, duplicate documentation, and developer-only options from the ordinary user path.
5. **Honest positioning:** Explain precisely what NetScope does relative to packet viewers, protocol analyzers, and IDS tools.

### Scope rules

- Preserve working capture, flow tracking, PCAP export, and dashboard behavior while their tests and examples are built. Remove a feature only after its usage and maintenance cost are reviewed.
- Do not add a broad protocol suite, signature engine, cloud service, or new dashboard framework as part of this effort.
- Treat SYN flood and port scan alerts as threshold-based heuristics. Document their sensitivity, false positives, and blind spots.
- Publish no new absolute speed or memory claim until the workload, machine, command, and raw results are saved.
- Make the default path work without root: `--read-pcap` with a checked-in synthetic fixture.
- Finish with five concise reader-facing pages plus this plan. Delete old pages after their useful content has one clear home; do not preserve a page merely because it already exists.

### Non-goals for this cleanup

- A general protocol dissector comparable to Wireshark/TShark.
- A signature IDS, inline prevention engine, or replacement for Zeek or Suricata.
- TCP stream reassembly, TLS decryption, encrypted ClientHello inspection, or a packet-history database.
- A remote, multi-user dashboard platform or a new frontend framework.
- Guaranteed zero loss during unrestricted live capture. The goal is to **measure and report** the loss boundary under a stated setup.
- Backward compatibility for developer-only benchmark commands or obsolete performance scripts. Any user-facing CLI/config change must appear in the [change history appendix](#change-history).
- A large cross-product test suite. The test selection rule below controls verification work.

### Test selection rule

Tests must protect an observable behavior or a concrete regression risk. Add a test when it would catch a failure that a user could encounter: lost offline packets, incorrect summary accounting, a parser accepting or crashing on malformed input, an alert firing at the wrong threshold, or inline and pipeline modes disagreeing on the same trace. Prefer a small number of end-to-end fixture checks for complete workflows and focused unit tests for boundary logic that is hard to exercise through the CLI.

Before adding any test, identify the failure it would catch and check whether an existing test can be extended. Do **not** add one test per getter, struct, configuration field, output label, or implementation branch. Do not duplicate the same assertion across every protocol and mode when those cases share the same path. Keep benchmark verification separate from correctness tests; timing thresholds do not belong in ordinary unit tests. Delete obsolete tests when their feature or assertion is removed.

## Target product contract

This is the intended externally visible behavior after the cleanup. Implementation phases below may change internal structure, but they should not quietly weaken this contract.

| Area | Retained or required behavior | Explicit boundary |
| --- | --- | --- |
| Offline input | `netscope --read-pcap <path>` works without elevated privileges; optional BPF filtering and a count limit retain their documented behavior. | The reproducibility baseline is a checked-in classic PCAP. Other formats and link types are claimed only after verification. |
| Live input | libpcap capture on a selected or default interface; BPF, snaplen, timeout, and buffer controls remain available. | Permissions and loss depend on the OS, interface, driver, and workload. |
| Parsing | Supported link, network, and transport headers are decoded with bounded reads. DNS and TLS SNI keep their narrow documented scope. | Partial decode is visible; malformed transport input is not reported as fully parsed. No stream reassembly is promised. |
| Flows | Bidirectional counters and the currently supported TCP observations; bounded storage and explicit eviction accounting. | The configured flow limit has one documented meaning across inline and pipeline modes. |
| Anomalies | SYN flood and port scan heuristics with documented windows, thresholds, cooldowns, and alert schema. | A mode cannot silently use weaker thresholds. If equivalent pipeline detection is too costly, the CLI rejects that combination rather than claiming parity. |
| Pipeline | Optional worker sharding for throughput; every offline input frame is processed or returned as a visible error. | Live queue overflow is allowed only when counted as dispatch loss. |
| Output | Human-readable final summary, versioned machine-readable summary, flow/alert exports, optional PCAP writing, optional local dashboard and metrics. | No output claims success after a write or flush failure. Web samples are not a complete capture record. |
| Performance | Reproducible offline CPU, wall time, throughput, and peak RSS; controlled live drop measurement. | Criterion numbers describe isolated functions and cannot stand in for capture throughput. |

### Run-accounting invariants

- Every run reports its source, mode, version, final status, elapsed wall time, and packet/byte totals even when the PCAP ends before a periodic stats tick.
- Offline pipeline accounting reconciles input, dispatch, worker completion, and any failure. A full bounded queue applies backpressure rather than dropping file input.
- Live kernel/libpcap, interface, and application dispatch drops remain separate. Unavailable counters are marked unavailable, never silently shown as zero.
- Final summaries are written only after workers and output sinks have drained. A failed sink or incomplete worker shutdown changes the exit status.
- Identical synthetic PCAPs and config produce the same flow and alert decisions in supported modes, aside from explicitly documented presentation ordering.

## Target implementation shape

Keep one binary and one capture/parse/flow model. The CLI offers an offline-first investigation path and optional live capture, pipeline, web, and export switches. Share packet classification and summary accounting across inline and pipeline paths to avoid two sets of definitions. Keep feature-specific work behind optional flags so the baseline capture path does not pay for dashboard or anomaly formatting when those features are off.

The capture reader owns PCAP input and live libpcap statistics. Inline processing owns its flow table and optional detector. Pipeline workers own flow shards; the capture reader uses bounded queues, and the final aggregator owns the completed run summary. A benchmark runner outside the binary measures process CPU and RSS. This is an ownership target, not a mandate to split every responsibility into a new module.

## Starting inventory and known gaps

The current repository already contains libpcap capture, classic PCAP reading, BPF filtering, Ethernet/Linux SLL/loopback/raw-IP parsing, IPv4/IPv6, TCP/UDP/ICMP, DNS decoding, packet-level TLS SNI extraction, flow tracking, two anomaly detectors, exports, Prometheus metrics, a web dashboard, and a sharded pipeline. These are implementation areas to verify, not a list of newly promised work.

| Observation | Evidence in this repository | Consequence |
| --- | --- | --- |
| `cargo fmt -- --check` passed during the planning audit. Tests could not be run locally because `ahash` was not cached and the environment could not resolve `static.crates.io`. | `Cargo.lock`, `.github/workflows/ci.yml` | Restore a real build/test baseline before changing code; do not label the project broken based on this environment failure. |
| Criterion measures isolated hot-path functions. `docs/performance.md` contains old approximate numbers without a saved machine, commit, PCAP, and raw run record. | `benches/hot_path.rs`, `docs/performance.md` | Keep microbenchmarks, but remove or qualify unsupported headline results. Add whole-program measurement. |
| Integration tests write temporary one-packet PCAPs; no sample PCAP is tracked. | `tests/offline_read_pcap.rs`, `tests/pcap_rotation.rs` | A new reviewer cannot reproduce a meaningful investigation from the checkout. |
| A fast offline file can finish before the periodic stats tick; the final summary lacks elapsed time and full processing counts. | `src/main.rs` inline and pipeline capture loops | Console stats are unsuitable as a benchmark data source. |
| Offline pipeline dispatch uses `try_send`, so a fast file reader can drop packets when a worker queue is full. | `src/main.rs` pipeline capture loop | Offline results can be incomplete even though there is no live capture pressure. |
| Pipeline anomalies are per worker, while routing hashes the canonical full flow tuple. Multiple sources attacking one destination can land on different workers. | `src/pipeline/router.rs`, `src/pipeline/worker.rs`, `docs/pipeline.md` | Current alert thresholds are not globally equivalent between inline and pipeline modes; the former destination-to-one-shard claim has been corrected in the reader guides. |
| Anomaly cleanup retains a nonempty queue for an inactive key without removing old events from that queue. | `src/analysis/anomaly.rs` | One-time sources can retain detection state longer than intended. |
| The live throughput script starts replay before capture; the combined validation script uses macOS-specific `/usr/bin/time -l`. | `scripts/perf/validate-throughput.sh`, `scripts/perf/validate.sh` | Existing scripts cannot establish reliable loss or portable resource measurements. |
| `.gitignore` contains literal Markdown fences; ignored `target/` output occupies about 6 GB locally. | `.gitignore`, local `target/` | Clean the ignore rules and generated output after a fresh build is reproducible. |

## Feature and file removal inventory

Delete a superseded path together with its code, tests, docs, config, and CI references. A replacement must pass its exit gate first; this is a removal plan, not a request to delete unverified user data.

| Area | Planned disposition | Replacement or condition |
| --- | --- | --- |
| Documentation catalogue | Merge and delete 11 superseded guides listed in Phase 7. | Five concise reader-facing pages and one investigation guide. |
| Unverifiable performance numbers | Remove the approximate results table from `docs/performance.md`. | Publish measured results with raw runs, host, commit, and PCAP hash. |
| Old perf scripts | Retire `scripts/perf/validate.sh`, `validate-throughput.sh`, `validate-web.sh`, and their two TOML profiles when the new runner and live runbook cover their jobs. | One offline runner plus one controlled live procedure; no replay-before-capture path. |
| Public synthetic-flow memory mode | Remove `--synthetic-flows` from the ordinary CLI and remove `src/memory.rs` if its only remaining use disappears. | Run scale-memory measurement from the developer benchmark harness. |
| Ignore-rule clutter | Remove literal Markdown fences, duplicate patterns, and broad patterns with no project use from `.gitignore`. | Explicit rules for `target/`, local caches, generated traces, and benchmark output. |
| Local generated output | Clean old ignored `target/` artifacts after a fresh build works. | Source, tracked fixtures, and user data remain untouched. |
| Duplicate or unused runtime surface | Audit export variants, CLI flag pairs, config keys, web TLS/auth, and direct dependencies. | Remove only a slice with a tested replacement or a clear decision in the [change history appendix](#change-history); no speculative mass deletion. |

Expected retained areas are capture, protocol parsing, flow tracking, two narrow anomaly heuristics, optional pipeline, bounded exports, a local dashboard, and metrics. The intent is fewer paths and clearer ownership, not a directory shuffle that leaves the same complexity in place.

## Delivery map and phase dependencies

The phases are ordered so later measurements depend on verified behavior. A phase is complete only when its listed evidence exists and its exit gate passes.

| Phase | Main deliverable | Depends on |
| --- | --- | --- |
| 0. Baseline | Clean-checkout build and current-behavior record | None |
| 1. Accounting and offline correctness | Stable final summary; lossless offline pipeline | Phase 0 |
| 2. Fixtures and investigations | Synthetic PCAPs, generator, expected outcomes | Phase 1 summary contract |
| 3. Protocol and anomaly hardening | Mode parity, bounded state, documented limits | Phase 2 fixtures |
| 4. Offline benchmark system | Repeatable CPU, throughput, and memory reports | Phases 1–3 |
| 5. Live loss validation | Controlled replay procedure and loss report | Phase 1 counters, Phase 4 runner conventions |
| 6. Tool comparison | Capability matrix and reproducible examples | Phases 2, 4, and 5 |
| 7. Simplification and release gate | Focused docs, scripts, CLI, and CI | Evidence from all earlier phases |

Expected file locations are guides, not mandates: `fixtures/pcap/` for small tracked traces, `scripts/fixtures/` for their generator, `examples/README.md` for investigations, `scripts/bench/` for benchmark tooling, and `docs/performance.md` plus `docs/comparison.md` for published findings. Large traces and run output belong under ignored `tmp/bench/` until a specific result is selected for publication. The exact documentation merge and deletion map is in Phase 7.

## Phase 0 — Establish the baseline

### Steps

- [x] Verify `rust-toolchain.toml`, `Cargo.lock`, libpcap headers, and the documented build command on a clean checkout. Do not depend on old binaries in `target/`.
- [x] Run the existing CI gates: `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, and `cargo build --locked --release`.
- [x] Record the command, commit, OS, toolchain, libpcap version, exit code, and any failures. Separate environment failures from source failures.
- [x] Run one temporary known PCAP through inline and pipeline modes. Save current console summaries, flow exports, alert output, and exit status as baseline observations. These are diagnostic records, not published benchmarks.
- [x] Inventory CLI flags, config keys, outputs, and documentation claims. Mark each as tested, untested, inaccurate, or internal-only. Include the `--synthetic-flows` path and all `--no-*` override pairs.
- [x] List parser and capture limitations precisely: supported link types, classic PCAP versus other capture formats, fragmentation, IPv6 extension headers, DNS scope, and packet-level TLS SNI scope.

**Deliverables:** The detailed baseline record in this plan, linked raw run outputs, and a prioritized issue list; a prioritized issue list with a reproduction for each confirmed defect. Add a regression check when the defect has a plausible recurrence and an observable expected result.

**Exit gate:** A fresh checkout builds and runs an offline trace without privileges. Any remaining baseline failures have a reproducible command and clear owner.

<a id="phase-0-baseline-evidence"></a>
### Detailed Phase 0 baseline record — 2026-09-25

**Status:** Complete. The baseline was built and run from a clean local Git clone of `main` at `eb9338b`, with an empty Git status and a fresh target directory. The executable code is unchanged from the plan's inspected baseline commit `6355f8c`; the difference between those commits is README and planning documentation.

#### Build and CI gates

Environment: macOS 27.0, Apple silicon (`arm64`), Rust `1.93.1` from `rust-toolchain.toml`, Cargo `1.93.0`, and libpcap `1.10.1`. `pcap-config` supplied the libpcap include and link flags, and a C probe against the installed headers/library returned the version above. The clean clone used `CARGO_TARGET_DIR=/tmp/netscope-phase0-20260925/checkout-target`; it did not use the repository's ignored `target/` output.

| Command | Final result | Notes |
| --- | --- | --- |
| `cargo fmt -- --check` | Pass, exit 0 | Clean local clone. |
| `cargo clippy --locked --all-targets -- -D warnings` | Pass, exit 0 | Clean local clone. |
| `cargo test --locked` | Pass, exit 0; 137 tests | 120 library, 5 binary, 8 offline-PCAP integration, and 4 rotation tests. The first sandboxed attempt had 117 pass and 3 websocket tests fail because loopback bind returned `PermissionDenied`; rerunning the same suite from the clean clone with loopback access passed all 137. This was an environment restriction, not a source failure. |
| `cargo build --locked --release` | Pass, exit 0 | Clean local clone. |

#### Offline run baseline

A temporary, synthetic classic PCAP contains two Ethernet/IPv4/TCP packets: a SYN and its SYN-ACK. It is 164 bytes, has SHA-256 `2fbe9c477444278c85282d8de0c944ced9041629432533eb7ef6a677959365f9`, and was read without elevated privileges. The exact raw terminal output, flow JSON, empty alert JSONL files, and exit codes are retained under `docs/baseline/phase-0-2026-09-25/`:

- [Inline terminal output](baseline/phase-0-2026-09-25/inline.stdout), [flow export](baseline/phase-0-2026-09-25/inline-flows.json), [alerts](baseline/phase-0-2026-09-25/inline-alerts.jsonl)
- [Pipeline terminal output](baseline/phase-0-2026-09-25/pipeline.stdout), [flow export](baseline/phase-0-2026-09-25/pipeline-flows.json), [alerts](baseline/phase-0-2026-09-25/pipeline-alerts.jsonl), [exit codes](baseline/phase-0-2026-09-25/exit-status.txt)

Commands were `netscope --read-pcap <trace> --quiet --anomalies --alerts-jsonl <alerts> --export-json <flows>` and the same command with `--pipeline --workers 2`. Both exited 0, exported one equal flow record with 2 packets and 108 wire bytes, and emitted an empty alert file. The inline summary reported 2 captured packets, 0 parse errors, and 100% success. The pipeline summary reported 2 captured packets and 0 dispatch drops. It also printed kernel and interface drops as `0`, although those counters are unavailable for offline input. Neither summary reports elapsed wall time, input bytes, or a complete parse classification.

A one-packet Ethernet PCAPNG probe also exited 0 on libpcap 1.10.1. This verifies only a minimal, single-interface Ethernet PCAPNG block; classic PCAP remains the reproducible baseline. Multi-interface PCAPNG, alternate timestamp resolutions, and other PCAPNG options were not checked.

##### Reproduce the diagnostic inputs

From the repository root, [the standard-library generator](../scripts/phase0_repros.py) recreates the temporary PCAPs and configs. Its hashes match the recorded two-packet, malformed-TCP, 10,000-frame, and 100-flow inputs. The 32-source SYN trace has SHA-256 `33da91fd9876b38273a994f6b348478260e7960028045cabe3a26cd28e7308c0`.

```sh
OUT=$(mktemp -d)
python3 scripts/phase0_repros.py "$OUT"
git clone --no-local . "$OUT/baseline"
git -C "$OUT/baseline" checkout --detach eb9338b
(cd "$OUT/baseline" && cargo build --locked --release)
BASE_BIN="$OUT/baseline/target/release/netscope"
```

The baseline binary above is necessary to reproduce the historical offline queue drops. Drop totals depend on scheduling; 2,090 was one observed run, not a fixed expected count. The remaining commands also use that binary so they describe the recorded Phase 0 behavior. Build the current working tree separately to check the Phase 1.2 correction.

```sh
"$BASE_BIN" --read-pcap "$OUT/known-two-packet.pcap" --quiet --anomalies --alerts-jsonl "$OUT/inline-alerts.jsonl" --export-json "$OUT/inline-flows.json"
"$BASE_BIN" --read-pcap "$OUT/known-two-packet.pcap" --quiet --anomalies --alerts-jsonl "$OUT/pipeline-alerts.jsonl" --export-json "$OUT/pipeline-flows.json" --pipeline --workers 2
"$BASE_BIN" --read-pcap "$OUT/backpressure-10000.pcap" --config "$OUT/capacity-1.toml" --pipeline --workers 1 --quiet
"$BASE_BIN" --read-pcap "$OUT/malformed-tcp.pcap" --quiet --export-json "$OUT/malformed-flows.json"
"$BASE_BIN" --read-pcap "$OUT/syn-flood-32-sources.pcap" --config "$OUT/syn-flood.toml" --quiet --alerts-jsonl "$OUT/syn-inline.jsonl"
"$BASE_BIN" --read-pcap "$OUT/syn-flood-32-sources.pcap" --config "$OUT/syn-flood.toml" --quiet --alerts-jsonl "$OUT/syn-pipeline.jsonl" --pipeline --workers 2
"$BASE_BIN" --read-pcap "$OUT/many-flows-spread.pcap" --quiet --max-flows 1 --flow-timeout-s 0 --export-json "$OUT/max-inline.json"
"$BASE_BIN" --read-pcap "$OUT/many-flows-spread.pcap" --quiet --max-flows 1 --flow-timeout-s 0 --export-json "$OUT/max-pipeline.json" --pipeline --workers 2
```

The malformed trace should report zero parse errors while exporting an empty flow array. The SYN trace should produce one inline alert and no pipeline alert with zero dispatch drops. The 100-flow trace should leave more than one final flow in each mode; the recorded run left 10 inline and 8 pipeline flows. A one-packet PCAPNG probe can be repeated with `"$BASE_BIN" --read-pcap "$OUT/one-packet.pcapng" --quiet`.

The stale anomaly-queue finding below comes from source inspection, not a saved runtime measurement. To inspect the failure path, follow `AnomalyDetector::observe` in `src/analysis/anomaly.rs`: add one event to a key at time 1, then observe a different key after time 31 to trigger cleanup without revisiting the first key. Both cleanup methods retain any nonempty queue without first removing its expired events. A focused state test belongs with the Phase 3.2 fix.

#### Inventory

##### CLI flags

**Tested:** `--config`, `--read-pcap`, `--count`, `--quiet`, `--write-pcap`, `--write-pcap-rotate-mb`, `--write-pcap-max-files`, `--export-json`, `--anomalies`, `--alerts-jsonl`, `--flow-timeout-s`, `--max-flows`, `--pipeline`, `--workers`, and `--help`. Coverage comes from the clean-checkout suite and the temporary baseline/reproduction runs.

**Untested in this baseline:** `--interface`, `--filter`, `--promiscuous`, `--no-promiscuous`, `--snaplen`, `--timeout-ms`, `--list-interfaces`, `--hex-dump`, `--no-hex-dump`, `--no-quiet`, `--verbose`, `--export-csv`, `--expired-flows-jsonl`, `--expired-flows-csv`, `--stats`, `--no-stats`, `--stats-interval-ms`, `--top-flows`, `--no-anomalies`, `--web`, `--no-web`, `--web-bind`, `--web-port`, `--web-tls`, `--no-web-tls`, `--web-tls-cert`, `--web-tls-key`, `--web-auth`, `--no-web-auth`, `--web-auth-user`, `--web-auth-pass-file`, and `--version`.

The tested/untested lists refer to long option names. Short aliases `-i`, `-f`, `-c`, `-p`, `-s`, `-t`, `-l`, `-v`, `-h`, and `-V` were not separately invoked.

The eight boolean override pairs are `--promiscuous`/`--no-promiscuous`, `--hex-dump`/`--no-hex-dump`, `--quiet`/`--no-quiet`, `--stats`/`--no-stats`, `--anomalies`/`--no-anomalies`, `--web`/`--no-web`, `--web-tls`/`--no-web-tls`, and `--web-auth`/`--no-web-auth`. Their mutual exclusion is declared in Clap, but their config-override behavior has no direct test in the baseline suite. Existing coverage tests clearable path overrides instead.

**Internal-only:** `--synthetic-flows <N>` is the planned developer memory-measurement path, not an ordinary user workflow. A 10-flow smoke run exited 0, but macOS reported RSS as unavailable, so no memory figure or budget result was produced. The current `docs/performance.md` wording should be qualified by platform until the replacement benchmark runner exists.

##### TOML config keys

The following keys were exercised by loading TOML during tests or reproductions:

- `[analysis] alerts_jsonl`; `[output] expired_flows_jsonl` (path clearing test).
- `[analysis.anomalies] enabled`; `[analysis.anomalies.syn_flood] enabled`, `window_secs`, `syn_threshold`, `unique_src_threshold`, `cooldown_secs`; `[analysis.anomalies.port_scan] enabled` (32-source alert reproduction).
- `[pipeline] channel_capacity` (one-slot offline stress reproduction).

All other TOML keys are **untested as TOML inputs**: `[capture] interface`, `read_pcap`, `promiscuous`, `snaplen`, `timeout_ms`, `buffer_size_mb`, `immediate_mode`, `filter`; `[run] count`; `[output] write_pcap`, `write_pcap_rotate_mb`, `write_pcap_max_files`, `export_json`, `export_csv`, `expired_flows_csv`, `hex_dump`, `quiet`; `[flow] timeout_secs`, `max_flows`; `[stats] enabled`, `interval_ms`, `top_flows`; `[analysis] rtt`, `retrans`, `out_of_order`; `[analysis.anomalies.port_scan] window_secs`, `unique_ports_threshold`, `unique_hosts_threshold`, `cooldown_secs`; `[web] enabled`, `bind`, `port`, `tick_ms`, `top_n`, `packet_buffer`, `sample_rate`, `payload_bytes`; `[web.tls] enabled`, `cert_path`, `key_path`; `[web.auth] enabled`, `username`, `password`, `password_file`; `[pipeline] enabled`, `workers`.

This is TOML-input coverage, not a claim that all corresponding code is untested: the suite has unit coverage for flow tracking, web validation/auth, parser behavior, and export serialization. It does not load every key through a single config example or verify every CLI/config precedence pair.

##### Outputs

| Output | Status |
| --- | --- |
| Final terminal summary | Tested on the two-packet trace; final run accounting is incomplete. Per-packet output was not exercised. |
| Flow JSON | Tested inline and pipeline; parsed flow records are equal. |
| Flow CSV | Serialization layout has unit tests; CLI file output was not exercised here. |
| PCAP write and rotation | Integration-tested by the clean-checkout suite. |
| Alert JSONL | Tested with an empty baseline and a positive inline SYN-flood reproduction; pipeline mismatch is recorded below. |
| Expired-flow JSONL/CSV | Path clearing and CSV serialization have unit coverage; end-to-end sink behavior was not exercised here. |
| Web health/auth/metrics/WebSocket behavior | Unit-tested; the full suite needed loopback socket access. No live capture-to-dashboard run was made. |
| Periodic stats and live kernel/interface drop counters | Untested in this run. Offline pipeline output currently displays unavailable kernel/interface counters as zero. |
| Output write/flush errors and machine-readable final summary | Not verified; the versioned final summary is not implemented yet. |

##### Reader-facing documentation claims

| Page / claim | Status | Evidence or limitation |
| --- | --- | --- |
| `README.md`: unprivileged offline PCAP path | **Tested** | Clean release binary read the synthetic trace without elevated privileges. |
| `README.md`: supported parser families and IPv4/IPv6 fragment limits | **Tested** | Parser unit tests and source inspection support the stated scope; live capture remains untested. |
| `getting-started.md`: live permissions and installation steps | **Untested** | This baseline only verifies the macOS build and offline path. |
| `usage.md`: offline read, pipeline, and export recipes | **Tested** | Offline path, both modes, JSON export, and PCAP rotation integration cases ran. Other live examples were not exercised. |
| [CLI appendix](#cli-reference): option names and rotation prerequisites | **Tested** | `--help` agrees with `src/cli.rs`; runtime validation requires `--write-pcap` and both positive rotation settings. Most option behavior remains untested as listed above. |
| `configuration.md`: defaults and complete schema | **Untested** | Field names/defaults match `src/config.rs` by inspection. Only the TOML keys listed above were exercised through config loading. |
| `pipeline.md`: same bidirectional flow maps to one shard | **Tested** | Router unit tests cover reversed flow directions and supported link types. |
| `pipeline.md`: offline input can be dropped at a full queue | **Tested on baseline; fixed in current working tree** | The 10,000-frame reproduction recorded 2,090 dispatch drops on `eb9338b`; current Phase 1.2 work switches offline input to backpressure. |
| `flow-tracking.md`: pipeline flow caps apply per shard | **Tested** | The 100-flow reproduction retained more than `max_flows = 1`; the configured cap is per worker and pruning is periodic, so burst-time memory may exceed the apparent limit. |
| `anomaly-detection.md`: per-worker thresholds and cleanup | **Corrected after baseline** | Full-flow-tuple routing does not pin all sources for a destination to one shard; stale nonempty queues survive cleanup if their keys are never revisited. The guide now states both limits. |
| `exports.md`: JSON, PCAP, and rotation outputs | **Tested** | Flow JSON and rotation integrations passed. CSV and expired-flow sinks have only partial serializer/path coverage. |
| `web-dashboard.md`: health, auth, metrics, and WebSocket behavior | **Tested at unit level** | Test suite passed with loopback access. No live capture or browser session was run. |
| `performance.md`: current benchmark table and memory check | **Untested** | The numbers lack raw environment/run records and remain microbenchmarks. On this Mac, `--synthetic-flows 10` could not report RSS or a budget result, so the memory-check wording needs qualification. |
| `development.md` and `troubleshooting.md`: developer scripts and operational recipes | **Untested** | The CI gates ran; the standalone replay and validation scripts were not run in this baseline. |

#### Parser and capture limits

- Offline input goes through libpcap. Classic PCAP passed the baseline; only a minimal one-interface Ethernet PCAPNG file was separately verified. Live capture requires the usual OS/interface permissions and was not exercised.
- The parser maps Ethernet (DLT 1), Linux cooked SLL (113), loopback NULL (0), loopback LOOP (108), and raw IP (12 and 101). Other data-link values are rejected. Existing integration tests cover Ethernet, SLL, NULL loopback, and raw-IP value 101; value 12 and LOOP capture-file dispatch were not separately exercised.
- Ethernet parsing recognizes 802.1Q and 802.1ad VLAN tags. The parsed VLAN stack stores up to 4 tags; excess tags set its truncated marker. The suite covers VLAN/QinQ parsing and stack overflow.
- IPv4 and IPv6 headers are parsed with length bounds. IPv4 and IPv6 non-initial fragments are skipped for flow tracking; there is no fragment reassembly. IPv6 walks at most 16 recognized extension headers (Hop-by-Hop, Routing, Fragment, AH, and Destination Options); ESP, No Next Header, and unrecognized next-header values stop the walk. Depth and truncated-extension cases have unit tests.
- TCP, UDP, ICMP, and ICMPv6 headers are recognized; only TCP and UDP create flows. A malformed TCP or UDP header is currently converted to `transport = None` while the overall packet parse succeeds. It can therefore be reported as a 100% successful packet even though no transport header or flow was recognized.
- DNS decoding is packet-level and limited to UDP involving port 53. It does not claim DNS-over-TCP or encrypted DNS inspection.
- TLS SNI extraction is best-effort over one TCP payload containing a ClientHello. There is no TCP stream reassembly, so split ClientHello messages may be missed; ECH can hide the real SNI. Only valid ASCII hostname values are surfaced.

#### Prioritized findings and reproductions

| Priority | Finding and reproduction | Owner / status |
| --- | --- | --- |
| P0 | **Offline pipeline can lose frames.** On baseline `eb9338b`, one run of a 10,000-frame repeated-TCP PCAP with `[pipeline] channel_capacity = 1`, `--pipeline --workers 1`, and `--quiet` exited 0 but reported 2,090 dispatch drops. Input hash: `ae572a29ff4d02214f40412cdaa1437a6020fe17ff82ea806f0a052b5360678e`. | Phase 1.2. The current working-tree change replaces offline `try_send` with bounded blocking dispatch and adds a one-slot regression test; that test's pass is recorded in the plan. |
| P1 | **Malformed transport is reported as fully parsed.** A single truncated TCP-header PCAP (hash `a05ee6e17587e68b3070e9ee7b0af6f5c7ecbe02b7446858b62a90c5ffb98add`) run with `--read-pcap <file> --quiet --export-json <flows>` exited 0, printed `Parse errors: 0` and `Success rate: 100.0%`, and exported no flow. UDP follows the same `parse_transport` error-swallowing path. | Phase 1.3. Add targeted malformed TCP/UDP classification assertions. |
| P1 | **Final summaries do not account for a run.** The two-packet trace has no elapsed time, input-byte total, transport-parse count, or worker-completion count. In offline pipeline mode, unavailable kernel/interface counters are displayed as `0`. | Phase 1.1. Define and test the versioned final summary and explicit unavailable values. |
| P1 | **Pipeline anomaly decisions differ from inline.** The generated 32-source SYN trace for one destination with `syn_threshold = 32` and `unique_src_threshold = 32` emitted one inline alert, but none with two pipeline workers and zero dispatch drops. Shard selection hashes the canonical full flow tuple, so a shared destination does not imply a shared shard. | Phase 3.2. Make mode semantics equivalent or reject unsupported pipeline/anomaly combinations. The reader guides now state this limitation. |
| P2 | **`max_flows` is a soft, per-worker bound.** A 100-flow trace spread over 10 seconds (SHA-256 `93b2b62855fbd306d5d987d0cd1e935c32fee38cf1fe62d094327af4edcb0c0c`) run with `--max-flows 1 --flow-timeout-s 0 --export-json <flows>` retained 10 inline flows and 8 across two pipeline workers. Pruning is periodic (at most once per second), and each worker gets its own configured limit. | Phase 1.3. Add skewed-shard and burst tests; document the total budget and transient overshoot. |
| P2 | **Anomaly windows can retain stale per-key queues.** Source-level repro: observe one event for each of many unique scan sources or SYN-flood destinations, then advance beyond the configured window and the 30-second cleanup interval without revisiting those keys. Cleanup removes empty queues, but stale events are only popped when the same key is observed again, so these queues remain nonempty. | Phase 3.2. Add a bounded-state test after event-time advances. The guide now states this limit. |
| P3 | **Performance evidence is not reproducible yet.** The Criterion table in `docs/performance.md` has no saved machine, commit, input hash, or raw run record; it describes isolated functions and cannot substantiate whole-program capture throughput. The synthetic RSS path also returned unavailable on this macOS host. | Phase 4 and Phase 7. Replace or qualify the headline numbers after the reproducible runner is built. |

The Phase 1.2 regression already present in the working tree covers the first finding. The remaining findings have observable expected results and are assigned to their owning phase above; this baseline does not add failing tests ahead of those fixes.

**Completion record (2026-09-25):** All Phase 0 gates passed from a clean local clone of `eb9338b`; all 137 tests passed after allowing loopback sockets for the WebSocket tests. A no-root PCAP run completed in both modes and its raw outputs are saved in [the detailed Phase 0 record below](#phase-0-baseline-evidence). Confirmed gaps, reproductions, and phase owners are included in the detailed record below. The offline pipeline-drop issue is already addressed by the existing, uncommitted Phase 1.2 change.

## Phase 1 — Make every run account for its work

### 1.1 Define final-run counters and output

- [x] Add a final summary that is emitted after worker shutdown, output flushes, and flow export. Offer a machine-readable JSON form, for example `--summary-json <PATH>`, while preserving a readable terminal summary.
- [x] Version the JSON schema. Define stable names and units for input frames, input wire bytes, packets parsed, packets with a recognized transport header, malformed or unsupported packets, worker-processed packets, flows created/expired/evicted, alerts emitted, elapsed wall seconds, and output errors.
- [x] Report dispatch, kernel/libpcap, and interface drops as separate fields. Use `null` or an explicit unavailable state for counters that an offline PCAP cannot provide; never convert “unavailable” into zero.
- [x] Count at the layer where each event occurs. Reconcile `frames_read = dispatched + dispatch_drops` in pipeline mode and `dispatched = worker_processed + worker_failures` after draining workers. State whether a packet with an unrecognized higher layer still counts as parsed at the link or network layer.
- [x] Include mode, source, worker count, effective config, and application version in the summary or its adjacent run manifest. Keep the summary cheap enough that normal use does not require the benchmark runner.
- [x] Add a compact set of boundary tests for zero packets, a short run without a stats tick, malformed or unsupported input, and pipeline shutdown. Combine cases where one fixture can verify several counters; test both modes where their behavior can differ.

### 1.2 Make offline pipeline processing lossless

- [x] Use bounded backpressure when reading an offline file. The reader may wait for worker queue space because a PCAP has already been captured and can be processed at the workers' rate.
- [x] Keep live capture nonblocking where waiting would shift loss into libpcap or the kernel. Record every dispatch failure.
- [x] Ensure shutdown and error paths drain or explicitly account for queued packets. A worker disconnect now returns a visible error; an integration regression case uses a one-packet queue and verifies the final flow export after worker shutdown.
- [x] Validate output PCAP and flow exports when live dispatch drops occur. A deterministic queue-full live-dispatch simulation verifies that the captured PCAP retains the dropped input, dispatch accounting records the drop, and the flow export contains the already-queued flow without the dropped flow.

**Progress record (2026-09-25):** Implemented blocking dispatch for offline PCAP input, kept live dispatch nonblocking with counted queue-full drops, and made worker disconnections fail visibly. The one-slot, 10,000-frame offline regression passes with zero drops; inline and pipeline runs produce identical capture PCAPs, flow exports, and packet-accounting totals. A deterministic live queue-full simulation verifies capture-PCAP and flow-export behavior across the capture/worker boundary.

### 1.3 Clarify parsing and flow limits

- [x] Stop counting a malformed TCP or UDP header as a fully successful transport parse. Keep partial link/network decode available and expose the classification.
- [x] Make `max_flows` have an honest pipeline meaning. Prefer a documented global budget divided among workers if that can be enforced without shared hot-path contention; test skewed shard distribution and explain early eviction if the budget is partitioned.
- [x] Add bounds checks and tests for truncated VLAN, IPv4/IPv6, TCP/UDP, DNS, and TLS inputs. Reuse existing parser tests; add only cases that close an identified gap.

### Phase 1 implementation details

**Final run summary**

- Added `--summary-json <PATH>` and `output.summary_json`. Schema version 1 is written after capture processing, worker shutdown, sink flushes, and flow export. The terminal summary remains available without JSON output.
- The stable top-level fields are `schema_version`, `application_version`, `status`, `run_error`, `mode`, `source`, `worker_count`, `elapsed_wall_seconds`, `effective_config`, `frames_read`, `input_wire_bytes`, `packets_parsed`, `packets_with_transport_header`, `malformed_or_unsupported_packets`, `dispatched_frames`, `dispatch_drops`, `worker_processed_frames`, `worker_failures`, `flows_created`, `flows_expired`, `flows_evicted`, `alerts_emitted`, `kernel_drops`, `interface_drops`, and `output_errors`.
- `status` is `success`, `failed`, or `interrupted`; `source` identifies either `pcap:<path>` or `interface:<name>`. `effective_config` records the effective capture, flow, analysis, stats, output, web, and pipeline settings without credentials. Its named settings include `capture` (`link_type`, `filter`, `snaplen`, `timeout_ms`, `promiscuous`, `buffer_size_mb`, `immediate_mode`), `packet_limit`, `flow_timeout_secs`, `max_flows`, `rtt_tracking`, `retransmission_tracking`, `out_of_order_tracking`, `anomaly_detection`, `anomaly_settings`, `stats`, `output`, `web`, `pipeline_enabled`, `requested_workers`, and `pipeline_channel_capacity`.
- `input_wire_bytes` sums the original wire lengths. `packets_parsed` counts frames whose link header was recognized; `packets_with_transport_header` counts recognized transport headers. A partial packet can count as parsed and also as malformed or unsupported. Pipeline counters are `null` in inline mode, and kernel/interface drop counters are `null` for offline input or when unavailable.
- Pipeline accounting reconciles `frames_read = dispatched_frames + dispatch_drops` and, after worker shutdown, `dispatched_frames = worker_processed_frames + worker_failures`. Flow lifecycle and alert counters report observed events. Output open, write, flush, and export failures are recorded in `output_errors` and make the run fail.

**Dispatch and output behavior**

- Offline PCAP input uses blocking sends to bounded worker queues, so queue pressure slows file reading instead of dropping frames. Live capture uses nonblocking sends; queue-full and disconnected sends are counted as dispatch drops.
- Worker and aggregator shutdown is attempted on capture and PCAP output error paths. Pipeline flow export uses final worker snapshots after shutdown.
- `--write-pcap` records capture-thread input before dispatch. A live frame dropped from a full worker queue remains in the output PCAP and is absent from worker-side flow tracking and its exports.

**Parsing and flow budget**

- Recognized link/network data is retained when a TCP or UDP header is malformed. The parser marks malformed transport data separately; unknown protocols are marked unsupported. Such partial packets no longer count as having a recognized transport header.
- In pipeline mode, nonzero `flow.max_flows` is a total budget split across workers, with any remainder assigned to the first workers. The actual worker count is reduced when necessary to give every shard a quota. A busy shard can evict early while another has spare quota; pruning runs at most once per second, so a burst can temporarily exceed a shard quota. Zero remains unlimited.

**Regression coverage**

- Zero-frame, malformed-transport, and output-open-error integration cases check summary values and failure status.
- `offline_pipeline_backpressures_and_processes_every_frame` uses a one-slot queue and 10,000 frames; it checks zero dispatch drops, reconciled counts, identical inline/pipeline PCAP output, and identical flow exports.
- `live_dispatch_drop_keeps_capture_pcap_and_counts_the_drop` forces a full live-dispatch queue; it checks the dropped frame remains in the capture PCAP, accounting reports the drop, and the flow export contains only the already-queued flow.
- Parser boundary coverage includes truncated VLAN, IPv4/IPv6, TCP/UDP, DNS, and TLS input. The full `cargo test --locked --offline` suite passes with loopback access for WebSocket tests.

**Existing documentation updated**

- CLI reference: added the summary option and a short behavior note; the field-level contract lives in this plan and the full flag list is in [Appendix A](#cli-reference).
- `docs/configuration.md`: documented `output.summary_json`, offline queue behavior, and the pipeline-wide `flow.max_flows` budget.
- `docs/pipeline.md`: documented live/offline dispatch, which stage the PCAP and flow exports represent, the global flow budget, and corrected shard-routing behavior.
- `docs/flow-tracking.md`: explained per-shard quotas, early eviction, and the once-per-second pruning check.
- Change history: recorded the summary output, parsing correction, pipeline flow budget, and offline backpressure changes in [Appendix B](#change-history).

**Deliverables:** Stable summary contract, corrected offline dispatch, targeted regression tests, updated CLI/config docs.

**Exit gate:** Short and large offline fixtures finish with zero dispatch drops, their counts reconcile, and inline/pipeline results represent the same input packets.

**Completion record (2026-09-25):** All Phase 1 checks and its exit gate pass. The 10,000-frame parity regression confirms equal inline/pipeline packet accounting, PCAP output, and flow export. `cargo fmt -- --check` and `cargo clippy --locked --offline --all-targets -- -D warnings` pass. `cargo test --locked --offline` passes when run with loopback access for the WebSocket tests.

## Phase 2 — Ship sample PCAPs and investigations

### 2.1 Build the fixture set

- [x] Create a deterministic, streaming PCAP generator using Python's standard library or existing Rust code. Fix the random seed, timestamps, addresses, packet ordering, and byte layout. Avoid adding a packet-crafting dependency solely for fixtures.
- [x] Commit generated **small** classic PCAP files, a generation command, a manifest with packet counts and SHA-256 hashes, and a short provenance statement confirming that traffic is synthetic.
- [x] Keep benchmark-sized traces generated on demand. Do not commit multi-gigabyte PCAPs or captures from real users.

| Proposed fixture | Required contents | Expected observation |
| --- | --- | --- |
| `normal.pcap` | TCP handshake and data, a DNS query/response, packet-level TLS ClientHello with visible SNI | Flow directions and counts, DNS fields, best-effort SNI, no anomaly alert |
| `port-scan.pcap` | One source contacting multiple distinct ports and/or hosts at fixed intervals | Exactly documented port-scan alert behavior under a fixture-specific config |
| `syn-flood.pcap` | Multiple synthetic sources sending initial SYNs to one destination/port | A SYN-flood alert in the supported modes; tests expose any sharding mismatch |
| `protocol-edges.pcap` | IPv6, VLAN/QinQ, ICMP, a truncated transport header, and a packet the parser cannot fully classify | Supported layers decoded; malformed/unsupported counters match the manifest |

The anomaly fixtures should use explicit demo thresholds in a checked-in config. Keep production defaults independent of example size so a future threshold change cannot silently invalidate the demonstration.

### 2.2 Write investigations people can follow

- [x] Put the investigations in one `examples/README.md` with short sections and direct links to the PCAPs and demo config. Avoid one Markdown file per tiny example.
- [x] Add a normal-traffic investigation: the question, exact command, relevant flow or packet fields, expected result, and what the result does **not** prove.
- [x] Add a port-scan investigation with alert JSONL output, the specific unique-port/host condition, and one benign pattern that could also trigger the heuristic.
- [x] Add a SYN-flood investigation showing source diversity, time window, cooldown, and the limitation of packet-only evidence.
- [x] Include expected result files only when they can be normalized for unstable ordering or timestamps. Keep machine assertions focused on IDs, counts, fields, and alert kinds rather than prose formatting.
- [x] Link the shortest example from the README so the first successful run takes one command after building.

### 2.3 Turn examples into regression checks

- [x] Run representative fixtures in both modes for packet accounting and flow parity. Run anomaly fixtures in both modes because sharding can change their result. Avoid a full fixture-by-mode matrix when it repeats the same processing path without a new failure risk.
- [x] Assert manifest packet count, summary reconciliation, a few essential flow fields, alert kinds and counts, and zero offline dispatch drops. Avoid snapshots of full human-readable output.
- [x] Verify generator output hashes in CI so checked-in PCAPs and source cannot drift apart.

**Deliverables:** Small tracked PCAPs, generator and manifest, three concise investigation sections in one guide, and targeted integration tests.

**Exit gate:** A new contributor can run the normal and anomaly examples from a clean checkout without root and obtain the documented results.

**Completion record (2026-09-26):** Added four deterministic fixtures (8, 16, 64, and 6 packets), a standard-library streaming generator, a manifest with hashes, counts, and expected parser results, fixture-specific anomaly thresholds, three investigations, and parser-boundary notes. The README now runs the normal fixture as its offline quickstart, and CI verifies the checked-in PCAP hashes against regenerated output. The Phase 2 integration tests pass in inline and two-worker pipeline modes, including directional flow parity; release smoke runs confirm the documented one-alert inline and two-alert pipeline results for both anomaly examples, with zero offline dispatch drops.

`python3 scripts/generate_examples.py --check`, `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo build --locked --release`, `cargo test --locked --test phase2_examples`, and `git diff --check` pass. A full `cargo test --locked` attempt ran 126 library tests: 123 passed, while three existing WebSocket tests could not bind their loopback listeners in this restricted environment (`PermissionDenied`). This environment-only failure is separate from the passing Phase 2 integration tests.

## Phase 3 — Harden protocol and anomaly behavior

### 3.1 Make the protocol matrix precise

- [ ] Document the actual decoding level for every supported protocol: header recognized, fields displayed, flow tracked, and payload inspected. Treat DNS on UDP/53 and TLS ClientHello SNI as their narrow implemented cases.
- [ ] Check Ethernet, Linux SLL, loopback, raw IP, VLAN/QinQ, IPv4 fragments, and bounded IPv6 extension walking against fixture or unit-test evidence.
- [ ] Verify flow keys and direction across retransmissions, out-of-order segments, TCP state changes, and timestamp gaps. Record which cases use packet-level inference rather than reassembly.
- [ ] Make unsupported formats and partial parsing visible in the final summary. Avoid a blanket “success rate” that hides how far a packet was decoded.

### 3.2 Bound anomaly state and establish mode semantics

- [ ] During cleanup, remove events older than each configured window even for keys that receive no new packets, then remove empty queues and expired cooldowns.
- [ ] Test state size after many unique one-time sources and after the clock advances beyond the windows. Cover out-of-order PCAP timestamps explicitly.
- [ ] Choose a single pipeline policy based on correctness and a measured cost: global detection with equivalent thresholds, or a clear restriction to inline mode. Do not silently divide thresholds by worker count or claim destination affinity from a full-flow hash.
- [ ] Make alert schema stable: timestamp, kind, source/target identifiers when available, threshold/window context, and human-readable description. Preserve compatibility deliberately if existing consumers use JSONL.
- [ ] Test threshold boundaries and cooldown rearming with a few focused cases. Exercise the demo configuration through one investigation test; avoid repeating the entire detector test set for each configuration.

**Deliverables:** Corrected anomaly state, explicit mode behavior, protocol capability matrix, focused tests, and concise material for the consolidated `docs/design.md`.

**Exit gate:** The same supported fixture produces the same alert decisions in both modes, or unsupported combinations fail clearly before processing begins. Long-running detector state stays bounded by its configured windows and active keys.

## Phase 4 — Reproducible offline benchmarks and profiling

### 4.1 Build realistic deterministic workloads

- [ ] Generate fixed-seed traces for existing-flow small packets, high-cardinality new flows, mixed packet sizes and protocols, and an analysis-heavy case with TCP tracking and anomalies enabled.
- [ ] Record packet size distribution, protocol mix, flow cardinality, timestamp spacing, PCAP hash, and expected input count in each workload manifest.
- [ ] Provide at least one short smoke workload and larger measurement workloads (for example 100,000; 1,000,000; and 5,000,000 packets). Stream generation to disk; do not hold the entire trace in memory.
- [ ] Measure inline and pipeline modes with explicit worker counts. Measure the dashboard separately; keep per-packet terminal printing and file exports off unless that output path is the workload being studied.

### 4.2 Implement the runner and result format

- [ ] Build with `cargo build --locked --release`; record the source commit and whether the worktree is dirty. Refuse a published run when the binary cannot be tied to the recorded source.
- [ ] Warm the workload consistently, then run at least five measured repetitions on the same host. Save per-run stdout, stderr, exit code, summary JSON, resource readings, command line, and config.
- [ ] Capture OS, CPU model and core count, memory, Rust version, libpcap version, relevant tool versions, power mode/governor if known, and notable background load. Record missing fields as unavailable.
- [ ] Report median and range or interquartile range. If results vary widely, repeat under a quieter setup rather than choosing the fastest run.
- [ ] Keep raw records in a documented JSON schema and generate the Markdown report from them. Results selected for publication must include raw data or an accessible artifact, not a manually typed table alone.

### 4.3 Define the metrics without ambiguity

| Metric | Definition | Important limit |
| --- | --- | --- |
| Packet throughput | Worker-processed packets divided by measured wall seconds | State whether file open and shutdown are inside the timed interval. Use one definition across runs. |
| Bit throughput | Sum of original wire lengths × 8 divided by wall seconds | Label Mbps as decimal; do not substitute captured snaplen bytes without saying so. |
| CPU time | User CPU seconds + system CPU seconds for the NetScope process and its threads | A multi-core run can use more than one CPU-second per wall second. |
| CPU utilization | CPU time ÷ wall time × 100 | Values above 100% are expected with multiple active cores. |
| CPU cost per packet | CPU seconds ÷ worker-processed packets, usually shown per million packets | Useful for comparing worker counts and feature switches. |
| Peak memory | Peak resident set size, normalized to bytes and MiB | Record OS-specific collection method; distinguish process peak from flow-table estimates. |
| Offline loss | Input-versus-processed reconciliation and dispatch drop count | A PCAP says nothing about packets lost before the file was created. |

Resource measurement should live in the runner so it does not add hot-path work to the application. Use platform-specific adapters for RSS and CPU readings, and preserve the raw operating-system output when normalization differs.

### 4.4 Optimize based on profiles

- [ ] Establish the baseline first. Profile the slowest meaningful workload, identify the actual hot function or allocation source, and change one cause at a time.
- [ ] Compare before and after on identical hashes, hardware, configs, and build settings. Keep Criterion for parser/flow/routing regression diagnosis; never use its isolated packet-per-second number as capture throughput.
- [ ] Investigate a repeated median regression greater than roughly 10% under controlled conditions, but do not make shared CI machines enforce an absolute throughput threshold.
- [ ] Check that performance changes preserve fixture results, bounded memory, and zero offline dispatch drops.

**Deliverables:** Benchmark generator, runner, manifests, raw-result schema, first reproducible report, and revised `docs/performance.md`.

**Exit gate:** Another machine can recreate each workload and report. Every published number identifies its commit, input hash, command, environment, and raw repetitions.

## Phase 5 — Measure live capture and packet loss

Live capture is a separate experiment because NIC, driver, kernel buffers, scheduling, and privileges affect its result.

### Steps

- [ ] Prefer an isolated Linux `veth` sender/receiver pair with a dedicated BPF filter and a finite replay. Document setup and teardown commands. Provide a macOS manual procedure only where equivalent isolation is practical.
- [ ] Start NetScope before replay. Wait for an explicit readiness signal rather than sleeping a fixed second. Confirm the selected interface, filter, snaplen, queue capacity, worker count, and capture buffer.
- [ ] Replay a known finite number of packets at several offered rates; use a timeout and signal-safe cleanup so a run cannot hang when packets are lost.
- [ ] Record replay tool packet count, NetScope frames read and processed, kernel/libpcap drops, interface drops, dispatch drops, wall time, CPU, RSS, and full command output.
- [ ] Repeat each rate. Identify the highest tested sustained rate with zero observed loss and the first tested rate that shows loss. Show the interval between them rather than inventing an exact maximum.
- [ ] State when replay counts and capture counts have different meanings on the selected OS or interface. Use input packet identifiers or a controlled finite trace where practical to resolve ambiguous counts.
- [ ] Replace the current replay-before-capture scripts or keep them only as explicitly labeled manual smoke checks. The new procedure must never claim a clean loss result from a run that missed startup traffic.

**Deliverables:** Repeatable setup script or runbook, raw live run records, and one clearly qualified loss/throughput report.

**Exit gate:** The published live rate and drop numbers include the trace hash, host, interface setup, replay settings, and each drop source.

## Phase 6 — Compare NetScope with ordinary inspection tools

The comparison has two parts: a capability table and optional measured workloads. Keep them separate because processing scope affects speed.

### Steps

- [ ] Compare NetScope with `tcpdump` for capture/filter/read/write workflows, TShark/Wireshark for broad decode and statistics, Zeek for connection and protocol logs, and Suricata for IDS/IPS and event output. Verify each row against the tools' current manuals.
- [ ] Describe NetScope's actual strengths: focused Rust implementation, flow tracking, simple offline example, optional live dashboard, and documented resource behavior once measured.
- [ ] Describe its limits: narrower protocol coverage, heuristic rather than signature detection, packet-level TLS SNI, no general TCP stream reassembly, and supported PCAP/link types only.
- [ ] Give exact commands for all tools against the same small sample PCAP. Compare observable outputs and setup effort, not just feature checkmarks.
- [ ] If timing tools, choose matched tasks and publish all flags, output destinations, versions, input hashes, and resource measurements. Explain where tasks still differ. Avoid a headline ranking from unlike workloads.
- [ ] Link primary documentation: [tcpdump manual](https://manpages.debian.org/trixie/tcpdump/tcpdump.8.en.html), [TShark manual](https://www.wireshark.org/docs/man-pages/tshark), [Zeek quick start](https://docs.zeek.org/en/master/quickstart.html), and [Suricata overview](https://docs.suricata.io/en/latest/what-is-suricata.html).

**Deliverables:** `docs/comparison.md`, a capability matrix, sample commands, and any clearly qualified measurements.

**Exit gate:** A reader can select the appropriate tool for packet viewing, protocol investigation, network logs, or intrusion detection without being told that NetScope replaces broader tools.

## Phase 7 — Simplify the repository and close the release gate

### 7.1 Restructure and reduce the documentation

The legacy `docs/` set has 12 feature and reference pages with repeated setup, options, caveats, and cross-links. Target **five reader-facing pages plus this execution plan**. The README is the front door; `examples/README.md` holds the three investigations. Each topic has one canonical page.

| Final location | Purpose | Migrate useful content from | Remove after migration |
| --- | --- | --- | --- |
| `README.md` | What NetScope does, one offline command, limits, and a short navigation list | Current README | Replace its long feature list and 13-row doc menu with a compact overview |
| `docs/quickstart.md` | Build, first PCAP, live permissions, a few common commands, and brief troubleshooting | `getting-started.md`, `usage.md`, `troubleshooting.md` | All three old pages |
| `docs/reference.md` | CLI/config defaults and precedence, export schemas, and concise option tables | `CLI appendix`, `configuration.md`, `exports.md` | All three old pages |
| `docs/design.md` | Pipeline, flow model, supported protocol depth, anomaly semantics, dashboard behavior, and contributor notes | `pipeline.md`, `flow-tracking.md`, `anomaly-detection.md`, `web-dashboard.md`, `development.md` | All five old pages |
| `docs/performance.md` | Benchmark method, measured results, tuning grounded in data, and live-loss method | Current `performance.md` | Replace its unsupported result table and repeated tuning prose |
| `docs/comparison.md` | Honest tool roles and exact comparison commands | New Phase 6 work | No legacy page |
| `docs/streamlining-plan.md` | Execution plan, baseline evidence, full CLI reference, and consolidated change history | This plan and the former CLI, Phase 0, and changelog documents | Retain as the single project record; do not recreate standalone CLI or changelog documents |

- [ ] Migrate only accurate, useful content. Rewrite repeated paragraphs into a table, a command example, or a short explanation; do not paste old pages together into a larger wall of text.
- [ ] Keep each reader page task-oriented: start with the answer or command, then include the minimum detail needed to use it correctly. Put exhaustive generated CLI help in `netscope --help` rather than prose copies of every flag.
- [ ] Use one canonical source for defaults and option behavior. Ensure reference tables, example config, and `--help` agree; remove duplicate default tables elsewhere.
- [ ] Replace the README's current long documentation menu with links to quickstart, examples, reference, design, performance, and comparison. Keep the plan link separate as an active-work item.
- [ ] Search all Markdown links and command references before deleting any old page. Update README, examples, CI, and remaining docs, then check that no local link points to a removed file.
- [ ] Delete the 11 superseded pages only after the new pages contain the necessary commands, caveats, and output schemas. Review the final docs list and remove placeholder pages that add no distinct value.
- [ ] At final handoff, transfer durable product guidance and measured findings to the reader-facing docs. Retain this consolidated plan as the execution and change-history record.

**Documentation exit gate:** A reader can find the first runnable example in the README, answer a usage question from quickstart/reference, and understand the main tradeoffs from design/performance without following a chain of near-duplicate pages.

### 7.2 Remove other clutter with evidence

- [ ] Remove literal Markdown fences and duplicate patterns from `.gitignore`. Ignore generated benchmark output and temporary traces while allowing intentional tracked sample PCAPs.
- [ ] Replace stale or overlapping `scripts/perf/` entry points once the new runner and live runbook cover their workflows. Delete scripts that no longer have a tested purpose.
- [ ] Remove unsupported old benchmark numbers from `docs/performance.md`. Preserve a historical result only if its raw data, environment, and command can be recovered and labeled.
- [ ] Remove `--synthetic-flows` from the ordinary CLI after the benchmark harness provides its replacement. Remove `src/memory.rs` if its remaining code is no longer used.
- [ ] Audit unused dependencies, exports, config keys, and code paths with compiler and search evidence before removing them. Keep Chart.js licensing intact while the dashboard uses its vendored asset.
- [ ] Clean ignored local build artifacts after the dependency/build path is verified. Do not delete tracked sample data or uncommitted user work as part of disk cleanup.

### 7.3 Make CI reflect the product

- [ ] Run format, Clippy, unit and integration tests, release build, fixture hash verification, and nonprivileged offline smoke examples in CI.
- [ ] Reuse the targeted fixture tests for inline/pipeline reconciliation, anomaly mode policy, and malformed input classifications. Add CI checks only for behavior that can regress independently.
- [ ] Keep long performance and privileged live-replay jobs outside ordinary PR gates. Publish their results with machine metadata when they run.
- [ ] Verify docs commands from a clean checkout, including exact relative paths and permissions. Check that the README, CLI help, and config reference agree.

### 7.4 Final review checklist

- [ ] No generated large trace or benchmark cache is tracked accidentally.
- [ ] Every public speed, memory, and loss number has raw evidence and caveats.
- [ ] Sample PCAPs contain synthetic data only and regenerate to their manifest hashes.
- [ ] Offline examples work without root; live examples state required privileges.
- [ ] Exit codes and summaries expose partial processing and output failures.
- [ ] `docs/` contains five reader pages plus this consolidated plan; superseded standalone pages and their links are gone.
- [ ] The final diff removes more confusion than it adds, and each retained feature has a tested path.

**Deliverables:** Focused README/docs, cleaned scripts and ignore rules, final CI workflow, an updated change-history appendix, and a reviewed plan-to-outcome crosswalk.

**Exit gate:** A clean checkout passes CI, the sample investigations reproduce, and the performance and comparison pages cite concrete evidence.

## Migration and breaking changes

The cleanup should avoid gratuitous user-facing churn, but it should not keep a misleading compatibility path. Record every actual CLI, config, output-schema, and documentation-path change in the [change history appendix](#change-history).

- `--synthetic-flows` is a developer measurement path scheduled to leave the normal CLI after its replacement exists. Benchmark scripts that call it must migrate to the new runner.
- If `--summary-json` is added, version its schema from the first release. Existing human-readable output remains for people, but scripts should consume JSON rather than scrape prose.
- If pipeline anomaly detection cannot meet the target semantics, reject `--pipeline --anomalies` with a clear message and document the inline command. Do not keep the weaker per-shard interpretation under the same flag combination.
- Consolidated docs replace 11 legacy paths. Update all repository links and commands before deletion; list moved topics in the [change history appendix](#change-history). Avoid maintaining 11 redirect stubs just to preserve the old catalogue.
- Existing user PCAPs, flow exports, and alert files are data. The cleanup does not delete or rewrite them. A changed export schema needs a version note and a sample record.
- Existing `target/` binaries and `tmp/` results are generated local artifacts. Cleaning them is separate from source removal and occurs only after the build and benchmark paths work.

## Risks and mitigations

| Risk | Mitigation and evidence |
| --- | --- |
| Missing local crate cache blocks build verification | Restore dependency access, run locked commands from a clean checkout, and record environment errors separately from source failures. |
| Offline backpressure stalls shutdown or deadlocks a full queue | Use bounded shutdown and worker-drain semantics; verify with one deliberately tiny queue and a finite PCAP. |
| Pipeline throughput improves while packet or flow results change | Reconcile counters and compare essential flow/alert results on fixed PCAP hashes before accepting a speedup. |
| Global anomaly semantics reduce pipeline throughput | Measure the cost. If it is material, make anomaly detection an explicit inline workflow rather than silently weakening thresholds. |
| Parser refactoring changes partial-decode behavior | Define decode levels in the summary and use malformed/truncated fixtures to check the user-visible classification. |
| A benchmark rewards only one synthetic packet shape | Use multiple packet sizes, protocol mixes, and flow cardinalities; publish workload manifests and hashes. |
| CPU or RSS results differ by platform | Save raw platform readings, normalize units carefully, and compare within a controlled host before making a regression claim. |
| Live replay counts are mistaken for a complete loss explanation | Start capture first, use finite traffic, report each drop counter separately, and explain OS/interface count semantics. |
| Documentation consolidation hides an important caveat | Inventory each old page, migrate only still-true requirements, verify links and example commands, then delete the old page. |
| Broad cleanup deletes useful data or licensed assets | Limit deletion to listed source/doc paths and generated repository-local output; keep tracked fixture provenance and Chart.js license while the dashboard uses it. |

## Decisions to make from evidence

These decisions are deliberately scheduled after the relevant measurements or tests. They are not reasons to postpone earlier work.

| Decision | Evidence required | Default direction |
| --- | --- | --- |
| Pipeline anomaly implementation | Inline/pipeline fixture parity and CPU cost of global detection | Prefer equivalent global semantics; otherwise restrict the unsupported combination clearly. |
| Inline versus pipeline default | Whole-program throughput, CPU per packet, peak RSS, and drop behavior on multiple workloads | Keep inline as the simpler default until pipeline shows a repeatable benefit. |
| Flow cap behavior | Skewed-shard tests and memory measurements | Expose a total bounded budget with documented partition behavior. |
| Dashboard and remote TLS/auth surface | Tested user workflow, maintenance cost, dependency impact, and security of the remaining bind options | Preserve the local dashboard while it is useful; simplify only with a tested replacement path. |
| Export format variants | Example use, integration coverage, and maintenance cost | Keep formats that serve a distinct workflow; consolidate redundant paths. |
| Protocol additions | A concrete investigation blocked by the missing protocol, plus parser/test cost | Add one scoped protocol at a time; avoid breadth for its own sake. |

## Fixed assumptions

- Keep one Rust binary and the existing flag-based CLI shape; do not introduce a command framework or companion service for this cleanup.
- Inline processing stays the default. Pipeline mode remains opt-in until whole-program measurements justify changing that default.
- Offline PCAP analysis is the first-run demo and the basis for repeatable correctness and CPU/memory measurements.
- The dashboard stays local by default and remains optional; captured packet samples are sensitive data.
- Small checked-in traces are synthetic. Large benchmark traces are generated from saved seeds and manifests.
- Live throughput and loss claims are environment-specific. They never substitute for offline correctness.
- Do not rewrite Git history or delete captures, exports, or other user data outside generated repository-local paths.

## Final acceptance checklist

### Product behavior

- [ ] A clean checkout builds and runs a checked-in PCAP without root.
- [ ] Normal, port-scan, and SYN-flood investigations produce the documented results.
- [ ] Offline input, dispatch, processing, parsing, flows, and alerts reconcile in the final summary; offline dispatch loss is zero.
- [ ] Live kernel/interface/dispatch drops are distinct, and unavailable counters are labeled unavailable.
- [ ] Anomaly thresholds have clear semantics in every supported mode; unsupported flag combinations fail before capture.
- [ ] Malformed and partially decoded packets are classified honestly; no parser panic or unbounded allocation is known on the curated malformed cases.

### Evidence

- [ ] CPU, packet/bit throughput, peak RSS, and controlled live loss have raw results, hashes, commands, and environment records.
- [ ] Criterion results are labeled as isolated measurements, and the performance page has no unexplained speed claim.
- [ ] The comparison with `tcpdump`, TShark/Wireshark, Zeek, and Suricata reflects each tool's actual role and tested command.
- [ ] A changed implementation is accepted only after its focused correctness check and before/after benchmark agree with the stated goal.

### Repository quality

- [ ] README, five final reader pages, CLI help, example config, and actual behavior agree; superseded docs and their internal links are gone.
- [ ] Old perf scripts, developer-only CLI paths, unsupported numbers, and generated clutter have been removed or replaced according to the inventory.
- [ ] Ordinary CI runs only the useful nonprivileged checks; long performance and live replay evidence is recorded separately.
- [ ] The change-history appendix lists behavior changes, removals, and evidence. A plan-to-outcome crosswalk confirms every accepted phase gate.

The final handoff should state what changed, the exact verification commands that passed, the measured results and their limits, and any remaining risks. No numeric target will be invented to manufacture a pass; the first measured baseline establishes the starting point for future improvement.

<a id="cli-reference"></a>
## Appendix A — CLI reference

This is the complete flag reference formerly maintained in `docs/cli-reference.md`. The configuration schema remains in [Configuration](configuration.md).

```
Usage: netscope [OPTIONS]
```

This section lists CLI flags only. Some runtime tuning knobs are config-file only; see [Configuration](configuration.md) for the full schema.

Defaults below refer to the compiled defaults before any `--config` file is loaded. If a config file is present, explicitly provided CLI flags still take precedence.

For boolean flags, the "Default" column describes the resulting default behavior, not that the flag is implicitly passed on the command line.

### Capture Options

| Flag                  | Short | Type   | Default | Description                                                                                      |
| --------------------- | ----- | ------ | ------- | ------------------------------------------------------------------------------------------------ |
| `--interface <IFACE>` | `-i`  | string | (auto)  | Network interface to capture on (e.g., `en0`, `eth0`). If omitted, the system default is used.   |
| `--read-pcap <PATH>`  |       | path   | (none)  | Read packets from an offline pcap file. Conflicts with `--interface` and promiscuous mode flags. |
| `--filter <EXPR>`     | `-f`  | string | (none)  | BPF filter expression (e.g., `"tcp port 80"`, `"host 192.168.1.1"`).                             |
| `--count <N>`         | `-c`  | int    | 0       | Maximum packets to process. 0 = unlimited (live: Ctrl-C; offline: EOF).                          |
| `--promiscuous`       | `-p`  | flag   | on      | Capture in promiscuous mode.                                                                     |
| `--no-promiscuous`    |       | flag   |         | Disable promiscuous mode.                                                                        |
| `--snaplen <N>`       | `-s`  | int    | 65535   | Maximum bytes captured per packet.                                                               |
| `--timeout-ms <MS>`   | `-t`  | int    | 100     | Read timeout in milliseconds for the pcap handle.                                                |
| `--list-interfaces`   | `-l`  | flag   |         | List available network interfaces and exit.                                                      |

libpcap buffer sizing and immediate mode are configured through the `[capture]` section of the config file.

### Output Options

| Flag                           | Short | Type  | Default | Description                                                                                                         |
| ------------------------------ | ----- | ----- | ------- | ------------------------------------------------------------------------------------------------------------------- |
| `--hex-dump`                   |       | flag  | off     | Show detailed per-packet output with a hex-dump preview.                                                            |
| `--no-hex-dump`                |       | flag  |         | Disable hex dump output.                                                                                            |
| `--quiet`                      |       | flag  | off     | Suppress per-packet terminal output. Useful for stats-only or web-only runs.                                        |
| `--no-quiet`                   |       | flag  |         | Re-enable per-packet output (overrides config file).                                                                |
| `--verbose`                    | `-v`  | count | 0       | Increase verbosity. `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE.                                                     |
| `--write-pcap <PATH>`          |       | path  | (none)  | Write captured packets to a pcap file.                                                                              |
| `--write-pcap-rotate-mb <MB>`  |       | int   | 0       | Rotate pcap output when a segment reaches this many MiB. Requires `--write-pcap` + `--write-pcap-max-files`.        |
| `--write-pcap-max-files <N>`   |       | int   | 0       | Keep only the newest `N` rotated pcap segments (delete oldest). Requires `--write-pcap` + `--write-pcap-rotate-mb`. |
| `--export-json <PATH>`         |       | path  | (none)  | Export the flow table to JSON on exit.                                                                              |
| `--export-csv <PATH>`          |       | path  | (none)  | Export the flow table to CSV on exit.                                                                               |
| `--summary-json <PATH>`        |       | path  | (none)  | Write versioned final run accounting as JSON after workers and outputs finish.                                      |
| `--expired-flows-jsonl <PATH>` |       | path  | (none)  | Write expired/evicted flow records as JSON lines (inline and pipeline modes).                                       |
| `--expired-flows-csv <PATH>`   |       | path  | (none)  | Write expired/evicted flow records as streaming CSV (inline and pipeline modes).                                    |

When rotation is enabled, `--write-pcap` is treated as a base template and NetScope writes numbered segments like `capture.000001.pcap`, `capture.000002.pcap`, and so on (the unsuffixed `capture.pcap` file is not created).

The `--summary-json` file uses schema version 1 and records final packet, pipeline, flow, alert, drop, timing, and output-error accounting. Pipeline-only counters are `null` in inline mode; live kernel/interface counters are `null` for offline input or when unavailable. Malformed transport headers can be partially parsed and counted in `malformed_or_unsupported_packets`. Output errors make the command exit unsuccessfully. The full Phase 1 field contract is in [Phase 1 implementation details](#phase-1-implementation-details).

Note: verbosity level `-vv` or higher also enables detailed per-packet output even if `--hex-dump` is not set.

### Stats Options

| Flag                       | Type | Default | Description                                                       |
| -------------------------- | ---- | ------- | ----------------------------------------------------------------- |
| `--stats`                  | flag | off     | Enable periodic throughput stats printed to stdout.               |
| `--no-stats`               | flag |         | Disable periodic stats.                                           |
| `--stats-interval-ms <MS>` | int  | 1000    | How often to print stats (milliseconds).                          |
| `--top-flows <N>`          | int  | 0       | Number of top flows (by bandwidth delta) to show each stats tick. |

### Flow Options

| Flag                      | Type  | Default | Description                                                                                            |
| ------------------------- | ----- | ------- | ------------------------------------------------------------------------------------------------------ |
| `--flow-timeout-s <SECS>` | float | 60.0    | Flow inactivity timeout in seconds. Flows with no traffic for this long are expired. 0 = never expire. |
| `--max-flows <N>`         | int   | 100000  | Maximum number of tracked flows. When exceeded, the oldest flows are evicted. 0 = unlimited.           |

### Anomaly Detection

| Flag                    | Type | Default | Description                                                               |
| ----------------------- | ---- | ------- | ------------------------------------------------------------------------- |
| `--anomalies`           | flag | off     | Enable anomaly detection (SYN flood, port scan).                          |
| `--no-anomalies`        | flag |         | Disable anomaly detection.                                                |
| `--alerts-jsonl <PATH>` | path | (none)  | Write anomaly alerts as JSON lines to a file (inline and pipeline modes). |

See [Anomaly Detection](anomaly-detection.md) for threshold configuration (requires a config file).

### Web Dashboard

| Flag                          | Type   | Default     | Description                                |
| ----------------------------- | ------ | ----------- | ------------------------------------------ |
| `--web`                       | flag   | off         | Enable the web dashboard.                  |
| `--no-web`                    | flag   |             | Disable the web dashboard.                 |
| `--web-bind <ADDR>`           | string | `127.0.0.1` | HTTP server bind address.                  |
| `--web-port <PORT>`           | int    | 8080        | HTTP server port.                          |
| `--web-tls`                   | flag   | off         | Enable HTTPS for the web dashboard.        |
| `--no-web-tls`                | flag   |             | Disable HTTPS for the web dashboard.       |
| `--web-tls-cert <PATH>`       | path   | (none)      | PEM certificate path for HTTPS serving.    |
| `--web-tls-key <PATH>`        | path   | (none)      | PEM private key path for HTTPS serving.    |
| `--web-auth`                  | flag   | off         | Enable HTTP Basic auth for the dashboard.  |
| `--no-web-auth`               | flag   |             | Disable HTTP Basic auth for the dashboard. |
| `--web-auth-user <USER>`      | string | (none)      | Username for HTTP Basic auth.              |
| `--web-auth-pass-file <PATH>` | path   | (none)      | File containing HTTP Basic auth password.  |

Tick cadence, packet sampling, packet-buffer sizing, payload truncation, and richer auth/TLS defaults can be configured through the `[web]`, `[web.tls]`, and `[web.auth]` sections.

See [Web Dashboard](web-dashboard.md) for full details.

### Pipeline Options

| Flag            | Type | Default | Description                                                                                                                                                       |
| --------------- | ---- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--pipeline`    | flag | off     | Enable the sharded pipeline for multi-core packet processing.                                                                                                     |
| `--workers <N>` | int  | 0       | Number of pipeline worker threads. 0 = auto-detect (half of CPU count, clamped to 1..8). Setting `--workers` to a non-zero value implicitly enables `--pipeline`. |

Queue sizing (`pipeline.channel_capacity`) is configured through the config file.

See [Sharded Pipeline](pipeline.md) for architecture and tuning details.

### General

| Flag                    | Short | Description                                                                                                   |
| ----------------------- | ----- | ------------------------------------------------------------------------------------------------------------- |
| `--config <PATH>`       |       | Load a TOML configuration file. CLI flags override config values.                                             |
| `--synthetic-flows <N>` |       | Insert `N` synthetic scale-mode flows and print memory stats, then exit. Useful for memory-budget validation. |
| `--help`                | `-h`  | Print help text.                                                                                              |
| `--version`             | `-V`  | Print version.                                                                                                |

### Boolean Flag Pairs

Several options come in `--flag` / `--no-flag` pairs. This lets you override config file values in either direction from the CLI:

```bash
# Config file has quiet = true, but you want per-packet output this time:
sudo netscope --config my.toml --no-quiet

# Config file has promiscuous = true, but you want to disable it:
sudo netscope --config my.toml --no-promiscuous
```

Each pair is mutually exclusive -- specifying both `--flag` and `--no-flag` is an error.

<a id="change-history"></a>
## Appendix B — Change history

This appendix preserves the complete release history formerly kept in `CHANGELOG.md`. New behavior, compatibility, and documentation changes belong here so the project has one consolidated plan and change record.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

### [Unreleased]

#### Added

- Four deterministic synthetic classic PCAP fixtures and a shared investigation guide covering normal traffic, the anomaly heuristics, and parser boundaries.
- A standard-library fixture generator, a manifest with packet counts, wire bytes, hashes, and expected parser results, and a CI check to keep checked-in example traces synchronized with their source.
- Targeted offline integration coverage for fixture accounting, inline/pipeline flow parity, decoded DNS/TLS fields, anomaly alert counts, and parser classification.
- `--summary-json <PATH>` and `output.summary_json` for versioned final packet, flow, alert, drop, timing, and output-error accounting.
- `--read-pcap <PATH>` and `capture.read_pcap` to analyze offline pcaps (supports BPF filters and can be paired with `--write-pcap` to rewrite pcaps).
- Size-based rotation with bounded retention for pcap output (`--write-pcap`) via `--write-pcap-rotate-mb` / `--write-pcap-max-files` (and matching `[output]` config keys).
- `--expired-flows-jsonl <PATH>` to continuously write expired/evicted flow records as JSONL during capture (includes `reason = timeout | eviction`).
- `--expired-flows-csv <PATH>` to continuously write expired/evicted flow records as streaming CSV during capture (and matching `output.expired_flows_csv`).
- Prometheus-compatible metrics endpoint at `/metrics` on the web dashboard server (shares web TLS/auth settings).
- Live kernel/libpcap drop and interface drop deltas/totals in periodic stats ticks and the web dashboard.
- DNS (UDP/53) decoding in CLI packet views and the web packet inspector.
- TLS ClientHello SNI extraction in CLI packet views and the web packet inspector (best-effort, packet-level; no TCP reassembly; ECH can hide SNI).
- ICMPv6 parsing in CLI packet views and the web packet inspector.
- ARP parsing in CLI packet views and the web packet inspector.
- QinQ (802.1ad) stacked VLAN support (TPID `0x88A8`) for double-tagged frames in CLI and web packet details.
- Vendored Chart.js for the embedded web dashboard so charts render in offline/airgapped environments (no CDN runtime dependency).
- Web dashboard hardening: optional HTTPS (`web.tls.*` / `--web-tls`) and HTTP Basic auth (`web.auth.*` / `--web-auth`).
- Non-Ethernet packet parsing for Linux cooked capture (SLL), loopback NULL/LOOP, and raw IP datalink captures.
- Development: pinned Rust toolchain via `rust-toolchain.toml` and added CI checks for formatting, clippy, and tests.

#### Fixed

- Malformed TCP/UDP transport headers retain partial link/network decoding and are counted as malformed instead of fully successful packets.
- Avoid duplicate DNS parsing when building web packet summaries + details.
- `--alerts-jsonl` now works in pipeline mode (single-writer JSONL output owned by the aggregator).
- `--list-interfaces` no longer depends on successfully loading a config file.
- Web packet detail lookups are resilient to out-of-order `PacketStored` events in pipeline mode.
- Pipeline aggregator waits for all shard shutdown snapshots before exiting (prevents incomplete exports on Ctrl-C).
- Pipeline aggregator stores final snapshots by shard id and replaces duplicate shutdown snapshots deterministically.
- Web ingest flushes buffered packet samples/alerts on shutdown to avoid dropping the final partial interval.
- Static file handler returns 404 for unknown `/api/*` paths instead of serving the SPA fallback.
- IPv6 shard routing walks common extension headers so flows consistently hash to the same shard.
- Shard routing now honors non-Ethernet datalink offsets (SLL, loopback, raw IP) so flow hashing remains stable in pipeline mode.
- Pipeline capture now always shuts down worker/aggregator threads before returning, including pcap write/flush error paths.
- Pipeline errors now preserve the aggregator's output failure when worker dispatch also reports a disconnect.
- IPv6 non-initial fragments are no longer treated as transport-bearing packets for flow/anomaly tracking and shard port hashing.
- Compact flow keys no longer silently accept unexpected IP protocol numbers (logs a one-time warning and defaults to TCP; debug builds assert).

#### Changed

- Pipeline `flow.max_flows` is now divided across shards; actual worker count is reduced when needed to keep the configured total budget.
- Offline pipeline processing now waits for worker queue space instead of dropping frames; live capture remains nonblocking and counts dispatch drops.
- Clarified configuration fields and streamlined CLI documentation examples.
- Documentation now includes `/metrics` scrape examples and notes that it shares the web dashboard TLS/auth settings.
- Restored technical limitations and prerequisites to project documentation.
- Refined tuning guides regarding web dashboard performance and memory optimization.
- Pcap output now flushes periodically and on shutdown; flush failures abort capture instead of silently continuing.
- IPv6 parsing now walks common extension headers to expose the effective transport protocol and payload offset.
- IPv6 extension-header walk depth increased (bounded) to cover deeper valid chains.
- Packet detail store now uses fixed-size O(1) slot storage keyed by packet id modulo capacity, with stale-id rejection outside the active window.
- Local perf validation is now captured via `scripts/perf/validate.sh` (release build + representative benchmark + CLI synthetic-flow memory validation).
- Internal refactors to improve maintainability (flow module split, shared output sinks, shared packet formatting helpers).
- Flow CSV export avoids per-row string allocations by writing fields directly.
- Perf helper scripts print `tcpreplay` install hints and removed stale accepted-baseline text.

#### Removed

- Removed low-signal and perf/size guard tests (including the ignored 1M-flow RSS budget test and layout size assertions).

### [0.2.0] - 2026-03-15

#### Added

- Criterion benchmark `handshake_sequence` for TCP 3-way handshake hot path measurement
- Dashboard usability and performance improvements
- Synthetic memory benchmark and scale-mode regression fixes
- Phase 4 scale-mode storage with compact IPv4/IPv6 flow tables
- Frame sequencing, rAF rendering with performance overlay, and streaming heavy-hitters with exact deltas
- PCap configuration knobs, buffer pool, drop statistics, and aggregator deadline
- Pre-sized flow table allocation based on `flow.max_flows` to reduce hash map resizes
- RTT optimization removing per-call heap allocation by streaming samples from ACK handling
- Comprehensive documentation updates and .gitignore improvements

#### Changed

- Documentation refresh clarifying web, config, and performance sections
- Updated CLI vs config-only documentation with examples
- Linked Getting Started and Troubleshooting documentation pages
- Removed perf-validation documentation (guidance moved to performance.md and scripts/perf/)
- Closed validation targets and cleaned up related documentation
- Added documentation for scale-mode flow storage and pipeline operation
- Batched per-tick events into merged frame messages; decoupled CLI and web top-flows
- Added documentation for streaming heavy-hitters and performance mode
- Added capture buffer/immediate options and reordered imports
- Honored web.tick_ms configuration; removed 500ms clamp, lowered receive timeout, added minimum validation
- Reformatted documentation tables; removed CONTRIBUTING directory and index.md
- Flow tracking switches to compact scale-mode store with split IPv4/IPv6 tables when advanced analysis disabled
- Pipeline heavy-hitter tracking now uses compact internal flow-key path in scale mode
- Pipeline-mode web updates use merged websocket `frame` messages with latest-frame replay
- Pipeline-mode top-flow reporting decouples CLI `stats.top_flows` from dashboard `web.top_n`
- Updated documentation for performance benchmarks and flow table sizing behavior
- Refreshed documentation to reduce overlap between setup, usage, CLI, configuration, and feature guides

#### Removed

- `CONTRIBUTING.md`
- `docs/index.md` (fully redundant with main README.md documentation table)
- `docs/perf-validation.md` (guidance moved to performance.md and scripts/perf/)

### [0.1.0] - 2026-02-27

#### Added

- Live packet capture via libpcap with BPF filter support.
- Zero-copy protocol parsing for Ethernet II, 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP.
- Bidirectional flow tracking with TCP state machine (SYN, SYN-ACK, Established, FIN, RST).
- TCP analysis: RTT estimation (EWMA, alpha=0.125), retransmission detection, out-of-order segment detection.
- Sharded pipeline for multi-core packet processing with lock-free per-shard flow tracking.
- Shard routing via fast 5-tuple extraction from raw bytes (no full parse on capture thread).
- Anomaly detection: SYN flood and port scan alerts with sliding windows and cooldowns.
- Web dashboard with real-time throughput charts, top flows table, packet inspector, and alerts tab.
- WebSocket protocol for live stats, sampled packets, packet detail requests, and alerts.
- Frontend embedded in the binary via `rust-embed` (no external files needed).
- TOML configuration file support with full CLI override (including `--no-*` flag pairs).
- Flow export to JSON and CSV on capture exit.
- Alert export to JSONL file.
- Pcap file output (`--write-pcap`).
- Periodic throughput stats with top-N flows by bandwidth delta.
- Criterion benchmarks for parsing, flow tracking, and shard routing.
- Comprehensive documentation in `docs/`.
