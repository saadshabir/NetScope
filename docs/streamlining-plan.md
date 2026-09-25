# NetScope streamlining plan

- **Status:** Planning document; implementation has not started.
- **Change type:** Focused cleanup with explicit behavior changes where current behavior is misleading.
- **Baseline inspected:** 2026-09-24, `main` at `6355f8c`.
- **Target:** A dependable Rust packet and flow investigation tool with reproducible correctness and performance evidence.

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
- Backward compatibility for developer-only benchmark commands or obsolete performance scripts. Any user-facing CLI/config change must appear in the changelog.
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
| Pipeline anomalies are per worker, while routing hashes the canonical full flow tuple. Multiple sources attacking one destination can land on different workers. | `src/pipeline/router.rs`, `src/pipeline/worker.rs`, `docs/pipeline.md` | Current alert thresholds are not globally equivalent between inline and pipeline modes; the destination-to-one-shard sentence in `docs/pipeline.md` is wrong. |
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
| Duplicate or unused runtime surface | Audit export variants, CLI flag pairs, config keys, web TLS/auth, and direct dependencies. | Remove only a slice with a tested replacement or a clear decision in the changelog; no speculative mass deletion. |

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

- [ ] Verify `rust-toolchain.toml`, `Cargo.lock`, libpcap headers, and the documented build command on a clean checkout. Do not depend on old binaries in `target/`.
- [ ] Run the existing CI gates: `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, and `cargo build --locked --release`.
- [ ] Record the command, commit, OS, toolchain, libpcap version, exit code, and any failures. Separate environment failures from source failures.
- [ ] Run one temporary known PCAP through inline and pipeline modes. Save current console summaries, flow exports, alert output, and exit status as baseline observations. These are diagnostic records, not published benchmarks.
- [ ] Inventory CLI flags, config keys, outputs, and documentation claims. Mark each as tested, untested, inaccurate, or internal-only. Include the `--synthetic-flows` path and all `--no-*` override pairs.
- [ ] List parser and capture limitations precisely: supported link types, classic PCAP versus other capture formats, fragmentation, IPv6 extension headers, DNS scope, and packet-level TLS SNI scope.

**Deliverables:** A short baseline record in the eventual results area; a prioritized issue list with a reproduction for each confirmed defect. Add a regression check when the defect has a plausible recurrence and an observable expected result.

**Exit gate:** A fresh checkout builds and runs an offline trace without privileges. Any remaining baseline failures have a reproducible command and clear owner.

## Phase 1 — Make every run account for its work

### 1.1 Define final-run counters and output

- [ ] Add a final summary that is emitted after worker shutdown, output flushes, and flow export. Offer a machine-readable JSON form, for example `--summary-json <PATH>`, while preserving a readable terminal summary.
- [ ] Version the JSON schema. Define stable names and units for input frames, input wire bytes, packets parsed, packets with a recognized transport header, malformed or unsupported packets, worker-processed packets, flows created/expired/evicted, alerts emitted, elapsed wall seconds, and output errors.
- [ ] Report dispatch, kernel/libpcap, and interface drops as separate fields. Use `null` or an explicit unavailable state for counters that an offline PCAP cannot provide; never convert “unavailable” into zero.
- [ ] Count at the layer where each event occurs. Reconcile `frames_read = dispatched + dispatch_drops` in pipeline mode and `dispatched = worker_processed + worker_failures` after draining workers. State whether a packet with an unrecognized higher layer still counts as parsed at the link or network layer.
- [ ] Include mode, source, worker count, effective config, and application version in the summary or its adjacent run manifest. Keep the summary cheap enough that normal use does not require the benchmark runner.
- [ ] Add a compact set of boundary tests for zero packets, a short run without a stats tick, malformed or unsupported input, and pipeline shutdown. Combine cases where one fixture can verify several counters; test both modes where their behavior can differ.

### 1.2 Make offline pipeline processing lossless

- [ ] Use bounded backpressure when reading an offline file. The reader may wait for worker queue space because a PCAP has already been captured and can be processed at the workers' rate.
- [ ] Keep live capture nonblocking where waiting would shift loss into libpcap or the kernel. Record every dispatch failure.
- [ ] Ensure shutdown and error paths drain or explicitly account for queued packets. Test with a queue capacity small enough to force backpressure.
- [ ] Validate that output PCAP and flow exports represent the documented stage of processing, especially when live dispatch drops occur.

### 1.3 Clarify parsing and flow limits

- [ ] Stop counting a malformed TCP or UDP header as a fully successful transport parse. Keep partial link/network decode available and expose the classification.
- [ ] Make `max_flows` have an honest pipeline meaning. Prefer a documented global budget divided among workers if that can be enforced without shared hot-path contention; test skewed shard distribution and explain early eviction if the budget is partitioned.
- [ ] Add bounds checks and tests for truncated VLAN, IPv4/IPv6, TCP/UDP, DNS, and TLS inputs. Reuse existing parser tests; add only cases that close an identified gap.

**Deliverables:** Stable summary contract, corrected offline dispatch, targeted regression tests, updated CLI/config docs.

**Exit gate:** Short and large offline fixtures finish with zero dispatch drops, their counts reconcile, and inline/pipeline results represent the same input packets.

## Phase 2 — Ship sample PCAPs and investigations

### 2.1 Build the fixture set

- [ ] Create a deterministic, streaming PCAP generator using Python's standard library or existing Rust code. Fix the random seed, timestamps, addresses, packet ordering, and byte layout. Avoid adding a packet-crafting dependency solely for fixtures.
- [ ] Commit generated **small** classic PCAP files, a generation command, a manifest with packet counts and SHA-256 hashes, and a short provenance statement confirming that traffic is synthetic.
- [ ] Keep benchmark-sized traces generated on demand. Do not commit multi-gigabyte PCAPs or captures from real users.

| Proposed fixture | Required contents | Expected observation |
| --- | --- | --- |
| `normal.pcap` | TCP handshake and data, a DNS query/response, packet-level TLS ClientHello with visible SNI | Flow directions and counts, DNS fields, best-effort SNI, no anomaly alert |
| `port-scan.pcap` | One source contacting multiple distinct ports and/or hosts at fixed intervals | Exactly documented port-scan alert behavior under a fixture-specific config |
| `syn-flood.pcap` | Multiple synthetic sources sending initial SYNs to one destination/port | A SYN-flood alert in the supported modes; tests expose any sharding mismatch |
| `protocol-edges.pcap` | IPv6, VLAN/QinQ, ICMP, a truncated transport header, and a packet the parser cannot fully classify | Supported layers decoded; malformed/unsupported counters match the manifest |

The anomaly fixtures should use explicit demo thresholds in a checked-in config. Keep production defaults independent of example size so a future threshold change cannot silently invalidate the demonstration.

### 2.2 Write investigations people can follow

- [ ] Put the investigations in one `examples/README.md` with short sections and direct links to the PCAPs and demo config. Avoid one Markdown file per tiny example.
- [ ] Add a normal-traffic investigation: the question, exact command, relevant flow or packet fields, expected result, and what the result does **not** prove.
- [ ] Add a port-scan investigation with alert JSONL output, the specific unique-port/host condition, and one benign pattern that could also trigger the heuristic.
- [ ] Add a SYN-flood investigation showing source diversity, time window, cooldown, and the limitation of packet-only evidence.
- [ ] Include expected result files only when they can be normalized for unstable ordering or timestamps. Keep machine assertions focused on IDs, counts, fields, and alert kinds rather than prose formatting.
- [ ] Link the shortest example from the README so the first successful run takes one command after building.

### 2.3 Turn examples into regression checks

- [ ] Run representative fixtures in both modes for packet accounting and flow parity. Run anomaly fixtures in both modes because sharding can change their result. Avoid a full fixture-by-mode matrix when it repeats the same processing path without a new failure risk.
- [ ] Assert manifest packet count, summary reconciliation, a few essential flow fields, alert kinds and counts, and zero offline dispatch drops. Avoid snapshots of full human-readable output.
- [ ] Verify generator output hashes in CI so checked-in PCAPs and source cannot drift apart.

**Deliverables:** Small tracked PCAPs, generator and manifest, three concise investigation sections in one guide, and targeted integration tests.

**Exit gate:** A new contributor can run the normal and anomaly examples from a clean checkout without root and obtain the documented results.

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
| `docs/reference.md` | CLI/config defaults and precedence, export schemas, and concise option tables | `cli-reference.md`, `configuration.md`, `exports.md` | All three old pages |
| `docs/design.md` | Pipeline, flow model, supported protocol depth, anomaly semantics, dashboard behavior, and contributor notes | `pipeline.md`, `flow-tracking.md`, `anomaly-detection.md`, `web-dashboard.md`, `development.md` | All five old pages |
| `docs/performance.md` | Benchmark method, measured results, tuning grounded in data, and live-loss method | Current `performance.md` | Replace its unsupported result table and repeated tuning prose |
| `docs/comparison.md` | Honest tool roles and exact comparison commands | New Phase 6 work | No legacy page |
| `docs/streamlining-plan.md` | Temporary work tracking and decision record | This plan | After acceptance, summarize the outcome in `CHANGELOG.md` and remove this plan from maintained docs |

- [ ] Migrate only accurate, useful content. Rewrite repeated paragraphs into a table, a command example, or a short explanation; do not paste old pages together into a larger wall of text.
- [ ] Keep each reader page task-oriented: start with the answer or command, then include the minimum detail needed to use it correctly. Put exhaustive generated CLI help in `netscope --help` rather than prose copies of every flag.
- [ ] Use one canonical source for defaults and option behavior. Ensure reference tables, example config, and `--help` agree; remove duplicate default tables elsewhere.
- [ ] Replace the README's current long documentation menu with links to quickstart, examples, reference, design, performance, and comparison. Keep the plan link separate as an active-work item.
- [ ] Search all Markdown links and command references before deleting any old page. Update README, examples, CI, and remaining docs, then check that no local link points to a removed file.
- [ ] Delete the 11 superseded pages only after the new pages contain the necessary commands, caveats, and output schemas. Review the final docs list and remove placeholder pages that add no distinct value.
- [ ] At final handoff, transfer accepted decisions and measured evidence to maintained docs and `CHANGELOG.md`, remove this execution plan, and remove its README link. Keep it until all phase gates have been checked.

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
- [ ] `docs/` contains five reader pages at final handoff; old links, superseded pages, and this temporary plan are gone after their accepted decisions are recorded.
- [ ] The final diff removes more confusion than it adds, and each retained feature has a tested path.

**Deliverables:** Focused README/docs, cleaned scripts and ignore rules, final CI workflow, release notes or changelog entry, and a reviewed plan-to-outcome crosswalk before this temporary plan is removed.

**Exit gate:** A clean checkout passes CI, the sample investigations reproduce, and the performance and comparison pages cite concrete evidence.

## Migration and breaking changes

The cleanup should avoid gratuitous user-facing churn, but it should not keep a misleading compatibility path. Record every actual CLI, config, output-schema, and documentation-path change in one compact changelog table.

- `--synthetic-flows` is a developer measurement path scheduled to leave the normal CLI after its replacement exists. Benchmark scripts that call it must migrate to the new runner.
- If `--summary-json` is added, version its schema from the first release. Existing human-readable output remains for people, but scripts should consume JSON rather than scrape prose.
- If pipeline anomaly detection cannot meet the target semantics, reject `--pipeline --anomalies` with a clear message and document the inline command. Do not keep the weaker per-shard interpretation under the same flag combination.
- Consolidated docs replace 11 legacy paths. Update all repository links and commands before deletion; list moved topics in the changelog. Avoid maintaining 11 redirect stubs just to preserve the old catalogue.
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
- [ ] The changelog lists behavior changes, removals, and evidence. A plan-to-outcome crosswalk confirms every accepted phase gate before this temporary plan is removed.

The final handoff should state what changed, the exact verification commands that passed, the measured results and their limits, and any remaining risks. No numeric target will be invented to manufacture a pass; the first measured baseline establishes the starting point for future improvement.
