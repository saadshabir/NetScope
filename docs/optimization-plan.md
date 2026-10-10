**NetScope debloat and optimization plan — 2026-10-10**

Audit baseline: commit `0ffcb38`. This is a proposed implementation sequence; no runtime changes or new throughput measurements were made during the audit.

**Shipping status — 2026-10-10:** The first implementation phase is ready for review. The original audit and remaining sequence are preserved below; this is not completion of every proposed optimization.

- Completed: reproducible baseline, dependency trims, default-enabled dashboard feature, headless CLI, CI coverage for both builds, and rejection of unavailable dashboard requests before capture/output files are opened.
- Accepted: skipping disabled inline stats clock reads, deferring scale-mode IPv6 reservation until the first IPv6 flow, and bounded exact top-N selection with independent CLI/dashboard deltas.
- Rejected: worker batches of 32/64 did not consistently reduce CPU cost; capped initial flow reservation increased peak memory during burst growth. Existing worker processing and IPv4 preallocation are retained.
- Deferred at the request to ship this phase: anomaly shrink policy, profiling-dependent heavy-hitter/key changes, main-module extraction, overflow-eviction cleanup, historical workload/fixture cleanup, and local build-cache cleanup.

Measurements and their limits are recorded in [Performance](performance.md#2026-10-10-build-and-reporting-pass). Raw measurements, source snapshots, workload hashes, and prototype artifacts remain under ignored `tmp/perf/`; they are not published in the repository.

Keep the existing capture, parsing, flow, anomaly, export, and dashboard behavior. Prioritize fewer compiled dependencies and less repeated work, with one independently measurable change per commit.

| Verified finding | Implication |
| --- | --- |
| Tracked files total 6,675,177 bytes; ignored `target/` occupies about 5.2 GB, including 4.4 GB of debug output. | Local build-cache cleanup offers the largest disk saving. It does not improve packet throughput. |
| `Cargo.toml` always includes the web/TLS stack and enables Tokio `full`. | A headless build and narrower dependency features are the main build-footprint opportunities. |
| `Cargo.lock` includes 246 packages across runtime, development, and platform dependencies. WebSocket tests use `tokio-tungstenite` 0.23 while Axum uses 0.28. | Align the test client where compatible; do not treat the lockfile count as the number of runtime dependencies. |
| `src/main.rs` contains 2,034 lines before its test module. | Capture lifecycle, rotation, configuration, and mode-specific processing have useful extraction boundaries. |
| `src/flow.rs` contains 68 lines before its test module. | Its apparent size mostly comes from regression coverage; line-count reduction alone would be misleading. |
| Workers check the clock before a receive and again after processing each packet. | Bounded receive batches are a plausible CPU optimization requiring measurement. |
| Inline top-flow selection scans retained flows and allocates a candidate vector; pipeline heavy-hitter replacement scans its bounded counter map. | Measure each reporting path separately before changing its algorithm. |

1. **Establish a reproducible baseline.**

Use the pinned toolchain and locked dependencies. Restore the dependency cache first: the audit's `cargo tree --locked --offline --duplicates` could not complete because `ahash 0.8.12` was not cached. The existing release binary is about 8.2 MB, but it is not a freshly verified build of this commit.

Record release size, resolved normal dependencies, clean-build time in a separate target directory, CPU seconds per million packets, median throughput with ranges, and peak RSS. Preserve the source revision, binary hash, workload hashes, and raw measurements. Use the existing performance scripts; keep measurements under ignored `tmp/perf/` and review paths before publishing results.

Compare inline and 2/4-worker processing over steady-flow, high-cardinality, and mixed workloads; run analysis-heavy inline. Include full and scale storage, bounded and unlimited retention, exports on/off, and a separate dashboard scenario. Start with focused cases and expand only after a candidate passes. Use at least one warm-up and five repetitions, alternating baseline and candidate for final comparisons. Add long-duration expiry/churn and IPv6 cases where a change affects them.

2. **Trim dependency features and provide a headless build.**

First make small dependency changes independently: remove the unused `tracing-subscriber` `env-filter` feature; remove `rust-embed` MIME metadata support if compilation confirms the existing direct `mime_guess` lookup is sufficient; align the development WebSocket client with the already-locked Axum client version. Replace Tokio `full` with the features actually required by the locked dependency graph and tests. Tokio documents selective feature activation as a way to reduce compiled code; inspect transitive feature activation before claiming savings. [Tokio feature documentation](https://docs.rs/tokio/latest/tokio/#feature-flags).

Evaluate replacing the one `num_cpus::get()` call with `std::thread::available_parallelism()`, preserving the current half-CPU/clamp policy and handling lookup failure. Verify container/affinity behavior because the APIs are estimates with platform limitations. [Rust API documentation](https://doc.rust-lang.org/std/thread/fn.available_parallelism.html).

Then introduce one `dashboard` Cargo feature, enabled by default to preserve normal builds. Make the HTTP, WebSocket, embedded-assets, authentication, and TLS dependencies optional together. `cargo build --locked --release --no-default-features` should produce the headless CLI. Cargo supports grouping optional dependencies under a feature. [Cargo feature documentation](https://doc.rust-lang.org/cargo/reference/features.html#optional-dependencies).

This requires a real boundary: `src/lib.rs` builds dashboard packet data, `src/config.rs` calls web origin validation, and the pipeline aggregator directly imports Tokio channels. Isolate those uses and presentation types so a headless build has no normal dependency on Tokio/Axum/TLS. Keep generic capture configuration and summary contracts stable. Reject a request to enable an unavailable dashboard before opening capture or output files. Keep remote TLS/auth and origin requirements intact in dashboard builds.

Accept when both build variants pass their applicable checks, default dashboard behavior is preserved, and build/size differences are measured. Test normal dependency graphs separately from development dependencies.

3. **Reduce packet-loop overhead.**

Prototype a bounded worker drain after the first blocking receive, starting with small batches such as 32 and 64 packets. Amortize deadline checks and avoid repeatedly setting up timed receives while work is already queued. Bound delay by both batch size and elapsed time; still expire flows and emit ticks while input is idle. Preserve per-packet capture-time watermarks, accounting, buffer returns, offline backpressure, live dispatch-drop accounting, and shutdown draining.

Skip the inline stats clock read when periodic stats are disabled, while retaining any clock reads needed by live capture and dashboard deadlines. Consider returning the already-derived compact flow key from flow observation for pipeline heavy-hitter accounting, instead of reconstructing it, only if profiling justifies the API change.

Accept only with repeatable CPU/throughput improvement and unchanged packet/flow results. Verify tick responsiveness under sustained load, idle shutdown, worker failure, and queued-packet draining. Keep batching separate from flow-storage changes.

4. **Reduce allocation and reporting costs where measurements justify it.**

`FlowTracker::new` reserves the configured flow limit plus 25% immediately, and scale mode also reserves a separate IPv6 table. Compare capped initial reservation and lazy IPv6 allocation with current behavior on tiny traces, burst growth, and high cardinality. Preserve the retention limit; lower initial allocation must not quietly lower capacity. Keep current preallocation if growth costs outweigh the memory benefit.

Anomaly cleanup calls `shrink_to_fit()` on event and cooldown maps each cleanup interval. Test delayed or hysteresis-based shrinking against alternating bursts and idle periods. Preserve detector evidence limits, cooldowns, timestamp ordering, and eventual memory reclamation.

For inline top-N reporting, compare reusable candidate storage with a bounded exact-selection heap. A heap can reduce temporary memory but does not eliminate the full-table scan and may cost more CPU. Preserve independent CLI/dashboard delta state and existing report semantics. Do not silently switch exact inline reporting to the pipeline's approximate heavy-hitter method. Replace the pipeline's minimum-counter scan only if dashboard-enabled profiling identifies it as significant.

5. **Simplify code without building another framework.**

Extract capture-source and rotating-PCAP handling from `src/main.rs`; move CLI override/validation logic into a focused runtime-configuration module; then separate inline and pipeline orchestration. Consolidate the duplicated parsed-packet accounting with a small shared helper. Keep mode-specific lifecycle and backpressure explicit. These are maintainability changes, not assumed speedups.

Review the older sorted overflow-eviction paths in `src/flow/tracker.rs`: admission now enforces capacity before insertion. Remove the fallback only after proving no production insertion path needs it and adjusting synthetic test setup to respect the same invariant. Keep timeout expiry and second-chance eviction coverage.

`docs/benchmarks/legacy-workloads-v1.py` has no current textual references. Remove it only after confirming it is no longer needed for historical reproduction. The four 10k benchmark PCAPs account for roughly 5.4 MB of tracked data; moving these to generation-on-demand is optional and lower priority. Preserve manifests, reproducible hashes, a documented generation command, and the tiny investigation fixtures. Keep the existing benchmark harness, parser tests, and vendored Chart.js license.

6. **Validate and finish.**

Run the repository's formatting, locked Clippy, Rust tests, release build, fixture verification, and Python checks. Extend CI to cover default and headless builds once features exist. Use targeted regression coverage for the changed behavior, including malformed transports, IPv6 fragments, out-of-order timestamps, expiry/eviction, export parity, drop accounting, and shutdown. Run the dashboard smoke check for default builds.

Reject a throughput claim if repeated ranges remain too noisy to distinguish the change; repeat selected scenarios using the existing runner. Do not accept materially worse memory, latency, or correctness in exchange for an isolated throughput result without explicitly documenting the tradeoff. Offline results do not establish live capture loss bounds; use the existing Linux procedure for those claims.

After baseline artifacts and any useful profiles are preserved, reclaim disposable build output with Cargo's cleanup command if local disk space is the goal. Expect dependencies to rebuild afterward. Cache cleanup is separate from source and binary optimization.

Audit validation: all four synthetic investigation fixtures verified; one workload test and six live-run classification/environment tests passed. Rust tests and fresh performance measurements were not run in this planning pass.
