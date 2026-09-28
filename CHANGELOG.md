# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Remote dashboard TLS/auth configuration and run-summary field guidance.
- Five concise reader-facing pages for quickstart, reference, design, performance, and tool comparison; the README now links to them and the synthetic PCAP investigations.
- A same-PCAP comparison command set for NetScope, tcpdump, TShark, Zeek, and Suricata, with official manual links and execution limits stated.
- CI coverage for locked Clippy/tests/build, Python benchmark-runner checks, fixture-hash verification, and a rootless release-binary smoke run.
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

### Fixed

- Malformed TCP/UDP transport headers retain partial link/network decoding and are counted as malformed instead of fully successful packets.
- Avoid duplicate DNS parsing when building web packet summaries + details.
- Pipeline runs with enabled anomaly detection now fail before capture, preventing misleading per-worker alert thresholds; `--alerts-jsonl` remains available in inline mode.
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

### Changed

- Consolidated the README and ten overlapping guides into five reader pages and the investigation guide; removed duplicate CLI tables and corrected local links.
- Moved `scripts/perf/validate-web.sh` and `scripts/perf/perf-web.toml` to `scripts/smoke/dashboard.sh` and `scripts/smoke/dashboard.toml` so the manual live-dashboard check is not presented as a benchmark.
- Replaced malformed `.gitignore` fences and broad patterns with explicit local build, benchmark, smoke, and trace rules.
- CI now uses locked Rust checks, verifies benchmark-runner logic, builds release, and runs a rootless PCAP smoke example. Long benchmarks and privileged live replay remain outside CI.
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
- A previous local performance check used `scripts/perf/validate.sh`; it was retired on 2026-09-27 after the offline PCAP runner replaced its whole-process checks and the developer-only memory CLI was removed.
- Internal refactors to improve maintainability (flow module split, shared output sinks, shared packet formatting helpers).
- Flow CSV export avoids per-row string allocations by writing fields directly.
- Perf helper scripts print `tcpreplay` install hints and removed stale accepted-baseline text.

### Removed

- Ten superseded standalone documentation pages and the duplicated full CLI appendix table.
- The completed `docs/streamlining-plan.md`; its release history is retained here. The Linux live-loss matrix is outside the current release scope, and no live-loss figure is published.
- The developer-only `--synthetic-flows` CLI option and its now-unused `src/memory.rs`; flow insertion remains only as a `#[cfg(test)]` helper.
- The unused direct `tower-http` dependency after source search and `cargo tree` showed no consumer.
- `scripts/perf/validate.sh` and the unused throughput profile; the PCAP runner provides process RSS and CPU measurements.
- Removed low-signal and perf/size guard tests (including the ignored 1M-flow RSS budget test and layout size assertions).

## [0.2.0] - 2026-03-15

### Added

- Criterion benchmark `handshake_sequence` for TCP 3-way handshake hot path measurement
- Dashboard usability and performance improvements
- Synthetic memory benchmark and scale-mode regression fixes
- Scale-mode storage with compact IPv4/IPv6 flow tables
- Frame sequencing, rAF rendering with performance overlay, and streaming heavy-hitters with exact deltas
- PCap configuration knobs, buffer pool, drop statistics, and aggregator deadline
- Pre-sized flow table allocation based on `flow.max_flows` to reduce hash map resizes
- RTT optimization removing per-call heap allocation by streaming samples from ACK handling
- Comprehensive documentation updates and .gitignore improvements

### Changed

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

### Removed

- `CONTRIBUTING.md`
- `docs/index.md` (fully redundant with main README.md documentation table)
- `docs/perf-validation.md` (guidance moved to performance.md and scripts/perf/)

## [0.1.0] - 2026-02-27

### Added

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
