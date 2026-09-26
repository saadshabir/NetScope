# Development Guide

## Repository Layout

```
netscope/
  Cargo.toml                    # Package manifest
  netscope.example.toml         # Complete example config file
  LICENSE                       # MIT License
  README.md                     # Project landing page
  docs/                         # Documentation
    streamlining-plan.md          # Plan, baseline, CLI reference, and consolidated history
  scripts/
    perf/                       # Perf helper scripts and example configs
  benches/
    hot_path.rs                 # Criterion benchmarks for parsing, flow, routing
  web/
    static/
      index.html                # Web dashboard frontend (embedded at compile time)
      vendor/chartjs/           # Vendored Chart.js bundle + license (offline/airgapped dashboard)
  src/
    main.rs                     # Binary entry point, CLI arg merging, capture loops
    lib.rs                      # Library crate root: re-exports all modules, shared helpers used by main.rs and pipeline workers (maybe_analyze_anomaly, build_packet_data)
    cli.rs                      # Clap CLI argument definitions
    config.rs                   # TOML config structs, defaults, deserialization
    display.rs                  # CLI packet display (summary, detail, hex dump)
    jsonl.rs                    # JSON Lines sink helper (append-only JSONL writing)
    sinks.rs                    # Shared output sinks (alerts + expired flows)
    flow.rs                     # Flow module root: re-exports flow types and helpers
    flow/
      export.rs                 # Flow JSON/CSV export helpers
      key.rs                    # Flow key/endpoint/protocol types and compact keys
      model.rs                  # Flow entry/snapshot models and TCP state helpers
      scale.rs                  # Compact scale-mode flow entry representation
      tcp.rs                    # TCP flags/sequence tracking helpers
      tracker.rs                # FlowTracker implementation
    packet_format.rs            # Shared packet summary/hex/timestamp formatting helpers
    memory.rs                   # RSS estimation and memory-scale helpers
    capture/
      mod.rs                    # Module declaration
      engine.rs                 # libpcap wrapper (open capture, list interfaces)
    protocol/
      mod.rs                    # Packet parsing entry point, ParsedPacket type
      ethernet.rs               # Ethernet II header parser
      arp.rs                    # ARP parser (variable-length addresses)
      loopback.rs               # Loopback NULL/LOOP header parser
      sll.rs                    # Linux cooked capture (SLL) header parser
      ipv4.rs                   # IPv4 header parser (with checksum verification)
      ipv6.rs                   # IPv6 header parser
      tcp.rs                    # TCP header parser
      udp.rs                    # UDP header parser
      icmp.rs                   # ICMP header parser
      icmpv6.rs                 # ICMPv6 header parser
      dns.rs                    # DNS message parser (UDP/53)
      tls.rs                    # TLS ClientHello parser (SNI extraction)
    analysis/
      mod.rs                    # Module declaration
      anomaly.rs                # SYN flood and port scan detection
    pipeline/
      mod.rs                    # Pipeline spawn, OwnedPacket, PipelineHandle
      router.rs                 # Fast 5-tuple extraction and shard routing
      worker.rs                 # Per-shard worker (parse, flow, anomaly, tick)
      aggregator.rs             # Merges shard ticks, forwards to CLI/web
      pool.rs                   # Shared reusable packet-buffer pool
      top_flows.rs              # Streaming heavy-hitter tracker for dashboard top flows
    web/
      mod.rs                    # Module declaration
      server.rs                 # Axum HTTP/WebSocket server, tokio runtime
      messages.rs               # WebSocket message types (server->client, client->server)
      packet_store.rs           # Ring buffer for packet detail lookups
```

## Vendored Frontend Dependencies

The dashboard frontend is embedded at compile time (no separate frontend build). Chart.js is vendored under `web/static/vendor/chartjs/` and loaded from `/vendor/chartjs/chart.umd.min.js` so the dashboard works in offline/airgapped environments.

When updating Chart.js, keep these files in sync:

- `web/static/vendor/chartjs/chart.umd.min.js`
- `web/static/vendor/chartjs/VERSION.txt`
- `web/static/vendor/chartjs/LICENSE.md`

## Building

```bash
cargo build              # Debug build
cargo build --release    # Optimized build
```

NetScope pins Rust via `rust-toolchain.toml` (currently Rust 1.93.1). With rustup, invoking `cargo` will auto-install the pinned toolchain on first use. To pre-install it (including `rustfmt` and `clippy`):

```bash
rustup toolchain install 1.93.1 --component rustfmt --component clippy
rustup show
```

## Running Tests

```bash
cargo test
```

## Fast Local Quality Checks

Run these before opening a PR:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

For local performance/memory sanity checks, use `scripts/perf/validate.sh` (release build + a representative hot-path benchmark + synthetic-flow memory validation). These checks are intentionally separate from the unit/integration test suite.

Replay-based perf checks (`scripts/perf/validate-throughput.sh`, `scripts/perf/validate-web.sh`) require `tcpreplay`.
On macOS: `brew install tcpreplay`. On Debian/Ubuntu: `sudo apt-get install tcpreplay`.

Tests are co-located with the source code in `#[cfg(test)]` modules. Key test areas:

- `src/flow/key.rs` -- flow key ordering/canonicalization and compact key types (including scale-mode IPv4/IPv6 keys).
- `src/flow.rs` -- TCP state transitions, sequence tracking, RTT sampling, and core tracker behavior.
- `src/pipeline/router.rs` -- shard routing correctness (same flow both directions = same shard).
- `src/protocol/*.rs` -- header parsing, field extraction, edge cases (truncated packets, wrong versions).

## Running Benchmarks

```bash
cargo bench
```

Benchmarks are in `benches/hot_path.rs` using Criterion. They measure:

- `parse_packet` -- full protocol stack parsing (e.g., Ethernet + IPv4 + TCP).
- `flow_observe` -- flow table lookup and update for existing and new flows.
- `shard_routing` -- 5-tuple extraction and hash computation.
- `handshake_sequence` -- combined `parse_packet + FlowTracker::observe` for a full TCP 3-way handshake (SYN → SYN-ACK → ACK).

Note: `flow_observe (new flow)` includes flow tracker setup and is sensitive to changes like flow table pre-sizing. Use it as a cold-path baseline rather than a steady-state throughput proxy.

HTML reports are generated in `target/criterion/`.

Maintainer perf helper scripts and example replay configs live in `scripts/perf/`.

## Adding a New Protocol

To add support for a new protocol (e.g., DNS, GRE):

1. Create `src/protocol/your_protocol.rs` with a zero-copy header struct:
   ```rust
   pub struct YourHeader<'a> {
       data: &'a [u8],
   }
   ```
2. Implement `parse(data: &'a [u8]) -> Result<Self, ParseError>` with length/validity checks.
3. Add the module to `src/protocol/mod.rs`.
4. Add a variant to `TransportHeader` (or create a new header enum if it's a different layer).
5. Wire it into `parse_packet()` in `src/protocol/mod.rs`.
6. Update `display.rs` for CLI output and `lib.rs` for web dashboard layers.
7. Add tests for valid parsing, truncated input, and invalid headers.

All protocol parsers follow the same pattern: borrow the byte slice, validate minimum length, provide accessor methods with `#[inline]`.

## Adding a New Anomaly Detector

1. Add a new state struct and detection logic in `src/analysis/anomaly.rs`, following the pattern of `SynFloodState` / `PortScanState`.
2. Add a new `AlertKind` variant.
3. Add configuration fields to `AnomalyConfig` in `src/config.rs`.
4. Wire it into `AnomalyDetector::observe()`.
5. Add a cleanup method and call it from the periodic cleanup sweep.

## Logging

NetScope uses the `tracing` crate for structured logging. Log levels:

| Level | Controlled by | What's logged                                           |
| ----- | ------------- | ------------------------------------------------------- |
| WARN  | default       | Warnings and errors                                     |
| INFO  | `-v`          | Capture start/stop, interface selection, web server URL |
| DEBUG | `-vv`         | Config resolution, parse errors per packet              |
| TRACE | `-vvv`        | Per-packet traces, channel drops, aggregator events     |

Add logging with:

```rust
tracing::info!(interface = %name, "capture started");
tracing::debug!(error = %e, "parse error on packet #{}", id);
tracing::trace!(shard, "worker channel full, dropping packet");
```

Logging convention:

- Use `println!` for user-facing CLI output.
- Use `tracing::{error,warn,info,debug,trace}` for logs.
- Avoid non-interactive `eprintln!` for logging.

## Docs Maintenance

When changing flags, config defaults, web message shapes, or pipeline behavior, update the matching docs in the same change:

- [CLI appendix](streamlining-plan.md#cli-reference) for changes in `src/cli.rs`
- `docs/configuration.md` and `netscope.example.toml` for schema/default changes in `src/config.rs`
- feature guides in `docs/` for behavioral changes in pipeline, flow tracking, anomaly detection, exports, or web code

## Code Style

- Protocol parsers are zero-copy: `struct FooHeader<'a> { data: &'a [u8] }`.
- Accessor methods are `#[inline]` and read from fixed offsets.
- Error types implement `Display` and `std::error::Error`.
- Serialization uses `serde` with `#[serde(rename_all = "snake_case")]`.
- Hash maps use `ahash::AHashMap` instead of `std::collections::HashMap` on hot paths.
