# Reference

Use `./target/release/netscope --help` for the complete option list generated from the CLI. The checked-in [`netscope.example.toml`](../netscope.example.toml) covers the configuration sections and their current values; [`src/config.rs`](../src/config.rs) defines the compiled defaults. This page explains precedence and output contracts without copying every flag or default into another table.

## Configuration and precedence

Load TOML with `--config <PATH>`; no config file is loaded automatically. File values override compiled defaults, and supplied CLI settings generally override the file:

- Boolean pairs such as `--web` / `--no-web` and `--anomalies` / `--no-anomalies` can enable or disable a file setting.
- `--interface` replaces a configured PCAP source; `--read-pcap` replaces a configured interface. Supplying both flags is rejected.
- `--pipeline` enables pipeline mode. A positive `--workers N` also enables it and overrides the worker count. `--workers 0` preserves the config value; it selects automatic sizing only when that value is also zero. There is no `--no-pipeline`; set `[pipeline] enabled = false` in TOML and omit enabling CLI flags for inline mode.

Relative paths in TOML resolve from the process's working directory, including input, output, certificate, key, and password paths. Create output parent directories before running.

| Section | Settings covered |
| --- | --- |
| `[capture]`, `[run]` | Interface or PCAP input, BPF filter, capture controls, packet limit |
| `[output]` | PCAP writing and rotation, flow exports, run summary, expired-flow sinks, terminal output |
| `[flow]`, `[stats]` | Flow timeout and budget, periodic statistics, top-flow count |
| `[analysis]` | TCP RTT/retransmission/order tracking and alert output |
| `[analysis.anomalies.*]` | SYN-flood and port-scan windows, thresholds, and cooldowns |
| `[web]`, `[web.tls]`, `[web.auth]` | Local dashboard, sampling, HTTPS, and HTTP Basic auth |
| `[pipeline]` | Worker count and bounded per-worker queue capacity |

The example config includes all sections and output paths. Empty path strings in TOML disable file outputs. `capture.interface` and `capture.read_pcap` are mutually exclusive. PCAP rotation requires `write_pcap` and both positive rotation settings; `capture.pcap` becomes `capture.000001.pcap`, `capture.000002.pcap`, and so on, retaining the configured number of newest segments.

Settings available only through TOML include `capture.buffer_size_mb`, `capture.immediate_mode`, the TCP-analysis switches under `[analysis]`, anomaly thresholds, dashboard sampling/tick settings, and `pipeline.channel_capacity`. CLI and TOML forms are both listed in `--help` and the example config respectively.

## Output behavior

| Output | Contract |
| --- | --- |
| `--export-json` | On exit, writes a JSON array of TCP/UDP flows still retained in the table, sorted by total bytes. |
| `--export-csv` | On exit, writes the same flow fields as one row per flow with a header. |
| `--expired-flows-jsonl` / `--expired-flows-csv` | Streams removed flow snapshots with `ts` and `reason = timeout` or `eviction`. Does not emit retained flows just because capture ends. |
| `--alerts-jsonl` | Writes versioned alert objects as JSON Lines. Anomaly detection is inline-only. |
| `--write-pcap` | Writes captured input frames. In pipeline mode, writing occurs before worker dispatch, so the PCAP may include frames later counted as dispatch drops. |
| `--summary-json` | Writes schema-versioned final accounting after worker shutdown and output flushes. |

Use an expired-flow sink together with a final export to retain removed and remaining flows. A tuple seen again after removal creates a new flow record. Final JSON/CSV, summary JSON, alert JSONL, expired-flow JSONL, and unrotated PCAP outputs replace existing files; expired-flow CSV appends and writes a header only when the file is empty. Use fresh output paths for each investigation.

Flow JSON is an array of records with `protocol`, `endpoint_a`/`endpoint_b` (`ip` and `port`), `first_seen`, `last_seen`, `duration_secs`, directional and total packet/byte counts, `avg_bps`, and TCP tracking fields (`tcp_state`, `client`, retransmission/order counts, RTT samples). CSV uses the same data as one row per flow. Flow endpoint order is canonical; the A-to-B and B-to-A counts preserve direction. TCP state and tracking values are inferred from observed packets, not stream reassembly. Scale mode keeps RTT values null and retransmission/order counters at zero because those analyses are disabled. CSV is emitted as plain comma-separated numeric, enum, and IP fields without quoting.

Input PCAPs, the config file, TLS/auth files, and all outputs must have distinct file identities. Validation rejects output aliases through relative paths, symlinks, hard links, and the rotated PCAP filename namespace before opening writers.

`first_seen` and `last_seen` are Unix seconds from the earliest and latest capture timestamps; expired-record `ts` is the removal time in Unix seconds. Flow byte counts use original frame wire lengths, including headers, rather than captured payload sizes. `avg_bps` is bits per second over the observed flow duration and is zero for a zero-duration flow. `--flow-timeout-s 0` disables timeout removal, while `--max-flows 0` disables budget eviction. See [processing modes](design.md#processing-modes) for expiry timing.

Alert JSONL schema version 1 includes `ts`, `kind`, optional source/target addresses and target port, `window_secs`, configured `thresholds`, observed counts, and a description. The threshold and observed objects use `syn_count`, `unique_sources`, `unique_ports`, and `unique_hosts`; fields that do not apply to that alert kind are null.

Summary JSON schema version 1 includes application version, run status and error, source and mode, effective configuration, elapsed wall seconds, input frame and wire-byte totals, parser-layer counts, flow lifecycle events, alert count, pipeline reconciliation, separate drop counters, and output errors. Inline runs set pipeline-only counts to `null`. Offline input and unavailable live counters use `null`, never zero. A partial decode may count as a parsed packet and also as malformed or unsupported. Sink, worker, or capture failures make the run unsuccessful and are reflected in `output_errors` or `run_error`.

`--quiet` suppresses per-packet output; startup messages, periodic stats when enabled, and the terminal run summary remain. Read `--summary-json` for machine-readable accounting. Check both the process exit code and `status`: graceful Ctrl-C can exit with code 0 and `status = "interrupted"`. Configuration, input-open, PCAP-output-open, or dashboard-start failures can occur before a summary exists; failure to write the summary itself is reported on stderr.

### Run-summary fields

| Fields | Meaning |
| --- | --- |
| `schema_version`, `application_version` | Output schema and producing application version. |
| `status`, `run_error` | `success`, `failed`, or `interrupted`, and an optional failure description. |
| `mode`, `source`, `worker_count`, `effective_config` | Inline or pipeline execution, `pcap:<path>` or `interface:<name>`, worker count, and settings without credentials. |
| `elapsed_wall_seconds`, `frames_read`, `input_wire_bytes` | Duration from capture setup through processing/exports, frames read after BPF filtering, and their original wire lengths. |
| `packets_parsed`, `packets_with_network_header`, `packets_with_transport_header` | Frames returned by the parser and those with recognized network or transport headers. |
| `packet_parse_errors`, `transport_parse_errors`, `unsupported_packets` | Link/network parse failures, malformed supported transport headers, and unsupported payloads or fragments. |
| `malformed_or_unsupported_packets` | Compatibility aggregate counting each affected frame once. |
| `dispatched_frames`, `dispatch_drops`, `worker_processed_frames`, `worker_failures` | Pipeline dispatch and worker accounting; `null` in inline mode. |
| `flows_created`, `flows_expired`, `flows_evicted`, `alerts_emitted` | Observed flow lifecycle and alert events. |
| `kernel_drops`, `interface_drops` | Separate libpcap drop counters; `null` for offline input or when unavailable. |
| `output_errors` | Output open, write, flush, and export failures. |

After workers drain, pipeline accounting reconciles `frames_read = dispatched_frames + dispatch_drops` and `dispatched_frames = worker_processed_frames + worker_failures`. A partial decode can increment `packets_parsed` and a malformed or unsupported counter. Offline queue pressure slows reading instead of causing dispatch drops.

## Dashboard endpoints

Enable the server with `--web`. It lives for the duration of the capture process.

| Endpoint | Response |
| --- | --- |
| `/` | Embedded dashboard and static assets. |
| `/api/health` | Plain text `ok`; confirms HTTP availability, not capture completeness or packet loss. |
| `/metrics` | Prometheus text format with capture totals, active flows, drop totals, build version, and uptime. |
| `/ws` | WebSocket stats, sampled packets, packet-detail requests, and alerts. |

While a local capture with `--web` is running, use a second terminal:

```sh
curl -fsS http://127.0.0.1:8080/api/health
curl -fsS http://127.0.0.1:8080/metrics
```

Capture metrics update on dashboard ticks; they can lag behind packet processing. Use the final run summary for reconciled accounting and unavailable-counter semantics. HTTP Basic auth and TLS apply to every endpoint when enabled.

## Remote dashboard

Save this as `dashboard.toml`, replacing `capture.example` with the hostname or address used in your browser, and using existing PEM certificate/key files and a password file readable by NetScope:

```toml
[web]
enabled = true
bind = "0.0.0.0"
port = 8443
allowed_origins = ["https://capture.example:8443"]

[web.tls]
enabled = true
cert_path = "/etc/netscope/dashboard.crt"
key_path = "/etc/netscope/dashboard.key"

[web.auth]
enabled = true
username = "operator"
password_file = "/etc/netscope/dashboard.pass"
```

Run `sudo ./target/release/netscope --config dashboard.toml --quiet` and open `https://<host>:8443`. The password file contains only the password; use either `password` or `password_file`, not both. Basic auth protects all endpoints, including `/api/health`, `/metrics`, and `/ws`. Without TLS, Basic auth credentials travel over cleartext HTTP. Self-signed certificates work, but browsers require you to trust them.

To scrape metrics with a trusted certificate, replace `capture-host` with its certificate hostname. Curl prompts for the password:

```sh
curl --fail --cacert /etc/netscope/dashboard.crt --user operator \
  https://capture-host:8443/metrics
```

## Minimal config

```toml
[capture]
read_pcap = "examples/pcaps/normal.pcap"

[output]
quiet = true
summary_json = "/tmp/netscope-summary.json"
export_json = "/tmp/netscope-flows.json"
```

Run it with `./target/release/netscope --config run.toml`. For live-use examples and permission notes, see [Quickstart](quickstart.md). For protocol scope, mode behavior, and dashboard semantics, see [Design](design.md).
