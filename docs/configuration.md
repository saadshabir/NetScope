# Configuration

NetScope supports TOML configuration files for persistent settings. Load a config file with `--config`:

```bash
sudo netscope --config netscope.toml
```

This page is the authoritative configuration schema. The defaults in the tables below mirror the compiled defaults in `src/config.rs`.

A full template is provided in [`netscope.example.toml`](../netscope.example.toml) at the repository root.

## Precedence Rules

1. **CLI flags** always override config file values when explicitly provided.
2. **Config file values** override compiled defaults.
3. **Compiled defaults** apply when neither CLI nor config file specifies a value.

For boolean options, `--flag` and `--no-flag` pairs let you override in either direction:

```bash
# Config says quiet = true, CLI overrides it back to false:
sudo netscope --config my.toml --no-quiet
```

## CLI vs Config-only Settings

The CLI exposes common capture, output, and mode toggles, but some tuning knobs are only available in TOML. Common config-only examples include:

- `capture.buffer_size_mb` and `capture.immediate_mode`
- `analysis.rtt`, `analysis.retrans`, and `analysis.out_of_order`
- `web.tick_ms`, `web.top_n`, `web.packet_buffer`, `web.sample_rate`, `web.payload_bytes`, `web.tls.*`, and `web.auth.*`
- `pipeline.channel_capacity`

Use [CLI appendix](streamlining-plan.md#cli-reference) for flag-level help and this page for the full config schema.

## Path Fields

In TOML, path fields (`capture.read_pcap`, `write_pcap`, `export_json`, `export_csv`, `expired_flows_jsonl`, `expired_flows_csv`, `alerts_jsonl`, `web.tls.cert_path`, `web.tls.key_path`, `web.auth.password_file`) accept file paths. Setting a path to an empty string (`""`) is treated as disabled -- equivalent to omitting the key entirely.

```toml
[output]
write_pcap = ""     # disabled
export_json = ""    # disabled
expired_flows_jsonl = "" # disabled
expired_flows_csv = "" # disabled
```

## Config Reference

### `[capture]`

| Key              | Type   | Default | Description                                                                                              |
| ---------------- | ------ | ------- | -------------------------------------------------------------------------------------------------------- |
| `interface`      | string | (auto)  | Network interface name (e.g., `"en0"`). Omit for system default.                                         |
| `read_pcap`      | path   | (none)  | Read packets from an offline pcap file instead of a live interface. Mutually exclusive with `interface`. |
| `promiscuous`    | bool   | `true`  | Capture in promiscuous mode.                                                                             |
| `snaplen`        | int    | `65535` | Maximum bytes captured per packet.                                                                       |
| `timeout_ms`     | int    | `100`   | Capture read timeout in milliseconds.                                                                    |
| `buffer_size_mb` | int    | (none)  | libpcap capture buffer size in megabytes. Omit the key (or set to 0) to use the libpcap default.         |
| `immediate_mode` | bool   | `false` | Enable libpcap immediate mode (if supported by your libpcap build).                                      |
| `filter`         | string | (none)  | BPF filter expression.                                                                                   |

Note: `capture.interface` and `capture.read_pcap` are mutually exclusive. If both are set, NetScope exits with a configuration error. If neither is set, NetScope captures from the system default interface. When `capture.read_pcap` is set, live-capture-only settings like `promiscuous`, `timeout_ms`, `buffer_size_mb`, and `immediate_mode` have no effect.

### `[run]`

| Key     | Type | Default | Description                                                             |
| ------- | ---- | ------- | ----------------------------------------------------------------------- |
| `count` | int  | `0`     | Maximum packets to process. 0 = unlimited (live: Ctrl-C; offline: EOF). |

### `[output]`

| Key                    | Type | Default | Description                                                                                          |
| ---------------------- | ---- | ------- | ---------------------------------------------------------------------------------------------------- |
| `write_pcap`           | path | (none)  | Write captured packets to a pcap file.                                                               |
| `write_pcap_rotate_mb` | int  | `0`     | Rotate pcap output when the active segment reaches this many MiB. `0` disables rotation.             |
| `write_pcap_max_files` | int  | `0`     | Keep only the newest `N` rotated pcap files (delete oldest). Must be `> 0` when rotation is enabled. |
| `export_json`          | path | (none)  | Export flow table to JSON on exit.                                                                   |
| `export_csv`           | path | (none)  | Export flow table to CSV on exit.                                                                    |
| `summary_json`         | path | (none)  | Write versioned final run accounting as JSON after workers and outputs finish.                       |
| `expired_flows_jsonl`  | path | (none)  | Write expired or evicted flows as JSON lines during capture (inline and pipeline modes).             |
| `expired_flows_csv`    | path | (none)  | Write expired or evicted flows as streaming CSV during capture (inline and pipeline modes).          |
| `hex_dump`             | bool | `false` | Show hex dump of each packet.                                                                        |
| `quiet`                | bool | `false` | Suppress per-packet terminal output.                                                                 |

When rotation is enabled (`write_pcap_rotate_mb > 0` and `write_pcap_max_files > 0`), NetScope treats `write_pcap` as a base template and writes numbered segments such as `capture.000001.pcap`, `capture.000002.pcap`, and so on (the unsuffixed `capture.pcap` file is not created).

If either `write_pcap_rotate_mb` or `write_pcap_max_files` is set without the other, NetScope exits with a configuration error.

### `[flow]`

| Key            | Type  | Default  | Description                                                                                                                                           |
| -------------- | ----- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `timeout_secs` | float | `60.0`   | Flow inactivity timeout in seconds. 0 = never expire.                                                                                                 |
| `max_flows`    | int   | `100000` | Maximum tracked flows. In pipeline mode this is split into per-worker quotas; 0 = unlimited. Used to pre-size each flow table. |

### `[stats]`

| Key           | Type | Default | Description                                 |
| ------------- | ---- | ------- | ------------------------------------------- |
| `enabled`     | bool | `false` | Enable periodic throughput stats on stdout. |
| `interval_ms` | int  | `1000`  | Stats reporting interval in milliseconds.   |
| `top_flows`   | int  | `0`     | Number of top flows to show per stats tick. |

### `[analysis]`

| Key            | Type | Default | Description                                                                  |
| -------------- | ---- | ------- | ---------------------------------------------------------------------------- |
| `rtt`          | bool | `true`  | Compute TCP RTT estimates.                                                   |
| `retrans`      | bool | `true`  | Detect TCP retransmissions.                                                  |
| `out_of_order` | bool | `true`  | Detect out-of-order TCP segments.                                            |
| `alerts_jsonl` | path | (none)  | Write anomaly alerts as JSON lines to this file (inline and pipeline modes). |

When `analysis.rtt`, `analysis.retrans`, and `analysis.out_of_order` are all `false`, NetScope automatically switches flow tracking to its compact scale-mode storage path to reduce per-flow memory usage.

### `[analysis.anomalies]`

| Key       | Type | Default | Description               |
| --------- | ---- | ------- | ------------------------- |
| `enabled` | bool | `false` | Enable anomaly detection. |

### `[analysis.anomalies.syn_flood]`

| Key                    | Type  | Default | Description                                         |
| ---------------------- | ----- | ------- | --------------------------------------------------- |
| `enabled`              | bool  | `true`  | Enable SYN flood detection.                         |
| `window_secs`          | float | `5.0`   | Sliding window duration for counting SYNs.          |
| `syn_threshold`        | int   | `200`   | SYN count that triggers an alert.                   |
| `unique_src_threshold` | int   | `50`    | Minimum unique source IPs required to trigger.      |
| `cooldown_secs`        | float | `10.0`  | Minimum seconds between alerts for the same target. |

### `[analysis.anomalies.port_scan]`

| Key                      | Type  | Default | Description                                         |
| ------------------------ | ----- | ------- | --------------------------------------------------- |
| `enabled`                | bool  | `true`  | Enable port scan detection.                         |
| `window_secs`            | float | `10.0`  | Sliding window duration.                            |
| `unique_ports_threshold` | int   | `25`    | Unique destination ports that trigger an alert.     |
| `unique_hosts_threshold` | int   | `10`    | Unique destination hosts that trigger an alert.     |
| `cooldown_secs`          | float | `30.0`  | Minimum seconds between alerts for the same source. |

### `[web]`

| Key             | Type   | Default       | Description                                                                         |
| --------------- | ------ | ------------- | ----------------------------------------------------------------------------------- |
| `enabled`       | bool   | `false`       | Enable the web dashboard.                                                           |
| `bind`          | string | `"127.0.0.1"` | HTTP server bind address.                                                           |
| `port`          | int    | `8080`        | HTTP server port.                                                                   |
| `tick_ms`       | int    | `1000`        | How often stats are pushed to WebSocket clients (ms). Minimum 16ms.                 |
| `top_n`         | int    | `10`          | Number of top flows included in each stats tick.                                    |
| `packet_buffer` | int    | `2000`        | Number of packets kept in the ring buffer for detail inspection.                    |
| `sample_rate`   | int    | `1`           | Send every Nth packet to the UI. Set to 0 to disable the live packet feed entirely. |
| `payload_bytes` | int    | `256`         | Maximum raw bytes stored per packet for hex dump display.                           |

These keys apply only when `web.enabled = true`. Packet sampling uses the capture-wide packet id, so `sample_rate` is global in both inline and pipeline modes. Packet detail storage is keyed by packet id, so lookups remain stable even if pipeline events arrive slightly out of order.

Note: `payload_bytes` limits how many bytes are stored for the web packet detail hex dump (see `build_packet_data` in `src/lib.rs`). It does not change capture `snaplen` or what is written to pcap.

Prometheus-compatible metrics are served at `GET /metrics` when the web dashboard is enabled. This endpoint shares the same TLS (`[web.tls]`) and HTTP Basic auth (`[web.auth]`) settings as the rest of the dashboard.

### `[web.tls]`

| Key         | Type | Default | Description                                                   |
| ----------- | ---- | ------- | ------------------------------------------------------------- |
| `enabled`   | bool | `false` | Enable HTTPS for the web dashboard.                           |
| `cert_path` | path | (none)  | PEM certificate path. Required when `web.tls.enabled = true`. |
| `key_path`  | path | (none)  | PEM private key path. Required when `web.tls.enabled = true`. |

When enabled, NetScope serves the dashboard over HTTPS and expects certificate/key files to be readable at startup.

### `[web.auth]`

| Key             | Type   | Default | Description                                                                       |
| --------------- | ------ | ------- | --------------------------------------------------------------------------------- |
| `enabled`       | bool   | `false` | Enable HTTP Basic auth for all dashboard routes (including `/ws` and `/metrics`). |
| `username`      | string | `""`    | HTTP Basic auth username. Required when `web.auth.enabled = true`.                |
| `password`      | string | (none)  | Inline password value. Use either this key or `password_file`, not both.          |
| `password_file` | path   | (none)  | File containing the password value. Use either this key or `password`.            |

Validation rules when `web.auth.enabled = true`:

- `username` must be non-empty.
- Exactly one secret source must be configured: `password` or `password_file`.

For safer operations, prefer `password_file` over inline `password` so credentials are not stored directly in shared config templates.

### `[pipeline]`

| Key                | Type | Default | Description                                                                                        |
| ------------------ | ---- | ------- | -------------------------------------------------------------------------------------------------- |
| `enabled`          | bool | `false` | Enable the sharded pipeline for multi-core processing.                                             |
| `workers`          | int  | `0`     | Number of worker threads. 0 = auto-detect (half of CPU count, clamped 1..8).                       |
| `channel_capacity` | int  | `4096`  | Bounded channel size per worker shard. Live capture drops and counts packets when full; offline PCAP processing waits for queue space. |

For feature-specific explanations of these settings, see [Web Dashboard](web-dashboard.md), [Sharded Pipeline](pipeline.md), and the other focused guides. This page remains the source of truth for compiled defaults.

## Minimal Config Example

```toml
[capture]
interface = "en0"
filter = "tcp"

[output]
quiet = true

[stats]
enabled = true
top_flows = 5

[web]
enabled = true
```

## Full Example

See [`netscope.example.toml`](../netscope.example.toml) for a full template covering all sections with comments and representative optional keys. Use the tables above as the source of truth for compiled defaults.
