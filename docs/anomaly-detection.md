# Anomaly Detection

NetScope includes built-in anomaly detection for two common attack patterns: SYN floods and port scans. Enable it with `--anomalies` or `analysis.anomalies.enabled = true` in the config file.

```bash
sudo netscope --anomalies --alerts-jsonl alerts.jsonl
```

## SYN Flood Detection

Triggers when a destination `(ip, port)` receives a high volume of SYN packets from many distinct sources within a sliding time window.

**Conditions (all must be met):**

1. The number of SYN packets to the target is at least `syn_threshold` within `window_secs`.
2. The SYNs come from at least `unique_src_threshold` unique source IPs.

Only initial SYN packets (SYN flag set, ACK flag not set) are counted. SYN-ACK responses are excluded.

### Configuration

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable/disable SYN flood detection. |
| `window_secs` | `5.0` | Sliding window duration (seconds). |
| `syn_threshold` | `200` | Number of SYNs that triggers an alert. |
| `unique_src_threshold` | `50` | Minimum unique source IPs required. |
| `cooldown_secs` | `10.0` | Minimum time between alerts for the same `(dst_ip, dst_port)`. |

Set under `[analysis.anomalies.syn_flood]` in the config file.

## Port Scan Detection

Triggers when a single source IP contacts an unusually high number of unique destination ports or hosts within a sliding time window.

**Conditions (either triggers an alert):**

1. The source contacts at least `unique_ports_threshold` unique destination ports, OR
2. The source contacts at least `unique_hosts_threshold` unique destination hosts.

Only SYN-only TCP packets and UDP packets are considered. Established TCP connections (packets with ACK set) are excluded.

### Configuration

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable/disable port scan detection. |
| `window_secs` | `10.0` | Sliding window duration (seconds). |
| `unique_ports_threshold` | `25` | Unique destination ports that trigger an alert. |
| `unique_hosts_threshold` | `10` | Unique destination hosts that trigger an alert. |
| `cooldown_secs` | `30.0` | Minimum time between alerts for the same source IP. |

Set under `[analysis.anomalies.port_scan]` in the config file.

## Alert Output

Alerts are:

1. **Printed to stdout** in the format `[alert] <description>`.
2. **Sent to the web dashboard** (if enabled) in real time.
3. **Written to a JSONL file** (if `--alerts-jsonl` is specified, in both inline and pipeline modes).

### JSONL Format

Each line in the alerts file is a JSON object:

```json
{"ts":1706123456.789,"kind":"syn_flood","description":"SYN flood suspected: 250 syns, 60 sources to 10.0.0.1:443"}
```

| Field | Type | Description |
|---|---|---|
| `ts` | float | Timestamp (seconds since Unix epoch, microsecond precision). |
| `kind` | string | Alert type: `"syn_flood"` or `"port_scan"`. |
| `description` | string | Human-readable alert description. |

### Web Dashboard Alerts

Alerts appear in the "Alerts" tab of the web dashboard with timestamp, kind, and description columns.

## Cooldown Mechanism

After an alert fires for a specific target (SYN flood) or source (port scan), subsequent alerts for the same key are suppressed for `cooldown_secs`. This prevents alert floods during sustained attacks.

Cooldown timers are cleaned up every 30 seconds. An inactive key's event queue can retain expired entries until that key receives another packet; this state limit is scheduled for correction in Phase 3.2.

## Pipeline Mode Caveat

In [pipeline mode](pipeline.md), each worker shard has its own anomaly detector. Thresholds are evaluated per-shard, not globally. This means:

- Distributed attacks that spread across shards may not trigger alerts if no single shard sees enough traffic to exceed the threshold.
- Traffic targeting one destination can still spread across shards because the router hashes the full flow tuple, including the source endpoint.

Pipeline mode can miss an alert that inline mode would emit for the same packets. Use inline mode when these alert decisions matter; reducing thresholds by worker count does not make the modes equivalent.

## Configuration Summary

For authoritative defaults and the full schema, see [Configuration](configuration.md). The snippet below is a representative example.

```toml
[analysis]
alerts_jsonl = "alerts.jsonl"  # optional file output

[analysis.anomalies]
enabled = true

[analysis.anomalies.syn_flood]
enabled = true
window_secs = 5.0
syn_threshold = 200
unique_src_threshold = 50
cooldown_secs = 10.0

[analysis.anomalies.port_scan]
enabled = true
window_secs = 10.0
unique_ports_threshold = 25
unique_hosts_threshold = 10
cooldown_secs = 30.0
```
