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
3. **Written to a JSONL file** (if `--alerts-jsonl` is specified in inline mode).

### JSONL Format

Each line in the alerts file is a JSON object:

```json
{"schema_version":1,"ts":1706123456.789,"kind":"syn_flood","source_ip":null,"target_ip":"10.0.0.1","target_port":443,"window_secs":5.0,"thresholds":{"syn_count":200,"unique_sources":50,"unique_ports":null,"unique_hosts":null},"observed":{"syn_count":250,"unique_sources":60,"unique_ports":null,"unique_hosts":null},"description":"SYN flood suspected: 250 syns, 60 sources to 10.0.0.1:443"}
```

| Field | Type | Description |
|---|---|---|
| `ts` | float | Timestamp (seconds since Unix epoch, microsecond precision). |
| `kind` | string | Alert type: `"syn_flood"` or `"port_scan"`. |
| `description` | string | Human-readable alert description. |

`schema_version` is `1`. The existing `ts`, `kind`, and `description` fields remain unchanged; added fields provide structured source/target context, the configured window and thresholds, and observed counts. Fields that do not apply to an alert kind are `null`. Consumers that require an exact set of keys should accept the additional properties before upgrading.

### Web Dashboard Alerts

Alerts appear in the "Alerts" tab of the web dashboard with timestamp, kind, and description columns.

## Cooldown Mechanism

After an alert fires for a specific target (SYN flood) or source (port scan), subsequent alerts for the same key are suppressed for `cooldown_secs`. This prevents alert floods during sustained attacks.

The detector uses the greatest captured-frame timestamp seen so far as its event-time watermark, including malformed and unsupported frames, so out-of-order PCAP timestamps do not move window or cooldown time backwards. Each key's queue is pruned when that key is observed, and a sweep every 30 seconds removes expired events and empty queues for inactive keys. Expired cooldowns stop suppressing alerts immediately and are removed from the map during a sweep. Stale entries can remain until the next sweep after their event window or cooldown expires.

## Pipeline Mode

Anomaly detection is supported in inline mode only. Pipeline workers shard flows by the full canonical flow tuple, so per-worker detectors cannot reproduce the same global thresholds. NetScope rejects pipeline runs when anomaly detection is enabled, before capture starts. Disable pipeline or set `[analysis.anomalies].enabled = false` to continue. Lowering thresholds by worker count does not provide equivalent decisions.

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
