# Exports

NetScope can export data in several formats: raw packets to pcap, the flow table to JSON or CSV, and anomaly alerts to JSONL.

## Pcap Output

Write all captured packets to a pcap file:

```bash
sudo netscope --write-pcap capture.pcap
```

The file uses standard pcap format and can be opened with Wireshark, tcpdump, or any pcap-compatible tool. In pipeline mode, pcap writing happens on the capture thread before dispatch, so all packets are written regardless of dispatch drops.

Enable size-based rotation to prevent unbounded pcap growth:

```bash
sudo netscope --write-pcap capture.pcap --write-pcap-rotate-mb 256 --write-pcap-max-files 8
```

With rotation enabled, `--write-pcap` is treated as a base template and NetScope writes numbered segments like `capture.000001.pcap`, `capture.000002.pcap`, and so on (the unsuffixed `capture.pcap` file is not created). Once the max-files limit is reached, the oldest segment is deleted when a new one is created.

You can also use `--read-pcap` with `--write-pcap` to produce a filtered or trimmed pcap (no sudo required):

```bash
netscope --read-pcap trace.pcap -f "tcp port 443" --count 10000 --write-pcap filtered.pcap --quiet
```

## Flow Table Export

Export the flow table on exit:

```bash
sudo netscope --export-json flows.json --export-csv flows.csv
```

Both formats contain the same data -- a snapshot of all tracked flows at capture exit. Flows are sorted by total bytes (descending). In pipeline mode, the export contains merged snapshots from all worker shards. When scale mode is active, RTT fields remain `null` and retransmission / out-of-order counters remain `0` in exported snapshots.

### JSON Format

Pretty-printed array of flow objects. Example (single flow):

```json
[
  {
    "protocol": "tcp",
    "endpoint_a": { "ip": "192.168.1.42", "port": 54321 },
    "endpoint_b": { "ip": "93.184.216.34", "port": 443 },
    "first_seen": 1706123400.123456,
    "last_seen": 1706123460.654321,
    "duration_secs": 60.530865,
    "packets_a_to_b": 150,
    "packets_b_to_a": 200,
    "bytes_a_to_b": 12400,
    "bytes_b_to_a": 485000,
    "packets_total": 350,
    "bytes_total": 497400,
    "avg_bps": 65712.3,
    "tcp_state": "established",
    "client": "a_to_b",
    "retransmissions": 2,
    "out_of_order": 0,
    "rtt_last_ms": 15.2,
    "rtt_min_ms": 12.8,
    "rtt_ewma_ms": 14.1,
    "rtt_samples": 45
  }
]
```

### CSV Format

One row per flow, with a header row. Columns:

```
protocol, endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port,
first_seen, last_seen, duration_secs, packets_a_to_b, packets_b_to_a,
bytes_a_to_b, bytes_b_to_a, packets_total, bytes_total, avg_bps,
tcp_state, client, retransmissions, out_of_order,
rtt_last_ms, rtt_min_ms, rtt_ewma_ms, rtt_samples
```

Example row:

```
tcp,192.168.1.42,54321,93.184.216.34,443,1706123400.123456,1706123460.654321,60.530865,150,200,12400,485000,350,497400,65712.300,established,a_to_b,2,0,15.200,12.800,14.100,45
```

The CSV export currently writes plain comma-separated fields without quoting/escaping. This is safe for the current schema because fields are numeric values, enum labels, and IP addresses.
If you need strict CSV quoting/escaping for downstream ingestion, prefer the JSON export or post-process the CSV with a CSV library.

### Field Reference

| Field                               | Type           | Description                                                                                              |
| ----------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------- |
| `protocol`                          | string         | `"tcp"` or `"udp"`.                                                                                      |
| `endpoint_a` / `endpoint_b`         | object         | IP + port. Endpoint A is the canonically "smaller" endpoint.                                             |
| `first_seen` / `last_seen`          | float          | Unix timestamps with microsecond precision.                                                              |
| `duration_secs`                     | float          | `last_seen - first_seen`.                                                                                |
| `packets_a_to_b` / `packets_b_to_a` | int            | Packet counts per direction.                                                                             |
| `bytes_a_to_b` / `bytes_b_to_a`     | int            | Byte counts per direction (wire length).                                                                 |
| `packets_total` / `bytes_total`     | int            | Sum of both directions.                                                                                  |
| `avg_bps`                           | float          | Average bits per second over the flow's duration.                                                        |
| `tcp_state`                         | string or null | TCP state: `syn_sent`, `syn_ack`, `established`, `fin_wait`, `closed`, `reset`, `unknown`. Null for UDP. |
| `client`                            | string or null | Which side initiated: `"a_to_b"` or `"b_to_a"`. Null if no SYN was observed.                             |
| `retransmissions`                   | int            | Detected TCP retransmissions.                                                                            |
| `out_of_order`                      | int            | Detected out-of-order segments.                                                                          |
| `rtt_last_ms`                       | float or null  | Most recent RTT sample (ms).                                                                             |
| `rtt_min_ms`                        | float or null  | Minimum observed RTT (ms).                                                                               |
| `rtt_ewma_ms`                       | float or null  | EWMA RTT (ms).                                                                                           |
| `rtt_samples`                       | int            | Number of RTT samples collected.                                                                         |

## Alert Export (JSONL)

Write anomaly alerts to a JSON Lines file:

Anomaly alerts are supported in inline mode only; pipeline mode rejects anomaly-enabled runs before capture.

```bash
sudo netscope --anomalies --alerts-jsonl alerts.jsonl
```

Each line is a standalone JSON object:

```json
{"schema_version":1,"ts":1706123456.789,"kind":"syn_flood","source_ip":null,"target_ip":"10.0.0.1","target_port":443,"window_secs":5.0,"thresholds":{"syn_count":200,"unique_sources":50,"unique_ports":null,"unique_hosts":null},"observed":{"syn_count":250,"unique_sources":60,"unique_ports":null,"unique_hosts":null},"description":"SYN flood suspected: 250 syns, 60 sources to 10.0.0.1:443"}
{"schema_version":1,"ts":1706123470.123,"kind":"port_scan","source_ip":"10.0.0.99","target_ip":null,"target_port":null,"window_secs":10.0,"thresholds":{"syn_count":null,"unique_sources":null,"unique_ports":25,"unique_hosts":10},"observed":{"syn_count":null,"unique_sources":null,"unique_ports":30,"unique_hosts":1},"description":"Port scan suspected: 30 ports, 1 hosts from 10.0.0.99"}
```

See [Anomaly Detection](anomaly-detection.md) for details on alert types and thresholds.

## Expired Flow Export (JSONL)

Write continuously expired or evicted flows to a JSON Lines file:

Works in both inline and pipeline modes.

```bash
sudo netscope --expired-flows-jsonl expired-flows.jsonl
```

Each line is a standalone JSON object with `reason` (`"timeout"` or `"eviction"`) plus the flow snapshot fields:

```json
{
  "ts": 1706123500.25,
  "reason": "timeout",
  "protocol": "tcp",
  "endpoint_a": { "ip": "10.0.0.5", "port": 51514 },
  "endpoint_b": { "ip": "10.0.0.10", "port": 443 },
  "first_seen": 1706123492.11,
  "last_seen": 1706123498.98,
  "duration_secs": 6.87,
  "packets_a_to_b": 12,
  "packets_b_to_a": 9,
  "bytes_a_to_b": 1640,
  "bytes_b_to_a": 9020,
  "packets_total": 21,
  "bytes_total": 10660,
  "avg_bps": 12417.17,
  "tcp_state": "established",
  "client": "a_to_b",
  "retransmissions": 0,
  "out_of_order": 0,
  "rtt_last_ms": 2.1,
  "rtt_min_ms": 1.8,
  "rtt_ewma_ms": 2.0,
  "rtt_samples": 5
}
```

## Expired Flow Export (CSV)

Write continuously expired or evicted flows to a CSV file:

Works in both inline and pipeline modes.

```bash
sudo netscope --expired-flows-csv expired-flows.csv
```

The CSV stream includes a header row. Columns are `ts` and `reason` followed by the standard flow CSV columns:

```
ts,reason,protocol,endpoint_a_ip,endpoint_a_port,endpoint_b_ip,endpoint_b_port,first_seen,last_seen,duration_secs,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,packets_total,bytes_total,avg_bps,tcp_state,client,retransmissions,out_of_order,rtt_last_ms,rtt_min_ms,rtt_ewma_ms,rtt_samples
```

Example row:

```
1706123500.250000,timeout,tcp,10.0.0.5,51514,10.0.0.10,443,1706123492.110000,1706123498.980000,6.870000,12,9,1640,9020,21,10660,12417.170,established,a_to_b,0,0,2.100,1.800,2.000,5
```

The CSV output uses the same plain comma-separated formatting as the flow table export (no quoting/escaping). The header is written once if the file is empty; appending to an existing file does not repeat the header.
