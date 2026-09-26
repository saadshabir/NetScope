# Troubleshooting

This page focuses on common problems after initial setup. For install steps, first-run commands, and permission setup, see [Getting Started](getting-started.md).

Commands below assume `netscope` is on your PATH. If you built from source and did not install it, replace `netscope` with `./target/release/netscope`.

## Permission Errors

**Symptom:** `error: pcap error: ...permission denied` or `no interfaces found`.

**Cause:** Packet capture requires elevated privileges.

**Fix:**

```bash
# Quickest fix
sudo netscope
```

If you want a persistent Linux capability-based setup instead of running with `sudo`, see [Getting Started](getting-started.md#permissions).

## No Interfaces Listed

**Symptom:** `--list-interfaces` shows no interfaces.

**Fix:** Run with the same elevated privileges described in [Getting Started](getting-started.md#permissions). Without root access, libpcap cannot enumerate interfaces on most systems.

## Configuration Errors

**Symptom:** NetScope exits immediately with an error like:

- `configuration error: capture.interface and capture.read_pcap are mutually exclusive`
- `configuration error: offline capture requires capture.read_pcap path`

**Cause:** Invalid or inconsistent capture configuration.

**Fixes:**

1. Set **at most one** of `--interface` / `capture.interface` and `--read-pcap` / `capture.read_pcap`.
2. For offline analysis, always provide a pcap path via `--read-pcap <PATH>` (or `capture.read_pcap` in TOML).
3. If you intend to use live capture but set `capture.read_pcap = ""`, that disables offline mode (empty strings are treated as unset) and NetScope will fall back to the default interface unless `capture.interface` is specified.

## No Packets Captured

Possible causes:

1. **Wrong interface** -- Use `--list-interfaces` to find the correct name, then `-i <name>`.
2. **BPF filter too restrictive** -- Remove the filter temporarily to confirm traffic exists.
3. **No traffic** -- Run `sudo tcpdump -i <interface> -c 10` to verify the interface has traffic.
4. **Firewall** -- Some firewalls block promiscuous mode. Try `--no-promiscuous`.

## Unsupported Datalink Type

**Symptom:** NetScope prints something like `Datalink: Unsupported(<n>)` at startup, and the summary shows a high `Parse errors` count (often equal to the number of captured packets).

**Cause:** The capture interface or pcap file uses a link-layer format NetScope does not currently decode.

**Fixes:**

1. Prefer capturing on a specific interface (for example `-i eth0`) instead of pseudo-devices that may use uncommon datalink formats.
2. If you are generating pcaps with `tcpdump`, consider forcing a supported datalink type via `-y` (for example `-y EN10MB` for Ethernet or `-y LINUX_SLL` for Linux cooked capture v1).
3. For existing pcaps, re-capture with a supported link type when possible.

Supported datalink types currently include Ethernet, Linux SLL, loopback NULL/LOOP, and raw IP.

Note: raw-IP pcaps are commonly tagged as link type `101` or `12` depending on the tool; NetScope treats both as raw IP.

## High Kernel Drop Rate

**Symptom:** Summary shows high `Kernel dropped` count or drop rate.

**Causes and fixes:**

- **Processing too slow** -- Enable pipeline mode (`--pipeline`).
- **Too much traffic** -- Apply a BPF filter (`-f "tcp port 443"`).
- **Per-packet output** -- Use `--quiet` to skip terminal printing.
- **Hex dump enabled** -- Disable `--hex-dump` in high-traffic captures.

## High Dispatch Drops (Pipeline Mode)

**Symptom:** Summary shows high `Dispatch drops` count.

**Causes and fixes:**

- **Channel too small** -- Increase `channel_capacity` in config (default: 4096).
- **Not enough workers** -- Increase `--workers`.
- **Uneven shard distribution** -- Some 5-tuples may hash to the same shard. This is expected with a small number of active flows. Use a BPF filter to reduce volume.

## Capture Stops With Pcap Write Error

**Symptom:** Capture exits with an error like `pcap write error` or `pcap flush error` while `--write-pcap` is enabled.

**Cause:** NetScope now treats pcap write/flush failures as fatal to avoid silent output corruption or data loss.

**Fixes:**

1. Ensure the output path exists and is writable.
2. Verify there is enough free disk space (`df -h`).
3. Capture to a faster or local filesystem.
4. Enable bounded rotation for long captures: `--write-pcap-rotate-mb <MB> --write-pcap-max-files <N>` (writes numbered segments and deletes the oldest when the limit is reached).
5. Disable `--write-pcap` if raw packet archiving is not required.

## Web Dashboard Not Reachable

**Symptom:** Browser shows "connection refused" at `http://127.0.0.1:8080` (or `https://...` when TLS is enabled).

**Fixes:**

1. Verify `--web` flag is present.
2. Check the terminal for `Web dashboard: http://...` or `Web dashboard: https://...` confirmation.
3. Check for port conflicts: `lsof -i :8080`.
4. If accessing from another machine, use `--web-bind 0.0.0.0`.

## Web Dashboard TLS Startup Error

**Symptom:** Startup prints an error about TLS cert/key path or fails to start HTTPS listener.

**Fixes:**

1. Ensure `web.tls.cert_path` and `web.tls.key_path` are set when `web.tls.enabled = true`.
2. Verify both files exist and are readable by the NetScope process.
3. Ensure certificate/key are PEM-formatted and match each other.

## Web Dashboard Returns 401 Unauthorized

**Symptom:** Browser or API client receives `401 Unauthorized` from dashboard endpoints.

**Causes:**

1. `web.auth.enabled = true` but no/invalid HTTP Basic credentials were provided.
2. Username/password mismatch between browser/client and NetScope config.
3. `password_file` content changed without restarting NetScope.

**Fixes:**

1. Verify `web.auth.username` and secret source (`password` or `password_file`) are correct.
2. If using `password_file`, ensure the file contains only the password (trailing newline is fine).
3. Retry with explicit credentials in a terminal client for isolation, for example:

```bash
curl -u netscope:YOUR_PASSWORD https://127.0.0.1:8443/api/health
curl -u netscope:YOUR_PASSWORD https://127.0.0.1:8443/metrics
```

## Web Dashboard Shows No Data

**Symptom:** Dashboard connects but shows `--` for all metrics and no packets.

**Causes:**

1. **No traffic** -- Verify packets are being captured (check terminal output without `--quiet`).
2. **`sample_rate = 0`** -- This disables the packet feed entirely. Set to 1 or higher.
3. **Filter too restrictive** -- Remove the BPF filter temporarily.
4. **Pipeline mode timing** -- The aggregator tries to merge all shard updates for a tick, but it also forces a merge shortly after the tick deadline so idle shards do not stall the dashboard.

Note: `sample_rate = 0` disables live packet samples only; stats and alerts can still continue to update. Metrics can also lag slightly during uneven traffic, but completely idle shards should not block frames indefinitely.

## Web Dashboard Laggy or Dropping Data

**Symptom:** Charts stutter, packet list has gaps, or TRACE logs show `web event channel full`.

**Fixes:**

- Increase `sample_rate` (e.g., 10 or 100) to reduce packet feed volume.
- In pipeline mode, sampling is still capture-wide, so raising `sample_rate` reduces total samples rather than samples per shard.
- Reduce `top_n` to send fewer flows per tick.
- Increase `tick_ms` to reduce update frequency.
- Reduce `payload_bytes` to store less data per packet.
- Open `/?perf=1` to inspect fps, latency percentiles, dropped frames, and client/server clock offset while tuning.

## Anomaly Alerts Not Firing

**Causes:**

1. **Anomalies not enabled** -- Ensure `--anomalies` flag is present or `analysis.anomalies.enabled = true`.
2. **Thresholds too high** -- Lower `syn_threshold` or `unique_ports_threshold` for testing.
3. **Cooldown active** -- After an alert fires, subsequent alerts for the same key are suppressed for `cooldown_secs`.
4. **Pipeline mode** -- Anomaly detection is unsupported in pipeline mode. NetScope rejects the combination before capture; disable pipeline or set `[analysis.anomalies].enabled = false`.

## Flow Export is Empty

**Causes:**

1. **No flows tracked** -- Only TCP and UDP traffic creates flow entries. ARP, ICMP, and ICMPv6 do not.
2. **All flows expired** -- If capture runs long enough with `flow.timeout_secs` set low, flows may expire before export.
3. **Fragmented traffic** -- IPv4 and IPv6 non-initial fragments are skipped for flow tracking.

## Timestamps Show Wrong Time

NetScope formats timestamps as `HH:MM:SS.microseconds` derived from pcap timestamps (seconds since Unix epoch). These are UTC-based. If times look wrong, verify your system clock and consider that pcap timestamps come from the kernel, not application code.

## Build Errors

### `pcap.h not found`

libpcap headers or developer tools are missing. See [Getting Started](getting-started.md#installing-libpcap) for platform-specific installation steps.

### Rust version too old

NetScope pins Rust via `rust-toolchain.toml` (currently 1.93.1; edition 2024). Install the pinned toolchain with:

```bash
rustup toolchain install 1.93.1
```

If you plan to run the repo quality checks, also install:

```bash
rustup component add rustfmt clippy --toolchain 1.93.1
```

See [Getting Started](getting-started.md#prerequisites) for the current baseline toolchain requirements.
