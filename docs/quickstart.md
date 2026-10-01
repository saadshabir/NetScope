# Quickstart

Run the commands below from the repository root.

## Build requirements

Use the Rust toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) and install libpcap development headers if your platform does not provide them. On Debian or Ubuntu:

```sh
sudo apt-get install libpcap-dev
```

macOS provides libpcap with the Xcode Command Line Tools. See the [Rust install guide](https://www.rust-lang.org/tools/install) if `cargo` is unavailable.

## First offline run

Build NetScope and analyze the checked-in synthetic capture without elevated privileges:

```sh
cargo build --locked --release
./target/release/netscope \
  --read-pcap examples/pcaps/normal.pcap \
  --quiet \
  --summary-json /tmp/netscope-summary.json \
  --export-json /tmp/netscope-flows.json
```

The trace contains eight Ethernet frames: one TCP flow with a packet-level TLS ClientHello and one UDP DNS exchange. The summary should report `status = "success"`, `frames_read = 8`, `packet_parse_errors = 0`, `alerts_emitted = 0`, and `output_errors = []`. The flow export should contain two flows. With Python 3 available, inspect both files:

```sh
python3 -m json.tool /tmp/netscope-summary.json
python3 -m json.tool /tmp/netscope-flows.json
```

Offline input runs as fast as it can and exits at EOF; it does not replay the original packet timing. The [investigations](../examples/README.md) show the expected fields and limits in more detail.

## Live capture

Live capture needs permission to read the interface, usually `sudo` on Linux and macOS. List interfaces, then choose one and apply a BPF capture filter:

```sh
sudo ./target/release/netscope --list-interfaces
sudo ./target/release/netscope --interface eth0 --filter 'tcp port 443' --quiet --stats
```

Replace `eth0` with an interface shown by the first command. On Linux, a deployment may grant `CAP_NET_RAW` instead of running the process as root. Offline `--read-pcap` analysis does not need capture privileges.

Stop live capture with Ctrl-C to drain workers and write final exports. Add `--count 1000` to stop after 1,000 input frames instead. The count applies after the BPF filter; it includes frames that cannot be fully decoded.

## Common tasks

```sh
# Filter and write a smaller PCAP without root.
./target/release/netscope --read-pcap input.pcap --filter 'tcp port 443' \
  --write-pcap filtered.pcap --quiet

# Track flows with worker sharding; offline file input applies backpressure.
./target/release/netscope --read-pcap input.pcap --pipeline --workers 4 \
  --quiet --summary-json /tmp/pipeline-summary.json

# Save removed flows during the run and retained flows on exit.
./target/release/netscope --read-pcap input.pcap --quiet \
  --expired-flows-jsonl /tmp/expired-flows.jsonl \
  --export-json /tmp/retained-flows.json

# Start the local dashboard (default: http://127.0.0.1:8080).
sudo ./target/release/netscope --interface eth0 --web --quiet
```

Anomaly detection is supported in inline mode. NetScope rejects pipeline runs when an anomaly detector is enabled. Use `--no-anomalies` to override an enabled detector in a config file. For a rootless alert example, follow the [port-scan investigation](../examples/README.md#port-scan-heuristic).

The dashboard is available while the capture process runs and closes when capture ends; a short offline trace may finish before a browser connects. Open [the local dashboard](http://127.0.0.1:8080) during live capture. See [dashboard endpoints](reference.md#dashboard-endpoints) for health and metrics commands, and use the [TLS and authentication example](reference.md#remote-dashboard) before exposing it beyond the local machine.

## If something fails

- `pcap.h` is missing: install the platform's libpcap development package and rebuild.
- Live capture reports permission denied: rerun with the required interface privileges; offline PCAP analysis does not need them.
- Every packet is reported as unsupported: check the capture's link type. NetScope supports Ethernet, Linux SLL v1, NULL/LOOP loopback, and raw IP.
- No anomaly alert appears: verify the detector is enabled and its thresholds fit the trace. Pipeline plus enabled anomaly detection is rejected before input is opened.
- A flow export is empty: only TCP and UDP create flows; ARP, ICMP, and ICMPv6 are decoded without flow records.
- Flows are missing from the final export: expired or evicted flows have left the table. Enable an expired-flow sink as well as the final export to retain both sets of records.
- An output cannot be opened: create its parent directory and check write permissions. Relative paths are resolved from the working directory, including paths in TOML.
- The dashboard cannot bind its port: choose another port with `--web-port 8081` and open that port in the browser.

Run `./target/release/netscope --help` for the complete current option list. See [Reference](reference.md) for config and output behavior, and [Design](design.md) for protocol and mode limits.
