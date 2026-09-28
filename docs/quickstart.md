# Quickstart

Build NetScope and analyze the checked-in synthetic capture without elevated privileges:

```sh
cargo build --locked --release
./target/release/netscope \
  --read-pcap examples/pcaps/normal.pcap \
  --quiet \
  --summary-json /tmp/netscope-summary.json \
  --export-json /tmp/netscope-flows.json
```

The trace contains eight Ethernet frames: one TCP flow with a packet-level TLS ClientHello and one UDP DNS exchange. The summary should report eight frames, zero packet parse errors, and zero alerts. The flow export should contain two flows. The [investigations](../examples/README.md) show the expected fields and limits in more detail.

## Build requirements

Use the Rust toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) and install libpcap development headers if your platform does not provide them. On Debian or Ubuntu:

```sh
sudo apt-get install libpcap-dev
```

macOS provides libpcap with the Xcode Command Line Tools. See the [Rust install guide](https://www.rust-lang.org/tools/install) if `cargo` is unavailable.

## Live capture

Live capture needs permission to read the interface, usually `sudo` on Linux and macOS. List interfaces, then choose one and apply a BPF capture filter:

```sh
sudo ./target/release/netscope --list-interfaces
sudo ./target/release/netscope --interface eth0 --filter 'tcp port 443' --quiet --stats
```

Replace `eth0` with an interface shown by the first command. On Linux, a deployment may grant `CAP_NET_RAW` instead of running the process as root. Offline `--read-pcap` analysis does not need capture privileges.

## Common tasks

```sh
# Filter and write a smaller PCAP without root.
./target/release/netscope --read-pcap input.pcap --filter 'tcp port 443' \
  --write-pcap filtered.pcap --quiet

# Track flows with worker sharding; offline file input applies backpressure.
./target/release/netscope --read-pcap input.pcap --pipeline --workers 4 \
  --quiet --summary-json /tmp/pipeline-summary.json

# Start the local dashboard (default: http://127.0.0.1:8080).
sudo ./target/release/netscope --web --quiet
```

Anomaly detection is supported in inline mode. NetScope rejects pipeline runs when an anomaly detector is enabled. The dashboard binds to loopback by default; use the [TLS and authentication example](reference.md#remote-dashboard) before exposing it beyond the local machine.

## If something fails

- `pcap.h` is missing: install the platform's libpcap development package and rebuild.
- Live capture reports permission denied: rerun with the required interface privileges; offline PCAP analysis does not need them.
- Every packet is reported as unsupported: check the capture's link type. NetScope supports Ethernet, Linux SLL v1, NULL/LOOP loopback, and raw IP.
- No anomaly alert appears: verify the detector is enabled and its thresholds fit the trace. Pipeline plus enabled anomaly detection is rejected before input is opened.
- A flow export is empty: only TCP and UDP create flows; ARP, ICMP, and ICMPv6 are decoded without flow records.

Run `./target/release/netscope --help` for the complete current option list. See [Reference](reference.md) for config and output behavior, and [Design](design.md) for protocol and mode limits.
