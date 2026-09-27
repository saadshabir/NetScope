# Quickstart

## Build and run an offline trace

Requirements: the Rust toolchain pinned in `rust-toolchain.toml` and libpcap headers. Install libpcap with `sudo apt-get install libpcap-dev` on Debian/Ubuntu, `sudo dnf install libpcap-devel` on Fedora, or `sudo pacman -S libpcap` on Arch. macOS includes libpcap; install the Xcode Command Line Tools if its headers are missing.

From the repository root:

```sh
cargo build --locked --release
./target/release/netscope --read-pcap examples/pcaps/normal.pcap --quiet
```

`--read-pcap` works without elevated privileges. Add `--summary-json /tmp/netscope-summary.json` for final machine-readable accounting, or `--export-json /tmp/netscope-flows.json` to save the flow table. The four small sample captures are synthetic and can be regenerated or hash-checked with `python3 scripts/generate_examples.py --check`.

## Common investigations

Apply a BPF filter and limit the number of packets read:

```sh
./target/release/netscope --read-pcap trace.pcap --filter 'tcp port 443' --count 10000 --quiet
```

Export flows and enable the inline anomaly heuristics:

```sh
./target/release/netscope \
  --read-pcap examples/pcaps/port-scan.pcap \
  --config examples/anomaly-demo.toml \
  --quiet \
  --summary-json /tmp/netscope-summary.json \
  --export-json /tmp/netscope-flows.json \
  --alerts-jsonl /tmp/netscope-alerts.jsonl
```

See the [investigation guide](../examples/README.md) for expected fields and the limits of each sample. Use `netscope --help` for the complete flag list; the consolidated defaults and option notes are in the [CLI appendix](streamlining-plan.md#cli-reference).

## Live capture and dashboard

Live capture needs access to the selected interface, typically `sudo` on Linux and macOS. On Linux, a deployment may grant `CAP_NET_RAW` to the binary instead. List interfaces and start a filtered capture with:

```sh
sudo ./target/release/netscope --list-interfaces
sudo ./target/release/netscope --interface eth0 --filter 'tcp port 443' --stats
```

Press Ctrl-C to stop. To use the dashboard, add `--web --quiet` and open <http://127.0.0.1:8080>. It binds to loopback by default. Remote access should use TLS and authentication; see the [web settings](reference.md#web) and [dashboard design notes](design.md#dashboard).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Permission denied or no interfaces listed | Confirm capture permissions and the interface name. Offline PCAP reads do not need them. |
| No packets appear | Check the selected interface, BPF filter, and whether the trace contains matching traffic. |
| Unsupported datalink type | NetScope currently parses Ethernet, Linux SLL, loopback NULL/LOOP, and raw IP. |
| Config file is rejected | TOML keys are case-sensitive; compare sections and defaults with the [reference](reference.md) and `netscope.example.toml`. |
| Flow export is empty | Check the input summary for malformed or unsupported headers and confirm the capture includes a supported TCP or UDP packet. |
| Dashboard is unreachable | Check that `--web` is enabled, use the configured port, and keep the loopback bind when connecting locally. |

For parser depth, counters, exports, and mode behavior, see [Reference](reference.md) and [Design](design.md). The [Performance guide](performance.md) covers reproducible measurements and the Linux-only live-loss procedure.
