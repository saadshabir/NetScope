# NetScope

NetScope is a Rust and libpcap tool for reading packet captures, summarizing bidirectional flows, and inspecting a small set of protocol and anomaly signals. Offline analysis runs without capture privileges; live capture and the optional local dashboard are available when needed.

Build and inspect the checked-in sample without root:

```sh
cargo build --locked --release
./target/release/netscope --read-pcap examples/pcaps/normal.pcap --quiet
```

The parser supports Ethernet, Linux SLL, loopback, and raw IP captures, with bounded IPv6 extension walking. DNS inspection is limited to UDP/53; TLS SNI is best-effort from a complete ClientHello in one packet. SYN-flood and port-scan alerts are threshold heuristics supported in inline mode. See [Design](docs/design.md) for behavior and limits.

## Guides

- [Quickstart](docs/quickstart.md) — build, first run, common commands, permissions, and troubleshooting.
- [Synthetic PCAP investigations](examples/README.md) — normal traffic, the anomaly heuristics, and parser boundaries.
- [Reference](docs/reference.md) — configuration defaults and schemas, exports, and command-line pointers.
- [Design](docs/design.md) — processing modes, flows, protocol depth, anomalies, dashboard, and contributor notes.
- [Performance](docs/performance.md) — reproducible offline measurements and the separate live-loss procedure.
- [Tool comparison](docs/comparison.md) — what NetScope, tcpdump, TShark/Wireshark, Zeek, and Suricata are suited to.

Active implementation record: [streamlining plan](docs/streamlining-plan.md).

## License

MIT License. See [LICENSE](LICENSE). The dashboard vendors Chart.js; its license is in `web/static/vendor/chartjs/LICENSE.md`.
