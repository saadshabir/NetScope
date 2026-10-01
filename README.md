# NetScope

NetScope is a Rust packet and flow investigation tool. It reads a PCAP or captures live traffic, tracks bidirectional TCP/UDP flows, reports two configurable anomaly heuristics, and can serve an optional local dashboard. Offline analysis is the rootless, reproducible starting point.

Use the pinned Rust toolchain and libpcap development headers ([setup instructions](docs/quickstart.md#build-requirements)). Run these commands from the repository root:

```sh
cargo build --locked --release
./target/release/netscope --read-pcap examples/pcaps/normal.pcap --quiet \
  --summary-json /tmp/netscope-summary.json \
  --export-json /tmp/netscope-flows.json
```

The checked-in trace contains eight synthetic packets across one TCP/TLS and one UDP/DNS flow. It is small, deterministic, and requires no capture privileges. See [all PCAP investigations](examples/README.md) for expected fields and parser-edge cases.

Live capture requires permission to read the interface, usually `sudo` or Linux `CAP_NET_RAW`. The dashboard binds to `127.0.0.1` by default. See [Quickstart](docs/quickstart.md) for setup, live capture, and troubleshooting.

## Documentation

- [Quickstart](docs/quickstart.md): build, first PCAP, live permissions, and troubleshooting.
- [Reference](docs/reference.md): config precedence, output retention, summary semantics, and dashboard endpoints.
- [Design](docs/design.md): parsing scope, flows, anomalies, pipeline, and dashboard boundaries.
- [Performance](docs/performance.md): reproducible offline measurements and the Linux live-loss procedure.
- [Tool comparison](docs/comparison.md): commands against the same sample PCAP and tool-selection guidance.
- [Changelog](CHANGELOG.md): release history and cleanup record.

## License

MIT. See [LICENSE](LICENSE). Chart.js is vendored for the embedded dashboard; its license is retained at [`web/static/vendor/chartjs/LICENSE.md`](web/static/vendor/chartjs/LICENSE.md).
