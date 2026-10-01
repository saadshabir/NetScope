# Tool comparison

Run each command below against the same checked-in [normal trace](../examples/pcaps/normal.pcap). The trace contains synthetic TCP/TLS and UDP/DNS traffic; it is intentionally small so differences are easy to inspect. These tools answer different questions, so this is a role comparison rather than a speed ranking.

| Tool | Setup for this workflow | Good fit | Output and boundary |
| --- | --- | --- | --- |
| **NetScope** | Build the checked-out Rust project once. | A small Rust codebase for bidirectional flow counters, a versioned run summary, two configurable anomaly heuristics, and an optional local dashboard. | Narrow protocol depth; DNS is UDP/53 only, TLS SNI is packet-level, and no general TCP stream reassembly is provided. |
| **tcpdump** | Install the command-line utility. | Capturing, filtering, printing, and writing packets with a compact command-line workflow. | Primarily packet-level output; no NetScope-style flow table or dashboard. |
| **TShark / Wireshark** | Install TShark; Wireshark adds the interactive GUI. | Broad protocol dissection, display filters, selectable fields, and statistics. | Better choice when investigation needs dissectors or packet detail beyond NetScope's focused parser. |
| **Zeek** | Install Zeek and run it in a clean output directory. | Network security monitoring that turns packet streams into connection and protocol logs and can be extended with scripts. | Produces structured event logs rather than a packet-list-first workflow; broader policy/script environment. |
| **Suricata** | Install Suricata and configure its YAML and rules for alerting. | Rule-based network IDS/IPS, protocol events, and EVE JSON output. | Detection depends on installed rules and configuration; it is not a like-for-like flow-table benchmark against NetScope. |

## Same-file commands

Build NetScope once. The sample file is classic Ethernet PCAP and needs no capture privileges:

```sh
cargo build --locked --release
PCAP="$(pwd)/examples/pcaps/normal.pcap"
OUT="$(mktemp -d)"
```

NetScope shows the run summary and writes final run and flow records:

```sh
./target/release/netscope --read-pcap "$PCAP" --quiet \
  --summary-json "$OUT/netscope-summary.json" \
  --export-json "$OUT/netscope-flows.json"
```

The summary accounts for eight input frames; the flow export contains one TCP and one UDP flow. Use the [investigation guide](../examples/README.md) for exact DNS/SNI and directional flow expectations.

Use tcpdump to print the packet-level view or apply a BPF filter to the same file:

```sh
tcpdump -nn -r "$PCAP"
tcpdump -nn -r "$PCAP" 'tcp port 443'
```

TShark can select decoded fields or collect protocol statistics:

```sh
tshark -n -r "$PCAP" -T fields -E header=y \
  -e frame.number -e frame.protocols -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
  -e dns.qry.name -e tls.handshake.extensions_server_name
tshark -n -r "$PCAP" -q -z io,phs
```

Run Zeek in a dedicated output directory to get structured connection and applicable protocol logs:

```sh
mkdir -p "$OUT/zeek"
(cd "$OUT/zeek" && zeek -r "$PCAP" LogAscii::use_json=T)
```

Run Suricata in offline PCAP mode and keep logs separate from the other tools:

```sh
mkdir -p "$OUT/suricata"
suricata -r "$PCAP" -l "$OUT/suricata"
```

Suricata's alert output depends on the installed rule set and `suricata.yaml`; a quiet synthetic trace is not expected to trigger an alert by itself. EVE can also emit protocol and flow events when enabled in that configuration.

The commands intentionally inspect different outputs: packet records (tcpdump/TShark), flow and alert summaries (NetScope), protocol logs (Zeek), and IDS events (Suricata). Output volume, analysis semantics, default rules, and installed dependencies differ, so elapsed-time comparisons would not be meaningful without a task-specific setup. No comparative timing claim is made here.

## References

- [tcpdump manual](https://manpages.debian.org/trixie/tcpdump/tcpdump.8.en.html): capture filters and `-r` / `-w` file handling.
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark): saved-file input, field output, display filters, and statistics.
- [Zeek quick start](https://docs.zeek.org/en/master/quickstart.html) and [command-line invocation](https://docs.zeek.org/en/master/tutorial/invoking-zeek.html): reading PCAPs and writing logs.
- [Suricata command-line options](https://docs.suricata.io/en/latest/command-line-options.html), [offline PCAP example](https://docs.suricata.io/en/latest/manpages/suricata.html), and [EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html).
- [What is Suricata?](https://docs.suricata.io/en/latest/what-is-suricata.html): project overview of its IDS, IPS, and network-security roles.

TShark, Zeek, and Suricata are not installed on the macOS host used for this repository's current run. Their commands above are matched to each tool's current official documentation; they have not been executed locally. tcpdump is available for the packet-level command.
