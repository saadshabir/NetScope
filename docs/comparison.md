# Choosing a packet inspection tool

NetScope is a small, focused option for repeatable PCAP investigations and flow summaries. It does not replace a general packet dissector, a network security monitoring platform, or a signature IDS/IPS. Choose the tool by the question you need to answer.

## At a glance

| Tool | Best fit | What it produces from the sample below | Setup and boundary |
| --- | --- | --- | --- |
| NetScope | A compact offline investigation with packet accounting, bidirectional flows, narrow DNS/TLS details, optional exports, and a live dashboard. | Packet details, a final run summary, and a JSON flow export: eight frames, two flows, and no alerts with the demo anomaly settings enabled. | Build the repository once. Offline PCAP reading needs no capture privileges. Protocol and link-layer support are deliberately narrower than Wireshark/TShark. |
| `tcpdump` | Quickly capture, filter, print, count, or write packets with BPF syntax. | One text summary per matching packet; the sample's TCP/443-or-DNS filter selects all eight packets. | Commonly available with libpcap. Offline reads need no capture privileges. Its normal output is packet-oriented rather than a flow or event log. |
| TShark / Wireshark | Broad protocol dissection, display filters, packet details, and protocol/conversation statistics. Use TShark for scripts and Wireshark for interactive inspection. | TShark can emit selected fields for each packet; Wireshark opens the same trace as a packet list and detail tree. | Install Wireshark (which includes TShark) or the TShark package. It exposes much broader protocol detail than NetScope. |
| Zeek | Network security monitoring and structured connection and protocol logs that are easy to pivot or feed into other systems. | Logs such as `conn.log`, `dns.log`, and `ssl.log`, rather than one line per packet. | Install Zeek; `zeek-cut` is included for reading its tab-separated logs. Zeek's event-driven logs answer different questions from a packet viewer. |
| Suricata | Rule-based IDS/IPS and network security events, including alert output in EVE JSON. | EVE records depend on enabled output types, loaded rules, and what the trace matches. A benign trace does not imply that detection is working. | Install and configure Suricata, its EVE outputs, and a rule set for signature alerts. Offline replay does not require live-capture privileges. |

All tools below use the same checked-in synthetic classic Ethernet PCAP. It has eight packets and 618 wire bytes; its SHA-256 is `2008c03cc5ccf77b16545c52bec1b0d632bedc6380e9f5c1cada9b9be19041e3`. The fixture contains a six-packet TCP exchange with a single-packet TLS ClientHello, plus a two-packet DNS A query and response. It contains no traffic captured from a user or network. See the [fixture manifest](../examples/pcaps/manifest.json) and [investigation guide](../examples/README.md).

From the repository root, set the shared input path:

```sh
PCAP=examples/pcaps/normal.pcap
```

## Commands and expected views

### NetScope

Build once, then print packet details and produce the run summary and flow export. The fixture's demo config enables anomaly detection with thresholds intended only for these synthetic examples:

```sh
cargo build --locked --release
./target/release/netscope \
  --read-pcap "$PCAP" \
  --config examples/anomaly-demo.toml \
  --no-quiet \
  --summary-json /tmp/netscope-normal-summary.json \
  --export-json /tmp/netscope-normal-flows.json
```

The summary reports eight frames and 618 input wire bytes, eight network and transport headers, zero parse errors, two flows, and zero alerts with anomaly detection enabled. The flow export has one TCP flow with six packets and one UDP flow with two packets. The packet output shows DNS details and the SNI `api.example.test`; the TLS result is based on a complete ClientHello in one captured TCP payload, not stream reassembly.

### tcpdump

Print the whole trace, apply a BPF filter, or write the matching packets to another PCAP:

```sh
tcpdump -nn -tttt -r "$PCAP"
tcpdump -nn -tttt -r "$PCAP" 'tcp port 443 or udp port 53'
tcpdump -r "$PCAP" -w /tmp/netscope-normal-filtered.pcap 'tcp port 443 or udp port 53'
```

The filtered print produces eight packet summaries: TCP flags, sequence and acknowledgment numbers, lengths, and the DNS question/answer. The output is useful for a quick packet-level view or for creating a filtered capture. It does not aggregate packets into NetScope-style flow records.

### TShark and Wireshark

Use a Wireshark display filter for offline selection, then select the fields needed for a report:

```sh
tshark -r "$PCAP" \
  -Y 'tcp.port == 443 || dns' \
  -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
  -e dns.qry.name -e tls.handshake.extensions_server_name
```

This selects the same eight packets and emits tab-separated decoded fields. The SNI field is populated for the packet carrying the complete ClientHello. To get protocol hierarchy and per-transport conversation statistics from the same trace:

```sh
tshark -r "$PCAP" -q -z io,phs -z conv,tcp -z conv,udp
```

To inspect a packet interactively, open the same file in Wireshark:

```sh
wireshark -r "$PCAP"
```

TShark and Wireshark provide a much wider set of protocol dissectors, packet details, filters, and statistics. Their displayed fields and exact text formatting depend on the installed Wireshark version and preferences.

### Zeek

Run in a fresh output directory so existing logs are not overwritten, then read the connection, DNS, and TLS logs:

```sh
repo="$PWD"
out="$(mktemp -d)"
(cd "$out" && zeek -r "$repo/$PCAP")
zeek-cut id.orig_h id.resp_h id.resp_p proto service orig_pkts resp_pkts < "$out/conn.log"
zeek-cut query qtype_name answers < "$out/dns.log"
zeek-cut server_name < "$out/ssl.log"
```

The useful output is structured activity: the two conversations and protocol-specific DNS/TLS records. Zeek writes logs to the working directory and does not print a packet list by default. Which logs and fields appear depends on the analyzers and Zeek version.

### Suricata

Replay the same file using the configuration installed on the host. The example path is common on Linux packages; pass the actual config path with `-c` if it differs:

```sh
out="$(mktemp -d)"
suricata -c /etc/suricata/suricata.yaml -r "$PCAP" -l "$out"
```

When EVE JSON and its DNS/TLS event types are enabled, inspect the protocol and alert events with:

```sh
jq -c 'select(.event_type == "alert" or .event_type == "dns" or .event_type == "tls")' "$out/eve.json"
```

Suricata's alert output is rule-dependent. Confirm that the configured rule files loaded before interpreting an empty alert stream; the normal sample is not intended to trigger an IDS signature. Suricata's purpose is to match configured detections and report security events, not to replace a general packet decoder.

## What NetScope covers, and where it stops

NetScope's useful niche is a focused Rust implementation with a short offline path: read a small PCAP without elevated privileges, classify supported headers, summarize bidirectional flows, expose a narrow set of DNS and TLS details, and optionally export JSON or view live results in a local dashboard. Its [performance page](performance.md) links reproducible offline measurements with saved input hashes, run records, and stated limitations. Those measurements describe NetScope's own workloads; they are not a head-to-head result against these tools. The Phase 5 live-capture report still has no measured Linux loss bracket.

Its limits matter when choosing it:

- Protocol coverage is narrower than Wireshark/TShark. Supported decoding is documented in the [protocol table](design.md#protocol-support-and-depth); unsupported protocols and malformed headers are accounted for rather than fully dissected.
- DNS inspection is limited to UDP port 53 and the first question. TLS SNI is extracted only when a complete ClientHello is present in one captured TCP payload. There is no general TCP stream reassembly, TLS decryption, or broad application-layer session analysis.
- SYN-flood and port-scan alerts are threshold heuristics, not signature-based detection or proof of malicious intent. Anomaly detection is currently supported in inline mode; pipeline mode rejects enabled anomaly detection.
- The reproducible examples use classic Ethernet PCAPs. Do not assume an unlisted file format or link type is supported without checking it against the implementation and a fixture.
- Live capture requires the relevant interface permissions, and observed loss depends on the operating system and capture setup. Offline benchmark results do not establish live capture capacity.

## How the comparison was checked

The fixture walkthrough was run on 2026-09-27 with the workspace's NetScope binary and `tcpdump 4.99.1` / libpcap `1.10.1`. NetScope's quiet summary reported eight frames, 618 wire bytes, two flows, and zero alerts; `tcpdump` printed eight packet lines, and its TCP/443-or-UDP/53 filter selected all eight. The demo-config command above follows the established [normal investigation](../examples/README.md#normal-traffic), which documents the DNS details and ClientHello SNI. TShark, Wireshark, Zeek, and Suricata were not installed on this host, so their commands and output descriptions are based on the official manuals linked below, not a local execution. Exact output formatting and optional logs can vary with version and configuration.

No external timing comparison is published. The eight-packet teaching fixture is too small for resource measurements, and the Phase 4 NetScope benchmarks do not represent matched TShark, Zeek, or Suricata workloads. A future timing study should use larger identical input hashes, record each tool's version and full options, match output work as closely as possible, save CPU/RSS and raw runs, and explain any remaining differences before making a performance claim.

## Primary documentation

Manuals checked on 2026-09-27:

- [tcpdump manual](https://manpages.debian.org/trixie/tcpdump/tcpdump.8.en.html)
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark)
- [Wireshark manual](https://www.wireshark.org/docs/man-pages/wireshark)
- [Zeek quick start](https://docs.zeek.org/en/master/quickstart.html), [invoking Zeek](https://docs.zeek.org/en/master/tutorial/invoking-zeek.html), and [Zeek logs](https://docs.zeek.org/en/master/tutorial/logs.html)
- [Suricata overview](https://docs.suricata.io/en/latest/what-is-suricata.html), [command-line options](https://docs.suricata.io/en/latest/command-line-options.html), and [EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
