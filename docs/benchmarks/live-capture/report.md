# Live capture and packet-loss report

**Status:** Measured on November 7, 2026 (America/Toronto; November 8 UTC). Both Linux matrices completed: **30 trials, 72,000,000 packets sent and captured, 71,999,108 frames processed, and 892 application dispatch drops**.

**Network-isolation limitation:** the [final runtime snapshot](linux-orbstack-2026-11-07/runtime-after.json) records 72,001,692 packets and 3,888,151,728 bytes transmitted on the container's `eth0`, consistent with forwarding essentially the entire synthetic workload outside the veth pair. The original forwarding setting was not recorded. Packet accounting remains valid, but these runs do not establish isolated-veth performance: the additional forwarding and Docker/VM network work can affect achieved rates and resource measurements. The [corrected rerun procedure](linux-orbstack-2026-11-07/README.md) disables IPv4 forwarding; no matrix has been rerun with that correction.

The highest requested rate with zero observed loss in all three repetitions was **400,000 packets/s**, achieved at 399,999.76–399,999.92 packets/s. However, one qualified 300,000 packets/s repetition dropped 892 frames between capture and worker processing. Results are **non-monotonic**: no single maximum or continuous zero-loss rate range is established. Targets of 500,000–1,000,000 packets/s exceeded the sender's achieved rate and cannot establish NetScope's capture capacity at those targets.

## Host and measured configuration

- Apple M4, 16 GiB host RAM, macOS 27.2; Debian 12 aarch64 container in OrbStack's Linux VM, kernel `7.2.12-orbstack-00394-gbecdd6130068`.
- Guest: 10 logical CPUs and 8,392,671,232 bytes RAM (about 7.82 GiB). Container CPU set `0-9`, no container CPU quota or memory limit. The desktop and VM were shared; existing Kubernetes CoreDNS and local-path provisioner services remained running.
- Rust/Cargo 1.93.1, libpcap 1.10.3, tcpreplay 4.4.3 with `PF_PACKET send()` injection, iproute2 6.1.0, GNU time package 1.9-0.2. The container had `NET_ADMIN` and `NET_RAW`; no host networking was used.
- Named, verified veth peers; no addresses or routes configured by the harness. The container also had an `eth0` interface; the veth pair did not establish isolation from the container's existing network. NetScope started before replay and emitted verified `NETSCOPE_READY` settings for every trial.
- Default release build with dashboard support compiled in, dashboard disabled. Two pipeline workers, queue capacity 8,192 per worker; scale-mode flow storage with unlimited flows and no expiry; TCP deep analysis, anomalies, and periodic stats disabled.
- Capture filter `ip and tcp dst port 443 and dst host 203.0.113.1`; snaplen 65,535; read timeout 20 ms; requested libpcap buffer 8 MiB; promiscuous and immediate modes disabled. Actual allocated capture-buffer size is unavailable.
- Deterministic `steady-flow` workload: one IPv4/TCP flow, 54-byte Ethernet frames, a shared five-million-packet trace with unique sequence IDs; each replay uses the finite prefix specified below. This does not exercise traffic diversity or establish physical-NIC capture performance. Traffic beyond the container's `eth0` was not measured.
- PCAP recording enabled for reconciliation. Input, captures, and build output used the container's overlay filesystem at `/bench`; the source mount at `/source` was read-only. Resource figures include PCAP writing and its filesystem/cache behavior.
- Three measured repetitions per target, ascending target order within each matrix, no separate warm-up. Minimum offered duration five seconds; minimum one million packets per trial. The intermediate matrix followed the default matrix after sender shortfalls were observed; its 1,000,000 target preserves the identical trace size and hash. Every repetition from both matrices is retained.

## Packet accounting and offered rates

Each row contains three repetitions; lists are in repetition order. Counts are **per repetition**, not totals. A repetition qualifies at its requested target only if the finite replay succeeds and achieves at least 99.5% of that target. An under-rate trial remains inconclusive at its target even when every sent packet was captured and processed.

| Matrix | Requested packets/s | Sent per repetition | Achieved packets/s, repetitions 1 / 2 / 3 | Captured per repetition | Worker processed per repetition | Dispatch drops, repetitions 1 / 2 / 3 | Target-qualified repetitions |
| --- | ---: | ---: | --- | ---: | --- | --- | ---: |
| Default | 100,000 | 1,000,000 | 100,000.08 / 100,000.07 / 100,000.02 | 1,000,000 | 1,000,000 each | 0 / 0 / 0 | 3/3 |
| Default | 250,000 | 1,250,000 | 223,310.10 / 250,000.10 / 250,000.00 | 1,250,000 | 1,250,000 each | 0 / 0 / 0 | 2/3 |
| Default | 500,000 | 2,500,000 | 430,726.73 / 430,744.84 / 433,076.43 | 2,500,000 | 2,500,000 each | 0 / 0 / 0 | 0/3 |
| Default | 750,000 | 3,750,000 | 428,539.64 / 425,423.87 / 365,438.16 | 3,750,000 | 3,750,000 each | 0 / 0 / 0 | 0/3 |
| Default | 1,000,000 | 5,000,000 | 425,480.24 / 367,628.59 / 405,218.23 | 5,000,000 | 5,000,000 each | 0 / 0 / 0 | 0/3 |
| Intermediate | 150,000 | 1,000,000 | 150,000.06 / 150,000.10 / 150,000.08 | 1,000,000 | 1,000,000 each | 0 / 0 / 0 | 3/3 |
| Intermediate | 200,000 | 1,000,000 | 200,000.12 / 200,000.12 / 200,000.12 | 1,000,000 | 1,000,000 each | 0 / 0 / 0 | 3/3 |
| Intermediate | 300,000 | 1,500,000 | 300,000.00 / 300,000.00 / 291,350.95 | 1,500,000 | 1,500,000 / 1,499,108 / 1,500,000 | 0 / 892 / 0 | 2/3 |
| Intermediate | 400,000 | 2,000,000 | 399,999.92 / 399,999.76 / 399,999.92 | 2,000,000 | 2,000,000 each | 0 / 0 / 0 | 3/3 |
| Intermediate | 1,000,000 | 5,000,000 | 430,529.90 / 427,982.04 / 377,335.65 | 5,000,000 | 5,000,000 each | 0 / 0 / 0 | 0/3 |

**Other counters, every trial:** tcpreplay failed sends `0`; libpcap kernel/interface drops `0/0`; veth receiver RX/sender TX drops `0/0` and errors `0/0`; worker failures `0`. All counters were available. Every captured PCAP contained the full expected sequence set, with no missing, duplicate, unexpected, or unparseable sequence identifiers. All NetScope processes completed normally with no output errors.

The [300,000 packets/s second repetition](linux-orbstack-2026-11-07/intermediate-matrix/runs/rate-300000-r02/record.json) is a qualified loss observation: the sender achieved 300,000.00 packets/s, NetScope captured all 1,500,000 frames, and workers processed 1,499,108. The 892-frame difference exactly matches dispatch drops (0.0595% of input). Captured-PCAP reconciliation establishes capture completeness; worker accounting establishes the downstream loss. This experiment does not identify the cause of that isolated dispatch loss.

All repetitions at requested 100,000, 150,000, 200,000, and 400,000 packets/s qualified with zero observed loss. At 250,000, two repetitions qualified and one was under-rate. At 300,000, one qualified repetition had zero loss, one had dispatch loss, and one was under-rate. Every trial at 500,000–1,000,000 was under-rate. The highest achieved average in those sender-limited trials was 433,076.43 packets/s; that individual loss-free observation does not establish a repeatable zero-loss target.

## CPU, elapsed time, and memory

CPU is NetScope user plus system CPU seconds from GNU time, excluding tcpreplay and the Python harness. CPU values show median [minimum–maximum]; RSS is the largest per-process peak across all three repetitions. Elapsed time is the median from NetScope's final summary. Under-rate trials are included, so resource values describe their achieved workloads. Different targets use different packet counts and run durations.

| Matrix | Requested packets/s | Median elapsed (s) | Process CPU seconds, median [range] | Maximum peak RSS (MiB) |
| --- | ---: | ---: | --- | ---: |
| Default | 100,000 | 10.027 | 1.050 [0.400–1.190] | 47.8 |
| Default | 250,000 | 5.023 | 2.940 [1.880–3.060] | 47.7 |
| Default | 500,000 | 5.832 | 5.180 [4.890–5.410] | 47.8 |
| Default | 750,000 | 8.833 | 7.760 [7.730–7.820] | 47.9 |
| Default | 1,000,000 | 12.364 | 9.450 [9.300–10.320] | 47.8 |
| Intermediate | 150,000 | 6.682 | 1.290 [1.000–1.470] | 47.8 |
| Intermediate | 200,000 | 5.025 | 1.170 [0.640–1.270] | 47.8 |
| Intermediate | 300,000 | 5.028 | 2.990 [0.920–3.900] | 47.8 |
| Intermediate | 400,000 | 5.022 | 4.120 [3.970–4.130] | 47.8 |
| Intermediate | 1,000,000 | 11.707 | 10.540 [10.360–10.590] | 47.8 |

The shared host and short trials produced substantial CPU variation, including at the same target. These are observations for this virtualized, single-flow, PCAP-recording configuration with evidence of workload forwarding through `eth0`; they do not establish isolated-veth, bare-metal, physical-interface, sustained long-run, or general traffic-mix performance.

## Provenance, evidence, and reproduction

- Clean measured source: `e938017a7d86dc942e5cedf80975191b458bfd4a`; source fingerprint `0b0cdc19a3c60ce1981dc786cf03ab8a454484abac096638329f41f369ba4098`. Source and binary remained unchanged throughout both matrices.
- Build: `cargo build --locked --release`, default features. Linux executable SHA-256: `71a30d6e157c10b03ed918d2882df08fceb8dbd6968695b8f1d41b245506933f`.
- Identical input trace SHA-256 in both matrices: `1743c658cfc03a041512f1e928c10fc20bf069918a6b8b967d622a552850f7d4`.
- [Default suite JSON](linux-orbstack-2026-11-07/default-matrix/suite.json) and [generated report](linux-orbstack-2026-11-07/default-matrix/report.md); [intermediate suite JSON](linux-orbstack-2026-11-07/intermediate-matrix/suite.json) and [generated report](linux-orbstack-2026-11-07/intermediate-matrix/report.md). Each bundle includes all 15 run records, exact commands/configs, readiness events, separate summaries, full sender/application/time logs, before/after interface counters, workload manifest, build logs, and source snapshot.
- [Export verification](linux-orbstack-2026-11-07/verification.json) reconciles the exported records, raw logs, resource readings, classifications, and packet accounting; trace and captured-PCAP sizes/hashes were checked after export. [Evidence checksums](linux-orbstack-2026-11-07/SHA256SUMS) cover the checked-in bundle.
- [Reproduction instructions and container recipe](linux-orbstack-2026-11-07/README.md), [host context](linux-orbstack-2026-11-07/host-context.json), and [runtime/package metadata](linux-orbstack-2026-11-07/runtime-before.json) retain the environment details.
- Large PCAPs and the measured Linux executable are retained locally under ignored `tmp/perf/live-capture-2026-11-07/`; they are not checked in. Their hashes remain in the workload manifests, run records, and suite metadata. The published metadata alone cannot independently reparse those captures; regenerate them using the documented procedure.
- The existing Linux-only idle shutdown integration test passed after measurement, covering inline/pipeline, immediate mode on/off, and timeout 0/20 ms: [full validation log](linux-orbstack-2026-11-07/linux-live-shutdown.log). All seven Python benchmark/classification tests also passed.
