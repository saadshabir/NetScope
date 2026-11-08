# Live capture and packet-loss report

> **Post-run network-isolation qualification:** `runtime-after.json` records 72,001,692 packets transmitted on the container's `eth0` across both matrices, consistent with forwarding the workload outside the veth pair. The original generated body below predates that review; its isolation descriptions are unverified. Counts and rate qualifications remain observations of that setup, not isolated-veth performance. See the [published qualification and corrected rerun procedure](../../report.md).

Generated: `2026-11-08T04:10:27Z`  
Trace: `steady-flow-5000000.pcap`  
Trace SHA-256: `1743c658cfc03a041512f1e928c10fc20bf069918a6b8b967d622a552850f7d4`  
Host: `Linux-7.2.12-orbstack-00394-gbecdd6130068-aarch64-with-glibc2.36` / `aarch64`; CPU `unavailable` (10 logical CPUs); RAM `8004 MiB`  
Toolchain: Rust `rustc 1.93.1 (01f6ddf75 2026-02-11)
binary: rustc
commit-hash: 01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf
commit-date: 2026-02-11
host: aarch64-unknown-linux-gnu
release: 1.93.1
LLVM version: 21.1.8`; Cargo `cargo 1.93.1 (083ac5135 2025-12-15)`; libpcap `1.10.3`; iproute2 `ip utility, iproute2-6.1.0, libbpf 1.1.2`; GNU time `time (GNU Time) UNKNOWN
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David Keppel, David MacKenzie, and Assaf Gordon.`  
Source: commit `e938017a7d86dc942e5cedf80975191b458bfd4a`; dirty `False`; fingerprint `0b0cdc19a3c60ce1981dc786cf03ab8a454484abac096638329f41f369ba4098`; snapshot `source-snapshot/`.  
Binary SHA-256: `71a30d6e157c10b03ed918d2882df08fceb8dbd6968695b8f1d41b245506933f`

## Run configuration

- Interface pair: `veth-ns-tx` (TX MAC `02:00:00:00:00:02`) → `veth-ns-rx` (RX MAC `02:00:00:00:00:01`); isolated Linux veth with no IP addresses or routes.
- Requested rates and finite replay limits: 150,000 pps / 1000000 packets, 200,000 pps / 1000000 packets, 300,000 pps / 1500000 packets, 400,000 pps / 2000000 packets, 1,000,000 pps / 5000000 packets.
- Repetitions per rate: `3`; minimum duration: `5.0` s; minimum packets: `1000000`.
- Capture: filter `ip and tcp dst port 443 and dst host 203.0.113.1`; snaplen `65535`; timeout `20` ms; requested buffer `8` MiB; promiscuous and immediate modes disabled.
- Pipeline: `2` workers; queue capacity `8192` per worker.
- Replay tool: `tcpreplay` `tcpreplay version: 4.4.3 (build git:v4.4.3) (debug)
Copyright 2013-2022 by Fred Klassen <tcpreplay at appneta dot com> - AppNeta
Copyright 2000-2012 by Aaron Turner <aturner at synfin dot net>
The entire Tcpreplay Suite is licensed under the GPLv3
Cache file supported: 04
Compiled against libdnet: 1.16.1 (libdumbnet)
Compiled against libpcap: 1.10.3
64 bit packet counters: enabled
Verbose printing via tcpdump: enabled
Packet editing: disabled
Fragroute engine: enabled
Injection method: PF_PACKET send()
Not compiled with netmap`; command template: `tcpreplay --intf1=<TX> --pps=<target> --loop=1 --limit=<count> --stats=1 --no-flow-stats <trace>`.

The isolated veth trials replay a finite synthetic trace after NetScope emits `NETSCOPE_READY`. NetScope records the received packets to a PCAP so the runner can reconcile the trace's unique TCP sequence identifiers. Resource figures include that PCAP write and therefore describe this instrumented capture configuration.

A requested rate is eligible for the loss bracket when tcpreplay completes the full replay and achieves at least 99.5% of it. The table retains each achieved average rate; the bracket labels requested rates and does not assert exact achieved rates. Observed loss during an under-rate or incomplete replay is retained in the raw result but cannot establish the requested rate as a loss endpoint. The fixed BPF filter is checked against every packet in the generated trace before replay.

The runner builds the release binary with `cargo build --locked --release` after saving `source.json` and the complete source snapshot. Build output is retained in `build/`. A source change during the build, or a source or binary change during measurement, invalidates the suite.

`tcpreplay` counts packets accepted by its send path; that count does not prove peer delivery. NetScope frames, captured sequence identifiers, libpcap counters, application dispatch counters, and veth RX counters are reported separately. A missing counter is unknown, never zero.

## Rate bracket

Results are non-monotonic: zero-loss requested rate 400,000 packets/s is at or above first observed-loss requested rate 300,000 packets/s. Keep the per-run records; no single maximum is claimed.

All 15 requested trials are recorded.

## Repetitions

| Target rate (packets/s) | Runs | tcpreplay sent / failed | tcpreplay rate (packets/s) | NetScope read / worker processed | libpcap drops kernel / interface | veth RX / TX drops | veth RX / TX errors | dispatch drops | Result |
| ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- |
| 150,000 | 3 | 1000000, 1000000, 1000000 / 0, 0, 0 | 150000.06, 150000.1, 150000.08 | 1000000/1000000, 1000000/1000000, 1000000/1000000 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0, 0, 0 | zero observed loss in all repetitions |
| 200,000 | 3 | 1000000, 1000000, 1000000 / 0, 0, 0 | 200000.12, 200000.12, 200000.12 | 1000000/1000000, 1000000/1000000, 1000000/1000000 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0, 0, 0 | zero observed loss in all repetitions |
| 300,000 | 3 | 1500000, 1500000, 1500000 / 0, 0, 0 | 300000.0, 300000.0, 291350.95 | 1500000/1500000, 1500000/1499108, 1500000/1500000 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0, 892, 0 | loss observed in at least one repetition |
| 400,000 | 3 | 2000000, 2000000, 2000000 / 0, 0, 0 | 399999.92, 399999.76, 399999.92 | 2000000/2000000, 2000000/2000000, 2000000/2000000 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0, 0, 0 | zero observed loss in all repetitions |
| 1,000,000 | 3 | 5000000, 5000000, 5000000 / 0, 0, 0 | 430529.9, 427982.04, 377335.65 | 5000000/5000000, 5000000/5000000, 5000000/5000000 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0/0, 0/0, 0/0 | 0, 0, 0 | inconclusive |

## Runtime resources

| Target rate (packets/s) | Median NetScope elapsed (s) | Median process CPU (s) | Maximum peak RSS (MiB) |
| ---: | ---: | ---: | ---: |
| 150,000 | 6.682 | 1.290 | 47.8 |
| 200,000 | 5.025 | 1.170 | 47.8 |
| 300,000 | 5.028 | 2.990 | 47.8 |
| 400,000 | 5.022 | 4.120 | 47.8 |
| 1,000,000 | 11.707 | 10.540 | 47.8 |

Elapsed time comes from NetScope's final summary. CPU and RSS are measured for the timed NetScope process group by GNU `time`; CPU is user plus system time. The veth and tcpreplay columns preserve their own counters rather than treating the replay send count as peer delivery.

## Raw records

Each run directory retains `record.json`, full NetScope and tcpreplay output, GNU time output, effective TOML config, summary JSON, veth counters before/after, and the captured PCAP used for sequence reconciliation.

- `rate-150000-r01`: zero_observed_loss at 150000 packets/s; see `runs/rate-150000-r01/record.json`.
- `rate-150000-r02`: zero_observed_loss at 150000 packets/s; see `runs/rate-150000-r02/record.json`.
- `rate-150000-r03`: zero_observed_loss at 150000 packets/s; see `runs/rate-150000-r03/record.json`.
- `rate-200000-r01`: zero_observed_loss at 200000 packets/s; see `runs/rate-200000-r01/record.json`.
- `rate-200000-r02`: zero_observed_loss at 200000 packets/s; see `runs/rate-200000-r02/record.json`.
- `rate-200000-r03`: zero_observed_loss at 200000 packets/s; see `runs/rate-200000-r03/record.json`.
- `rate-300000-r01`: zero_observed_loss at 300000 packets/s; see `runs/rate-300000-r01/record.json`.
- `rate-300000-r02`: loss_observed at 300000 packets/s; see `runs/rate-300000-r02/record.json`.
- `rate-300000-r03`: inconclusive at 300000 packets/s; see `runs/rate-300000-r03/record.json`.
- `rate-400000-r01`: zero_observed_loss at 400000 packets/s; see `runs/rate-400000-r01/record.json`.
- `rate-400000-r02`: zero_observed_loss at 400000 packets/s; see `runs/rate-400000-r02/record.json`.
- `rate-400000-r03`: zero_observed_loss at 400000 packets/s; see `runs/rate-400000-r03/record.json`.
- `rate-1000000-r01`: inconclusive at 1000000 packets/s; see `runs/rate-1000000-r01/record.json`.
- `rate-1000000-r02`: inconclusive at 1000000 packets/s; see `runs/rate-1000000-r02/record.json`.
- `rate-1000000-r03`: inconclusive at 1000000 packets/s; see `runs/rate-1000000-r03/record.json`.
