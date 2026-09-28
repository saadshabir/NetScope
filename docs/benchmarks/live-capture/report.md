# Live capture and packet-loss report

**Status:** Complete for the current release scope. Linux live measurements were excluded; no live packet-loss number or zero-loss rate is published.

The live-capture runner and runbook are implemented. The execution host is macOS 27.0 (Apple silicon), without Linux `veth` support or a container runtime. Its loopback interface does not provide an equivalent isolated sender/receiver experiment. No live matrix was run, and no capture result is inferred from offline PCAP benchmarks.

Run the documented Linux matrix in [`docs/performance.md`](../../performance.md#live-capture-and-packet-loss). It writes a generated report alongside complete raw run records. Review the trace hash, host, effective readiness settings, both counter sources, and every repetition before transferring qualified results here.

| Offered rate (packets/s) | Repetitions | Captured / processed frames | Drop counters | Result |
| ---: | ---: | --- | --- | --- |
| Not measured | 0 | Not available | Not available | Excluded from current scope |

**Rate bracket:** Not established. The highest tested zero-loss rate and the first tested rate showing loss remain unknown.
