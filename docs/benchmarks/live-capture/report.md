# Live capture and packet-loss report

**Status:** Measurement pending. No live packet-loss number or zero-loss rate is published yet.

The Phase 5 runner and runbook are implemented, but the current execution host is macOS 27.0 (Apple silicon). It has `tcpreplay` but no Linux `ip` utility, Docker, or Podman, so it cannot create the plan's isolated Linux `veth` pair. The available macOS loopback interface does not provide an equivalent isolated sender/receiver experiment. No replay was started and no capture result is inferred from offline PCAP benchmarks.

Run the documented Linux matrix in [`docs/performance.md`](../../performance.md#live-capture-and-packet-loss). It writes a generated report alongside complete raw run records. Review the trace hash, host, effective readiness settings, both counter sources, and every repetition before transferring qualified results here.

| Offered rate (packets/s) | Repetitions | Captured / processed frames | Drop counters | Result |
| ---: | ---: | --- | --- | --- |
| Not measured | 0 | Not available | Not available | Pending Linux veth run |

**Rate bracket:** Not established. The highest tested zero-loss rate and the first tested rate showing loss remain unknown.
