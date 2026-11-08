# Rerun the November 7 Linux live-loss matrices with forwarding disabled

The [published report](../report.md) interprets both complete matrices. The default matrix ran first. The intermediate targets were selected after observing sender-rate shortfalls; the repeated 1,000,000 target keeps the generated trace identical. No original trial was replaced or discarded. Both suites used the same clean source, build, host, capture settings, and trace hash.

**Original-run limitation:** the [final runtime snapshot](runtime-after.json) records 72,001,692 packets and 3,888,151,728 bytes transmitted on the container's `eth0`, consistent with forwarding the 72-million-packet workload outside the veth pair. The original IPv4 forwarding setting was not recorded, and network isolation was not established. The procedure below corrects that setup by disabling IPv4 forwarding before creating the pair. It has not been used to rerun the published matrices; collect a new suite before claiming results for the corrected topology.

Use a clean checkout of measured commit `e938017a7d86dc942e5cedf80975191b458bfd4a` as the read-only source. From a checkout containing this evidence directory, create that source checkout and build the container image:

```bash
git clone --no-local . /tmp/netscope-live-source
git -C /tmp/netscope-live-source checkout --detach e938017a7d86dc942e5cedf80975191b458bfd4a
docker build -t netscope-live-bench:rust-1.93.1 \
  docs/benchmarks/live-capture/linux-orbstack-2026-11-07
docker run -d --name netscope-live-matrix \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=0 \
  --mount type=bind,src=/tmp/netscope-live-source,dst=/source,readonly \
  netscope-live-bench:rust-1.93.1
docker exec netscope-live-matrix bash scripts/perf/live-veth.sh up
docker exec netscope-live-matrix sh -ec \
  'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0; test "$(cat /proc/sys/net/ipv4/conf/veth-ns-rx/forwarding)" = 0'
```

The [Dockerfile](Dockerfile) pins the Rust base-image digest. Debian package versions actually installed are recorded in [runtime-before.json](runtime-before.json); package mirrors can advance, so compare them on a rerun. [host-context.json](host-context.json) records the physical host, guest, container image ID, and background services. Cgroup limits and interface counters are saved in the before/after runtime files. There was no CPU quota or CPU pinning beyond the VM's ten available logical CPUs, and no container memory limit.

Run each full matrix sequentially only after the forwarding checks succeed. Each command rebuilds/verifies the source and binary, generates the same five-million-packet trace, waits for readiness before each replay, and retains every result:

```bash
docker exec netscope-live-matrix python3 scripts/perf/live_capture.py \
  --output-dir /bench/default-matrix
docker exec netscope-live-matrix python3 scripts/perf/live_capture.py \
  --output-dir /bench/intermediate-matrix \
  --rates 150000,200000,300000,400000,1000000
```

Keep the host otherwise quiet during measurement and record any background services. Do not run the shutdown test, export captures, or run other benchmarks concurrently with the matrices. Resource measurements include captured-PCAP writing on the container overlay filesystem. They exclude the sender and harness; they do not describe capture without recording.

Save the forwarding settings and counters for all interfaces before and after each matrix, including `eth0`, alongside the suite. Creating a veth pair without addresses does not prevent the kernel from forwarding received packets through an existing route. Check that non-benchmark interfaces do not transmit the replay workload before describing a rerun as isolated.

After measurement, run the existing Linux shutdown validation and export the complete evidence before removing the container:

```bash
docker exec -e NETSCOPE_LIVE_TEST_INTERFACE=veth-ns-rx \
  netscope-live-matrix cargo test --locked --release --test live_shutdown -- --ignored
mkdir -p tmp/perf/live-capture-rerun
docker cp netscope-live-matrix:/bench/default-matrix tmp/perf/live-capture-rerun/
docker cp netscope-live-matrix:/bench/intermediate-matrix tmp/perf/live-capture-rerun/
docker cp netscope-live-matrix:/bench/target/release/netscope \
  tmp/perf/live-capture-rerun/netscope-linux-aarch64
docker exec netscope-live-matrix bash scripts/perf/live-veth.sh down
docker rm -f netscope-live-matrix
```

The checked-in `default-matrix/` and `intermediate-matrix/` directories preserve the original non-PCAP run records without rewriting their paths or measurements. Their generated reports retain the original body with a clearly marked post-run network-isolation qualification. Absolute `/bench/<matrix>/...` paths in the records map to the corresponding exported matrix directories. The original complete exports, including PCAPs, are retained locally at `tmp/perf/live-capture-2026-11-07/`; the measured executable is alongside them. Each workload manifest and captured-PCAP record retains its SHA-256. The clean source snapshots contain empty patches and no untracked source inputs.

[verification.json](verification.json) records export checks: all rate/repetition pairs, unchanged provenance, matching standalone run/summary files, PCAP sizes and hashes, packet/worker/drop accounting, raw sender/time parsing, and run classifications. `SHA256SUMS` covers every checked-in evidence file except itself. From this directory, verify those files on Linux with:

```bash
sha256sum -c SHA256SUMS
```

The checked-in suite metadata is sufficient to inspect the measurements and qualification decisions, but the large captures must be retained locally or regenerated to independently reparse them. Under-rate replays do not qualify a requested-rate endpoint. The isolated 300,000 packets/s dispatch-loss observation and all sender-limited trials remain in both the raw and summarized evidence; the three loss-free 400,000 packets/s trials do not establish a monotonic capacity bound.
