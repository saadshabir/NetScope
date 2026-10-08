"""Compare retained flow exports against the saved pre-optimization binary."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/perf"))
from workloads import WORKLOADS, generate_workload

out = ROOT / "tmp/perf/optimization-20261008-export-equivalence"
out.mkdir(exist_ok=False)
binaries = {
    "before": ROOT / "tmp/perf/optimization-20261008-baseline/netscope-baseline",
    "after": ROOT / "target/release/netscope",
}
records = []
fields = ["frames_read", "input_wire_bytes", "packets_parsed", "packet_parse_errors",
          "transport_parse_errors", "flows_created", "flows_expired", "flows_evicted"]
for workload in WORKLOADS:
    trace = out / f"{workload}.pcap"
    manifest = generate_workload(workload, 5000, trace)
    for deep in [False, True]:
        mode = "full" if deep else "scale"
        config = out / f"{mode}.toml"
        value = str(deep).lower()
        config.write_text(f"[flow]\ntimeout_secs = 0.0\nmax_flows = 128\n"
                          f"[stats]\nenabled = false\n[analysis]\nrtt = {value}\n"
                          f"retrans = {value}\nout_of_order = {value}\n"
                          "[analysis.anomalies]\nenabled = false\n")
        observations = {}
        for label, binary in binaries.items():
            prefix = out / f"{workload}-{mode}-{label}"
            flows_path = prefix.with_suffix(".flows.json")
            summary_path = prefix.with_suffix(".summary.json")
            command = [str(binary), "--config", str(config), "--read-pcap", str(trace),
                       "--quiet", "--no-stats", "--no-anomalies", "--export-json",
                       str(flows_path), "--summary-json", str(summary_path)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            prefix.with_suffix(".stdout.txt").write_text(result.stdout)
            prefix.with_suffix(".stderr.txt").write_text(result.stderr)
            assert result.returncode == 0, result.stderr
            summary = json.loads(summary_path.read_text())
            assert summary["status"] == "success", summary
            flows = json.loads(flows_path.read_text())
            flows.sort(key=lambda flow: json.dumps(flow, sort_keys=True))
            observations[label] = (flows, {key: summary[key] for key in fields})
        assert observations["before"] == observations["after"], (workload, mode)
        records.append({"workload": workload, "flow_store": mode, "packets": 5000,
                        "max_flows": 128, "retained_flows": len(observations["after"][0]),
                        "pcap_sha256": manifest["pcap_sha256"], "passed": True})
        print(f"{workload}/{mode}: identical exports and accounting")
(out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
