"""Alternate the saved baseline and candidate binaries on one identical trace."""
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/perf"))
from run_offline import (aggregate_records, collect_environment, json_write, make_record,
                         run_process, sha256_file, time_adapter, utc_now, write_config)
from workloads import generate_workload

out = ROOT / "tmp/perf/optimization-20261008-paired"
out.mkdir(exist_ok=False)
adapter, adapter_name = time_adapter()
environment = collect_environment(os.getloadavg(), "Alternating saved baseline/candidate; no builds during measurement.")
binaries = {
    "before": ROOT / "tmp/perf/optimization-20261008-baseline/netscope-baseline",
    "after": ROOT / "target/release/netscope",
}
sources = {
    "before": json.loads((ROOT / "tmp/perf/optimization-20261008-baseline/source.json").read_text()),
    "after": json.loads((ROOT / "tmp/perf/optimization-20261008-final/source.json").read_text()),
}
hashes = {key: sha256_file(path) for key, path in binaries.items()}
records = []
with tempfile.TemporaryDirectory(prefix="netscope-paired-") as tmp:
    trace = Path(tmp) / "high-cardinality-1000000.pcap"
    manifest = generate_workload("high-cardinality", 1000000, trace)
    json_write(out / "workload.manifest.json", manifest)
    for workers in [2, 4]:
        for rep in range(8):
            phase = "warmup" if rep == 0 else "measured"
            for variant in (["before", "after"] if rep % 2 == 0 else ["after", "before"]):
                scenario = f"high-cardinality-pipeline-w{workers}-n1000000-{variant}"
                run_dir = out / "runs" / scenario / f"{phase}-{rep:02d}"
                run_dir.mkdir(parents=True)
                config = run_dir / "config.toml"
                write_config(config, anomalies=False, web=None)
                command = [str(binaries[variant]), "--config", str(config), "--read-pcap",
                           str(trace), "--quiet", "--no-stats", "--no-anomalies",
                           "--pipeline", "--workers", str(workers), "--summary-json",
                           str(run_dir / "summary.json")]
                process = run_process(command, run_dir, adapter, adapter_name, timeout=60)
                task = {"scenario_id": scenario, "workload": "high-cardinality",
                        "mode": "pipeline", "workers": workers,
                        "dashboard": False, "anomalies": False}
                record = make_record(task=task, phase=phase, repetition=rep, command=command,
                                     config_path=config, trace_path=trace, manifest=manifest,
                                     source=sources[variant], binary_sha=hashes[variant],
                                     process_result=process, run_dir=run_dir, artifact_root=out)
                assert record["validation"]["passed"], record["validation"]
                record["variant"] = variant
                records.append(record)
                print(f"w{workers} {phase} {rep} {variant}: "
                      f"{record['metrics']['packet_throughput_per_second']:,.0f} pps; "
                      f"{record['metrics']['peak_rss_mib']:.2f} MiB", flush=True)
assert hashes == {key: sha256_file(path) for key, path in binaries.items()}
environment["system_load_average_end"] = list(os.getloadavg())
json_write(out / "results.json", {"schema_version": 1, "created_at_utc": utc_now(),
                                "environment": environment, "sources": sources,
                                "binary_hashes": hashes, "workload": manifest,
                                "method": "One warmup per binary and worker count; seven measured repetitions; binary order alternates within each repetition.",
                                "records": records, "aggregates": aggregate_records(records)})
for workers in [2, 4]:
    for variant in ["before", "after"]:
        rows = [row for row in records if row["phase"] == "measured"
                and row["requested_workers"] == workers and row["variant"] == variant]
        print(f"w{workers} {variant} median: "
              f"{statistics.median(row['metrics']['packet_throughput_per_second'] for row in rows):,.0f} pps; "
              f"{statistics.median(row['metrics']['peak_rss_mib'] for row in rows):.2f} MiB")
