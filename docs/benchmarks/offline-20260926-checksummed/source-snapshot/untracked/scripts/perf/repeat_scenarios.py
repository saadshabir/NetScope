#!/usr/bin/env python3
"""Repeat selected scenarios from a saved run without changing its binary."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any

from run_offline import (
    ROOT,
    _run_task,
    aggregate_records,
    collect_environment,
    json_write,
    reserve_local_port,
    sha256_file,
    time_adapter,
    utc_now,
    write_report,
)
from workloads import generate_workload


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def current_load() -> list[float] | None:
    try:
        return list(os.getloadavg())
    except (AttributeError, OSError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="directory containing results.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scenario-id", action="append", required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=1800)
    parser.add_argument("--background-load-notes", help="manual notes about power mode and other active work")
    args = parser.parse_args()
    if args.repetitions < 5:
        parser.error("supplemental batches require at least five measured repetitions")
    if args.warmups < 1:
        parser.error("supplemental batches require at least one warm-up")

    baseline_dir = (ROOT / args.baseline).resolve() if not args.baseline.is_absolute() else args.baseline.resolve()
    output_root = (ROOT / args.output_dir).resolve() if not args.output_dir.is_absolute() else args.output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    baseline = load_json(baseline_dir / "results.json")
    source = load_json(baseline_dir / "source.json")
    binary_info = baseline["binary"]
    binary = Path(binary_info["path"]).resolve()
    if not binary.is_file() or sha256_file(binary) != binary_info["sha256"]:
        raise RuntimeError("the saved baseline binary is missing or its SHA-256 changed")

    adapter, adapter_name = time_adapter()
    load_start = current_load()
    environment = collect_environment(load_start, args.background_load_notes)
    environment["repeat_batch_started_at_utc"] = utc_now()
    batch_records: list[dict[str, Any]] = []
    workloads_dir = output_root / "workloads"
    configs_dir = output_root / "artifacts" / "configs"
    workloads_dir.mkdir(parents=True)
    configs_dir.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="netscope-repeat-") as temp_name:
        temporary_dir = Path(temp_name)
        for scenario_id in args.scenario_id:
            baseline_records = [
                row
                for row in baseline["records"]
                if row["scenario_id"] == scenario_id and row["phase"] == "measured"
            ]
            if not baseline_records:
                raise RuntimeError(f"no measured baseline record found for {scenario_id!r}")
            template_record = baseline_records[0]
            manifest_info = template_record["workload"]
            workload = manifest_info["workload"]
            packet_count = manifest_info["packet_count"]
            trace_path = temporary_dir / f"{workload}-{packet_count}.pcap"
            manifest = generate_workload(workload, packet_count, trace_path)
            if manifest["pcap_sha256"] != manifest_info["pcap_sha256"]:
                raise RuntimeError(f"regenerated PCAP hash changed for {scenario_id}")
            manifest_copy = dict(manifest)
            manifest_copy["pcap_file"] = trace_path.name
            json_write(workloads_dir / f"{workload}-{packet_count}.manifest.json", manifest_copy)

            task = {
                "scenario_id": scenario_id,
                "workload": workload,
                "mode": template_record["mode"],
                "workers": template_record["requested_workers"],
                "dashboard": template_record["dashboard_enabled"],
                "anomalies": template_record["anomaly_detection_enabled"],
            }
            original_config = baseline_dir / template_record["config_path"]
            if not original_config.is_file():
                raise RuntimeError(f"saved scenario config is missing: {original_config}")
            stage_config = configs_dir / f"{scenario_id}.toml"
            base_config_text = original_config.read_text()
            stage_config.write_text(base_config_text)
            prior_repetitions = max(row["repetition"] for row in baseline_records)
            print(f"Repeating {scenario_id}: {args.warmups} warm-up + {args.repetitions} measured")

            for index in range(1, args.warmups + 1):
                if task["dashboard"]:
                    port = reserve_local_port()
                    text = re.sub(r"(?m)^port = \d+$", f"port = {port}", base_config_text, count=1)
                    if text == base_config_text:
                        raise RuntimeError("dashboard config has no port setting to refresh")
                    stage_config.write_text(text)
                else:
                    port = None
                record = _run_task(
                    task,
                    phase="warmup",
                    repetition=prior_repetitions + index,
                    binary=binary,
                    trace_path=trace_path,
                    manifest=manifest_copy,
                    config_path=stage_config,
                    port=port,
                    output_root=output_root,
                    artifact_root=output_root,
                    adapter=adapter,
                    adapter_name=adapter_name,
                    timeout=args.timeout_seconds,
                    source=source,
                    binary_sha=binary_info["sha256"],
                )
                batch_records.append(record)

            for index in range(1, args.repetitions + 1):
                if task["dashboard"]:
                    port = reserve_local_port()
                    text = re.sub(r"(?m)^port = \d+$", f"port = {port}", base_config_text, count=1)
                    stage_config.write_text(text)
                else:
                    port = None
                record = _run_task(
                    task,
                    phase="measured",
                    repetition=prior_repetitions + args.warmups + index,
                    binary=binary,
                    trace_path=trace_path,
                    manifest=manifest_copy,
                    config_path=stage_config,
                    port=port,
                    output_root=output_root,
                    artifact_root=output_root,
                    adapter=adapter,
                    adapter_name=adapter_name,
                    timeout=args.timeout_seconds,
                    source=source,
                    binary_sha=binary_info["sha256"],
                )
                batch_records.append(record)
                print(
                    f"  {index}/{args.repetitions}: "
                    f"{record['metrics']['packet_throughput_per_second']:,.0f} packets/s"
                )

    load_end = current_load()
    environment["system_load_average_end"] = load_end
    environment["repeat_batch_captured_at_utc"] = utc_now()
    json_write(output_root / "environment.json", environment)
    selected_aggregates = aggregate_records(batch_records)

    repeat_batch = {
        "started_at_utc": environment["repeat_batch_started_at_utc"],
        "captured_at_utc": environment["repeat_batch_captured_at_utc"],
        "scenario_ids": args.scenario_id,
        "warmups": args.warmups,
        "repetitions": args.repetitions,
        "binary_sha256": binary_info["sha256"],
        "source_commit": source["commit"],
        "source_tree_sha256": source["source_tree_sha256"],
        "system_load_average_start": load_start,
        "system_load_average_end": load_end,
        "background_load_notes": args.background_load_notes or "not recorded manually",
        "environment": environment,
        "aggregates": selected_aggregates,
    }
    json_write(output_root / "repeat-batch.json", repeat_batch)
    json_write(output_root / "repeat-records.json", {"schema_version": 1, "records": batch_records})

    repeat_prefix = Path(os.path.relpath(output_root, baseline_dir))
    for record in batch_records:
        for field in (
            "raw_stdout_path",
            "raw_stderr_path",
            "raw_resource_output_path",
            "config_path",
        ):
            if record.get(field):
                record[field] = (repeat_prefix / record[field]).as_posix()

    baseline["records"].extend(batch_records)
    baseline["aggregates"] = aggregate_records(baseline["records"])
    baseline["method"].setdefault("supplemental_repeat_batches", []).append(repeat_batch)
    baseline["report_generated_at_utc"] = utc_now()
    json_write(baseline_dir / "results.json", baseline)
    write_report(baseline_dir / "report.md", baseline)
    print(f"Merged repeat records into {baseline_dir / 'results.json'}")
    print(f"Repeat artifacts: {output_root}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, socket.error) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
