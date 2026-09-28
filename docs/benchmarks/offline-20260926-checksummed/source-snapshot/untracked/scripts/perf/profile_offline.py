#!/usr/bin/env python3
"""Collect a separate CPU profile for one deterministic offline workload."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from run_offline import (
    ROOT,
    build_release,
    command_output,
    git_source_state,
    json_write,
    save_source_snapshot,
    sha256_file,
    utc_now,
    write_config,
)
from workloads import WORKLOADS, generate_workload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workload", choices=tuple(WORKLOADS), default="high-cardinality")
    parser.add_argument("--packets", type=int, default=5_000_000)
    parser.add_argument("--mode", choices=("inline", "pipeline"), default="pipeline")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--duration-seconds", type=int, default=1)
    args = parser.parse_args()
    if args.packets < 1 or args.duration_seconds < 1:
        parser.error("packet count and profile duration must be positive")
    if args.workers < 1:
        parser.error("workers must be a positive integer")
    if args.workload == "analysis-heavy" and args.mode == "pipeline":
        parser.error("pipeline mode does not support enabled anomaly detection")

    output_root = (ROOT / args.output_dir).resolve() if not args.output_dir.is_absolute() else args.output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    source = git_source_state(output_root)
    source["snapshot"] = save_source_snapshot(source, output_root)
    binary = build_release(output_root)
    if git_source_state(output_root)["source_tree_sha256"] != source["source_tree_sha256"]:
        raise RuntimeError("source files changed during release build; refusing an ambiguous profile")

    run_dir = output_root / "run"
    run_dir.mkdir()
    binary_sha = sha256_file(binary)
    config = output_root / "config.toml"
    anomalies = args.workload == "analysis-heavy"
    write_config(config, anomalies=anomalies, web=None)
    summary_path = run_dir / "summary.json"
    profile_path = output_root / ("sample.txt" if sys.platform == "darwin" else "perf.data")

    with tempfile.TemporaryDirectory(prefix="netscope-profile-") as temp_name:
        trace_path = Path(temp_name) / f"{args.workload}-{args.packets}.pcap"
        manifest = generate_workload(args.workload, args.packets, trace_path)
        manifest_copy = dict(manifest)
        manifest_copy["pcap_file"] = trace_path.name
        json_write(output_root / "workload.manifest.json", manifest_copy)

        command = [
            str(binary),
            "--config",
            str(config),
            "--read-pcap",
            str(trace_path),
            "--quiet",
            "--no-stats",
            "--no-anomalies" if not anomalies else "--anomalies",
            "--summary-json",
            str(summary_path),
        ]
        if args.mode == "pipeline":
            command.extend(["--pipeline", "--workers", str(args.workers)])

        stdout_path = run_dir / "stdout.txt"
        stderr_path = run_dir / "stderr.txt"
        started_at = utc_now()
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            app = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=stdout,
                stderr=stderr,
                start_new_session=(os.name == "posix"),
            )
            time.sleep(0.05)
            if sys.platform == "darwin":
                profiler_command = [
                    "/usr/bin/sample",
                    str(app.pid),
                    str(args.duration_seconds),
                    "1",
                    "-fullPaths",
                    "-file",
                    str(profile_path),
                ]
            elif sys.platform.startswith("linux"):
                profiler_command = [
                    "perf",
                    "record",
                    "--call-graph",
                    "dwarf",
                    "-F",
                    "99",
                    "-p",
                    str(app.pid),
                    "-o",
                    str(profile_path),
                    "--",
                    "sleep",
                    str(args.duration_seconds),
                ]
            else:
                app.kill()
                app.wait()
                parser.error(f"no offline profiler adapter for {sys.platform}")

            profiler = subprocess.run(
                profiler_command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=args.duration_seconds + 30,
                check=False,
            )
            (output_root / "profiler.stdout.txt").write_text(profiler.stdout)
            (output_root / "profiler.stderr.txt").write_text(profiler.stderr)
            app_exit = app.wait(timeout=1800)

    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
        except json.JSONDecodeError:
            summary = None
    else:
        summary = None

    record = {
        "schema_version": 1,
        "profiled_at_utc": started_at,
        "source": source,
        "binary": {
            "path": str(binary),
            "sha256": binary_sha,
            "version": command_output([str(binary), "--version"]) or "unavailable",
            "build_command": "cargo build --locked --release",
        },
        "workload": manifest_copy,
        "mode": args.mode,
        "requested_workers": args.workers if args.mode == "pipeline" else None,
        "command": command,
        "config_path": str(config),
        "profiler_command": profiler_command,
        "profiler_exit_code": profiler.returncode,
        "profile_output_path": str(profile_path),
        "profile_output_sha256": sha256_file(profile_path) if profile_path.is_file() else None,
        "application_exit_code": app_exit,
        "application_summary": summary,
        "measurement_note": "Sampling profile is separate from the timed benchmark repetitions and is not used for throughput claims.",
    }
    json_write(output_root / "profile.json", record)
    print(f"Application exit: {app_exit}; profiler exit: {profiler.returncode}")
    print(f"Profile: {profile_path}")
    print(f"Metadata: {output_root / 'profile.json'}")
    if profiler.returncode != 0:
        print("Profiler reported an error; inspect profiler.stderr.txt.", file=sys.stderr)
        return 2
    if app_exit != 0:
        return app_exit
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
