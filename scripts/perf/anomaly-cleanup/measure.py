"""Compare process CPU and peak RSS for two anomaly workload binaries."""

import argparse
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile


def measure(binary, workload, cycles):
    command = [str(binary), workload, str(cycles)]
    with tempfile.TemporaryFile(mode="w+t") as output:
        pid = os.posix_spawn(
            binary,
            command,
            os.environ,
            file_actions=[(os.POSIX_SPAWN_DUP2, output.fileno(), 1)],
        )
        _, status, usage = os.wait4(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise SystemExit(f"{binary.name} failed on {workload}: {status}")
        output.seek(0)
        fields = map(int, output.read().split())
        if sys.platform == "linux":
            observations, syn_alerts, scan_alerts, peak_rss_bytes = fields
        else:
            observations, syn_alerts, scan_alerts = fields
            peak_rss_bytes = usage.ru_maxrss

    return {
        "observations": observations,
        "syn_alerts": syn_alerts,
        "scan_alerts": scan_alerts,
        "user_cpu_seconds": usage.ru_utime,
        "system_cpu_seconds": usage.ru_stime,
        "cpu_seconds": usage.ru_utime + usage.ru_stime,
        "peak_rss_bytes": peak_rss_bytes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="directory containing before and after")
    parser.add_argument("workload", choices=("burst", "idle"))
    parser.add_argument("--cycles", type=int, default=600)
    parser.add_argument("--pairs", type=int, default=7, help="number of measured pairs")
    args = parser.parse_args()
    if args.cycles < 1 or args.pairs < 1:
        parser.error("cycles and pairs must be positive")
    if sys.platform not in ("darwin", "linux"):
        parser.error("the resource measurements require macOS or Linux")

    run_dir = args.run_dir.resolve()
    runs = {"before": [], "after": []}
    with (run_dir / f"results-{args.workload}.jsonl").open("x", encoding="utf-8") as log:
        for pair in range(args.pairs + 1):
            variants = ("before", "after") if pair % 2 == 0 else ("after", "before")
            for variant in variants:
                record = measure(run_dir / variant, args.workload, args.cycles)
                record.update(workload=args.workload, variant=variant, pair=pair, warmup=pair == 0)
                print(json.dumps(record), file=log, flush=True)
                if pair:
                    runs[variant].append(record)

    for variant, records in runs.items():
        cpu = [record["cpu_seconds"] for record in records]
        rss = [record["peak_rss_bytes"] / 2**20 for record in records]
        print(f"{variant} CPU seconds {statistics.median(cpu):.3f} [{min(cpu):.3f}–{max(cpu):.3f}]")
        print(f"{variant} peak RSS MiB {statistics.median(rss):.2f} [{min(rss):.2f}–{max(rss):.2f}]")


if __name__ == "__main__":
    main()
