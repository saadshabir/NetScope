import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description="Compare JSON flow export timings")
    parser.add_argument("run_dir", type=Path, help="directory containing before and after")
    parser.add_argument("trace", type=Path, help="synthetic high-cardinality PCAP")
    parser.add_argument("rows", type=int, help="number of flows to export")
    parser.add_argument("--pairs", type=int, default=7, help="number of measured pairs")
    args = parser.parse_args()
    if args.rows < 1 or args.pairs < 1:
        parser.error("rows and pairs must be positive")

    run_dir = args.run_dir.resolve()
    output = run_dir / f"flows-{args.rows}.json"
    raw = run_dir / f"results-{args.rows}.jsonl"
    expected = None
    timings = {"before": [], "after": []}
    with raw.open("x", encoding="utf-8") as log:
        for pair in range(args.pairs + 1):
            variants = ("before", "after") if pair % 2 == 0 else ("after", "before")
            for variant in variants:
                command = [run_dir / variant, args.trace, str(args.rows), output]
                elapsed, size = map(int, subprocess.check_output(command, text=True).split())
                hasher = hashlib.sha256()
                with output.open("rb") as written:
                    for chunk in iter(lambda: written.read(1024 * 1024), b""):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
                if expected is None:
                    expected = size, digest
                if (size, digest) != expected:
                    raise SystemExit(f"{variant} output differs in pair {pair}")

                record = {
                    "rows": args.rows,
                    "variant": variant,
                    "pair": pair,
                    "warmup": pair == 0,
                    "elapsed_ns": elapsed,
                    "bytes": size,
                    "sha256": digest,
                }
                print(json.dumps(record), file=log, flush=True)
                if pair > 0:
                    timings[variant].append(elapsed / 1e6)

    for variant, times in timings.items():
        print(variant, "median/min/max ms", statistics.median(times), min(times), max(times))
    print("speedup", statistics.median(timings["before"]) / statistics.median(timings["after"]))


if __name__ == "__main__":
    main()
