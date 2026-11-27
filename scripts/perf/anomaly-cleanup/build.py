"""Build the same anomaly workload against the baseline and current NetScope."""

import argparse
import json
from pathlib import Path
import subprocess


def build(manifest, target, output, workload):
    result = subprocess.run(
        [
            "cargo", "build", "--locked", "--release", "--no-default-features", "--lib",
            "--manifest-path", manifest,
            "--target-dir", target,
            "--message-format=json-render-diagnostics",
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    release = target / "release"
    link_args = ["-L", f"dependency={release / 'deps'}"]
    # Cargo's build scripts can add native library paths, including libpcap's.
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if message["reason"] == "build-script-executed":
            for path in message["linked_paths"]:
                link_args.extend(["-L", path])

    subprocess.run(
        [
            "rustc", "--crate-name", "anomaly_cleanup_bench", "--edition", "2024",
            "-C", "opt-level=3", workload,
            "--extern", f"netscope={release / 'libnetscope.rlib'}",
            *link_args, "-o", output,
        ],
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="directory containing the baseline checkout")
    run_dir = parser.parse_args().run_dir.resolve()
    workload = Path(__file__).with_name("workload.rs")
    build(
        run_dir / "baseline" / "Cargo.toml",
        run_dir / "baseline-target",
        run_dir / "before",
        workload,
    )
    build(Path("Cargo.toml"), run_dir / "candidate-target", run_dir / "after", workload)


if __name__ == "__main__":
    main()
