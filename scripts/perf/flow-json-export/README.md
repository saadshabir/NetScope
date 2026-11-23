# Reproduce the JSON flow export benchmark

Run these commands from the root of a NetScope checkout containing the buffering change. You need Python 3, the [pinned Rust toolchain](../../../rust-toolchain.toml), and [libpcap development headers](../../../docs/quickstart.md). Both executables use the same harness and deterministic high-cardinality PCAP. The harness builds a flow snapshot and sorts it before timing the export to a regular file on the checkout volume.

```sh
set -e
mkdir -p tmp/perf
run_dir=$(mktemp -d "$PWD/tmp/perf/flow-json-export.XXXXXX")
mkdir "$run_dir/baseline"
git archive d15a990113ec7a3aa361bec86c634c0ad13b4274 |
  tar -x -C "$run_dir/baseline"
python3 scripts/perf/workloads.py --output-dir "$run_dir/input" \
  --workload high-cardinality --counts 100000

harness=scripts/perf/flow-json-export/export.rs
CARGO_TARGET_DIR="$run_dir/baseline-target" \
  cargo build --manifest-path "$run_dir/baseline/Cargo.toml" \
    --locked --release --no-default-features --lib
rustc --crate-name flow_export_bench --edition 2024 -C opt-level=3 \
  "$harness" \
  --extern "netscope=$run_dir/baseline-target/release/libnetscope.rlib" \
  -L "dependency=$run_dir/baseline-target/release/deps" \
  -o "$run_dir/before"

CARGO_TARGET_DIR="$run_dir/candidate-target" \
  cargo build --locked --release --no-default-features --lib
rustc --crate-name flow_export_bench --edition 2024 -C opt-level=3 \
  "$harness" \
  --extern "netscope=$run_dir/candidate-target/release/libnetscope.rlib" \
  -L "dependency=$run_dir/candidate-target/release/deps" \
  -o "$run_dir/after"

trace="$run_dir/input/high-cardinality-100000.pcap"
python3 scripts/perf/flow-json-export/measure.py "$run_dir" "$trace" 25000
python3 scripts/perf/flow-json-export/measure.py "$run_dir" "$trace" 100000
```

Each command runs one warm-up pair and seven measured pairs, alternating which build goes first. The driver checks that the byte count and SHA-256 match across all exports at each size. It prints the median and range and saves each run in `results-25000.jsonl` or `results-100000.jsonl` under the new run directory. Add `--pairs 1` to each command for a shorter verification run in a fresh directory.
