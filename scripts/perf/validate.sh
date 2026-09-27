#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="$ROOT_DIR/tmp/perf"
mkdir -p "$OUT_DIR"
STAMP="$(date +"%Y%m%d-%H%M%S")"
LOG_PREFIX="$OUT_DIR/$STAMP"

echo "== NetScope performance validation =="
echo "Root: $ROOT_DIR"
echo "Logs: ${LOG_PREFIX}.*"

echo
echo "[1/3] Build release"
cargo build --release | tee "${LOG_PREFIX}.build.log"

echo
echo "[2/3] Handshake benchmark"
cargo bench --bench hot_path -- handshake_sequence | tee "${LOG_PREFIX}.bench.log"

echo
echo "[3/3] Memory validation (CLI synthetic flows)"
/usr/bin/time -l ./target/release/netscope --synthetic-flows 1000000 \
  2>&1 | tee "${LOG_PREFIX}.memory-cli.log"

cat <<EOF

Completed local automated checks.

To re-run manual spot checks when needed:
  python3 scripts/perf/live_capture.py --output-dir tmp/perf/live-capture/<run-id>
  scripts/perf/validate-web.sh [iface] [trace.pcap]

Artifacts:
  ${LOG_PREFIX}.build.log
  ${LOG_PREFIX}.bench.log
  ${LOG_PREFIX}.memory-cli.log
EOF
