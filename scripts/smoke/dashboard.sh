#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

cat <<'EOF'
Manual live-dashboard smoke only. This script does not measure throughput or
packet loss. For loss measurements, use scripts/perf/live_capture.py on an
isolated Linux veth pair.
EOF

usage() {
  cat <<'EOF'
Usage:
  scripts/smoke/dashboard.sh [interface] [trace.pcap]

The optional trace is replayed only after NetScope prints its NETSCOPE_READY
event. Replay is continuous and stops when you interrupt this script.

Environment overrides:
  PPS=100000
  CONFIG=scripts/smoke/dashboard.toml
  BINARY=./target/release/netscope
  TCPREPLAY_BIN=$(command -v tcpreplay)
  LOG_DIR=tmp/smoke
EOF
}

if [[ $# -gt 2 ]]; then
  usage >&2
  exit 2
fi

IFACE="${1:-}"
TRACE="${2:-}"
PPS="${PPS:-100000}"
CONFIG="${CONFIG:-scripts/smoke/dashboard.toml}"
BINARY="${BINARY:-./target/release/netscope}"
TCPREPLAY_BIN="${TCPREPLAY_BIN:-$(command -v tcpreplay || true)}"
LOG_DIR="${LOG_DIR:-tmp/smoke}"

if [[ "$BINARY" != /* ]]; then
  BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "error: config file not found: $CONFIG" >&2
  exit 1
fi
if [[ -n "$TRACE" && ! -f "$TRACE" ]]; then
  echo "error: trace file not found: $TRACE" >&2
  exit 1
fi
if [[ -n "$TRACE" && -z "$IFACE" ]]; then
  echo "error: an interface is required when a trace is provided" >&2
  exit 1
fi
if [[ -n "$TRACE" && -z "$TCPREPLAY_BIN" ]]; then
  echo "error: tcpreplay is required when replaying a trace" >&2
  exit 1
fi
if [[ ! -x "$BINARY" ]]; then
  echo "info: release binary missing, building..."
  cargo build --locked --release
fi

mkdir -p "$LOG_DIR"
STAMP="$(date +"%Y%m%d-%H%M%S")"
APP_LOG="$LOG_DIR/${STAMP}.web.netscope.log"
REPLAY_LOG="$LOG_DIR/${STAMP}.web.tcpreplay.log"
CAPTURE_PID=""
REPLAY_PID=""

stop_pid() {
  local pid="$1"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill -INT "$pid" >/dev/null 2>&1 || true
    for _ in {1..50}; do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        wait "$pid" 2>/dev/null || true
        return 0
      fi
      state="$(ps -o stat= -p "$pid" 2>/dev/null || true)"
      if [[ "$state" == Z* ]]; then
        wait "$pid" 2>/dev/null || true
        return 0
      fi
      sleep 0.1
    done
    kill -TERM "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  stop_pid "$REPLAY_PID"
  stop_pid "$CAPTURE_PID"
}
trap cleanup EXIT INT TERM

args=(--config "$CONFIG" --pipeline --quiet --web)
if [[ -n "$IFACE" ]]; then
  args+=(--interface "$IFACE")
fi

sudo "$BINARY" "${args[@]}" >"$APP_LOG" 2>&1 &
CAPTURE_PID="$!"

ready=0
for _ in {1..200}; do
  if grep -Fq 'NETSCOPE_READY ' "$APP_LOG"; then
    ready=1
    break
  fi
  if ! kill -0 "$CAPTURE_PID" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "error: NetScope did not become ready; see $APP_LOG" >&2
  exit 1
fi

echo "NetScope is ready. Settings:"
grep -F 'NETSCOPE_READY ' "$APP_LOG" | tail -n 1
echo "Open http://127.0.0.1:8080/?perf=1 to inspect the local dashboard."
echo "This is a manual dashboard smoke check; it does not establish a packet-loss result."
echo "Logs: $APP_LOG"

if [[ -n "$TRACE" ]]; then
  echo "Starting continuous replay after readiness: iface=$IFACE pps=$PPS"
  sudo "$TCPREPLAY_BIN" --intf1="$IFACE" --pps="$PPS" --loop=0 "$TRACE" >"$REPLAY_LOG" 2>&1 &
  REPLAY_PID="$!"
  echo "Replay log: $REPLAY_LOG"
fi

wait "$CAPTURE_PID"
