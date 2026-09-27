#!/usr/bin/env python3
"""Build NetScope and collect reproducible offline benchmark records."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import platform
import queue
import random
import re
import select
import shutil
import shlex
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workloads import WORKLOADS, generate_workload


ROOT = Path(__file__).resolve().parents[2]
RESULT_SCHEMA_VERSION = 1
DEFAULT_WORKERS = (2, 4)
ANALYSIS_HEAVY = "analysis-heavy"
VALIDATION_FIELDS = (
    "frames_read",
    "input_wire_bytes",
    "packets_parsed",
    "packets_with_network_header",
    "packets_with_transport_header",
    "packet_parse_errors",
    "transport_parse_errors",
    "unsupported_packets",
    "malformed_or_unsupported_packets",
    "flows_created",
    "flows_expired",
    "flows_evicted",
    "alerts_emitted",
    "worker_processed_frames",
    "dispatch_drops",
    "worker_failures",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")


def command_output(
    args: list[str], timeout: float = 5.0, cwd: Path | None = None
) -> str | None:
    try:
        result = subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def git_source_state(exclude_root: Path | None = None) -> dict[str, Any]:
    commit = command_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
    if commit is None:
        raise RuntimeError("cannot identify the source commit; run this command inside the Git checkout")

    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if status.returncode != 0:
        raise RuntimeError(f"git status failed: {status.stderr.strip()}")
    excluded_roots: list[str] = ["docs/benchmarks"]
    if exclude_root is not None:
        try:
            excluded_roots.append(exclude_root.resolve().relative_to(ROOT).as_posix())
        except ValueError:
            pass
    status_lines = []
    for line in status.stdout.splitlines():
        if not line:
            continue
        path = line[3:].replace("\\", "/")
        if any(path == excluded or path.startswith(excluded.rstrip("/") + "/") for excluded in excluded_roots):
            continue
        status_lines.append(line)
    patch = subprocess.run(
        ["git", "diff", "--binary", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if patch.returncode != 0:
        raise RuntimeError("git diff failed while fingerprinting benchmark source")

    untracked_hashes: list[dict[str, Any]] = []
    for line in status_lines:
        if line.startswith("?? "):
            relative = line[3:]
            path = ROOT / relative
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"cannot fingerprint untracked source path {relative}")
            untracked_hashes.append(
                {"path": relative, "sha256": sha256_file(path), "bytes": path.stat().st_size}
            )

    digest = hashlib.sha256()
    digest.update(commit.encode("ascii"))
    digest.update(patch.stdout)
    for entry in sorted(untracked_hashes, key=lambda row: row["path"]):
        digest.update(entry["path"].encode("utf-8"))
        digest.update(entry["sha256"].encode("ascii"))

    return {
        "commit": commit,
        "dirty": bool(status_lines),
        "status_porcelain": status_lines,
        "tracked_diff_sha256": hashlib.sha256(patch.stdout).hexdigest(),
        "untracked_files": sorted(untracked_hashes, key=lambda row: row["path"]),
        "source_tree_sha256": digest.hexdigest(),
        "fingerprint_method": "commit + binary diff from HEAD + SHA-256 of each untracked regular file",
    }


def save_source_snapshot(source: dict[str, Any], output_root: Path) -> dict[str, Any]:
    """Keep the exact dirty source inputs needed to reconstruct a published run."""
    snapshot_root = output_root / "source-snapshot"
    snapshot_root.mkdir(parents=True)
    patch = subprocess.run(
        ["git", "diff", "--binary", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if patch.returncode != 0:
        raise RuntimeError("git diff failed while saving the benchmark source snapshot")
    if hashlib.sha256(patch.stdout).hexdigest() != source["tracked_diff_sha256"]:
        raise RuntimeError("tracked source changed before its snapshot could be saved")
    (snapshot_root / "working-tree.patch").write_bytes(patch.stdout)

    for entry in source["untracked_files"]:
        relative = Path(entry["path"])
        original = ROOT / relative
        if original.is_symlink() or not original.is_file():
            raise RuntimeError(f"cannot snapshot untracked source file {relative}")
        if sha256_file(original) != entry["sha256"]:
            raise RuntimeError(f"untracked source changed before its snapshot: {relative}")
        saved = snapshot_root / "untracked" / relative
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, saved)
        if sha256_file(saved) != entry["sha256"]:
            raise RuntimeError(f"saved source snapshot differs from {relative}")

    (snapshot_root / "README.md").write_text(
        "# Reconstruct this benchmark source\n\n"
        f"Start from commit `{source['commit']}` in a clean checkout. "
        "Apply `working-tree.patch` with `git apply --binary`, then copy the "
        "contents of `untracked/` into that checkout, preserving paths. "
        "An empty patch means tracked files matched the commit. "
        "Verify all hashes against `../source.json` before rebuilding.\n"
    )
    return {
        "complete": True,
        "patch_path": "source-snapshot/working-tree.patch",
        "untracked_root": "source-snapshot/untracked",
        "reconstruction_guide": "source-snapshot/README.md",
    }


def _sysctl(name: str) -> str | None:
    return command_output(["/usr/sbin/sysctl", "-n", name]) or command_output(["sysctl", "-n", name])


def _cpu_model() -> str | None:
    if sys.platform == "darwin":
        return _sysctl("machdep.cpu.brand_string") or _sysctl("hw.model")
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith(("model name", "hardware", "processor")):
                _, _, value = line.partition(":")
                if value.strip():
                    return value.strip()
    return platform.processor() or None


def _memory_total_bytes() -> int | None:
    if sys.platform == "darwin":
        value = _sysctl("hw.memsize")
        return int(value) if value and value.isdigit() else None
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB", meminfo.read_text(), re.MULTILINE)
        if match:
            return int(match.group(1)) * 1024
    return None


def _physical_core_count() -> int | None:
    if sys.platform == "darwin":
        value = _sysctl("hw.physicalcpu")
        return int(value) if value and value.isdigit() else None
    output = command_output(["lscpu", "-p=CORE,SOCKET"])
    if output:
        cores = {line for line in output.splitlines() if line and not line.startswith("#")}
        return len(cores) or None
    return None


def _power_state() -> dict[str, str | None]:
    if sys.platform == "darwin":
        custom = command_output(["/usr/bin/pmset", "-g", "custom"])
        low_power: str | None = None
        if custom:
            matches = re.findall(r"lowpowermode\s+(\d+)", custom, re.IGNORECASE)
            if matches:
                low_power = ", ".join(sorted(set(matches)))
        return {
            "source": command_output(["/usr/bin/pmset", "-g", "batt"]),
            "low_power_mode_values_from_power_profiles": low_power or "unavailable",
            "cpu_governor": "unavailable on macOS",
        }
    governors = sorted(Path("/sys/devices/system/cpu").glob("cpu0/cpufreq/scaling_governor"))
    governor = None
    if governors:
        try:
            governor = governors[0].read_text().strip()
        except OSError:
            pass
    return {
        "source": command_output(["sh", "-c", "for p in /sys/class/power_supply/*/type; do test -r \"$p\" && read \"$p\"; done"]),
        "low_power_mode": None,
        "cpu_governor": governor or "unavailable",
    }


def collect_environment(load_start: tuple[float, ...] | None, note: str | None) -> dict[str, Any]:
    version = command_output(["rustc", "--version", "--verbose"])
    cargo_version = command_output(["cargo", "--version"])
    pcap_version = command_output(["pcap-config", "--version"]) or command_output(
        ["pkg-config", "--modversion", "libpcap"]
    )
    time_version = command_output(["/usr/bin/time", "--version"])
    if time_version is None and sys.platform == "darwin":
        time_version = "Apple /usr/bin/time (-l)"
    elif time_version is None:
        time_version = "unavailable"
    try:
        load_end = os.getloadavg()
    except (AttributeError, OSError):
        load_end = None

    return {
        "captured_at_utc": utc_now(),
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine_architecture": platform.machine(),
        "cpu_model": _cpu_model() or "unavailable",
        "logical_cpu_count": os.cpu_count(),
        "physical_cpu_count": _physical_core_count(),
        "memory_total_bytes": _memory_total_bytes(),
        "python_version": sys.version.split()[0],
        "rustc_version": version or "unavailable",
        "cargo_version": cargo_version or "unavailable",
        "libpcap_version": pcap_version or "unavailable",
        "resource_timer": time_version,
        "power_state": _power_state(),
        "system_load_average_start": list(load_start) if load_start is not None else None,
        "system_load_average_end": list(load_end) if load_end is not None else None,
        "background_load_notes": note or "not recorded manually",
    }


def time_adapter() -> tuple[list[str], str]:
    if not Path("/usr/bin/time").is_file():
        raise RuntimeError("/usr/bin/time is required for per-process CPU and peak RSS measurements")
    if sys.platform == "darwin":
        return ["/usr/bin/time", "-l", "-o"], "macos-bsd-time-l"
    if sys.platform.startswith("linux"):
        version = command_output(["/usr/bin/time", "--version"])
        if version and "GNU time" in version:
            return ["/usr/bin/time", "-v", "-o"], "linux-gnu-time-v"
    raise RuntimeError(f"no supported /usr/bin/time resource adapter for {sys.platform}")


def parse_time_output(text: str, adapter: str) -> dict[str, Any]:
    if adapter == "macos-bsd-time-l":
        bsd = re.search(
            r"^\s*([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys$",
            text,
            re.MULTILINE,
        )
        rss_bytes = re.search(
            r"^\s*(\d+)\s+maximum resident set size$", text, re.MULTILINE
        )
        return {
            "user_cpu_seconds": float(bsd.group(2)) if bsd else None,
            "system_cpu_seconds": float(bsd.group(3)) if bsd else None,
            "peak_rss_bytes": int(rss_bytes.group(1)) if rss_bytes else None,
            "wall_seconds_reported_by_time": float(bsd.group(1)) if bsd else None,
        }

    user = re.search(r"(?:User time \(seconds\)|^\s*([0-9.]+) user)$", text, re.MULTILINE)
    system = re.search(r"(?:System time \(seconds\)|^\s*([0-9.]+) sys)$", text, re.MULTILINE)
    if user and user.lastindex:
        user_seconds = float(user.group(1))
    else:
        match = re.search(r"User time \(seconds\):\s*([0-9.]+)", text)
        user_seconds = float(match.group(1)) if match else None
    if system and system.lastindex:
        system_seconds = float(system.group(1))
    else:
        match = re.search(r"System time \(seconds\):\s*([0-9.]+)", text)
        system_seconds = float(match.group(1)) if match else None

    rss = re.search(r"maximum resident set size \(kbytes\):\s*(\d+)", text, re.IGNORECASE)
    if not rss:
        rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text, re.IGNORECASE)
    peak_rss_bytes = int(rss.group(1)) * 1024 if rss else None

    wall = None
    wall_match = re.search(r"Elapsed \(wall clock\) time .*?:\s*([0-9:.]+)", text)
    if wall_match:
        parts = wall_match.group(1).split(":")
        try:
            if len(parts) == 3:
                wall = int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
            elif len(parts) == 2:
                wall = int(parts[0]) * 60 + float(parts[1])
            else:
                wall = float(parts[0])
        except ValueError:
            wall = None
    if wall is None and adapter == "macos-bsd-time-l":
        real = re.search(r"^\s*([0-9.]+) real$", text, re.MULTILINE)
        if real:
            wall = float(real.group(1))

    return {
        "user_cpu_seconds": user_seconds,
        "system_cpu_seconds": system_seconds,
        "peak_rss_bytes": peak_rss_bytes,
        "wall_seconds_reported_by_time": wall,
    }


def write_config(path: Path, *, anomalies: bool, web: dict[str, int] | None) -> None:
    lines = [
        "[flow]",
        "timeout_secs = 0.0",
        "max_flows = 0",
        "",
        "[stats]",
        "enabled = false",
        "interval_ms = 1000",
        "top_flows = 0",
        "",
        "[analysis]",
        f"rtt = {str(anomalies).lower()}",
        f"retrans = {str(anomalies).lower()}",
        f"out_of_order = {str(anomalies).lower()}",
        "",
        "[analysis.anomalies]",
        f"enabled = {str(anomalies).lower()}",
        "",
        "[analysis.anomalies.syn_flood]",
        "enabled = true",
        "window_secs = 5.0",
        "syn_threshold = 200",
        "unique_src_threshold = 50",
        "cooldown_secs = 10.0",
        "",
        "[analysis.anomalies.port_scan]",
        "enabled = false",
    ]
    if web is not None:
        lines.extend(
            [
                "",
                "[web]",
                "enabled = true",
                'bind = "127.0.0.1"',
                f"port = {web['port']}",
                f"tick_ms = {web['tick_ms']}",
                "top_n = 10",
                "packet_buffer = 256",
                "sample_rate = 1000",
                "payload_bytes = 64",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("dashboard websocket closed during a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _client_control_frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header + mask + masked


def _dashboard_connect(port: int) -> tuple[socket.socket, bytearray]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    sock.settimeout(5.0)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    received = bytearray()
    while b"\r\n\r\n" not in received:
        received.extend(sock.recv(4096))
        if len(received) > 16384:
            raise ConnectionError("dashboard returned oversized websocket headers")
    boundary = received.index(b"\r\n\r\n") + 4
    headers = bytes(received[:boundary]).decode("latin-1")
    if " 101 " not in headers.splitlines()[0]:
        raise ConnectionError(f"dashboard websocket upgrade failed: {headers.splitlines()[0]}")
    sock.setblocking(False)
    return sock, bytearray(received[boundary:])


def _decode_ws_buffer(buffer: bytearray) -> tuple[list[tuple[int, bytes]], bool]:
    frames: list[tuple[int, bytes]] = []
    while len(buffer) >= 2:
        first, second = buffer[0], buffer[1]
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < offset + 2:
                break
            length = struct.unpack("!H", buffer[offset : offset + 2])[0]
            offset += 2
        elif length == 127:
            if len(buffer) < offset + 8:
                break
            length = struct.unpack("!Q", buffer[offset : offset + 8])[0]
            offset += 8
        mask = b""
        if masked:
            if len(buffer) < offset + 4:
                break
            mask = bytes(buffer[offset : offset + 4])
            offset += 4
        if len(buffer) < offset + length:
            break
        payload = bytes(buffer[offset : offset + length])
        if masked:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        del buffer[: offset + length]
        frames.append((opcode, payload))
    return frames, any(opcode == 8 for opcode, _ in frames)


def read_dashboard_frames(
    sock: socket.socket,
    buffer: bytearray,
    process: subprocess.Popen[bytes],
    duration_limit: float,
) -> dict[str, Any]:
    start = time.perf_counter()
    deadline = start + duration_limit
    frame_records: list[dict[str, Any]] = []
    message_bytes = 0
    hello_received = False
    closed = False
    while time.perf_counter() < deadline:
        if process.poll() is not None and not select.select([sock], [], [], 0.1)[0]:
            break
        readable, _, _ = select.select([sock], [], [], 0.1)
        if readable:
            try:
                chunk = sock.recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            if not chunk:
                break
            buffer.extend(chunk)
            frames, closed = _decode_ws_buffer(buffer)
            now = time.perf_counter()
            for opcode, payload in frames:
                message_bytes += len(payload)
                if opcode == 9:
                    sock.sendall(_client_control_frame(10, payload))
                    continue
                if opcode != 1:
                    continue
                try:
                    message = json.loads(payload)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if message.get("type") == "hello":
                    hello_received = True
                elif message.get("type") == "frame":
                    # Serde's internally tagged newtype variant is flattened
                    # into the message envelope rather than nested under data.
                    data = message.get("data", message)
                    frame_records.append(
                        {
                            "frame_seq": data.get("frame_seq"),
                            "arrival_monotonic_seconds": now,
                            "payload_bytes": len(payload),
                            "packet_samples": len(data.get("packets", [])),
                            "server_ts": data.get("tick", {}).get("server_ts"),
                        }
                    )
            if closed:
                break

    elapsed = max(time.perf_counter() - start, 0.0)
    arrivals = [row["arrival_monotonic_seconds"] for row in frame_records]
    intervals_ms = [
        (right - left) * 1000.0 for left, right in zip(arrivals, arrivals[1:])
    ]
    ordered = sorted(intervals_ms)

    def percentile(values: list[float], fraction: float) -> float | None:
        if not values:
            return None
        return values[min(math.ceil(fraction * len(values)) - 1, len(values) - 1)]

    sequence_numbers = [row["frame_seq"] for row in frame_records if isinstance(row["frame_seq"], int)]
    gaps = sum(max(0, right - left - 1) for left, right in zip(sequence_numbers, sequence_numbers[1:]))
    return {
        "hello_received": hello_received,
        "frame_count": len(frame_records),
        "frame_sequence_gaps": gaps,
        "measured_seconds": elapsed,
        "frames_per_second": len(frame_records) / elapsed if elapsed > 0 else None,
        "frame_interval_ms_p50": percentile(ordered, 0.50),
        "frame_interval_ms_p95": percentile(ordered, 0.95),
        "frame_interval_ms_p99": percentile(ordered, 0.99),
        "websocket_payload_bytes": message_bytes,
        "packet_samples_received": sum(row["packet_samples"] for row in frame_records),
        "frames": frame_records,
        "measurement_limit": "server-to-local-WebSocket-client delivery; does not measure browser rendering",
    }


def _pump_pipe(pipe: Any, destination: Path, ready: threading.Event | None = None) -> None:
    with destination.open("wb") as output:
        while True:
            line = pipe.readline()
            if not line:
                break
            output.write(line)
            if ready is not None and b"Web dashboard:" in line:
                ready.set()


def run_process(
    command: list[str],
    output_dir: Path,
    adapter: list[str],
    adapter_name: str,
    *,
    timeout: float,
    dashboard_port: int | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / "stdout.txt"
    stderr_path = output_dir / "stderr.txt"
    resource_path = output_dir / "resource-output.txt"
    measured_command = [*adapter, str(resource_path), *command]
    started_at = utc_now()
    start = time.perf_counter()
    dashboard: dict[str, Any] | None = None
    process: subprocess.Popen[bytes]
    try:
        if dashboard_port is None:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    measured_command,
                    cwd=ROOT,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=(os.name == "posix"),
                )
                try:
                    exit_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise TimeoutError(f"benchmark process exceeded {timeout:g}s timeout")
        else:
            ready = threading.Event()
            process = subprocess.Popen(
                measured_command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                start_new_session=(os.name == "posix"),
            )
            assert process.stdout is not None and process.stderr is not None
            stdout_thread = threading.Thread(
                target=_pump_pipe,
                args=(process.stdout, stdout_path, ready),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_pump_pipe,
                args=(process.stderr, stderr_path),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            websocket: socket.socket | None = None
            websocket_buffer = bytearray()
            try:
                ready_until = time.monotonic() + min(timeout, 15.0)
                while not ready.is_set() and time.monotonic() < ready_until:
                    if process.poll() is not None:
                        break
                    ready.wait(0.02)
                if ready.is_set() and process.poll() is None:
                    websocket, websocket_buffer = _dashboard_connect(dashboard_port)
                    dashboard = read_dashboard_frames(websocket, websocket_buffer, process, timeout)
                else:
                    dashboard = {
                        "hello_received": False,
                        "frame_count": 0,
                        "connection_error": "dashboard readiness signal was not observed before the capture ended",
                        "measurement_limit": "server-to-local-WebSocket-client delivery; does not measure browser rendering",
                    }
                try:
                    exit_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise TimeoutError(f"dashboard benchmark exceeded {timeout:g}s timeout")
            finally:
                if websocket is not None:
                    websocket.close()
                stdout_thread.join(timeout=5.0)
                stderr_thread.join(timeout=5.0)
        wall = time.perf_counter() - start
    except BaseException:
        if "process" in locals() and process.poll() is None:
            process.kill()
            process.wait()
        raise

    raw_time = resource_path.read_text(errors="replace") if resource_path.exists() else ""
    resources = parse_time_output(raw_time, adapter_name)
    return {
        "exit_code": exit_code,
        "started_at_utc": started_at,
        "measured_wall_seconds": wall,
        "resource_adapter": adapter_name,
        "resource_output_path": str(resource_path.relative_to(output_dir.parent.parent.parent))
        if resource_path.is_relative_to(output_dir.parent.parent.parent)
        else str(resource_path),
        "raw_stdout_path": str(stdout_path.relative_to(output_dir.parent.parent.parent))
        if stdout_path.is_relative_to(output_dir.parent.parent.parent)
        else str(stdout_path),
        "raw_stderr_path": str(stderr_path.relative_to(output_dir.parent.parent.parent))
        if stderr_path.is_relative_to(output_dir.parent.parent.parent)
        else str(stderr_path),
        "resource_values": resources,
        "dashboard_probe": dashboard,
    }


def workload_config(task: dict[str, Any], config_dir: Path) -> tuple[Path, int | None]:
    dashboard = bool(task.get("dashboard"))
    port = reserve_local_port() if dashboard else None
    web = {"port": port, "tick_ms": 33} if port is not None else None
    path = config_dir / f"{task['scenario_id']}.toml"
    write_config(path, anomalies=task["anomalies"], web=web)
    return path, port


def summary_validation(
    summary: dict[str, Any] | None,
    expected: dict[str, Any],
    mode: str,
    expected_anomaly: bool,
) -> list[str]:
    errors: list[str] = []
    if summary is None:
        return ["summary JSON was not written"]
    if summary.get("schema_version") != 1:
        errors.append(f"unsupported run-summary schema {summary.get('schema_version')!r}")
    if summary.get("status") != "success":
        errors.append(f"application status is {summary.get('status')!r}")
    if summary.get("frames_read") != expected["packet_count"]:
        errors.append(
            f"frames_read={summary.get('frames_read')} expected {expected['packet_count']}"
        )
    if summary.get("input_wire_bytes") != expected["wire_bytes"]:
        errors.append(
            f"input_wire_bytes={summary.get('input_wire_bytes')} expected {expected['wire_bytes']}"
        )
    if summary.get("packet_parse_errors") != 0 or summary.get("transport_parse_errors") != 0:
        errors.append("valid generated workload reported a parser error")
    if mode == "pipeline":
        processed = summary.get("worker_processed_frames")
        if processed != expected["packet_count"]:
            errors.append(f"worker_processed_frames={processed} expected {expected['packet_count']}")
        if summary.get("dispatch_drops") != 0:
            errors.append(f"dispatch_drops={summary.get('dispatch_drops')} expected 0")
        if summary.get("worker_failures") != 0:
            errors.append(f"worker_failures={summary.get('worker_failures')} expected 0")
    if expected_anomaly and (summary.get("alerts_emitted") or 0) < 1:
        errors.append("analysis-heavy workload did not trigger the configured SYN-flood detector")
    return errors


def make_record(
    *,
    task: dict[str, Any],
    phase: str,
    repetition: int,
    command: list[str],
    config_path: Path,
    trace_path: Path,
    manifest: dict[str, Any],
    source: dict[str, Any],
    binary_sha: str,
    process_result: dict[str, Any],
    run_dir: Path,
    artifact_root: Path,
) -> dict[str, Any]:
    summary_path = run_dir / "summary.json"
    try:
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
    except json.JSONDecodeError:
        summary = None
    errors = summary_validation(
        summary,
        manifest,
        task["mode"],
        task["anomalies"],
    )

    resource = process_result["resource_values"]
    processed_packets = None
    if summary is not None:
        processed_packets = (
            summary.get("worker_processed_frames")
            if task["mode"] == "pipeline"
            else summary.get("frames_read")
        )
    wall = process_result["measured_wall_seconds"]
    wire_bytes = summary.get("input_wire_bytes") if summary else None
    cpu_user = resource.get("user_cpu_seconds")
    cpu_system = resource.get("system_cpu_seconds")
    cpu_total = cpu_user + cpu_system if cpu_user is not None and cpu_system is not None else None
    metrics = {
        "processed_packets": processed_packets,
        "input_wire_bytes": wire_bytes,
        "elapsed_wall_seconds": wall,
        "packet_throughput_per_second": processed_packets / wall
        if processed_packets is not None and wall > 0
        else None,
        "bit_throughput_mbps_decimal": wire_bytes * 8 / wall / 1_000_000
        if wire_bytes is not None and wall > 0
        else None,
        "user_cpu_seconds": cpu_user,
        "system_cpu_seconds": cpu_system,
        "total_cpu_seconds": cpu_total,
        "cpu_utilization_percent": cpu_total / wall * 100
        if cpu_total is not None and wall > 0
        else None,
        "cpu_seconds_per_million_packets": cpu_total / processed_packets * 1_000_000
        if cpu_total is not None and processed_packets
        else None,
        "peak_rss_bytes": resource.get("peak_rss_bytes"),
        "peak_rss_mib": resource["peak_rss_bytes"] / (1024 * 1024)
        if resource.get("peak_rss_bytes") is not None
        else None,
    }
    if process_result["exit_code"] != 0:
        errors.append(f"NetScope exited with status {process_result['exit_code']}")
    if process_result.get("dashboard_probe") is not None:
        probe = process_result["dashboard_probe"]
        if not probe.get("hello_received"):
            errors.append("dashboard WebSocket hello was not received")

    try:
        config_relative = str(config_path.relative_to(artifact_root))
    except ValueError:
        config_relative = str(config_path)
    trace_relative = f"generated-temporary/{trace_path.name} (deleted after run)"
    record = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "run_id": f"{task['scenario_id']}-{phase}-{repetition:02d}",
        "scenario_id": task["scenario_id"],
        "phase": phase,
        "repetition": repetition,
        "started_at_utc": process_result["started_at_utc"],
        "workload": {
            **manifest,
            "manifest_path": f"workloads/{manifest['workload']}-{manifest['packet_count']}.manifest.json",
            "trace_path": trace_relative,
            "pcap_retained": False,
            "regeneration_command": (
                "python3 scripts/perf/workloads.py --output-dir <dir> "
                f"--workload {manifest['workload']} --packets {manifest['packet_count']}"
            ),
        },
        "mode": task["mode"],
        "requested_workers": task["workers"],
        "dashboard_enabled": task["dashboard"],
        "anomaly_detection_enabled": task["anomalies"],
        "command": command,
        "config_path": config_relative,
        "binary_sha256": binary_sha,
        "source_commit": source["commit"],
        "source_dirty": source["dirty"],
        "source_tree_sha256": source["source_tree_sha256"],
        "exit_code": process_result["exit_code"],
        "resource_adapter": process_result["resource_adapter"],
        "raw_stdout_path": process_result["raw_stdout_path"],
        "raw_stderr_path": process_result["raw_stderr_path"],
        "raw_resource_output_path": process_result["resource_output_path"],
        "resource_readings": resource,
        "elapsed_wall_seconds": wall,
        "metrics": metrics,
        "dashboard_probe": process_result.get("dashboard_probe"),
        "run_summary": summary,
        "validation": {"passed": not errors, "errors": errors},
    }
    json_write(run_dir / "record.json", record)
    return record


def _make_task(workload: str, mode: str, workers: int | None, *, dashboard: bool = False) -> dict[str, Any]:
    suffix = "inline" if mode == "inline" else f"pipeline-w{workers}"
    if dashboard:
        suffix += "-websocket"
    return {
        "scenario_id": f"{workload}-{suffix}",
        "workload": workload,
        "mode": mode,
        "workers": workers,
        "dashboard": dashboard,
        "anomalies": workload == ANALYSIS_HEAVY,
    }


def _run_task(
    task: dict[str, Any],
    *,
    phase: str,
    repetition: int,
    binary: Path,
    trace_path: Path,
    manifest: dict[str, Any],
    config_path: Path,
    port: int | None,
    output_root: Path,
    artifact_root: Path,
    adapter: list[str],
    adapter_name: str,
    timeout: float,
    source: dict[str, Any],
    binary_sha: str,
) -> dict[str, Any]:
    run_dir = output_root / "runs" / task["scenario_id"] / f"{phase}-{repetition:02d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    run_config_path = run_dir / "config.toml"
    run_config_path.write_text(config_path.read_text())
    summary_path = run_dir / "summary.json"
    command = [
        str(binary),
        "--config",
        str(run_config_path),
        "--read-pcap",
        str(trace_path),
        "--quiet",
        "--no-stats",
        "--summary-json",
        str(summary_path),
    ]
    if task["anomalies"]:
        command.append("--anomalies")
    else:
        command.append("--no-anomalies")
    if task["dashboard"]:
        command.append("--web")
    if task["mode"] == "pipeline":
        command.extend(["--pipeline", "--workers", str(task["workers"])])

    process_result = run_process(
        command,
        run_dir,
        adapter,
        adapter_name,
        timeout=timeout,
        dashboard_port=port,
    )
    record = make_record(
        task=task,
        phase=phase,
        repetition=repetition,
        command=command,
        config_path=run_config_path,
        trace_path=trace_path,
        manifest=manifest,
        source=source,
        binary_sha=binary_sha,
        process_result=process_result,
        run_dir=run_dir,
        artifact_root=artifact_root,
    )
    if not record["validation"]["passed"]:
        raise RuntimeError(
            f"invalid benchmark run {record['run_id']}: "
            + "; ".join(record["validation"]["errors"])
        )
    return record


def _record_signature(record: dict[str, Any]) -> tuple[Any, ...]:
    summary = record.get("run_summary") or {}
    return tuple(summary.get(field) for field in VALIDATION_FIELDS)


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(math.ceil(fraction * len(ordered)) - 1, len(ordered) - 1)]


def aggregate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    measured = [record for record in records if record["phase"] == "measured"]
    buckets: dict[str, list[dict[str, Any]]] = {}
    for record in measured:
        buckets.setdefault(record["scenario_id"], []).append(record)

    aggregates: list[dict[str, Any]] = []
    for scenario_id, rows in sorted(buckets.items()):
        first = rows[0]
        signatures = {_record_signature(row) for row in rows}
        field_names = (
            "packet_throughput_per_second",
            "bit_throughput_mbps_decimal",
            "total_cpu_seconds",
            "cpu_utilization_percent",
            "cpu_seconds_per_million_packets",
            "peak_rss_mib",
        )
        values: dict[str, Any] = {}
        for name in field_names:
            sample = [row["metrics"].get(name) for row in rows]
            sample = [value for value in sample if isinstance(value, (int, float))]
            values[name] = {
                "median": statistics.median(sample) if sample else None,
                "min": min(sample) if sample else None,
                "max": max(sample) if sample else None,
                "p25": _percentile(sample, 0.25),
                "p75": _percentile(sample, 0.75),
                "spread_percent_of_median": (
                    (max(sample) - min(sample)) / statistics.median(sample) * 100
                    if sample and statistics.median(sample) != 0
                    else None
                ),
            }
        dashboard_probes = [row["dashboard_probe"] for row in rows if row.get("dashboard_probe")]
        dashboard_metrics = None
        if dashboard_probes:
            fps = [row.get("frames_per_second") for row in dashboard_probes]
            fps = [value for value in fps if isinstance(value, (int, float))]
            frame_count = [row.get("frame_count", 0) for row in dashboard_probes]
            sequence_gaps = [row.get("frame_sequence_gaps", 0) for row in dashboard_probes]
            dashboard_metrics = {
                "frames_per_second_median": statistics.median(fps) if fps else None,
                "frames_per_run_median": statistics.median(frame_count),
                "frame_sequence_gaps_total": sum(sequence_gaps),
                "frame_interval_ms_p50_median": statistics.median(
                    [row["frame_interval_ms_p50"] for row in dashboard_probes if row.get("frame_interval_ms_p50") is not None]
                )
                if any(row.get("frame_interval_ms_p50") is not None for row in dashboard_probes)
                else None,
                "frame_interval_ms_p95_median": statistics.median(
                    [row["frame_interval_ms_p95"] for row in dashboard_probes if row.get("frame_interval_ms_p95") is not None]
                )
                if any(row.get("frame_interval_ms_p95") is not None for row in dashboard_probes)
                else None,
                "measurement_limit": dashboard_probes[0].get("measurement_limit"),
            }
        aggregates.append(
            {
                "scenario_id": scenario_id,
                "workload": first["workload"]["workload"],
                "packet_count": first["workload"]["packet_count"],
                "pcap_sha256": first["workload"]["pcap_sha256"],
                "mode": first["mode"],
                "requested_workers": first["requested_workers"],
                "dashboard_enabled": first["dashboard_enabled"],
                "anomaly_detection_enabled": first["anomaly_detection_enabled"],
                "repetitions": len(rows),
                "deterministic_summary_across_repetitions": len(signatures) == 1,
                "metrics": values,
                "dashboard_metrics": dashboard_metrics,
                "run_ids": [row["run_id"] for row in rows],
            }
        )
    return aggregates


def _fmt(value: float | int | None, precision: int = 2) -> str:
    return "unavailable" if value is None else f"{value:,.{precision}f}"


def write_report(path: Path, envelope: dict[str, Any]) -> None:
    source = envelope["source"]
    env = envelope["environment"]
    aggregates = envelope["aggregates"]
    repeat_batches = envelope["method"].get("supplemental_repeat_batches", [])
    legacy_workloads = any(row.get("schema_version") == 1 for row in envelope["workloads"])
    generator_note = (
        "The historical generator in `source-snapshot/untracked/scripts/perf/workloads.py` recreates each zero-checksum trace."
        if legacy_workloads
        else "`scripts/perf/workloads.py` recreates each checksummed trace."
    )
    power_desc = env["power_state"].get("source") or env["power_state"].get("cpu_governor") or "unavailable"
    power_desc = " ".join(str(power_desc).split())
    background_notes = " ".join(str(env["background_load_notes"]).split()).rstrip()
    if not background_notes.endswith((".", "!", "?")):
        background_notes += "."
    lines = [
        "# Offline benchmark report",
        "",
        f"Generated: `{envelope.get('report_generated_at_utc', envelope['created_at_utc'])}`",
        f"Source commit: `{source['commit']}`; dirty worktree: **{str(source['dirty']).lower()}**; source fingerprint: `{source['source_tree_sha256']}`.",
        f"Binary SHA-256: `{envelope['binary']['sha256']}`.",
        f"Host: {env['os']}; CPU {env['cpu_model']}; {env['logical_cpu_count']} logical / {env['physical_cpu_count'] or 'unavailable'} physical CPUs; memory {_fmt((env['memory_total_bytes'] or 0) / (1024 * 1024), 0)} MiB.",
        f"Rust: `{env['rustc_version'].splitlines()[0]}`; libpcap: `{env['libpcap_version']}`; power/governor: `{power_desc}`.",
        "",
        "## Method",
        "",
        f"Command: `{envelope['invocation']}`.",
        f"The initial suite used {envelope['method']['warmups']} unreported warm-up run(s) and {envelope['method']['repetitions']} measured repetitions per scenario. Supplemental batches, when present, are listed separately below; the results table pools all measured repetitions. NetScope was built with `cargo build --locked --release` for the initial suite; supplemental batches reuse its recorded binary.",
        "Wall time starts immediately before launching the timed NetScope process and ends after exit; it includes PCAP open/read, processing, summary output, and shutdown. It excludes workload generation and compilation.",
        "Throughput uses worker-processed packets (inline uses frames read) divided by wall seconds. Mbps is decimal and uses original wire bytes from the run summary. CPU is process user+system time; utilization can exceed 100% in pipeline mode. RSS is process peak resident set size.",
        "Offline reconciliation compares generated manifest counts/bytes with NetScope's final summary and requires zero pipeline dispatch drops and worker failures. These PCAP results say nothing about packets lost before the files were created.",
        f"System load averages were {env['system_load_average_start']} at collection start and {env['system_load_average_end']} at collection end. Background-load notes: {background_notes}",
        "",
        "## Results",
        "",
        "Medians are shown with the observed min–max range. Aggregates and run metadata are in `results.json`; raw stdout, stderr, summaries, timer output, and copied configs are stored in each run directory.",
        "",
        "| Workload | Mode | Workers | Features | Measured reps | Packets/s median [range] | Mbps median [range] | CPU % median [range] | CPU s / M packets median [range] | Peak RSS MiB median [range] | Input / processed |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    if source.get("snapshot", {}).get("complete"):
        lines.insert(5, "The exact dirty source inputs are saved in `source-snapshot/`; see its `README.md` for reconstruction.")
    elif source["dirty"]:
        lines.insert(5, "Historical source limitation: this dirty-tree run saved hashes but not a complete source snapshot, so the recorded fingerprint alone cannot reconstruct the build.")
    for row in aggregates:
        m = row["metrics"]
        pps = m["packet_throughput_per_second"]
        mbps = m["bit_throughput_mbps_decimal"]
        cpu = m["cpu_utilization_percent"]
        cpu_per_million = m["cpu_seconds_per_million_packets"]
        rss = m["peak_rss_mib"]
        pps_text = f"{_fmt(pps['median'], 0)} [{_fmt(pps['min'], 0)}–{_fmt(pps['max'], 0)}]"
        mbps_text = f"{_fmt(mbps['median'])} [{_fmt(mbps['min'])}–{_fmt(mbps['max'])}]"
        cpu_text = f"{_fmt(cpu['median'])} [{_fmt(cpu['min'])}–{_fmt(cpu['max'])}]"
        cpu_per_million_text = (
            f"{_fmt(cpu_per_million['median'])} "
            f"[{_fmt(cpu_per_million['min'])}–{_fmt(cpu_per_million['max'])}]"
        )
        rss_text = f"{_fmt(rss['median'])} [{_fmt(rss['min'])}–{_fmt(rss['max'])}]"
        worker_count = row["requested_workers"] if row["requested_workers"] is not None else "—"
        features = "dashboard" if row["dashboard_enabled"] else (
            "anomalies" if row["anomaly_detection_enabled"] else "—"
        )
        lines.append(
            f"| {row['workload']} | {row['mode']} | {worker_count} | {features} | {row['repetitions']} | {pps_text} | {mbps_text} | "
            f"{cpu_text} | {cpu_per_million_text} | {rss_text} | "
            f"{row['packet_count']:,} / {row['packet_count']:,} |"
        )
    wide_spread = [
        row["scenario_id"]
        for row in aggregates
        if (row["metrics"]["packet_throughput_per_second"]["spread_percent_of_median"] or 0) > 10
    ]
    if wide_spread:
        lines.extend(
            [
                "",
                "Throughput spread exceeded 10% of the median for: "
                + ", ".join(f"`{scenario}`" for scenario in wide_spread)
                + ". The pooled ranges include every measured run; treat these comparisons as provisional and do not select the fastest run.",
            ]
        )
    repeated_scenarios = {
        row["scenario_id"]
        for batch in repeat_batches
        for row in batch["aggregates"]
    }
    not_repeated = [scenario for scenario in wide_spread if scenario not in repeated_scenarios]
    if not_repeated:
        lines.extend(
            [
                "",
                "No supplemental batch was recorded for: "
                + ", ".join(f"`{scenario}`" for scenario in not_repeated)
                + ". Repeat these scenarios before using their pooled medians for comparisons.",
            ]
        )
    if repeat_batches:
        lines.extend(
            [
                "",
                "Supplemental batches use the same saved release binary and regenerated PCAP hashes. Their warm-ups and measured repetitions are separate from the initial suite; every run remains in `results.json`.",
                "",
                "| Repeated scenario | Warm-ups / measured reps | Repeat-batch packets/s median [range] | Repeat spread | Load average start → end |",
                "| --- | ---: | ---: | ---: | --- |",
            ]
        )
        for batch in repeat_batches:
            for row in batch["aggregates"]:
                pps = row["metrics"]["packet_throughput_per_second"]
                lines.append(
                    f"| {row['scenario_id']} | {batch['warmups']} / {row['repetitions']} | "
                    f"{_fmt(pps['median'], 0)} [{_fmt(pps['min'], 0)}–{_fmt(pps['max'], 0)}] | "
                    f"{_fmt(pps['spread_percent_of_median'])}% | "
                    f"{batch['system_load_average_start']} → {batch['system_load_average_end']} |"
                )
        lines.append("")
        for batch in repeat_batches:
            batch_environment = batch.get("environment")
            if batch_environment is None:
                lines.append(
                    f"Repeat batch `{batch['started_at_utc']}`: host and power state were not "
                    "captured at repeat time; its load averages are shown above."
                )
                continue
            power = batch_environment.get("power_state") or {}
            power_description = power.get("source") or power.get("cpu_governor") or "unavailable"
            power_description = " ".join(str(power_description).split())
            lines.append(
                f"Repeat batch `{batch['started_at_utc']}`: {batch_environment.get('os', 'unavailable')}; "
                f"CPU {batch_environment.get('cpu_model', 'unavailable')}; "
                f"power/governor {power_description}; "
                f"background notes: {batch.get('background_load_notes', 'unavailable')}."
            )
    dashboard_rows = [row for row in aggregates if row.get("dashboard_metrics")]
    if dashboard_rows:
        lines.extend(
            [
                "",
                "## Dashboard delivery",
                "",
                "The dashboard scenario used a local WebSocket client and records server-to-client frame cadence, sequence gaps, and payload volume. It does not measure browser rendering FPS or frontend paint latency.",
                "",
                "| Scenario | Frames/run median | Server frames/s median | Interval p50 | Interval p95 | Sequence gaps |",
                "| --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in dashboard_rows:
            values = row["dashboard_metrics"]
            lines.append(
                f"| {row['scenario_id']} | {_fmt(values['frames_per_run_median'], 0)} | "
                f"{_fmt(values['frames_per_second_median'])} | "
                f"{_fmt(values['frame_interval_ms_p50_median'])} ms | "
                f"{_fmt(values['frame_interval_ms_p95_median'])} ms | {values['frame_sequence_gaps_total']} |"
            )
    if repeat_batches:
        latest_batch = repeat_batches[-1]
        wide_repeat = [
            row["scenario_id"]
            for row in latest_batch["aggregates"]
            if (row["metrics"]["packet_throughput_per_second"]["spread_percent_of_median"] or 0) > 10
        ]
        if wide_repeat:
            lines.extend(
                [
                    "",
                    "The latest repeat batch still had more than 10% throughput spread for: "
                    + ", ".join(f"`{scenario}`" for scenario in wide_repeat)
                    + ". Those results remain provisional.",
                ]
            )
    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "The exact invocation, source fingerprint, binary hash, and per-run commands are recorded in `metadata.json` and `results.json`. "
            + generator_note
            + " Each manifest records the deterministic seed, traffic profile, SHA-256, packet count, wire bytes, and flow cardinality.",
            "",
            "A spread over 10% of a scenario median is flagged for a quieter repeat; the report does not select the fastest repetition. See `results.json` for exact per-run spread and validation state.",
            "",
        ]
    )
    path.write_text("\n".join(lines))


def build_release(output_root: Path) -> Path:
    build_dir = output_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = build_dir / "stdout.txt"
    stderr_path = build_dir / "stderr.txt"
    result = subprocess.run(
        ["cargo", "build", "--locked", "--release"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    stdout_path.write_text(result.stdout)
    stderr_path.write_text(result.stderr)
    if result.returncode != 0:
        raise RuntimeError(
            f"cargo build --locked --release failed with exit {result.returncode}; see {stdout_path} and {stderr_path}"
        )
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    binary = target_dir / "release" / ("netscope.exe" if os.name == "nt" else "netscope")
    if not binary.is_file():
        raise RuntimeError(f"release build succeeded but binary was not found at {binary}")
    return binary.resolve()


def parse_workers(raw: str) -> tuple[int, ...]:
    try:
        values = tuple(sorted({int(item.strip()) for item in raw.split(",") if item.strip()}))
    except ValueError as error:
        raise argparse.ArgumentTypeError("workers must be a comma-separated list of positive integers") from error
    if not values or any(value < 1 for value in values):
        raise argparse.ArgumentTypeError("workers must contain positive integers")
    return values


def default_output_dir() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return ROOT / "docs" / "benchmarks" / f"offline-{stamp}"


def run_benchmarks(args: argparse.Namespace) -> int:
    if args.repetitions < 5:
        raise RuntimeError("Phase 4 runs require at least five measured repetitions")
    if args.warmups < 1:
        raise RuntimeError("Phase 4 runs require at least one consistent warm-up")
    if args.packets < 1 or args.dashboard_packets < 1:
        raise RuntimeError("packet counts must be positive")

    output_root = (ROOT / args.output_dir).resolve() if not args.output_dir.is_absolute() else args.output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    adapter, adapter_name = time_adapter()
    source_before = git_source_state(output_root)
    source_before["snapshot"] = save_source_snapshot(source_before, output_root)
    load_start: tuple[float, ...] | None
    try:
        load_start = os.getloadavg()
    except (AttributeError, OSError):
        load_start = None

    binary = build_release(output_root)
    source_after_build = git_source_state(output_root)
    if source_after_build["source_tree_sha256"] != source_before["source_tree_sha256"]:
        raise RuntimeError("source files changed during the release build; refusing to benchmark an ambiguous binary")
    binary_sha = sha256_file(binary)
    binary_version = command_output([str(binary), "--version"]) or "unavailable"
    environment = collect_environment(load_start, args.background_load_notes)
    environment["netscope_version"] = binary_version
    environment["build_command"] = "cargo build --locked --release"
    environment["build_stdout_path"] = "build/stdout.txt"
    environment["build_stderr_path"] = "build/stderr.txt"
    environment["workload_generation_excluded_from_timing"] = True
    json_write(output_root / "environment.json", environment)
    json_write(output_root / "source.json", source_before)

    artifacts = output_root / "artifacts"
    config_dir = artifacts / "configs"
    trace_dir = artifacts / "traces"
    workload_dir = output_root / "workloads"
    config_dir.mkdir(parents=True)
    trace_dir.mkdir(parents=True)
    workload_dir.mkdir(parents=True)
    records: list[dict[str, Any]] = []
    manifests: dict[tuple[str, int], dict[str, Any]] = {}
    trace_paths: dict[tuple[str, int], Path] = {}
    tasks: list[tuple[dict[str, Any], Path, dict[str, Any], Path, int | None]] = []

    with tempfile.TemporaryDirectory(prefix="netscope-offline-bench-") as temporary_name:
        temporary_dir = Path(temporary_name)
        counts: dict[str, int] = {name: args.packets for name in WORKLOADS}
        if args.dashboard:
            counts["high-cardinality-dashboard"] = args.dashboard_packets
        for workload_key, packet_count in counts.items():
            workload = "high-cardinality" if workload_key.startswith("high-cardinality-dashboard") else workload_key
            key = (workload, packet_count)
            if key not in manifests:
                trace_path = temporary_dir / f"{workload}-{packet_count}.pcap"
                manifest = generate_workload(workload, packet_count, trace_path)
                manifest_copy = dict(manifest)
                manifest_copy["pcap_file"] = f"{workload}-{packet_count}.pcap"
                json_write(workload_dir / f"{workload}-{packet_count}.manifest.json", manifest_copy)
                manifests[key] = manifest_copy
                trace_paths[key] = trace_path

        for workload in WORKLOADS:
            for mode, worker_count in [("inline", None)]:
                task = _make_task(workload, mode, worker_count)
                task["scenario_id"] += f"-n{args.packets}"
                config_path, port = workload_config(task, config_dir)
                tasks.append((task, trace_paths[(workload, args.packets)], manifests[(workload, args.packets)], config_path, port))
            if workload != ANALYSIS_HEAVY:
                for worker_count in args.workers:
                    task = _make_task(workload, "pipeline", worker_count)
                    task["scenario_id"] += f"-n{args.packets}"
                    config_path, port = workload_config(task, config_dir)
                    tasks.append((task, trace_paths[(workload, args.packets)], manifests[(workload, args.packets)], config_path, port))

        if args.dashboard:
            dashboard_count = args.dashboard_packets
            manifest = manifests[("high-cardinality", dashboard_count)]
            trace = trace_paths[("high-cardinality", dashboard_count)]
            for dashboard in (False, True):
                task = _make_task("high-cardinality", "pipeline", 4, dashboard=dashboard)
                task["scenario_id"] = (
                    f"high-cardinality-dashboard-control-pipeline-w4-n{dashboard_count}"
                    if not dashboard
                    else f"high-cardinality-dashboard-websocket-pipeline-w4-n{dashboard_count}"
                )
                config_path, port = workload_config(task, config_dir)
                tasks.append((task, trace, manifest, config_path, port))

        total_groups = len(tasks)
        total_invocations = total_groups * (args.warmups + args.repetitions)
        print(f"Built {binary_version} ({binary_sha})")
        print(f"Source {source_before['commit']} dirty={source_before['dirty']} fingerprint={source_before['source_tree_sha256']}")
        print(f"Running {total_groups} scenarios: {args.warmups} warm-up + {args.repetitions} measured each ({total_invocations} app runs).")

        for index, (task, trace, manifest, config_path, initial_port) in enumerate(tasks, start=1):
            port = initial_port
            if task["dashboard"]:
                # Avoid reusing an ephemeral port for warm-up and measured runs.
                port = reserve_local_port()
                web = {"port": port, "tick_ms": 33}
                write_config(config_path, anomalies=False, web=web)
            else:
                write_config(config_path, anomalies=task["anomalies"], web=None)
            print(f"[{index}/{total_groups}] {task['scenario_id']}")
            for repetition in range(1, args.warmups + 1):
                # The same task config and trace are used for warm-up and measurement.
                run_task = dict(task)
                if run_task["dashboard"]:
                    port = reserve_local_port()
                    write_config(config_path, anomalies=False, web={"port": port, "tick_ms": 33})
                record = _run_task(
                    run_task,
                    phase="warmup",
                    repetition=repetition,
                    binary=binary,
                    trace_path=trace,
                    manifest=manifest,
                    config_path=config_path,
                    port=port,
                    output_root=output_root,
                    artifact_root=output_root,
                    adapter=adapter,
                    adapter_name=adapter_name,
                    timeout=args.timeout_seconds,
                    source=source_before,
                    binary_sha=binary_sha,
                )
                records.append(record)
            baseline_signature: tuple[Any, ...] | None = None
            for repetition in range(1, args.repetitions + 1):
                run_task = dict(task)
                if run_task["dashboard"]:
                    port = reserve_local_port()
                    write_config(config_path, anomalies=False, web={"port": port, "tick_ms": 33})
                record = _run_task(
                    run_task,
                    phase="measured",
                    repetition=repetition,
                    binary=binary,
                    trace_path=trace,
                    manifest=manifest,
                    config_path=config_path,
                    port=port,
                    output_root=output_root,
                    artifact_root=output_root,
                    adapter=adapter,
                    adapter_name=adapter_name,
                    timeout=args.timeout_seconds,
                    source=source_before,
                    binary_sha=binary_sha,
                )
                signature = _record_signature(record)
                if baseline_signature is None:
                    baseline_signature = signature
                elif signature != baseline_signature:
                    raise RuntimeError(f"deterministic summary changed between repetitions of {task['scenario_id']}")
                records.append(record)
                print(
                    f"  repetition {repetition}: "
                    f"{record['metrics']['packet_throughput_per_second']:,.0f} packets/s, "
                    f"RSS={_fmt(record['metrics']['peak_rss_mib'])} MiB"
                )

    source_after_runs = git_source_state(output_root)
    if source_after_runs["source_tree_sha256"] != source_before["source_tree_sha256"]:
        raise RuntimeError("source files changed during benchmarking; refusing to publish results")
    try:
        environment["system_load_average_end"] = list(os.getloadavg())
    except (AttributeError, OSError):
        environment["system_load_average_end"] = None
    json_write(output_root / "environment.json", environment)
    aggregates = aggregate_records(records)
    envelope = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "created_at_utc": utc_now(),
        "report_generated_at_utc": utc_now(),
        "invocation": shlex.join(["python3", "scripts/perf/run_offline.py", *sys.argv[1:]]),
        "source": source_before,
        "binary": {
            "path": str(binary),
            "sha256": binary_sha,
            "version": binary_version,
            "build_command": "cargo build --locked --release",
        },
        "environment": environment,
        "method": {
            "warmups": args.warmups,
            "repetitions": args.repetitions,
            "wall_interval": "subprocess launch through process exit; includes PCAP open, read, processing, summary output, and shutdown; excludes build and generation",
            "throughput": "worker-processed packets (inline uses frames_read) divided by measured wall seconds",
            "wire_mbps": "input_wire_bytes * 8 / wall_seconds / 1,000,000 (decimal Mbps)",
            "cpu": "NetScope process user CPU seconds + system CPU seconds; utilization may exceed 100% with worker threads",
            "peak_memory": "OS process peak resident set size normalized to bytes and MiB",
            "offline_loss": "compare generated manifest with final summary; pipeline additionally requires all worker frames processed and zero dispatch drops/failures",
        },
        "workloads": [manifests[key] for key in sorted(manifests)],
        "records": records,
        "aggregates": aggregates,
    }
    json_write(output_root / "results.json", envelope)
    json_write(
        output_root / "metadata.json",
        {
            "output_directory": str(output_root),
            "reproduction_command": envelope["invocation"],
            "workload_generator": "scripts/perf/workloads.py",
            "runner": "scripts/perf/run_offline.py",
            "source_commit": source_before["commit"],
            "source_dirty": source_before["dirty"],
            "source_tree_sha256": source_before["source_tree_sha256"],
            "binary_sha256": binary_sha,
            "results_schema": "scripts/perf/result.schema.json",
        },
    )
    write_report(output_root / "report.md", envelope)
    print(f"Report: {output_root / 'report.md'}")
    print(f"Raw data: {output_root / 'results.json'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=default_output_dir())
    parser.add_argument("--packets", type=int, default=100_000)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--workers", type=parse_workers, default=DEFAULT_WORKERS)
    parser.add_argument("--dashboard", action="store_true", help="measure local WebSocket dashboard delivery separately")
    parser.add_argument("--dashboard-packets", type=int, default=1_000_000)
    parser.add_argument("--timeout-seconds", type=float, default=1800)
    parser.add_argument("--background-load-notes", help="manual notes about power mode and other active work")
    args = parser.parse_args()
    try:
        return run_benchmarks(args)
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
