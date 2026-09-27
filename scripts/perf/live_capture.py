#!/usr/bin/env python3
"""Measure finite live capture runs on an isolated Linux veth pair.

The runner starts NetScope first and waits for its NETSCOPE_READY event before
starting tcpreplay. Each trial retains complete command output, the application
summary, resource measurements, interface counter deltas, and a PCAP/sequence
reconciliation against the deterministic input workload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import queue
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from run_offline import build_release, git_source_state, save_source_snapshot


ROOT = Path(__file__).resolve().parents[2]
READY_PREFIX = "NETSCOPE_READY "
DEFAULT_RATES = "100000,250000,500000,750000,1000000"
LIVE_FILTER = "ip and tcp dst port 443 and dst host 203.0.113.1"
# tcpreplay reports an achieved average, which can fall just below --pps
# because timing includes send/setup overhead. Treat larger shortfalls as
# inconclusive and retain each achieved rate in the report.
MIN_ACHIEVED_RATE_FRACTION = 0.995
IDENTIFIER_PACKET_LIMIT = 2**31


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: list[str], *, timeout: float = 5.0) -> str | None:
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def positive_ints(raw: str) -> list[int]:
    parts = raw.split(",")
    if any(not part.strip() for part in parts):
        raise argparse.ArgumentTypeError("expected comma-separated positive integers without empty entries")
    try:
        values = [int(part.strip()) for part in parts]
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected comma-separated positive integers") from error
    if not values or any(value <= 0 for value in values):
        raise argparse.ArgumentTypeError("rates and packet counts must be positive")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("duplicate values are not allowed")
    return values


def parse_json_lines(raw: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"ip returned invalid JSON: {error}") from error
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        raise RuntimeError("ip returned no interface record")
    return value


def sysfs_interface_index(interface: str, attribute: str) -> int | None:
    try:
        return int((Path("/sys/class/net") / interface / attribute).read_text().strip())
    except (OSError, ValueError):
        return None


def interface_stats(interface: str) -> dict[str, Any]:
    raw = command_output(["ip", "-d", "-j", "-s", "link", "show", "dev", interface])
    if raw is None:
        return {"available": False, "error": "ip -d -j -s link show failed"}
    try:
        entry = parse_json_lines(raw)[0]
    except RuntimeError as error:
        return {"available": False, "error": str(error), "raw": raw}
    stats = entry.get("stats64") or entry.get("stats") or {}
    rx = stats.get("rx") or {}
    tx = stats.get("tx") or {}
    linkinfo = entry.get("linkinfo") or {}
    return {
        "available": True,
        "interface": entry.get("ifname", interface),
        "ifindex": sysfs_interface_index(interface, "ifindex"),
        "iflink": sysfs_interface_index(interface, "iflink"),
        "address": entry.get("address"),
        "flags": entry.get("flags"),
        "operstate": entry.get("operstate"),
        "kind": linkinfo.get("info_kind"),
        "rx": {key: rx.get(key) for key in ("packets", "bytes", "errors", "dropped")},
        "tx": {key: tx.get(key) for key in ("packets", "bytes", "errors", "dropped")},
        "raw": entry,
    }


def counter_delta(before: dict[str, Any], after: dict[str, Any], direction: str, name: str) -> int | None:
    if not before.get("available") or not after.get("available"):
        return None
    first = before.get(direction, {}).get(name)
    last = after.get(direction, {}).get(name)
    if not isinstance(first, int) or not isinstance(last, int):
        return None
    if last < first:
        return None
    return last - first


def check_linux_environment(args: argparse.Namespace) -> list[str]:
    if platform.system() != "Linux":
        raise RuntimeError("the isolated veth live runner requires Linux; use the manual runbook on macOS")
    missing = [name for name in ("ip", "tcpreplay") if shutil.which(name) is None]
    if missing:
        raise RuntimeError("missing required command(s): " + ", ".join(missing))
    if not Path("/usr/bin/time").is_file() or "GNU time" not in (command_output(["/usr/bin/time", "--version"]) or ""):
        raise RuntimeError("GNU /usr/bin/time is required for process CPU and peak RSS measurements")
    if os.geteuid() != 0:
        if shutil.which("sudo") is None or subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0:
            raise RuntimeError("run `sudo -v` once before this command; NetScope and tcpreplay need capture/send privileges")
    for interface in (args.tx_interface, args.capture_interface):
        state = interface_stats(interface)
        if not state.get("available"):
            raise RuntimeError(f"interface {interface!r} is unavailable; run scripts/perf/live-veth.sh up first")
        if "UP" not in (state.get("flags") or []):
            raise RuntimeError(f"interface {interface!r} is down; run scripts/perf/live-veth.sh up first")
        if state.get("kind") != "veth":
            raise RuntimeError(f"interface {interface!r} is not a veth device; refusing a non-isolated capture")
    tx_state = interface_stats(args.tx_interface)
    rx_state = interface_stats(args.capture_interface)
    if (
        tx_state.get("ifindex") is None
        or tx_state.get("iflink") != rx_state.get("ifindex")
        or rx_state.get("ifindex") is None
        or rx_state.get("iflink") != tx_state.get("ifindex")
    ):
        raise RuntimeError("sender and capture interfaces are not verified peers of the same veth pair")
    if str(tx_state.get("address") or "").lower() != "02:00:00:00:00:02" or str(rx_state.get("address") or "").lower() != "02:00:00:00:00:01":
        raise RuntimeError("veth MAC addresses do not match the isolated pair created by live-veth.sh")
    return ["sudo", "-n"] if os.geteuid() != 0 else []


def collect_environment(binary: Path, *, tx_interface: str, capture_interface: str) -> dict[str, Any]:
    memory_total_bytes = None
    try:
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB", Path("/proc/meminfo").read_text(), re.MULTILINE)
        if match:
            memory_total_bytes = int(match.group(1)) * 1024
    except OSError:
        pass
    try:
        load_start = list(os.getloadavg())
    except (AttributeError, OSError):
        load_start = None
    return {
        "schema_version": 1,
        "captured_at_utc": utc_now(),
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine_architecture": platform.machine(),
        "cpu_model": next(
            (
                value.strip()
                for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines()
                if line.lower().startswith(("model name", "hardware"))
                and (value := line.partition(":")[2].strip())
            ),
            platform.processor() or "unavailable",
        ),
        "logical_cpu_count": os.cpu_count(),
        "memory_total_bytes": memory_total_bytes,
        "python_version": sys.version.split()[0],
        "rustc_version": command_output(["rustc", "--version", "--verbose"]) or "unavailable",
        "cargo_version": command_output(["cargo", "--version"]) or "unavailable",
        "libpcap_version": command_output(["pkg-config", "--modversion", "libpcap"]) or command_output(["pcap-config", "--version"]) or "unavailable",
        "tcpreplay_version": command_output(["tcpreplay", "--version"]) or "unavailable",
        "ip_version": command_output(["ip", "-V"]) or "unavailable",
        "resource_timer": command_output(["/usr/bin/time", "--version"]) or "unavailable",
        "load_average_start": load_start,
        "binary_path": str(binary),
        "binary_sha256": sha256_file(binary),
        "tx_interface": tx_interface,
        "capture_interface": capture_interface,
    }


def stream_process_output(
    stream: BinaryIO,
    output_path: Path,
    lines: queue.Queue[str] | None = None,
) -> None:
    with output_path.open("wb") as output:
        for raw_line in iter(stream.readline, b""):
            output.write(raw_line)
            output.flush()
            if lines is not None:
                lines.put(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
    stream.close()


def signal_process_group(process: subprocess.Popen[bytes], signum: int) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def stop_process_group(process: subprocess.Popen[bytes], *, grace_seconds: float = 5.0) -> int:
    if process.poll() is None:
        signal_process_group(process, signal.SIGINT)
        try:
            return process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            signal_process_group(process, signal.SIGTERM)
            try:
                return process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                signal_process_group(process, signal.SIGKILL)
    return process.wait()


def wait_for_ready(
    process: subprocess.Popen[bytes],
    lines: queue.Queue[str],
    timeout_seconds: float,
    expected: dict[str, Any],
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None and lines.empty():
            raise RuntimeError(f"NetScope exited before readiness (exit {process.returncode})")
        try:
            line = lines.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
        except queue.Empty:
            continue
        if not line.startswith(READY_PREFIX):
            continue
        try:
            event = json.loads(line[len(READY_PREFIX) :])
        except json.JSONDecodeError as error:
            raise RuntimeError(f"NetScope emitted a malformed readiness event: {error}") from error
        if event.get("event") != "netscope.capture.ready" or event.get("schema_version") != 1:
            raise RuntimeError(f"unsupported readiness event: {event}")
        mismatches = {key: {"expected": value, "actual": event.get(key)} for key, value in expected.items() if event.get(key) != value}
        if mismatches:
            raise RuntimeError("effective capture settings do not match the requested run: " + json.dumps(mismatches, sort_keys=True))
        return event
    raise RuntimeError(f"NetScope did not emit NETSCOPE_READY within {timeout_seconds:g}s")


def pcap_records_and_tcp_sequences(path: Path, expected_packets: int) -> dict[str, Any]:
    record_count = 0
    tcp_sequence_count = 0
    live_filter_match_count = 0
    seen = bytearray((expected_packets + 7) // 8)
    unique_valid_sequence_ids = 0
    missing_sequence_ids = expected_packets
    unexpected_sequence_packets = 0
    duplicate_sequence_ids = 0

    def result(parse_error: str | None = None) -> dict[str, Any]:
        return {
            "pcap_records": record_count,
            "tcp_sequence_count": tcp_sequence_count,
            "live_filter_match_count": live_filter_match_count,
            "unique_valid_sequence_ids": unique_valid_sequence_ids,
            "missing_sequence_ids": missing_sequence_ids,
            "unexpected_sequence_packets": unexpected_sequence_packets,
            "duplicate_sequence_ids": duplicate_sequence_ids,
            "pcap_parse_error": parse_error,
        }

    try:
        with path.open("rb") as capture:
            global_header = capture.read(24)
            if len(global_header) != 24:
                return result("truncated PCAP global header")
            magic = global_header[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            else:
                return result(f"unsupported PCAP magic {magic.hex()}")
            linktype = int.from_bytes(global_header[20:24], "little" if endian == "<" else "big")
            if linktype != 1:  # LINKTYPE_ETHERNET / DLT_EN10MB
                return result(f"expected Ethernet PCAP linktype 1, found {linktype}")
            while True:
                record = capture.read(16)
                if not record:
                    break
                if len(record) != 16:
                    return result("truncated PCAP packet header")
                captured_length = int.from_bytes(record[8:12], "little" if endian == "<" else "big")
                frame = capture.read(captured_length)
                if len(frame) != captured_length:
                    return result("truncated PCAP packet data")
                record_count += 1
                if len(frame) < 14 or int.from_bytes(frame[12:14], "big") != 0x0800:
                    continue
                ip_offset = 14
                if len(frame) < ip_offset + 20 or frame[ip_offset] >> 4 != 4:
                    continue
                ip_header_length = (frame[ip_offset] & 0x0F) * 4
                if frame[ip_offset + 9] != 6 or ip_header_length < 20:
                    continue
                tcp_offset = ip_offset + ip_header_length
                if len(frame) >= tcp_offset + 8:
                    tcp_sequence_count += 1
                    if (
                        frame[ip_offset + 16 : ip_offset + 20] == b"\xcb\x00\x71\x01"
                        and frame[tcp_offset + 2 : tcp_offset + 4] == b"\x01\xbb"
                    ):
                        live_filter_match_count += 1
                    sequence = int.from_bytes(frame[tcp_offset + 4 : tcp_offset + 8], "big")
                    if sequence < expected_packets * 2 and sequence % 2 == 0:
                        sequence_index = sequence // 2
                        byte_index, bit_index = divmod(sequence_index, 8)
                        mask = 1 << bit_index
                        if seen[byte_index] & mask:
                            duplicate_sequence_ids += 1
                        else:
                            seen[byte_index] |= mask
                            unique_valid_sequence_ids += 1
                            missing_sequence_ids -= 1
                    else:
                        unexpected_sequence_packets += 1
    except OSError as error:
        return result(str(error))
    return result()


def parse_time_output(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return {"user_cpu_seconds": None, "system_cpu_seconds": None, "peak_rss_bytes": None, "wall_seconds_reported_by_time": None}
    user = re.search(r"User time \(seconds\):\s*([0-9.]+)", text)
    system = re.search(r"System time \(seconds\):\s*([0-9.]+)", text)
    rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    wall_match = re.search(r"Elapsed \(wall clock\) time .*?:\s*([0-9:.]+)", text)
    wall = None
    if wall_match:
        parts = wall_match.group(1).split(":")
        try:
            wall = (int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])) if len(parts) == 3 else (
                int(parts[0]) * 60 + float(parts[1]) if len(parts) == 2 else float(parts[0])
            )
        except ValueError:
            wall = None
    return {
        "user_cpu_seconds": float(user.group(1)) if user else None,
        "system_cpu_seconds": float(system.group(1)) if system else None,
        "peak_rss_bytes": int(rss.group(1)) * 1024 if rss else None,
        "wall_seconds_reported_by_time": wall,
        "raw": text,
    }


def tcpreplay_counts(text: str) -> dict[str, Any]:
    successful = re.search(r"Successful packets:\s*([\d,]+)", text, re.IGNORECASE)
    actual = re.search(r"Actual:\s*([\d,]+)\s+packets", text, re.IGNORECASE)
    failed = re.search(r"Failed packets:\s*([\d,]+)", text, re.IGNORECASE)
    rates = re.findall(r"Rated:.*?([\d,.]+)\s+pps", text, re.IGNORECASE)
    reported = successful or actual
    return {
        "reported_packet_count": int(reported.group(1).replace(",", "")) if reported else None,
        "packet_count_source": "Successful packets" if successful else ("Actual" if actual else None),
        "failed_packets": int(failed.group(1).replace(",", "")) if failed else None,
        "reported_packets_per_second": float(rates[-1].replace(",", "")) if rates else None,
    }


def classify_run(record: dict[str, Any], packet_count: int, target_rate: int) -> tuple[str, list[str]]:
    summary = record.get("netscope_summary") or {}
    interface = record.get("interface_counter_deltas") or {}
    identifiers = record.get("identifier_reconciliation") or {}
    replay = record.get("tcpreplay") or {}
    positive_loss: list[str] = []
    unknown: list[str] = []

    def check_counter(name: str, value: Any) -> None:
        if value is None:
            unknown.append(name + " unavailable")
        elif value > 0:
            positive_loss.append(f"{name}={value}")

    for key, label in (("kernel_drops", "libpcap/kernel drops"), ("interface_drops", "libpcap interface drops"),
                       ("dispatch_drops", "application dispatch drops")):
        check_counter(label, summary.get(key))
    check_counter("veth receiver RX drops", interface.get("capture_rx_dropped"))
    check_counter("veth sender TX drops", interface.get("sender_tx_dropped"))
    for key, label in (("capture_rx_errors", "veth receiver RX errors"), ("sender_tx_errors", "veth sender TX errors")):
        value = interface.get(key)
        if isinstance(value, int) and value > 0:
            unknown.append(f"{label}={value}")

    replay_packets = replay.get("reported_packet_count")
    replay_complete = True
    if replay_packets is None:
        unknown.append("tcpreplay successful packet count unavailable")
        replay_complete = False
    elif replay_packets != packet_count:
        unknown.append(f"incomplete replay: tcpreplay sent {replay_packets}/{packet_count} requested packets")
        replay_complete = False
    replay_rate = replay.get("reported_packets_per_second")
    if replay_rate is None:
        unknown.append("tcpreplay actual packet rate unavailable")
        replay_complete = False
    elif replay_rate < target_rate * MIN_ACHIEVED_RATE_FRACTION:
        unknown.append(
            f"tcpreplay achieved {replay_rate:g}/{target_rate} packets/s, below the "
            f"{MIN_ACHIEVED_RATE_FRACTION:.1%} minimum"
        )
        replay_complete = False
    if replay.get("failed_packets") is not None and replay["failed_packets"] > 0:
        unknown.append(f"tcpreplay failed to send {replay['failed_packets']} packets")
        replay_complete = False
    if record.get("tcpreplay_timed_out"):
        unknown.append("tcpreplay exceeded its timeout")
        replay_complete = False
    if record.get("tcpreplay_exit_code") != 0:
        unknown.append(f"tcpreplay did not exit successfully (exit {record.get('tcpreplay_exit_code', 'missing')})")
        replay_complete = False
    if record.get("run_error"):
        unknown.append(f"runner error: {record['run_error']}")
        replay_complete = False
    record["requested_rate_qualified"] = replay_complete

    summary_status = summary.get("status")
    summary_errors = summary.get("output_errors") or []
    if summary.get("run_error"):
        unknown.append(f"NetScope run error: {summary['run_error']}")
    if summary_errors:
        unknown.append(f"NetScope reported {len(summary_errors)} output error(s)")
    if record.get("netscope_exit_code") != 0:
        unknown.append(f"NetScope did not exit successfully (exit {record.get('netscope_exit_code', 'missing')})")
    summary_reconciliable = (
        summary_status in ("success", "interrupted")
        and not summary.get("run_error")
        and not summary_errors
        and record.get("netscope_exit_code") == 0
    )
    worker_failures = summary.get("worker_failures")
    if isinstance(worker_failures, int) and worker_failures > 0:
        positive_loss.append(f"pipeline worker failures={worker_failures}")

    captured = summary.get("frames_read")
    processed = summary.get("worker_processed_frames")
    if captured is None or processed is None:
        unknown.append("NetScope frame accounting unavailable")
    else:
        if replay_complete and summary_reconciliable and captured < packet_count:
            positive_loss.append(f"NetScope captured {captured}/{packet_count}")
        elif captured > packet_count:
            unknown.append(f"NetScope captured more than the finite input: {captured}/{packet_count}")
        if summary_reconciliable and processed < captured:
            positive_loss.append(f"workers processed {processed}/{captured} captured frames")
        elif processed > captured:
            unknown.append(f"worker accounting exceeds capture accounting: {processed}/{captured}")
    if identifiers.get("pcap_records") is None:
        unknown.append("captured PCAP sequence reconciliation unavailable")
    else:
        pcap_parse_error = identifiers.get("pcap_parse_error")
        pcap_records = identifiers.get("pcap_records")
        tcp_sequence_count = identifiers.get("tcp_sequence_count")
        if pcap_parse_error:
            unknown.append("captured PCAP could not be parsed completely")
        if captured is not None and pcap_records != captured:
            unknown.append("captured PCAP record count differs from NetScope frames read")
        if tcp_sequence_count != pcap_records:
            unknown.append("captured PCAP contains records without a parsed TCP sequence identifier")
        pcap_reconciliable = (
            summary_reconciliable
            and not pcap_parse_error
            and pcap_records == captured
            and tcp_sequence_count == pcap_records
        )
        if replay_complete and pcap_reconciliable and identifiers.get("missing_sequence_ids", 0) > 0:
            positive_loss.append(f"{identifiers['missing_sequence_ids']} input sequence IDs missing from captured PCAP")
        if identifiers.get("unexpected_sequence_packets", 0) > 0:
            unknown.append(f"{identifiers['unexpected_sequence_packets']} unexpected TCP sequence values in captured PCAP")
        if identifiers.get("duplicate_sequence_ids", 0) > 0:
            unknown.append(f"{identifiers['duplicate_sequence_ids']} duplicate sequence IDs in captured PCAP")
    if summary_status not in ("success", "interrupted"):
        unknown.append(f"NetScope status={summary_status or 'missing'}")
    if summary_status != "success":
        unknown.append(f"NetScope did not complete normally (status={summary_status or 'missing'})")

    if positive_loss:
        return "loss_observed", positive_loss + unknown
    if unknown:
        return "inconclusive", unknown
    if captured != packet_count or processed != packet_count or summary.get("status") != "success":
        return "inconclusive", ["the full finite input was not accounted for"]
    return "zero_observed_loss", []


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def write_report(path: Path, suite: dict[str, Any]) -> None:
    records = suite.get("runs", [])
    source = suite.get("source") or {}
    rates = sorted({record["target_rate_pps"] for record in records if "target_rate_pps" in record})
    rate_rows: list[tuple[int, str, list[dict[str, Any]]]] = []
    for rate in rates:
        at_rate = [record for record in records if record.get("target_rate_pps") == rate]
        classifications = [record.get("classification") for record in at_rate]
        expected_runs = suite.get("repetitions")
        repetition_numbers = [record.get("repetition") for record in at_rate]
        complete_repetitions = isinstance(expected_runs, int) and expected_runs > 0 and (
            len(at_rate) == expected_runs
            and all(isinstance(number, int) for number in repetition_numbers)
            and sorted(repetition_numbers) == list(range(1, expected_runs + 1))
        )
        if classifications and complete_repetitions and all(value == "zero_observed_loss" for value in classifications):
            result = "zero observed loss in all repetitions"
        elif any(
            record.get("classification") == "loss_observed" and record.get("requested_rate_qualified") is True
            for record in at_rate
        ):
            result = "loss observed in at least one repetition"
        elif "loss_observed" in classifications:
            result = "loss observed below or without a verified target rate"
        else:
            result = "inconclusive"
        rate_rows.append((rate, result, at_rate))

    clean_rates = [rate for rate, result, _ in rate_rows if result == "zero observed loss in all repetitions"]
    loss_rates = [rate for rate, result, _ in rate_rows if result == "loss observed in at least one repetition"]
    highest_clean = max(clean_rates) if clean_rates else None
    first_loss = min(loss_rates) if loss_rates else None
    if highest_clean is None and first_loss is None:
        bracket = "No rate could be classified from the saved runs."
    elif first_loss is None:
        bracket = f"Highest requested rate with zero observed loss in every repetition: {highest_clean:,} packets/s. No first-loss rate was established."
    elif highest_clean is None:
        bracket = f"Loss was observed at a requested rate of {first_loss:,} packets/s; no lower tested rate completed every repetition without observed loss."
    elif highest_clean < first_loss:
        bracket = f"Highest requested rate with zero observed loss: {highest_clean:,} packets/s. First requested rate with observed loss: {first_loss:,} packets/s. The tested target-rate bracket is [{highest_clean:,}, {first_loss:,}] packets/s; this does not claim an exact maximum."
    else:
        bracket = f"Results are non-monotonic: zero-loss requested rate {highest_clean:,} packets/s is at or above first observed-loss requested rate {first_loss:,} packets/s. Keep the per-run records; no single maximum is claimed."

    requested_rates = suite.get("rates_pps") or []
    expected_repetitions = suite.get("repetitions")
    expected_trial_ids = {
        (rate, repetition)
        for rate in requested_rates
        for repetition in range(1, expected_repetitions + 1)
    } if isinstance(expected_repetitions, int) and expected_repetitions > 0 else set()
    recorded_trial_ids = [
        (record.get("target_rate_pps"), record.get("repetition"))
        for record in records
    ]
    trials_recorded = (
        bool(expected_trial_ids)
        and len(recorded_trial_ids) == len(expected_trial_ids)
        and set(recorded_trial_ids) == expected_trial_ids
    )
    if trials_recorded and suite.get("status") == "complete":
        matrix_coverage = f"All {len(expected_trial_ids)} requested trials are recorded."
    elif trials_recorded:
        matrix_coverage = f"All {len(expected_trial_ids)} requested trials are recorded, but suite status is {suite.get('status', 'unknown')}."
    else:
        matrix_coverage = f"{len(records)} of {len(expected_trial_ids)} requested trials are recorded; the rate matrix is incomplete."
    packet_counts = suite.get("packet_counts_by_rate") or {}
    rate_plan = ", ".join(
        f"{rate:,} pps / {packet_counts.get(str(rate), 'unknown')} packets"
        for rate in suite.get("rates_pps", [])
    ) or "unavailable"
    environment = suite.get("environment", {})
    memory_total_bytes = environment.get("memory_total_bytes")
    memory_total_mib = f"{memory_total_bytes / (1024 * 1024):.0f} MiB" if isinstance(memory_total_bytes, int) else "unknown"

    lines = [
        "# Live capture and packet-loss report",
        "",
        f"Generated: `{suite.get('completed_at_utc', 'in progress')}`  ",
        f"Trace: `{suite.get('workload', {}).get('pcap_file', 'unavailable')}`  ",
        f"Trace SHA-256: `{suite.get('workload', {}).get('pcap_sha256', 'unavailable')}`  ",
        f"Host: `{environment.get('os', 'unavailable')}` / `{environment.get('machine_architecture', 'unavailable')}`; CPU `{environment.get('cpu_model', 'unavailable')}` ({environment.get('logical_cpu_count', 'unknown')} logical CPUs); RAM `{memory_total_mib}`  ",
        f"Toolchain: Rust `{environment.get('rustc_version', 'unavailable')}`; Cargo `{environment.get('cargo_version', 'unavailable')}`; libpcap `{environment.get('libpcap_version', 'unavailable')}`; iproute2 `{environment.get('ip_version', 'unavailable')}`; GNU time `{environment.get('resource_timer', 'unavailable')}`  ",
        f"Source: commit `{source.get('commit', 'unavailable')}`; dirty `{source.get('dirty', 'unavailable')}`; fingerprint `{source.get('source_tree_sha256', 'unavailable')}`; snapshot `source-snapshot/`.  ",
        f"Binary SHA-256: `{environment.get('binary_sha256', 'unavailable')}`",
        "",
        "## Run configuration",
        "",
        f"- Interface pair: `{suite.get('settings', {}).get('tx_interface', 'unavailable')}` (TX MAC `02:00:00:00:00:02`) → `{suite.get('settings', {}).get('capture_interface', 'unavailable')}` (RX MAC `02:00:00:00:00:01`); isolated Linux veth with no IP addresses or routes.",
        f"- Requested rates and finite replay limits: {rate_plan}.",
        f"- Repetitions per rate: `{suite.get('repetitions', 'unavailable')}`; minimum duration: `{suite.get('minimum_duration_seconds', 'unavailable')}` s; minimum packets: `{suite.get('minimum_packets_per_trial', 'unavailable')}`.",
        f"- Capture: filter `{suite.get('settings', {}).get('filter', 'unavailable')}`; snaplen `{suite.get('settings', {}).get('snaplen', 'unavailable')}`; timeout `{suite.get('settings', {}).get('timeout_ms', 'unavailable')}` ms; requested buffer `{suite.get('settings', {}).get('capture_buffer_size_mb_requested', 'unavailable')}` MiB; promiscuous and immediate modes disabled.",
        f"- Pipeline: `{suite.get('settings', {}).get('workers', 'unavailable')}` workers; queue capacity `{suite.get('settings', {}).get('channel_capacity', 'unavailable')}` per worker.",
        f"- Replay tool: `tcpreplay` `{suite.get('environment', {}).get('tcpreplay_version', 'unavailable')}`; command template: `tcpreplay --intf1=<TX> --pps=<target> --loop=1 --limit=<count> --stats=1 --no-flow-stats <trace>`.",
        "",
        "The isolated veth trials replay a finite synthetic trace after NetScope emits `NETSCOPE_READY`. NetScope records the received packets to a PCAP so the runner can reconcile the trace's unique TCP sequence identifiers. Resource figures include that PCAP write and therefore describe this instrumented capture configuration.",
        "",
        f"A requested rate is eligible for the loss bracket when tcpreplay completes the full replay and achieves at least {MIN_ACHIEVED_RATE_FRACTION:.1%} of it. The table retains each achieved average rate; the bracket labels requested rates and does not assert exact achieved rates. Observed loss during an under-rate or incomplete replay is retained in the raw result but cannot establish the requested rate as a loss endpoint. The fixed BPF filter is checked against every packet in the generated trace before replay.",
        "",
        "The runner builds the release binary with `cargo build --locked --release` after saving `source.json` and the complete source snapshot. Build output is retained in `build/`. A source change during the build, or a source or binary change during measurement, invalidates the suite.",
        "",
        "`tcpreplay` counts packets accepted by its send path; that count does not prove peer delivery. NetScope frames, captured sequence identifiers, libpcap counters, application dispatch counters, and veth RX counters are reported separately. A missing counter is unknown, never zero.",
        "",
        "## Rate bracket",
        "",
        bracket,
        "",
        matrix_coverage,
        "",
        "## Repetitions",
        "",
        "| Target rate (packets/s) | Runs | tcpreplay sent / failed | tcpreplay rate (packets/s) | NetScope read / worker processed | libpcap drops kernel / interface | veth RX / TX drops | veth RX / TX errors | dispatch drops | Result |",
        "| ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    if suite.get("source_changed_during_runs") or suite.get("binary_changed_during_runs"):
        lines[lines.index("## Rate bracket"):lines.index("## Rate bracket")] = [
            "**Invalid build provenance:** source files or the release binary changed during measurement; do not publish this suite.",
            "",
        ]
    for rate, result, at_rate in rate_rows:
        def values(records: list[dict[str, Any]], getter: Any) -> str:
            return ", ".join(str(value) if value is not None else "unknown" for value in (getter(record) for record in records))

        def show(value: Any) -> str:
            return "unknown" if value is None else str(value)

        sent = values(at_rate, lambda record: (record.get("tcpreplay") or {}).get("reported_packet_count"))
        replay_failed = values(at_rate, lambda record: (record.get("tcpreplay") or {}).get("failed_packets"))
        replay_rates = values(at_rate, lambda record: (record.get("tcpreplay") or {}).get("reported_packets_per_second"))
        read_processed = values(
            at_rate,
            lambda record: (
                f"{show((record.get('netscope_summary') or {}).get('frames_read'))}/"
                f"{show((record.get('netscope_summary') or {}).get('worker_processed_frames'))}"
                if (record.get("netscope_summary") or {}).get("frames_read") is not None
                else "unknown"
            ),
        )
        pcap_drops = values(
            at_rate,
            lambda record: (
                f"{show((record.get('netscope_summary') or {}).get('kernel_drops'))}/"
                f"{show((record.get('netscope_summary') or {}).get('interface_drops'))}"
                if record.get("netscope_summary") is not None
                else "unknown"
            ),
        )
        veth_drops = values(
            at_rate,
            lambda record: (
                f"{show((record.get('interface_counter_deltas') or {}).get('capture_rx_dropped'))}/"
                f"{show((record.get('interface_counter_deltas') or {}).get('sender_tx_dropped'))}"
            ),
        )
        veth_errors = values(
            at_rate,
            lambda record: (
                f"{show((record.get('interface_counter_deltas') or {}).get('capture_rx_errors'))}/"
                f"{show((record.get('interface_counter_deltas') or {}).get('sender_tx_errors'))}"
            ),
        )
        dispatch_drops = values(at_rate, lambda record: (record.get("netscope_summary") or {}).get("dispatch_drops"))
        lines.append(f"| {rate:,} | {len(at_rate)} | {sent} / {replay_failed} | {replay_rates} | {read_processed} | {pcap_drops} | {veth_drops} | {veth_errors} | {dispatch_drops} | {result} |")
    if not rate_rows:
        lines.append("| — | 0 | — | — | — | — | — | — | — | no completed runs |")
    lines.extend([
        "",
        "## Runtime resources",
        "",
        "| Target rate (packets/s) | Median NetScope elapsed (s) | Median process CPU (s) | Maximum peak RSS (MiB) |",
        "| ---: | ---: | ---: | ---: |",
    ])
    for rate, _, at_rate in rate_rows:
        elapsed = [
            (record.get("netscope_summary") or {}).get("elapsed_wall_seconds")
            for record in at_rate
            if isinstance((record.get("netscope_summary") or {}).get("elapsed_wall_seconds"), (float, int))
        ]
        cpu = []
        for record in at_rate:
            resources = record.get("resource_measurements") or {}
            user = resources.get("user_cpu_seconds")
            system = resources.get("system_cpu_seconds")
            if isinstance(user, (int, float)) or isinstance(system, (int, float)):
                cpu.append((user or 0.0) + (system or 0.0))
        rss = [
            (record.get("resource_measurements") or {}).get("peak_rss_bytes")
            for record in at_rate
            if isinstance((record.get("resource_measurements") or {}).get("peak_rss_bytes"), int)
        ]
        median_elapsed = f"{statistics.median(elapsed):.3f}" if elapsed else "unknown"
        median_cpu = f"{statistics.median(cpu):.3f}" if cpu else "unknown"
        peak_rss = f"{max(rss) / (1024 * 1024):.1f}" if rss else "unknown"
        lines.append(f"| {rate:,} | {median_elapsed} | {median_cpu} | {peak_rss} |")
    lines.extend(["", "Elapsed time comes from NetScope's final summary. CPU and RSS are measured for the timed NetScope process group by GNU `time`; CPU is user plus system time. The veth and tcpreplay columns preserve their own counters rather than treating the replay send count as peer delivery.", "", "## Raw records", "", "Each run directory retains `record.json`, full NetScope and tcpreplay output, GNU time output, effective TOML config, summary JSON, veth counters before/after, and the captured PCAP used for sequence reconciliation.", ""])
    for record in records:
        lines.append(f"- `{record.get('run_id')}`: {record.get('classification', 'incomplete')} at {record.get('target_rate_pps', 'unknown')} packets/s; see `runs/{record.get('run_id')}/record.json`.")
    lines.append("")
    path.write_text("\n".join(lines))


def run_one(
    *,
    output_dir: Path,
    run_id: str,
    target_rate: int,
    repetition: int,
    packet_count: int,
    args: argparse.Namespace,
    privilege_prefix: list[str],
    binary: Path,
    trace: Path,
    trace_hash: str,
) -> dict[str, Any]:
    run_dir = output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    config_path = run_dir / "config.toml"
    summary_path = run_dir / "summary.json"
    capture_path = run_dir / "captured.pcap"
    time_path = run_dir / "netscope.time.txt"
    config_path.write_text(
        "[capture]\n"
        f"snaplen = {args.snaplen}\n"
        f"timeout_ms = {args.timeout_ms}\n"
        f"buffer_size_mb = {args.buffer_mb}\n"
        "promiscuous = false\n"
        "immediate_mode = false\n\n"
        "[flow]\n"
        "timeout_secs = 0.0\n"
        "max_flows = 0\n\n"
        "[stats]\n"
        "enabled = false\n\n"
        "[analysis]\n"
        "rtt = false\n"
        "retrans = false\n"
        "out_of_order = false\n\n"
        "[analysis.anomalies]\n"
        "enabled = false\n\n"
        "[pipeline]\n"
        "enabled = true\n"
        f"workers = {args.workers}\n"
        f"channel_capacity = {args.channel_capacity}\n"
    )

    expected_ready = {
        "interface": args.capture_interface,
        "filter": LIVE_FILTER,
        "snaplen": args.snaplen,
        "timeout_ms": args.timeout_ms,
        "capture_buffer_size_mb_requested": args.buffer_mb,
        "promiscuous": False,
        "immediate_mode": False,
        "pipeline_enabled": True,
        "workers": args.workers,
        "channel_capacity": args.channel_capacity,
    }
    before_capture = interface_stats(args.capture_interface)
    before_tx = interface_stats(args.tx_interface)
    netscope_command = [
        *privilege_prefix,
        "/usr/bin/time",
        "-v",
        "-o",
        str(time_path),
        str(binary),
        "--config",
        str(config_path),
        "--interface",
        args.capture_interface,
        "--filter",
        LIVE_FILTER,
        "--pipeline",
        "--workers",
        str(args.workers),
        "--quiet",
        "--count",
        str(packet_count),
        "--summary-json",
        str(summary_path),
        "--write-pcap",
        str(capture_path),
    ]
    record: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at_utc": utc_now(),
        "target_rate_pps": target_rate,
        "repetition": repetition,
        "packet_count": packet_count,
        "trace_path": str(trace),
        "trace_sha256": trace_hash,
        "interface_setup": {"sender": args.tx_interface, "capture": args.capture_interface},
        "effective_settings_requested": expected_ready,
        "commands": {
            "netscope": netscope_command,
            "tcpreplay": [
                *privilege_prefix,
                "tcpreplay",
                "--intf1",
                args.tx_interface,
                "--pps",
                str(target_rate),
                "--loop=1",
                f"--limit={packet_count}",
                "--stats=1",
                "--no-flow-stats",
                str(trace),
            ],
        },
        "raw_artifacts": {
            "netscope_stdout": "netscope.stdout.log",
            "tcpreplay_output": "tcpreplay.stdout.log",
            "netscope_time": "netscope.time.txt",
            "summary_json": "summary.json",
            "config": "config.toml",
            "captured_pcap": "captured.pcap",
            "interface_before": "interface-before.json",
            "interface_after": "interface-after.json",
        },
    }
    atomic_json(run_dir / "interface-before.json", {"capture": before_capture, "sender": before_tx})

    app_process: subprocess.Popen[bytes] | None = None
    app_reader: threading.Thread | None = None
    app_lines: queue.Queue[str] = queue.Queue()
    replay_process: subprocess.Popen[bytes] | None = None
    replay_reader: threading.Thread | None = None
    app_start = time.monotonic()
    app_end: float | None = None
    replay_start: float | None = None
    replay_end: float | None = None
    replay_timeout = max(args.run_timeout, packet_count / target_rate * 4 + 10)
    try:
        app_process = subprocess.Popen(
            netscope_command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert app_process.stdout is not None
        app_reader = threading.Thread(
            target=stream_process_output,
            args=(app_process.stdout, run_dir / "netscope.stdout.log", app_lines),
            daemon=True,
        )
        app_reader.start()
        record["readiness"] = wait_for_ready(app_process, app_lines, args.ready_timeout, expected_ready)

        replay_command = record["commands"]["tcpreplay"]
        replay_start = time.monotonic()
        replay_process = subprocess.Popen(
            replay_command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert replay_process.stdout is not None
        replay_reader = threading.Thread(
            target=stream_process_output,
            args=(replay_process.stdout, run_dir / "tcpreplay.stdout.log"),
            daemon=True,
        )
        replay_reader.start()
        try:
            record["tcpreplay_exit_code"] = replay_process.wait(timeout=replay_timeout)
        except subprocess.TimeoutExpired:
            record["tcpreplay_timed_out"] = True
            stop_process_group(replay_process)
            record["tcpreplay_exit_code"] = replay_process.returncode
        replay_end = time.monotonic()

        try:
            record["netscope_exit_code"] = app_process.wait(timeout=args.drain_seconds)
        except subprocess.TimeoutExpired:
            record["netscope_interrupted_after_replay"] = True
            stop_process_group(app_process)
            record["netscope_exit_code"] = app_process.returncode
        app_end = time.monotonic()
    except KeyboardInterrupt as interrupted:
        record["runner_interrupted"] = True
        record["run_error"] = str(interrupted) or "measurement runner interrupted by SIGINT"
        if replay_process is not None:
            stop_process_group(replay_process)
            record["tcpreplay_exit_code"] = replay_process.returncode
        if app_process is not None:
            stop_process_group(app_process)
            record["netscope_exit_code"] = app_process.returncode
        app_end = time.monotonic()
        if replay_start is not None and replay_end is None:
            replay_end = time.monotonic()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        record["run_error"] = str(error)
        if replay_process is not None:
            stop_process_group(replay_process)
            record["tcpreplay_exit_code"] = replay_process.returncode
        if app_process is not None:
            stop_process_group(app_process)
            record["netscope_exit_code"] = app_process.returncode
        app_end = time.monotonic()
        if replay_start is not None and replay_end is None:
            replay_end = time.monotonic()
    finally:
        if replay_process is not None and replay_process.poll() is None:
            stop_process_group(replay_process)
        if app_process is not None and app_process.poll() is None:
            stop_process_group(app_process)
        if replay_reader is not None:
            replay_reader.join(timeout=2.0)
        if app_reader is not None:
            app_reader.join(timeout=2.0)

    after_capture = interface_stats(args.capture_interface)
    after_tx = interface_stats(args.tx_interface)
    atomic_json(run_dir / "interface-after.json", {"capture": after_capture, "sender": after_tx})
    record["interface_counter_deltas"] = {
        "capture_rx_packets": counter_delta(before_capture, after_capture, "rx", "packets"),
        "capture_rx_dropped": counter_delta(before_capture, after_capture, "rx", "dropped"),
        "capture_rx_errors": counter_delta(before_capture, after_capture, "rx", "errors"),
        "sender_tx_packets": counter_delta(before_tx, after_tx, "tx", "packets"),
        "sender_tx_dropped": counter_delta(before_tx, after_tx, "tx", "dropped"),
        "sender_tx_errors": counter_delta(before_tx, after_tx, "tx", "errors"),
    }
    record["process_elapsed_wall_seconds"] = (app_end or time.monotonic()) - app_start
    record["replay_elapsed_wall_seconds"] = replay_end - replay_start if replay_start is not None and replay_end is not None else None
    record["resource_measurements"] = parse_time_output(time_path)
    record["tcpreplay"] = tcpreplay_counts((run_dir / "tcpreplay.stdout.log").read_text(errors="replace") if (run_dir / "tcpreplay.stdout.log").exists() else "")
    try:
        summary = json.loads(summary_path.read_text())
        record["netscope_summary"] = summary
    except (OSError, json.JSONDecodeError):
        summary = None
        record["netscope_summary"] = None
    if capture_path.is_file():
        record["captured_pcap"] = {
            "path": str(capture_path),
            "bytes": capture_path.stat().st_size,
            "sha256": sha256_file(capture_path),
        }
        record["identifier_reconciliation"] = pcap_records_and_tcp_sequences(capture_path, packet_count)
        record["identifier_reconciliation"]["method"] = (
            "deterministic steady-flow TCP sequence field; expected sequence IDs are 0,2,...,2*(N-1)"
        )
    else:
        record["captured_pcap"] = None
        record["identifier_reconciliation"] = {"pcap_records": None, "pcap_parse_error": "captured PCAP was not created"}
    record["completed_at_utc"] = utc_now()
    record["classification"], record["classification_reasons"] = classify_run(record, packet_count, target_rate)
    atomic_json(run_dir / "record.json", record)
    return record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for retained run records and PCAPs")
    parser.add_argument("--packets", type=int, default=1_000_000, help="minimum finite packets per trial; larger rates scale to the duration")
    parser.add_argument("--duration-seconds", type=float, default=5.0, help="minimum offered-load duration for each rate")
    parser.add_argument("--rates", type=positive_ints, default=positive_ints(DEFAULT_RATES), help=f"comma-separated offered rates (default: {DEFAULT_RATES})")
    parser.add_argument("--repetitions", type=int, default=3, help="measured repetitions at each offered rate")
    parser.add_argument("--workers", type=int, default=2, help="NetScope pipeline workers")
    parser.add_argument("--channel-capacity", type=int, default=8192, help="capacity of each pipeline queue")
    parser.add_argument("--buffer-mb", type=int, default=8, help="requested libpcap capture buffer in MiB")
    parser.add_argument("--snaplen", type=int, default=65535, help="NetScope snaplen")
    parser.add_argument("--timeout-ms", type=int, default=20, help="libpcap read timeout")
    parser.add_argument("--tx-interface", default="veth-ns-tx", help="sender end of the veth pair")
    parser.add_argument("--capture-interface", default="veth-ns-rx", help="receiver end captured by NetScope")
    parser.add_argument("--ready-timeout", type=float, default=20.0, help="maximum seconds to wait for NETSCOPE_READY")
    parser.add_argument("--drain-seconds", type=float, default=15.0, help="maximum seconds to let capture and workers finish after replay before signaling NetScope")
    parser.add_argument("--run-timeout", type=float, default=60.0, help="minimum tcpreplay timeout per trial; scaled up for slow rates")
    args = parser.parse_args()
    if args.packets <= 0 or args.packets >= IDENTIFIER_PACKET_LIMIT:
        parser.error(f"--packets must be from 1 through {IDENTIFIER_PACKET_LIMIT - 1} for unique sequence identifiers")
    if not math.isfinite(args.duration_seconds) or args.duration_seconds <= 0:
        parser.error("--duration-seconds must be a finite positive number")
    try:
        packet_counts_by_rate = {
            rate: max(args.packets, math.ceil(rate * args.duration_seconds)) for rate in args.rates
        }
    except (OverflowError, ValueError):
        parser.error("rate multiplied by duration must fit within a finite packet count")
    if any(count >= IDENTIFIER_PACKET_LIMIT for count in packet_counts_by_rate.values()):
        parser.error(f"rate multiplied by duration must stay below {IDENTIFIER_PACKET_LIMIT} packets for unique sequence identifiers")
    args.packet_counts_by_rate = packet_counts_by_rate
    if args.repetitions <= 0 or args.workers <= 0 or args.channel_capacity <= 0:
        parser.error("--repetitions, --workers, and --channel-capacity must be positive")
    if args.buffer_mb <= 0 or args.snaplen <= 0 or args.timeout_ms < 0:
        parser.error("--buffer-mb and --snaplen must be positive; --timeout-ms must be nonnegative")
    if (
        not math.isfinite(args.ready_timeout)
        or not math.isfinite(args.drain_seconds)
        or not math.isfinite(args.run_timeout)
        or args.ready_timeout <= 0
        or args.drain_seconds < 0
        or args.run_timeout <= 0
    ):
        parser.error("timeouts must be finite and positive except --drain-seconds, which may be zero")
    if args.tx_interface == args.capture_interface:
        parser.error("sender and capture interfaces must be different")
    for interface in (args.tx_interface, args.capture_interface):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) or interface in (".", ".."):
            parser.error("interface names must be at most 15 safe Linux interface-name characters")
    return args


def main() -> int:
    def terminate_runner(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, terminate_runner)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, terminate_runner)
    args = parse_args()
    privilege_prefix = check_linux_environment(args)
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"output directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "runs").mkdir(exist_ok=True)

    source = git_source_state(output_dir)
    source["snapshot"] = save_source_snapshot(source, output_dir)
    atomic_json(output_dir / "source.json", source)
    binary = build_release(output_dir)
    if git_source_state(output_dir)["source_tree_sha256"] != source["source_tree_sha256"]:
        raise RuntimeError("source changed during the release build; refusing to measure an ambiguous binary")

    workload_dir = output_dir / "workload"
    workload_packet_count = max(args.packet_counts_by_rate.values())
    workload_result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/perf/workloads.py"), "--output-dir", str(workload_dir), "--workload", "steady-flow", "--counts", str(workload_packet_count)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (workload_dir / "generation.log").write_text(workload_result.stdout)
    if workload_result.returncode != 0:
        raise RuntimeError(f"workload generation failed; see {workload_dir / 'generation.log'}")
    trace = workload_dir / f"steady-flow-{workload_packet_count}.pcap"
    manifest = json.loads(trace.with_suffix(trace.suffix + ".manifest.json").read_text())
    trace_validation = pcap_records_and_tcp_sequences(trace, workload_packet_count)
    if (
        trace_validation["pcap_parse_error"]
        or trace_validation["pcap_records"] != workload_packet_count
        or trace_validation["live_filter_match_count"] != workload_packet_count
        or trace_validation["unique_valid_sequence_ids"] != workload_packet_count
        or trace_validation["duplicate_sequence_ids"]
        or trace_validation["unexpected_sequence_packets"]
    ):
        raise RuntimeError(
            "generated trace does not fully match the fixed live BPF filter and unique sequence IDs; "
            f"validation: {trace_validation}"
        )
    environment = collect_environment(binary, tx_interface=args.tx_interface, capture_interface=args.capture_interface)
    environment["build_command"] = ["cargo", "build", "--locked", "--release"]
    environment["build_stdout_path"] = "build/stdout.txt"
    environment["build_stderr_path"] = "build/stderr.txt"
    suite: dict[str, Any] = {
        "schema_version": 1,
        "started_at_utc": utc_now(),
        "status": "running",
        "rates_pps": args.rates,
        "repetitions": args.repetitions,
        "minimum_packets_per_trial": args.packets,
        "minimum_duration_seconds": args.duration_seconds,
        "packet_counts_by_rate": {str(rate): count for rate, count in args.packet_counts_by_rate.items()},
        "generated_trace_packet_count": workload_packet_count,
        "settings": {
            "workers": args.workers,
            "channel_capacity": args.channel_capacity,
            "capture_buffer_size_mb_requested": args.buffer_mb,
            "snaplen": args.snaplen,
            "timeout_ms": args.timeout_ms,
            "filter": LIVE_FILTER,
            "tx_interface": args.tx_interface,
            "capture_interface": args.capture_interface,
        },
        "workload": manifest,
        "trace_validation": trace_validation,
        "source": source,
        "environment": environment,
        "runs": [],
    }
    atomic_json(output_dir / "suite.json", suite)
    write_report(output_dir / "report.md", suite)
    print(f"Trace: {trace} ({workload_packet_count:,} packets, sha256={manifest['pcap_sha256']})", flush=True)
    print(f"Output: {output_dir}", flush=True)

    all_runs: list[dict[str, Any]] = []
    for rate in args.rates:
        for repetition in range(1, args.repetitions + 1):
            run_id = f"rate-{rate}-r{repetition:02d}"
            packet_count = args.packet_counts_by_rate[rate]
            print(f"[{run_id}] waiting for NetScope readiness, then replaying {packet_count:,} packets", flush=True)
            try:
                record = run_one(
                    output_dir=output_dir,
                    run_id=run_id,
                    target_rate=rate,
                    repetition=repetition,
                    packet_count=packet_count,
                    args=args,
                    privilege_prefix=privilege_prefix,
                    binary=binary,
                    trace=trace,
                    trace_hash=manifest["pcap_sha256"],
                )
            except Exception as error:  # save completed trials before stopping on a harness error
                record = {
                    "schema_version": 1,
                    "run_id": run_id,
                    "target_rate_pps": rate,
                    "repetition": repetition,
                    "packet_count": args.packet_counts_by_rate[rate],
                    "trace_sha256": manifest["pcap_sha256"],
                    "classification": "inconclusive",
                    "run_error": str(error),
                    "completed_at_utc": utc_now(),
                }
                failed_dir = output_dir / "runs" / run_id
                failed_dir.mkdir(parents=True, exist_ok=True)
                atomic_json(failed_dir / "record.json", record)
                all_runs.append(record)
                suite["runs"] = all_runs
                suite["status"] = "failed"
                suite["completed_at_utc"] = utc_now()
                atomic_json(output_dir / "suite.json", suite)
                write_report(output_dir / "report.md", suite)
                print(f"[{run_id}] harness error: {error}", file=sys.stderr, flush=True)
                return 2
            all_runs.append(record)
            suite["runs"] = all_runs
            atomic_json(output_dir / "suite.json", suite)
            write_report(output_dir / "report.md", suite)
            print(f"[{run_id}] {record['classification']}", flush=True)
            if record.get("runner_interrupted"):
                suite["status"] = "interrupted"
                suite["completed_at_utc"] = utc_now()
                atomic_json(output_dir / "suite.json", suite)
                write_report(output_dir / "report.md", suite)
                print("Stopped after saving the interrupted run record.", file=sys.stderr, flush=True)
                return 130

    suite["status"] = "complete"
    source_after_runs = git_source_state(output_dir)
    if source_after_runs["source_tree_sha256"] != source["source_tree_sha256"]:
        suite["status"] = "failed"
        suite["source_changed_during_runs"] = True
    if sha256_file(binary) != environment["binary_sha256"]:
        suite["status"] = "failed"
        suite["binary_changed_during_runs"] = True
    suite["completed_at_utc"] = utc_now()
    try:
        suite["environment"]["load_average_end"] = list(os.getloadavg())
    except (AttributeError, OSError):
        suite["environment"]["load_average_end"] = None
    atomic_json(output_dir / "suite.json", suite)
    write_report(output_dir / "report.md", suite)
    print(f"Report: {output_dir / 'report.md'}", flush=True)
    return 0 if suite["status"] == "complete" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
