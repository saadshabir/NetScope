"""Guard the live runner's rate and input-reconciliation decisions."""

from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from live_capture import check_linux_environment, classify_run, pcap_records_and_tcp_sequences, write_report
from run_offline import time_adapter
from workloads import generate_workload


def complete_record(rate: float, *, captured: int = 100) -> dict:
    return {
        "target_rate_pps": 100_000,
        "repetition": 1,
        "tcpreplay": {
            "reported_packet_count": 100,
            "reported_packets_per_second": rate,
            "failed_packets": 0,
        },
        "tcpreplay_exit_code": 0,
        "netscope_exit_code": 0,
        "netscope_summary": {
            "status": "success" if captured == 100 else "interrupted",
            "frames_read": captured,
            "worker_processed_frames": captured,
            "kernel_drops": 0,
            "interface_drops": 0,
            "dispatch_drops": 0,
            "worker_failures": 0,
        },
        "interface_counter_deltas": {"capture_rx_dropped": 0, "sender_tx_dropped": 0},
        "identifier_reconciliation": {
            "pcap_records": captured,
            "tcp_sequence_count": captured,
            "missing_sequence_ids": 100 - captured,
            "unexpected_sequence_packets": 0,
            "duplicate_sequence_ids": 0,
        },
    }


class LinuxEnvironmentTests(unittest.TestCase):
    def test_both_runners_accept_ubuntu_gnu_time_version(self) -> None:
        states = {
            "tx": {"available": True, "flags": ["UP"], "kind": "veth", "ifindex": 1, "iflink": 2, "address": "02:00:00:00:00:02"},
            "rx": {"available": True, "flags": ["UP"], "kind": "veth", "ifindex": 2, "iflink": 1, "address": "02:00:00:00:00:01"},
        }
        for version in ("GNU time 1.9", "time (GNU Time) UNKNOWN"):
            with self.subTest(version=version), \
                 patch("run_offline.sys.platform", "linux"), \
                 patch("run_offline.Path.is_file", return_value=True), \
                 patch("run_offline.command_output", return_value=version):
                self.assertEqual(time_adapter(), (["/usr/bin/time", "-v", "-o"], "linux-gnu-time-v"))
            with self.subTest(version=version), \
                 patch("live_capture.platform.system", return_value="Linux"), \
                 patch("live_capture.shutil.which", side_effect=lambda name: name), \
                 patch("live_capture.Path.is_file", return_value=True), \
                 patch("live_capture.command_output", return_value=version), \
                 patch("live_capture.os.geteuid", return_value=0), \
                 patch("live_capture.interface_stats", side_effect=lambda name: states[name]):
                self.assertEqual(check_linux_environment(Namespace(tx_interface="tx", capture_interface="rx")), [])

    def test_linux_timer_rejects_non_gnu_time(self) -> None:
        with patch("run_offline.sys.platform", "linux"), \
             patch("run_offline.Path.is_file", return_value=True), \
             patch("run_offline.command_output", return_value="BSD time"):
            with self.assertRaisesRegex(RuntimeError, "no supported"):
                time_adapter()
        with patch("live_capture.platform.system", return_value="Linux"), \
             patch("live_capture.shutil.which", side_effect=lambda name: name), \
             patch("live_capture.Path.is_file", return_value=True), \
             patch("live_capture.command_output", return_value="BSD time"):
            with self.assertRaisesRegex(RuntimeError, "GNU /usr/bin/time"):
                check_linux_environment(Namespace(tx_interface="tx", capture_interface="rx"))


class LiveCaptureDecisionTests(unittest.TestCase):
    def test_small_tcpreplay_rate_shortfall_still_qualifies(self) -> None:
        record = complete_record(99_999.69)
        result, reasons = classify_run(record, 100, 100_000)
        self.assertEqual((result, reasons), ("zero_observed_loss", []))
        self.assertTrue(record["requested_rate_qualified"])

    def test_material_rate_shortfall_without_loss_is_inconclusive(self) -> None:
        record = complete_record(99_000)
        result, reasons = classify_run(record, 100, 100_000)
        self.assertEqual(result, "inconclusive")
        self.assertFalse(record["requested_rate_qualified"])
        self.assertTrue(any("below the 99.5% minimum" in reason for reason in reasons))

    def test_under_rate_loss_does_not_set_requested_rate_bracket(self) -> None:
        record = complete_record(99_000, captured=99)
        record["netscope_summary"]["kernel_drops"] = 1
        record["classification"], _ = classify_run(record, 100, 100_000)
        self.assertEqual(record["classification"], "loss_observed")
        self.assertFalse(record["requested_rate_qualified"])
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.md"
            write_report(
                report_path,
                {"status": "complete", "rates_pps": [100_000], "repetitions": 1, "runs": [record]},
            )
            report = report_path.read_text()
        self.assertIn("loss observed below or without a verified target rate", report)
        self.assertIn("No rate could be classified from the saved runs", report)

    def test_trace_preflight_detects_packet_excluded_by_fixed_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "steady-flow.pcap"
            generate_workload("steady-flow", 4, trace)
            self.assertEqual(pcap_records_and_tcp_sequences(trace, 4)["live_filter_match_count"], 4)
            data = bytearray(trace.read_bytes())
            first_tcp_destination_port = 24 + 16 + 14 + 20 + 2
            data[first_tcp_destination_port : first_tcp_destination_port + 2] = b"\x00\x50"
            trace.write_bytes(data)
            self.assertEqual(pcap_records_and_tcp_sequences(trace, 4)["live_filter_match_count"], 3)


if __name__ == "__main__":
    unittest.main()
