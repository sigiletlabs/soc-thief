"""Synthetic tests for source-disabled verification and its external deadline."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from soc_thief.collector import CollectorConfig, CollectorError, WazuhIndexerCollector
from soc_thief.verify import _run_worker, _worker, main
from tests.test_collector import ORIGIN, PIT, START, Response, created, deleted, hit, page, responses

END = START + timedelta(minutes=15)


def metadata(identifier="synthetic-1"):
    result = hit(identifier)
    del result["_source"]
    return result


def _slow_worker(*args):
    time.sleep(30)


class VerifyTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        user, password = root / "user", root / "password"
        for path in (user, password):
            path.write_text("synthetic-value")
            path.chmod(0o600)
        self.config = CollectorConfig(ORIGIN, user, password, page_size=1, max_attempts=1)
        self.opener = Mock()

    def verify(self, *pages, config=None):
        self.opener.side_effect = [Response(json.dumps(p).encode()) for p in pages]
        collector = WazuhIndexerCollector(config or self.config, self.opener)
        return collector.verify_metadata(START, END)

    def test_two_metadata_pages_only(self):
        self.assertIs(self.verify(page([metadata()], 100), page([metadata("synthetic-2")], 100)), True)
        self.assertEqual(self.opener.call_count, 2)
        payloads = [json.loads(call.args[0].data) for call in self.opener.call_args_list]
        for payload in payloads:
            self.assertIs(payload["_source"], False)
            self.assertEqual(payload["size"], 1)
            self.assertNotIn("fields", payload)
        self.assertEqual(payloads[1]["search_after"], metadata()["sort"])
        self.assertEqual(payloads[0]["sort"], payloads[1]["sort"])

    def test_zero_or_one_record_is_inconclusive(self):
        self.assertIs(self.verify(page([])), False)
        self.assertIs(self.verify(page([metadata()]), page([], 1)), False)

    def test_native_numeric_date_cursor_and_supported_sort_options(self):
        first, second = metadata(), metadata("synthetic-2")
        for item in (first, second):
            item["sort"][0] = int(item["sort"][0])
        self.assertTrue(self.verify(page([first], 2), page([second], 2)))
        payloads = [json.loads(call.args[0].data) for call in self.opener.call_args_list]
        for payload in payloads:
            self.assertEqual(payload["sort"], [
                {"@timestamp": {"order": "asc"}}, {"_index": "asc"}, {"_id": "asc"},
            ])
        self.assertEqual(payloads[1]["search_after"], first["sort"])
        self.assertIs(type(payloads[1]["search_after"][0]), int)

    def test_source_or_fields_returned_unexpectedly_fails(self):
        for key, value in [("_source", {"synthetic": "private-marker"}), ("fields", {})]:
            bad = metadata(); bad[key] = value
            with self.assertRaises(CollectorError):
                self.verify(page([bad]))

    def test_cursor_replay_invalid_identity_and_window_fail(self):
        bad_cases = [metadata()]
        bad = metadata("synthetic-2"); bad["sort"][0] = "0"; bad_cases.append(bad)
        bad = metadata("synthetic-2"); bad["_id"] = None; bad_cases.append(bad)
        for bad in bad_cases:
            with self.assertRaises(CollectorError):
                self.verify(page([metadata()], 2), page([bad], 2))

    def test_missing_page_changed_total_and_partial_response_fail(self):
        for second in [page([], 2), page([metadata("synthetic-2")], 3), {"timed_out": True}]:
            with self.assertRaises(CollectorError):
                self.verify(page([metadata()], 2), second)

    def test_size_retry_and_window_bounds_checked_before_network(self):
        for config in [replace(self.config, page_size=2), replace(self.config, max_attempts=2)]:
            with self.assertRaises(ValueError):
                self.verify(config=config)
        collector = WazuhIndexerCollector(self.config, self.opener)
        for start, end in [(START, START), (START, START + timedelta(hours=2)),
                           (START.replace(tzinfo=None), END)]:
            with self.assertRaises(ValueError):
                collector.verify_metadata(start, end)
        self.opener.assert_not_called()

    def test_snapshot_probe_uses_and_releases_point_in_time(self):
        self.opener.side_effect = responses(created(), page([metadata()], 2), page([metadata("synthetic-2")], 2), deleted())
        collector = WazuhIndexerCollector(self.config, self.opener)
        self.assertIs(collector.verify_metadata(START, END, snapshot=True), True)
        requests = [call.args[0] for call in self.opener.call_args_list]
        self.assertEqual([r.method for r in requests], ["POST", "POST", "POST", "DELETE"])
        for search in requests[1:3]:
            payload = json.loads(search.data)
            self.assertIs(payload["_source"], False)
            self.assertEqual(payload["pit"], {"id": PIT, "keep_alive": "2m"})
            self.assertEqual(search.full_url, ORIGIN + "/_search?allow_partial_search_results=false")

    def test_snapshot_probe_inconclusive_and_release_failure(self):
        self.opener.side_effect = responses(created(), page([]), deleted())
        self.assertIs(WazuhIndexerCollector(self.config, self.opener).verify_metadata(START, END, snapshot=True), False)
        self.assertEqual(self.opener.call_count, 3)
        self.opener.reset_mock()
        self.opener.side_effect = responses(created(), page([metadata()], 2), page([metadata("synthetic-2")], 2),
                                            deleted(successful=False))
        with self.assertRaises(CollectorError):
            WazuhIndexerCollector(self.config, self.opener).verify_metadata(START, END, snapshot=True)
        self.opener.reset_mock()
        self.opener.side_effect = responses(created(), {"timed_out": True}, deleted())
        with self.assertRaises(CollectorError):
            WazuhIndexerCollector(self.config, self.opener).verify_metadata(START, END, snapshot=True)
        self.assertEqual(self.opener.call_args_list[-1].args[0].method, "DELETE")

    def test_snapshot_flag_reaches_worker_and_status(self):
        with patch("soc_thief.verify.CollectorConfig.from_environment", return_value=self.config):
            with patch("soc_thief.verify.WazuhIndexerCollector") as collector:
                collector.return_value.verify_metadata.return_value = True
                with self.assertRaises(SystemExit):
                    _worker(START, END, True)
        collector.return_value.verify_metadata.assert_called_once_with(START, END, snapshot=True)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("soc_thief.verify._run_worker", return_value=0) as worker:
            self.assertEqual(main(["--start", START.isoformat(), "--end", END.isoformat(), "--snapshot"]), 0)
        worker.assert_called_once_with(START, END, snapshot=True)
        self.assertEqual(output.getvalue(),
                         "Snapshot metadata pagination verified; no source fields requested. Deployment gates remain open.\n")

    def test_worker_hides_unexpected_error(self):
        output = io.StringIO()
        with patch("soc_thief.verify.CollectorConfig.from_environment", side_effect=RuntimeError("private-marker")):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaises(SystemExit) as result:
                    _worker(START, END)
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(output.getvalue(), "")

    def test_worker_forces_probe_limits(self):
        with patch("soc_thief.verify.CollectorConfig.from_environment", return_value=replace(self.config, page_size=500, max_attempts=3)):
            with patch("soc_thief.verify.WazuhIndexerCollector") as collector:
                collector.return_value.verify_metadata.return_value = True
                with self.assertRaises(SystemExit) as result:
                    _worker(START, END)
        self.assertEqual(result.exception.code, 0)
        config = collector.call_args.args[0]
        self.assertEqual((config.page_size, config.max_attempts), (1, 1))

    def test_hard_deadline_stops_child(self):
        before = time.monotonic()
        self.assertEqual(_run_worker(START, END, timeout=0.1, target=_slow_worker), 3)
        self.assertLess(time.monotonic() - before, 5)

    def test_cli_missing_configuration_is_sanitized(self):
        src = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [sys.executable, "-m", "soc_thief.verify", "--start", START.isoformat(), "--end", END.isoformat()],
            env={"PYTHONPATH": src}, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, "Verification failed; review required. Connection details withheld.\n")

    def test_bad_arguments_are_not_echoed(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit):
            main(["--private-marker"])
        self.assertNotIn("private-marker", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("soc_thief.verify._run_worker") as worker:
            self.assertEqual(main(["--start", "private-marker", "--end", END.isoformat()]), 1)
        self.assertNotIn("private-marker", output.getvalue())
        worker.assert_not_called()
