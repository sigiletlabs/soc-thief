"""Synthetic runner entrypoint checks; no Wazuh, model, or Discord endpoint is contacted."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

from soc_thief import runner
from soc_thief.runner import RunResult, _execute, _run_worker, approval_valid, daily_window, main, reconcile_window
from soc_thief.state import StateStore, opaque_key
from soc_thief.tuning import Tuning, TuningEntry


NOW = datetime(2026, 3, 10, 0, 0, tzinfo=timezone.utc)  # 11:00 Australia/Sydney (AEDT)
KEY = "ab" * 32


def _arg_count_worker(*args):
    raise SystemExit(10 + len(args))


def _slow_worker(*args):
    time.sleep(30)


class Fake:
    def __init__(self, error=False): self.error, self.payloads, self.calls = error, [], 0
    def send(self, payload):
        self.payloads.append(payload)
        if self.error: raise Exception("synthetic")
    def collect(self, start, end):
        self.calls += 1
        return iter(())


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "approval.json"

    def write(self, value, mode=0o600):
        self.path.write_text(value if type(value) is str else json.dumps(value))
        self.path.chmod(mode)
        return {"SOC_THIEF_RUNNER_APPROVAL_FILE": str(self.path)}

    def approval(self, **changes):
        value = {"approved_route": "daily-digest", "expires": "2026-03-12T00:00:00Z"}
        value.update(changes)
        return value

    def test_valid_unexpired_bounded_approval(self):
        self.assertTrue(approval_valid(self.write(self.approval()), NOW))
        self.assertTrue(approval_valid(self.write(self.approval(expires="2026-04-09T00:00:00+00:00")), NOW))

    def test_permanent_approval_is_valid_but_still_strictly_shaped(self):
        # "never" is the only undated value; the file's shape, route and mode still decide.
        self.assertEqual(runner.approval_expiry(self.write(self.approval(expires="never")), NOW),
                         runner.APPROVAL_PERMANENT)
        for value in (self.approval(expires="Never"), self.approval(expires="NEVER"),
                      self.approval(expires=" never"), self.approval(expires=""),
                      self.approval(expires=None), self.approval(approved_route="production", expires="never"),
                      {**self.approval(expires="never"), "extra": True}):
            with self.subTest(value=value):
                self.assertFalse(approval_valid(self.write(value), NOW))
        self.assertFalse(approval_valid(self.write(self.approval(expires="never"), mode=0o640), NOW))

    def test_invalid_approvals_fail_closed(self):
        cases = [
            self.approval(expires="2026-03-09T23:59:59Z"),            # expired
            self.approval(expires="2026-03-10T00:00:00Z"),            # expires now
            self.approval(expires="2026-04-09T00:00:01Z"),            # beyond thirty days
            self.approval(expires="2026-03-12T11:00:00+11:00"),       # not UTC
            self.approval(expires="2026-03-12T00:00:00"),             # naive
            self.approval(approved_route="production"),
            self.approval(expires=1),
            {**self.approval(), "extra": True},
            {"approved_route": "daily-digest"},
            [],
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertFalse(approval_valid(self.write(value), NOW))
        self.assertFalse(approval_valid(self.write('{"approved_route":"daily-digest","approved_route":"x","expires":"2026-03-12T00:00:00Z"}'), NOW))
        self.assertFalse(approval_valid(self.write("not json"), NOW))
        self.assertFalse(approval_valid(self.write(self.approval(), mode=0o640), NOW))
        self.assertFalse(approval_valid({}, NOW))
        self.assertFalse(approval_valid({"SOC_THIEF_RUNNER_APPROVAL_FILE": ""}, NOW))
        self.assertFalse(approval_valid({"SOC_THIEF_RUNNER_APPROVAL_FILE": str(self.path) + ".missing"}, NOW))
        self.write(self.approval())
        link = Path(self.temp.name) / "link.json"
        link.symlink_to(self.path)
        self.assertFalse(approval_valid({"SOC_THIEF_RUNNER_APPROVAL_FILE": str(link)}, NOW))


class WindowTests(unittest.TestCase):
    def test_daily_window_uses_most_recent_closed_sydney_boundary(self):
        start, end = daily_window(NOW)
        self.assertEqual((start, end), (datetime(2026, 3, 8, 21, tzinfo=timezone.utc), datetime(2026, 3, 9, 21, tzinfo=timezone.utc)))
        # 08:10 local is inside the lateness margin; the previous boundary is used.
        start, end = daily_window(datetime(2026, 3, 9, 21, 10, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 3, 8, 21, tzinfo=timezone.utc))
        start, end = daily_window(datetime(2026, 3, 9, 21, 15, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 3, 9, 21, tzinfo=timezone.utc))

    def test_daily_window_is_dst_correct(self):
        # DST ends 2026-04-05 03:00 AEDT: the report day ending 08:00 AEST that day is 25 hours.
        start, end = daily_window(datetime(2026, 4, 5, 0, tzinfo=timezone.utc))
        self.assertEqual((start, end), (datetime(2026, 4, 3, 21, tzinfo=timezone.utc), datetime(2026, 4, 4, 22, tzinfo=timezone.utc)))
        # DST starts 2026-10-04 02:00 AEST: the report day ending 08:00 AEDT that day is 23 hours.
        start, end = daily_window(datetime(2026, 10, 4, 0, tzinfo=timezone.utc))
        self.assertEqual((start, end), (datetime(2026, 10, 2, 22, tzinfo=timezone.utc), datetime(2026, 10, 3, 21, tzinfo=timezone.utc)))
        # The following day returns to 24 hours.
        start, end = daily_window(datetime(2026, 4, 6, 0, tzinfo=timezone.utc))
        self.assertEqual(end - start, timedelta(hours=24))

    def test_reconcile_window_is_the_day_before_the_most_recent_closed_day(self):
        self.assertEqual(reconcile_window(NOW), (datetime(2026, 3, 7, 21, tzinfo=timezone.utc), datetime(2026, 3, 8, 21, tzinfo=timezone.utc)))
        self.assertEqual(reconcile_window(NOW)[1], daily_window(NOW)[0])
        # Inside the lateness margin both windows step back together.
        self.assertEqual(reconcile_window(datetime(2026, 3, 9, 21, 10, tzinfo=timezone.utc)),
                         (datetime(2026, 3, 6, 21, tzinfo=timezone.utc), datetime(2026, 3, 7, 21, tzinfo=timezone.utc)))

    def test_reconcile_window_is_dst_correct(self):
        # The 25-hour day ending 08:00 AEST on 2026-04-05 is reconciled on 2026-04-06.
        start, end = reconcile_window(datetime(2026, 4, 6, 0, tzinfo=timezone.utc))
        self.assertEqual((start, end), (datetime(2026, 4, 3, 21, tzinfo=timezone.utc), datetime(2026, 4, 4, 22, tzinfo=timezone.utc)))
        # The 23-hour day ending 08:00 AEDT on 2026-10-04 is reconciled on 2026-10-05.
        start, end = reconcile_window(datetime(2026, 10, 5, 0, tzinfo=timezone.utc))
        self.assertEqual((start, end), (datetime(2026, 10, 2, 22, tzinfo=timezone.utc), datetime(2026, 10, 3, 21, tzinfo=timezone.utc)))
        start, end = reconcile_window(datetime(2026, 4, 7, 0, tzinfo=timezone.utc))
        self.assertEqual((start, end), (datetime(2026, 4, 4, 22, tzinfo=timezone.utc), datetime(2026, 4, 5, 22, tzinfo=timezone.utc)))


class MainGateTests(unittest.TestCase):
    def run_main(self, argv, env, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch("soc_thief.runner.CollectorConfig.from_environment", side_effect=AssertionError), \
                patch("soc_thief.runner.ModelConfig.from_environment", side_effect=AssertionError), \
                patch("soc_thief.runner.DiscordConfig.from_environment", side_effect=AssertionError), \
                patch("soc_thief.runner.StateStore", side_effect=AssertionError):
            code = main(argv, env=env, now=lambda: NOW, **kwargs)
        return code, output.getvalue()

    def forbidden(self, *args, **kwargs):
        raise AssertionError("no worker or delivery may run")

    def test_missing_or_invalid_approval_constructs_nothing_and_sends_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "approval.json"
            path.write_text(json.dumps({"approved_route": "daily-digest", "expires": "2026-01-01T00:00:00Z"}))
            path.chmod(0o600)
            for env in ({}, {"SOC_THIEF_RUNNER_APPROVAL_FILE": str(path)}):
                for argv in (["--daily"], ["--reconcile"]):
                    code, output = self.run_main(argv, env, run_worker=self.forbidden, send_health=self.forbidden)
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "Runner approval missing, invalid, or expired; no request made.\n")

    def test_selected_mode_is_passed_to_the_worker(self):
        calls = []
        with patch("soc_thief.runner.approval_valid", return_value=True):
            for argv in (["--daily"], ["--reconcile"]):
                code, output = self.run_main(argv, {}, run_worker=lambda *a, **k: calls.append((a, k)) or runner._outcome_code(
                    RunResult(True, False, False, "window already completed; no collection performed")), send_health=self.forbidden)
                self.assertEqual((code, output), (0, "window already completed; no collection performed\n"))
        self.assertEqual(calls, [(daily_window(NOW), {"stream": "daily", "catch_up": True}), (reconcile_window(NOW), {"stream": "reconcile", "catch_up": False})])

    def test_invalid_arguments_and_windows_are_rejected_without_detail(self):
        for argv in ([], ["--daily", "--start", "2026-03-09T00:00:00Z", "--end", "2026-03-09T01:00:00Z"],
                     ["--reconcile", "--daily"], ["--reconcile", "--start", "2026-03-09T00:00:00Z"],
                     ["--reconcile", "--end", "2026-03-09T01:00:00Z"],
                     ["--reconcile", "--start", "2026-03-09T00:00:00Z", "--end", "2026-03-09T01:00:00Z"],
                     ["--reconcile", "--daily", "--start", "2026-03-07T21:00:00Z", "--end", "2026-03-08T21:00:00Z"],
                     ["--start", "2026-03-09T00:00:00Z"], ["--bogus=secret"]):
            with self.subTest(argv=argv):
                code, output = self.run_main(argv, {}, run_worker=self.forbidden, send_health=self.forbidden)
                self.assertEqual(code, 2)
                self.assertNotIn("secret", output)
        for start, end in (("2026-03-09T00:00:00", "2026-03-09T01:00:00"),
                           ("2026-03-08T00:00:00Z", "2026-03-09T01:00:01Z"),
                           ("2026-03-09T23:50:00Z", "2026-03-09T23:50:00Z"),
                           ("2026-03-09T23:00:00Z", "2026-03-09T23:50:00Z")):
            with self.subTest(start=start, end=end):
                code, output = self.run_main(["--start", start, "--end", end], {}, run_worker=self.forbidden, send_health=self.forbidden)
                self.assertEqual((code, output), (2, "Invalid runner window.\n"))

    def recorded(self, argv, now=NOW):
        calls = []
        worker = lambda *a, **k: calls.append((a, k)) or runner._outcome_code(
            RunResult(True, False, False, "window completed; no delivery required"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("soc_thief.runner.approval_valid", return_value=True):
            code = main(argv, env={}, now=lambda: now, run_worker=worker, send_health=self.forbidden)
        return code, output.getvalue(), calls

    def test_explicit_reconcile_window_is_passed_to_the_reconcile_stream(self):
        start, end = reconcile_window(NOW)
        for argv in (["--reconcile", "--start", "2026-03-07T21:00:00Z", "--end", "2026-03-08T21:00:00Z"],
                     ["--reconcile", "--start", "2026-03-06T08:00:00+11:00", "--end", "2026-03-07T08:00:00+11:00"]):
            with self.subTest(argv=argv):
                code, output, calls = self.recorded(argv)
                self.assertEqual((code, output), (0, "window completed; no delivery required\n"))
                self.assertEqual(calls[0][1], {"stream": "reconcile", "catch_up": False})
                self.assertTrue(all(value.tzinfo is timezone.utc for value in calls[0][0]))
        self.assertEqual(self.recorded(["--reconcile", "--start", start.isoformat(), "--end", end.isoformat()])[2],
                         [((start, end), {"stream": "reconcile", "catch_up": False})])
        self.assertEqual(self.recorded(["--reconcile", "--start", "2026-03-06T08:00:00+11:00",
                                        "--end", "2026-03-07T08:00:00+11:00"])[2][0][0],
                         (start - timedelta(days=2), end - timedelta(days=2)))

    def test_explicit_reconcile_accepts_dst_aligned_days(self):
        # 25-hour day ending 08:00 AEST on 2026-04-05 and 23-hour day ending 08:00 AEDT on 2026-10-04.
        for start, end, now, hours in (
                ("2026-04-04T08:00:00+11:00", "2026-04-05T08:00:00+10:00", datetime(2026, 4, 7, 0, tzinfo=timezone.utc), 25),
                ("2026-10-03T08:00:00+10:00", "2026-10-04T08:00:00+11:00", datetime(2026, 10, 6, 0, tzinfo=timezone.utc), 23)):
            with self.subTest(start=start):
                code, output, calls = self.recorded(["--reconcile", "--start", start, "--end", end], now=now)
                self.assertEqual(code, 0)
                window = calls[0][0]
                self.assertEqual(window[1] - window[0], timedelta(hours=hours))
                self.assertEqual(calls[0][1], {"stream": "reconcile", "catch_up": False})

    def test_explicit_reconcile_rejects_misaligned_or_too_recent_windows(self):
        cases = (
            ("2026-03-06T09:00:00+11:00", "2026-03-07T09:00:00+11:00"),   # 09:00 local, not 08:00
            ("2026-03-06T07:00:00+11:00", "2026-03-07T07:00:00+11:00"),   # 07:00 local
            ("2026-03-06T08:00:00+11:00", "2026-03-07T09:00:00+11:00"),   # 25h, end not on boundary
            ("2026-03-06T08:00:00+11:00", "2026-03-06T20:00:00+11:00"),   # partial day
            ("2026-03-06T08:00:00+11:00", "2026-03-07T07:59:59+11:00"),
            ("2026-03-06T08:00:00.5+11:00", "2026-03-07T08:00:00.5+11:00"),
            ("2026-03-06T08:00:00Z", "2026-03-07T08:00:00Z"),               # 08:00 UTC, not Sydney
            ("2026-03-06T08:00:00", "2026-03-07T08:00:00"),                 # naive
            ("2026-03-05T08:00:00+11:00", "2026-03-07T08:00:00+11:00"),   # two days
            ("2026-03-07T08:00:00+11:00", "2026-03-06T08:00:00+11:00"),   # reversed
            ("2026-03-08T21:00:00Z", "2026-03-09T21:00:00Z"),               # daily window: newer than reconcile lag
            ("2026-04-04T08:00:00+11:00", "2026-04-05T08:00:00+11:00"),   # DST day with a 24h (misaligned) end
        )
        for start, end in cases:
            with self.subTest(start=start, end=end):
                code, output = self.run_main(["--reconcile", "--start", start, "--end", end], {},
                                             run_worker=self.forbidden, send_health=self.forbidden)
                self.assertEqual((code, output), (2, "Invalid runner window.\n"))
        # A window newer than the automatic lag is refused even when it is closed and aligned.
        start, end = daily_window(NOW)
        code, output = self.run_main(["--reconcile", "--start", start.isoformat(), "--end", end.isoformat()], {},
                                     run_worker=self.forbidden, send_health=self.forbidden)
        self.assertEqual((code, output), (2, "Invalid runner window.\n"))

    def test_explicit_reconcile_without_approval_constructs_nothing(self):
        start, end = reconcile_window(NOW)
        code, output = self.run_main(["--reconcile", "--start", start.isoformat(), "--end", end.isoformat()], {},
                                     run_worker=self.forbidden, send_health=self.forbidden)
        self.assertEqual((code, output), (2, "Runner approval missing, invalid, or expired; no request made.\n"))

    def test_fixed_outcomes_and_exit_codes(self):
        approved = patch("soc_thief.runner.approval_valid", return_value=True)
        outcomes = {
            runner._outcome_code(RunResult(True, True, False, "window completed and delivery acknowledged")): (0, "window completed and delivery acknowledged\n"),
            runner._outcome_code(RunResult(True, True, True, "window completed and delivery acknowledged")): (1, "window completed and delivery acknowledged; health review required\n"),
            runner._outcome_code(RunResult(False, True, True, "window failed; health report delivered")): (1, "window failed; health report delivered\n"),
            runner._outcome_code(RunResult(True, False, False, "window already completed; no collection performed")): (0, "window already completed; no collection performed\n"),
        }
        with approved:
            for worker_code, expected in outcomes.items():
                code, output = self.run_main(["--daily"], {}, run_worker=lambda *a, c=worker_code, **k: c, send_health=self.forbidden)
                self.assertEqual((code, output), expected)
            sent = []
            for worker_code, message in ((runner.DEADLINE_EXCEEDED, "Runner deadline exceeded; health report delivered.\n"),
                                         (1, "Runner failed; health report delivered.\n")):
                code, output = self.run_main(["--daily"], {}, run_worker=lambda *a, c=worker_code, **k: c,
                                             send_health=lambda *a: sent.append(a) or True)
                self.assertEqual((code, output), (1, message))
            self.assertEqual(len(sent), 2)
            code, output = self.run_main(["--daily"], {}, run_worker=lambda *a, **k: runner.DEADLINE_EXCEEDED, send_health=lambda *a: False)
            self.assertEqual((code, output), (1, "Runner deadline exceeded; health report could not be delivered.\n"))

    def test_worker_timeout_is_derived_from_runner_deadline(self):
        import inspect
        default = inspect.signature(_run_worker).parameters["timeout"].default
        self.assertEqual(default, runner.RunnerLimits().deadline_seconds + runner.WORKER_GRACE_SECONDS)
        self.assertEqual(default, 1560)

    def test_spawned_worker_receives_catch_up_only_when_asked(self):
        # Backfill passes its own three-argument target, so the default must stay three arguments.
        self.assertEqual(_run_worker(NOW - timedelta(days=1), NOW, target=_arg_count_worker), 13)
        self.assertEqual(_run_worker(NOW - timedelta(days=1), NOW, catch_up=True, target=_arg_count_worker), 14)

    def test_worker_is_killed_at_deadline(self):
        began = time.monotonic()
        self.assertEqual(_run_worker(NOW - timedelta(days=1), NOW, timeout=0.2, target=_slow_worker), runner.DEADLINE_EXCEEDED)
        self.assertLess(time.monotonic() - began, 15)


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.key_file = base / "identity"
        self.key_file.write_text(KEY + "\n"); self.key_file.chmod(0o600)
        self.state = base / "state"
        self.env = {"SOC_THIEF_IDENTITY_KEY_FILE": str(self.key_file), "STATE_PATH": str(self.state)}
        self.start, self.end = daily_window(NOW)

    def execute(self, delivery, collector, **kwargs):
        factories = dict(delivery_factory=lambda env: delivery, collector_factory=lambda env: collector,
                         model_factory=lambda env: object())
        factories.update(kwargs)
        return _execute(self.start, self.end, self.env, **factories)

    def checkpoint(self, end, stream="daily", start=None):
        with StateStore(self.state) as store:
            store.commit_window(opaque_key(bytes.fromhex(KEY), "stream", stream), start or end - timedelta(days=1), end, [], [],
                                recorded_at=end)

    def reconcile(self, delivery, collector, window=None):
        start, end = window or reconcile_window(NOW)
        return _execute(start, end, self.env, stream="reconcile", delivery_factory=lambda env: delivery,
                        collector_factory=lambda env: collector, model_factory=lambda env: object())

    def test_reconcile_refused_unless_daily_committed_the_window(self):
        rstart, rend = reconcile_window(NOW)
        failed = RunResult(False, True, True, "window failed; health report delivered")
        cases = (
            [],                                              # daily has never committed
            [(rstart, rstart - timedelta(days=1))],          # daily checkpoint ends before the window
            [(rend - timedelta(hours=1), rstart)],           # daily checkpoint inside the window
            [(self.end, self.start)],                        # daily origin is after the window start
        )
        for commits in cases:
            with self.subTest(commits=commits):
                for path in self.state.glob("*"):
                    path.unlink()
                for end, start in commits:
                    self.checkpoint(end, start=start)
                delivery, collector = Fake(), Fake()
                result = self.reconcile(delivery, collector)
                self.assertEqual(result, failed)
                self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))

    def test_reconcile_first_and_contiguous_windows_run_after_daily_commit(self):
        rstart, rend = reconcile_window(NOW)
        self.checkpoint(rend, start=rstart); self.checkpoint(self.end, start=rend)
        delivery, collector = Fake(), Fake()
        result = self.reconcile(delivery, collector)
        self.assertEqual(result, RunResult(True, False, False, "window completed; no delivery required"))
        self.assertEqual((collector.calls, delivery.payloads), (1, []))
        with StateStore(self.state) as store:
            self.assertEqual(store.checkpoint(opaque_key(bytes.fromhex(KEY), "stream", "reconcile")), rend)
            self.assertEqual(store.checkpoint(opaque_key(bytes.fromhex(KEY), "stream", "daily")), self.end)
        result = self.reconcile(delivery, collector, (rend, self.end))
        self.assertEqual(result.status, "window completed; no delivery required")

    def test_covered_reconcile_window_is_not_recollected(self):
        rstart, rend = reconcile_window(NOW)
        self.checkpoint(rend, start=rstart); self.checkpoint(rend, stream="reconcile", start=rstart)
        delivery, collector = Fake(), Fake()
        result = self.reconcile(delivery, collector)
        self.assertEqual(result, RunResult(True, False, False, "window already completed; no collection performed"))
        self.assertEqual((collector.calls, delivery.payloads), (0, []))

    def test_reconcile_gap_fails_closed_before_collection(self):
        rstart, rend = reconcile_window(NOW)
        earlier = rstart - timedelta(days=2)
        self.checkpoint(self.end, start=earlier)
        self.checkpoint(earlier + timedelta(days=1), stream="reconcile", start=earlier)
        delivery, collector = Fake(), Fake()
        result = self.reconcile(delivery, collector)
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))

    def test_missed_reconcile_days_are_recovered_with_explicit_windows(self):
        key = bytes.fromhex(KEY)
        d4 = reconcile_window(NOW)
        d3, d2, d1 = ((d4[0] - timedelta(days=n), d4[1] - timedelta(days=n)) for n in (1, 2, 3))
        self.checkpoint(self.end, start=d1[0])                 # daily stream covers D1..today
        self.checkpoint(d1[1], stream="reconcile", start=d1[0])  # reconcile committed D1; D2, D3 missed
        deliveries, collections = [], []

        def cli(argv):
            delivery, collector = Fake(), Fake()
            deliveries.append(delivery); collections.append(collector)
            worker = lambda start, end, stream, **k: runner._outcome_code(_execute(
                start, end, self.env, stream=stream, delivery_factory=lambda env: delivery,
                collector_factory=lambda env: collector, model_factory=lambda env: object()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch("soc_thief.runner.approval_valid", return_value=True):
                code = main(argv, env={}, now=lambda: NOW, run_worker=worker, send_health=lambda *a: False)
            return code, output.getvalue()

        explicit = lambda window: ["--reconcile", "--start", window[0].isoformat(), "--end", window[1].isoformat()]
        self.assertEqual(cli(["--reconcile"]), (1, "window failed; health report delivered\n"))
        self.assertEqual((collections[-1].calls, len(deliveries[-1].payloads)), (0, 1))
        for window in (d2, d3):
            self.assertEqual(cli(explicit(window)), (0, "window completed; no delivery required\n"))
            self.assertEqual((collections[-1].calls, deliveries[-1].payloads), (1, []))
            with StateStore(self.state) as store:
                self.assertEqual(store.checkpoint(opaque_key(key, "stream", "reconcile")), window[1])
        self.assertEqual(cli(["--reconcile"]), (0, "window completed; no delivery required\n"))
        self.assertEqual(collections[-1].calls, 1)
        # A repeated catch-up of a covered day performs no collection.
        self.assertEqual(cli(explicit(d2)), (0, "window already completed; no collection performed\n"))
        self.assertEqual(collections[-1].calls, 0)
        with StateStore(self.state) as store:
            self.assertEqual(store.checkpoint(opaque_key(key, "stream", "reconcile")), d4[1])
            self.assertEqual(store.checkpoint(opaque_key(key, "stream", "daily")), self.end)

    def daily_cli(self, argv, windows, *, clock=None, fail_on=None):
        delivery = Fake()
        class Recording(Fake):
            def collect(inner, start, end):
                windows.append((start, end))
                if (start, end) == fail_on:
                    raise RuntimeError("synthetic collection failure")
                return super().collect(start, end)
        collector = Recording()
        # The same exit-code encoding the spawned worker uses, catch-up offset included.
        worker = lambda start, end, stream, **k: runner._worker_code(_execute(
            start, end, self.env, stream=stream, catch_up=k.get("catch_up", False),
            delivery_factory=lambda env: delivery, collector_factory=lambda env: collector,
            model_factory=lambda env: object()))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("soc_thief.runner.approval_valid", return_value=True):
            code = main(argv, env={}, now=lambda: NOW, run_worker=worker, send_health=lambda *a: False,
                        monotonic=clock or (lambda: 0.0))
        return code, output.getvalue(), delivery

    def missed(self, days):
        return [(self.start - timedelta(days=n), self.end - timedelta(days=n)) for n in range(days, 0, -1)]

    def daily_checkpoint(self):
        with StateStore(self.state) as store:
            return store.checkpoint(opaque_key(bytes.fromhex(KEY), "stream", "daily"))

    def test_one_scheduled_daily_run_recovers_a_missed_gap_oldest_first_without_a_human(self):
        missed = self.missed(3)
        self.checkpoint(missed[0][0])                      # committed up to three days ago
        windows = []
        code, output, delivery = self.daily_cli(["--daily"], windows)
        self.assertEqual(code, 0)
        self.assertEqual(output, "missed day: window completed; no delivery required\n" * 3
                         + "window completed; no delivery required\n")
        self.assertEqual((windows, delivery.payloads), (missed + [(self.start, self.end)], []))
        self.assertEqual(self.daily_checkpoint(), self.end)
        code, output, _ = self.daily_cli(["--daily"], windows)
        self.assertEqual((code, output, len(windows)), (0, "window already completed; no collection performed\n", 4))

    def test_catch_up_stops_at_the_first_failure_and_at_the_time_budget(self):
        missed = self.missed(3)
        self.checkpoint(missed[0][0])
        windows = []
        code, output, _ = self.daily_cli(["--daily"], windows, fail_on=missed[1])
        self.assertEqual(code, 1)
        self.assertEqual(output, "missed day: window completed; no delivery required\n"
                                 "missed day: window failed; health report delivered\n")
        self.assertEqual((windows, self.daily_checkpoint()), (missed[:2], missed[0][1]))
        # A clock past the start limit after the first window: the rest wait for the next run.
        ticks = iter([0.0, runner.CATCH_UP_START_LIMIT_SECONDS + 1.0])
        windows = []
        code, output, _ = self.daily_cli(["--daily"], windows, clock=lambda: next(ticks))
        self.assertEqual((code, windows, self.daily_checkpoint()), (0, [missed[1]], missed[1][1]))

    def test_catch_up_refuses_explicit_runs_long_gaps_overlaps_and_misaligned_checkpoints(self):
        failed = (1, "window failed; health report delivered\n")
        explicit = ["--start", self.start.isoformat(), "--end", self.end.isoformat()]
        for argv, checkpoint in (
            (explicit, self.start - timedelta(days=2)),                          # operator window: strict gate
            (["--daily"], self.start - runner.CATCH_UP_LIMIT - timedelta(days=1)),  # too long
            (["--daily"], self.start + timedelta(hours=3)),                      # overlap
            (["--daily"], self.start - timedelta(days=2, hours=1)),              # not an 08:00 boundary
        ):
            with self.subTest(argv=argv[0], checkpoint=checkpoint):
                for path in self.state.glob("*"):
                    path.unlink()
                self.checkpoint(checkpoint)
                windows = []
                code, output, delivery = self.daily_cli(argv, windows)
                self.assertEqual((code, output, windows, len(delivery.payloads)), (*failed, [], 1))

    def test_catch_up_window_follows_daylight_saving(self):
        sydney = ZoneInfo("Australia/Sydney")
        before = datetime(2026, 4, 4, 8, tzinfo=sydney).astimezone(timezone.utc)
        start = datetime(2026, 4, 6, 8, tzinfo=sydney).astimezone(timezone.utc)
        first = runner.catch_up_window(before, start)
        self.assertEqual(first, (before, datetime(2026, 4, 5, 8, tzinfo=sydney).astimezone(timezone.utc)))
        self.assertEqual(first[1] - first[0], timedelta(hours=25))
        self.assertIsNone(runner.catch_up_window(start, start))

    def test_unknown_stream_fails_closed(self):
        delivery, collector = Fake(), Fake()
        result = _execute(self.start, self.end, self.env, stream="bogus", delivery_factory=lambda env: delivery,
                          collector_factory=lambda env: collector, model_factory=lambda env: object())
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertEqual(collector.calls, 0)

    def test_configuration_failure_sends_content_free_health_report(self):
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector, model_factory=lambda env: (_ for _ in ()).throw(ValueError("secret")))
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertEqual(len(delivery.payloads), 1); self.assertEqual(collector.calls, 0)
        self.assertNotIn("secret", json.dumps(delivery.payloads[0].payloads))
        for bad in ("short", "zz" * 32, KEY.upper()):
            self.key_file.write_text(bad)
            result = self.execute(Fake(), collector)
            self.assertEqual(result.status, "window failed; health report delivered")
        self.assertEqual(collector.calls, 0)

    def test_unloadable_delivery_reports_undeliverable_failure(self):
        result = _execute(self.start, self.end, self.env, delivery_factory=lambda env: (_ for _ in ()).throw(ValueError),
                          collector_factory=lambda env: Fake(), model_factory=lambda env: object())
        self.assertEqual(result, RunResult(False, False, True, "window failed; health report could not be delivered"))

    def test_completed_window_is_not_recollected(self):
        self.checkpoint(self.end)
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(True, False, False, "window already completed; no collection performed"))
        self.assertEqual((collector.calls, delivery.payloads), (0, []))

    def test_oldest_pending_daily_delivery_is_acknowledged_before_a_newer_window(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        earlier = self.start - timedelta(days=1)
        with StateStore(self.state) as store:
            store.commit_window(opaque_key(bytes.fromhex(KEY), "stream", "daily"), earlier, self.start, [], [],
                                recorded_at=self.start, pending_delivery=payload)
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))
        with StateStore(self.state) as store:
            token = opaque_key(bytes.fromhex(KEY), "stream", "daily")
            self.assertTrue(store.delivery_acknowledged(token, earlier))
            self.assertEqual(store.checkpoint(token), self.start)

    def test_oldest_pending_reconcile_delivery_is_acknowledged_before_a_newer_window(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        rstart, rend = reconcile_window(NOW)
        earlier = rstart - timedelta(days=1)
        self.checkpoint(self.end, start=earlier)
        with StateStore(self.state) as store:
            token = opaque_key(bytes.fromhex(KEY), "stream", "reconcile")
            store.commit_window(token, earlier, rstart, [], [], recorded_at=rstart, pending_delivery=payload)
        delivery, collector = Fake(), Fake()
        result = self.reconcile(delivery, collector)
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))
        with StateStore(self.state) as store:
            self.assertTrue(store.delivery_acknowledged(token, earlier))
            self.assertEqual(store.checkpoint(token), rstart)

    def test_oldest_pending_daily_delivery_precedes_source_and_model_construction(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        earlier = self.start - timedelta(days=1)
        with StateStore(self.state) as store:
            token = opaque_key(bytes.fromhex(KEY), "stream", "daily")
            store.commit_window(token, earlier, self.start, [], [], recorded_at=self.start,
                                pending_delivery=payload)
        constructed = []
        def forbidden(name):
            def factory(env):
                constructed.append(name)
                raise ValueError("synthetic dependency must not be constructed")
            return factory
        delivery = Fake()
        result = _execute(self.start, self.end, self.env, delivery_factory=lambda env: delivery,
                          collector_factory=forbidden("collector"), model_factory=forbidden("model"))
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((constructed, len(delivery.payloads)), ([], 1))
        with StateStore(self.state) as store:
            self.assertTrue(store.delivery_acknowledged(token, earlier))

    def test_oldest_pending_reconcile_delivery_precedes_source_and_model_construction(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        rstart, rend = reconcile_window(NOW)
        earlier = rstart - timedelta(days=1)
        self.checkpoint(self.end, start=earlier)
        with StateStore(self.state) as store:
            token = opaque_key(bytes.fromhex(KEY), "stream", "reconcile")
            store.commit_window(token, earlier, rstart, [], [], recorded_at=rstart,
                                pending_delivery=payload)
        constructed = []
        def forbidden(name):
            def factory(env):
                constructed.append(name)
                raise ValueError("synthetic dependency must not be constructed")
            return factory
        delivery = Fake()
        result = _execute(rstart, rend, self.env, stream="reconcile", delivery_factory=lambda env: delivery,
                          collector_factory=forbidden("collector"), model_factory=forbidden("model"))
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((constructed, len(delivery.payloads)), ([], 1))
        with StateStore(self.state) as store:
            self.assertTrue(store.delivery_acknowledged(token, earlier))

    def test_failed_oldest_pending_retry_stays_pending_without_new_collection(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        earlier = self.start - timedelta(days=1)
        with StateStore(self.state) as store:
            token = opaque_key(bytes.fromhex(KEY), "stream", "daily")
            store.commit_window(token, earlier, self.start, [], [], recorded_at=self.start, pending_delivery=payload)
        delivery, collector = Fake(error=True), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(False, False, True, "window failed; health report could not be delivered"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 2))
        with StateStore(self.state) as store:
            self.assertEqual(store.oldest_pending_delivery(token).payload, payload)
            self.assertEqual(store.checkpoint(token), self.start)

    def test_noncontiguous_checkpoint_fails_closed_before_collection(self):
        self.checkpoint(self.start - timedelta(days=1))
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))

    def tuning_file(self, value, mode=0o600):
        path = Path(self.temp.name) / "tuning"
        path.write_text(value); path.chmod(mode)
        self.env["SOC_THIEF_TUNING_FILE"] = str(path)

    def spy(self):
        calls = []
        def run_window(**kwargs):
            calls.append(kwargs)
            return RunResult(True, False, False, "window completed; no delivery required")
        return calls, patch("soc_thief.runner.run_window", side_effect=run_window)

    def test_tuning_is_loaded_from_file_and_passed_to_daily_and_reconcile(self):
        self.tuning_file('{"version": 1,\n "entries": [{"rule_id": "100", "action": "mute", "note": "n"}]}\n')
        calls, patched = self.spy()
        with patched:
            self.assertEqual(self.execute(Fake(), Fake()).status, "window completed; no delivery required")
            rstart, rend = reconcile_window(NOW)
            self.checkpoint(rend, start=rstart)
            self.reconcile(Fake(), Fake())
        self.assertEqual(len(calls), 2)
        for kwargs in calls:
            self.assertEqual(kwargs["tuning"], Tuning((TuningEntry("100", "mute", None, None),)))
            self.assertFalse(kwargs["tuning_failure"])
        self.assertEqual([kwargs["stream"] for kwargs in calls], ["daily", "reconcile"])

    def test_unset_tuning_is_empty_without_failure(self):
        calls, patched = self.spy()
        with patched:
            self.execute(Fake(), Fake())
        self.assertEqual((calls[0]["tuning"], calls[0]["tuning_failure"]), (Tuning(), False))

    def test_invalid_tuning_file_runs_without_tuning_and_flags_health(self):
        for value, mode in (('{"version":1,"entries":[]}', 0o644), ("not json", 0o600),
                            ('{"version":1,"entries":[{"rule_id":"1","action":"mute","x":1}]}', 0o600)):
            with self.subTest(value=value, mode=mode):
                self.tuning_file(value, mode)
                calls, patched = self.spy()
                with patched:
                    self.execute(Fake(), Fake())
                self.assertEqual((calls[0]["tuning"], calls[0]["tuning_failure"]), (Tuning(), True))

    def test_invalid_tuning_file_delivers_health_report_end_to_end(self):
        self.tuning_file("{}")
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(True, True, True, "window completed and delivery acknowledged"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (1, 1))
        self.assertIn("health failures: 1", delivery.payloads[0].payloads[0]["content"])

    def test_first_and_contiguous_windows_run(self):
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(True, False, False, "window completed; no delivery required"))
        self.assertEqual(collector.calls, 1)
        with StateStore(self.state) as store:
            self.assertEqual(store.checkpoint(opaque_key(bytes.fromhex(KEY), "stream", "daily")), self.end)


if __name__ == "__main__":
    unittest.main()
