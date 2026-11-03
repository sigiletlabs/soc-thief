"""Synthetic backfill orchestration checks; no Wazuh, model, or Discord endpoint is contacted."""
import contextlib
from datetime import date, datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from soc_thief import backfill, runner
from soc_thief.backfill import _execute, in_quiet_period, main, parse_origin, window_starting
from soc_thief.runner import RunResult
from soc_thief.state import StateStore, opaque_key
from soc_thief.tuning import Tuning, TuningEntry


KEY = "cd" * 32
# 2026-09-13 12:00 Australia/Sydney (AEST, +10): outside the daily report quiet period.
NOW = datetime(2026, 9, 13, 2, 0, tzinfo=timezone.utc)
ORIGIN = datetime(2026, 6, 5, 22, 0, tzinfo=timezone.utc)  # 2026-06-06 08:00 AEST
DAY = timedelta(days=1)
COMPLETE = "backfill complete; no collection performed"
DEFERRED = "backfill deferred; daily report period"
RANGE_INVALID = "backfill origin is after the daily origin; no collection performed"
FAILED = "window failed; health report delivered"
PAYLOAD = json.dumps({"content": "synthetic", "allowed_mentions": {"parse": []}}, separators=(",", ":")).encode()
SECOND_PAYLOAD = json.dumps({"content": "synthetic two", "allowed_mentions": {"parse": []}}, separators=(",", ":")).encode()


class Fake:
    def __init__(self, error=False): self.error, self.payloads, self.calls, self.windows = error, [], 0, []
    def send(self, payload):
        self.payloads.append(payload)
        if self.error: raise Exception("synthetic")
    def collect(self, start, end):
        self.calls += 1
        self.windows.append((start, end))
        return iter(())


class WindowTests(unittest.TestCase):
    def test_origin_is_0800_sydney_on_the_operator_date(self):
        self.assertEqual(parse_origin("2026-06-06", NOW), ORIGIN)
        # AEDT (+11) dates start at 21:00 UTC the previous day.
        self.assertEqual(parse_origin("2026-01-15", NOW), datetime(2026, 1, 14, 21, tzinfo=timezone.utc))

    def test_malformed_or_unclosed_origins_are_rejected(self):
        for value in ("20260606", "2026-6-06", "2026-06-06T08:00", " 2026-06-06", "2026-02-30", "٢٠٢٦-06-06", "",
                      "2026-09-13", "2027-01-01"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_origin(value, NOW)
        # The 2026-09-12 window closed at 2026-09-13 08:00 Sydney, before NOW minus the lateness margin.
        self.assertEqual(parse_origin("2026-09-12", NOW), datetime(2026, 9, 11, 22, tzinfo=timezone.utc))

    def test_windows_are_sydney_days_across_dst(self):
        self.assertEqual(window_starting(ORIGIN), (ORIGIN, ORIGIN + DAY))
        # DST ends 2026-04-05: the day from 04-04 08:00 AEDT to 04-05 08:00 AEST is 25 hours.
        start = datetime(2026, 4, 3, 21, tzinfo=timezone.utc)
        self.assertEqual(window_starting(start), (start, datetime(2026, 4, 4, 22, tzinfo=timezone.utc)))
        # DST starts 2026-10-04: the day from 10-03 08:00 AEST to 10-04 08:00 AEDT is 23 hours.
        start = datetime(2026, 10, 2, 22, tzinfo=timezone.utc)
        self.assertEqual(window_starting(start), (start, datetime(2026, 10, 3, 21, tzinfo=timezone.utc)))
        for bad in (ORIGIN + timedelta(minutes=1), ORIGIN.replace(tzinfo=None)):
            with self.assertRaises(ValueError):
                window_starting(bad)


class QuietPeriodTests(unittest.TestCase):
    def local(self, day, hour, minute, second=0):
        from zoneinfo import ZoneInfo
        return datetime.combine(day, datetime.min.time(), ZoneInfo("Australia/Sydney")).replace(
            hour=hour, minute=minute, second=second).astimezone(timezone.utc)

    def test_quiet_period_boundaries_on_standard_and_dst_days(self):
        for day in (date(2026, 3, 10), date(2026, 4, 5), date(2026, 9, 13), date(2026, 10, 4)):
            with self.subTest(day=day):
                self.assertFalse(in_quiet_period(self.local(day, 7, 29, 59)))
                self.assertTrue(in_quiet_period(self.local(day, 7, 30)))
                self.assertTrue(in_quiet_period(self.local(day, 8, 20)))
                self.assertTrue(in_quiet_period(self.local(day, 9, 29, 59)))
                self.assertFalse(in_quiet_period(self.local(day, 9, 30)))
                # The 10:30 reconcile pass has its own quiet period.
                self.assertFalse(in_quiet_period(self.local(day, 9, 59, 59)))
                self.assertTrue(in_quiet_period(self.local(day, 10, 0)))
                self.assertTrue(in_quiet_period(self.local(day, 11, 14, 59)))
                self.assertFalse(in_quiet_period(self.local(day, 11, 15)))

    def test_backfill_started_before_quiet_period_ends_before_daily_boundary(self):
        # The latest permitted start plus the whole unit timeout ends before the 08:00 boundary,
        # which precedes the 08:20 daily runner timer.
        latest = datetime.combine(date(2026, 9, 13), backfill.QUIET_PERIODS[0][0]) - timedelta(seconds=1)
        self.assertLessEqual(latest + backfill.UNIT_TIMEOUT,
                             datetime.combine(date(2026, 9, 13), runner.REPORT_BOUNDARY))
        self.assertLess(timedelta(seconds=backfill.WORKER_TIMEOUT), backfill.UNIT_TIMEOUT)
        self.assertEqual(backfill.WORKER_TIMEOUT,
                         runner.RunnerLimits().deadline_seconds + runner.WORKER_GRACE_SECONDS)


class MainTests(unittest.TestCase):
    def run_main(self, argv, env=None, now=NOW, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch("soc_thief.runner.CollectorConfig.from_environment", side_effect=AssertionError), \
                patch("soc_thief.runner.ModelConfig.from_environment", side_effect=AssertionError), \
                patch("soc_thief.runner.DiscordConfig.from_environment", side_effect=AssertionError), \
                patch("soc_thief.runner.StateStore", side_effect=AssertionError), \
                patch("soc_thief.backfill.StateStore", side_effect=AssertionError):
            code = main(argv, env={} if env is None else env, now=lambda: now, **kwargs)
        return code, output.getvalue()

    def forbidden(self, *args, **kwargs):
        raise AssertionError("no worker or delivery may run")

    def test_missing_approval_constructs_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "approval.json"
            path.write_text(json.dumps({"approved_route": "daily-digest", "expires": "2026-01-01T00:00:00Z"}))
            path.chmod(0o600)
            for env in ({}, {"SOC_THIEF_RUNNER_APPROVAL_FILE": str(path)}):
                code, output = self.run_main(["--from", "2026-06-06"], env, run_worker=self.forbidden, send_health=self.forbidden)
                self.assertEqual((code, output), (2, "Backfill approval missing, invalid, or expired; no request made.\n"))

    def test_invalid_arguments_are_rejected_without_detail(self):
        for argv in ([], ["--from"], ["--from", "secret"], ["--from", "2026-06-06", "--bogus=secret"],
                     ["--from", "2026-09-13"]):
            with self.subTest(argv=argv):
                with patch("soc_thief.backfill.approval_valid", side_effect=AssertionError):
                    code, output = self.run_main(argv, run_worker=self.forbidden, send_health=self.forbidden)
                self.assertEqual(code, 2)
                self.assertNotIn("secret", output)

    def test_quiet_period_defers_without_approval_read_or_construction(self):
        quiet = datetime(2026, 9, 12, 22, 0, tzinfo=timezone.utc)  # 2026-09-13 08:00 AEST
        with patch("soc_thief.backfill.approval_valid", side_effect=AssertionError):
            code, output = self.run_main(["--from", "2026-06-06"], now=quiet, run_worker=self.forbidden, send_health=self.forbidden)
        self.assertEqual((code, output), (0, DEFERRED + "\n"))

    def test_worker_receives_origin_and_bounded_timeout(self):
        calls = []
        def worker(*args, **kwargs):
            calls.append((args, kwargs))
            return backfill._outcome_code(RunResult(True, False, False, COMPLETE))
        with patch("soc_thief.backfill.approval_valid", return_value=True):
            code, output = self.run_main(["--from", "2026-06-06"], run_worker=worker, send_health=self.forbidden)
        self.assertEqual((code, output), (0, COMPLETE + "\n"))
        self.assertEqual(calls, [((ORIGIN, NOW), {"stream": backfill.STREAM, "timeout": backfill.WORKER_TIMEOUT,
                                                  "target": backfill._worker})])

    def test_fixed_outcomes_and_exit_codes(self):
        outcomes = (
            (RunResult(True, True, False, "window completed and delivery acknowledged"), (0, "window completed and delivery acknowledged\n")),
            (RunResult(True, False, False, "window completed; no delivery required"), (0, "window completed; no delivery required\n")),
            (RunResult(True, True, False, "pending delivery acknowledged"), (0, "pending delivery acknowledged\n")),
            (RunResult(True, True, True, "window completed and delivery acknowledged"), (1, "window completed and delivery acknowledged; health review required\n")),
            (RunResult(False, True, True, FAILED), (1, FAILED + "\n")),
            (RunResult(False, False, True, "window failed; health report could not be delivered"), (1, "window failed; health report could not be delivered\n")),
            (RunResult(True, False, False, COMPLETE), (0, COMPLETE + "\n")),
            (RunResult(False, False, False, RANGE_INVALID), (2, RANGE_INVALID + "\n")),
        )
        with patch("soc_thief.backfill.approval_valid", return_value=True):
            for result, expected in outcomes:
                with self.subTest(status=result.status, health=result.health_failure):
                    worker_code = backfill._outcome_code(result)
                    code, output = self.run_main(["--from", "2026-06-06"], run_worker=lambda *a, c=worker_code, **k: c,
                                                 send_health=self.forbidden)
                    self.assertEqual((code, output), expected)

    def test_spawned_worker_reports_fixed_status_without_configuration(self):
        # No webhook file is configured, so the real worker constructs nothing and makes no request.
        with patch.dict("os.environ", {}, clear=True):
            code = runner._run_worker(ORIGIN, NOW, stream=backfill.STREAM, timeout=60, target=backfill._worker)
            # Any other stream name is rejected by the backfill worker before configuration loads.
            rejected = runner._run_worker(ORIGIN, NOW, timeout=60, target=backfill._worker)
        self.assertEqual(code, backfill._outcome_code(
            RunResult(False, False, True, "window failed; health report could not be delivered")))
        self.assertEqual(rejected, 1)

    def test_worker_death_sends_parent_health_report(self):
        with patch("soc_thief.backfill.approval_valid", return_value=True):
            for worker_code, message in ((runner.DEADLINE_EXCEEDED, "Backfill deadline exceeded; health report delivered.\n"),
                                         (1, "Backfill failed; health report delivered.\n"),
                                         (-9, "Backfill failed; health report delivered.\n")):
                sent = []
                code, output = self.run_main(["--from", "2026-06-06"], run_worker=lambda *a, c=worker_code, **k: c,
                                             send_health=lambda *a: sent.append(a) or True)
                self.assertEqual((code, output), (1, message))
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0][:2], (ORIGIN, NOW))
            code, output = self.run_main(["--from", "2026-06-06"], run_worker=lambda *a, **k: 1,
                                         send_health=lambda *a: (_ for _ in ()).throw(Exception("secret")))
            self.assertEqual((code, output), (1, "Backfill failed; health report could not be delivered.\n"))


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.key_file = base / "identity"
        self.key_file.write_text(KEY + "\n"); self.key_file.chmod(0o600)
        self.state = base / "state"
        self.env = {"SOC_THIEF_IDENTITY_KEY_FILE": str(self.key_file), "STATE_PATH": str(self.state)}
        self.key = bytes.fromhex(KEY)
        self.backfill_token = opaque_key(self.key, "stream", "backfill")

    def commit(self, stream, start, count=1, pending=None):
        with StateStore(self.state) as store:
            for _ in range(count):
                end = window_starting(start)[1]
                store.commit_window(opaque_key(self.key, "stream", stream), start, end, [], [], recorded_at=end,
                                    pending_delivery=pending)
                start = end
        return start

    def execute(self, delivery, collector, origin=ORIGIN, **kwargs):
        factories = dict(delivery_factory=lambda env: delivery, collector_factory=lambda env: collector,
                         model_factory=lambda env: object())
        factories.update(kwargs)
        return _execute(origin, self.env, **factories)

    def checkpoint(self):
        with StateStore(self.state) as store:
            return store.checkpoint(self.backfill_token)

    def test_refuses_when_daily_stream_has_not_started(self):
        delivery, collector = Fake(), Fake()
        forbidden = lambda env: (_ for _ in ()).throw(AssertionError)
        result = self.execute(delivery, collector, collector_factory=forbidden, model_factory=forbidden)
        self.assertEqual(result, RunResult(False, True, True, FAILED))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))
        self.assertNotIn("synthetic", json.dumps(delivery.payloads[0].payloads))
        self.assertIsNone(self.checkpoint())

    def test_origin_after_daily_origin_is_invalid_without_collection(self):
        self.commit("daily", ORIGIN + 3 * DAY)
        delivery, collector = Fake(), Fake()
        forbidden = lambda env: (_ for _ in ()).throw(AssertionError)
        result = self.execute(delivery, collector, origin=ORIGIN + 4 * DAY, collector_factory=forbidden, model_factory=forbidden)
        self.assertEqual(result, RunResult(False, False, False, RANGE_INVALID))
        self.assertEqual((collector.calls, delivery.payloads), (0, []))

    def test_first_run_starts_at_origin_and_processes_one_window(self):
        self.commit("daily", ORIGIN + 3 * DAY)
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(True, False, False, "window completed; no delivery required"))
        self.assertEqual(collector.windows, [(ORIGIN, ORIGIN + DAY)])
        self.assertEqual(self.checkpoint(), ORIGIN + DAY)

    def test_resume_processes_exactly_the_next_window_then_completes(self):
        self.commit("daily", ORIGIN + 3 * DAY)
        self.commit("backfill", ORIGIN)
        for expected in (ORIGIN + DAY, ORIGIN + 2 * DAY):
            collector = Fake()
            result = self.execute(Fake(), collector)
            self.assertEqual(result.status, "window completed; no delivery required")
            self.assertEqual(collector.windows, [(expected, expected + DAY)])
            self.assertEqual(self.checkpoint(), expected + DAY)
        delivery, collector = Fake(), Fake()
        forbidden = lambda env: (_ for _ in ()).throw(AssertionError)
        result = self.execute(delivery, collector, collector_factory=forbidden, model_factory=forbidden)
        self.assertEqual(result, RunResult(True, False, False, COMPLETE))
        self.assertEqual((collector.calls, delivery.payloads), (0, []))

    def test_origin_equal_to_daily_origin_is_complete(self):
        self.commit("daily", ORIGIN)
        collector = Fake()
        self.assertEqual(self.execute(Fake(), collector), RunResult(True, False, False, COMPLETE))
        self.assertEqual(collector.calls, 0)

    def test_origin_mismatch_with_started_stream_fails_closed(self):
        self.commit("daily", ORIGIN + 5 * DAY)
        self.commit("backfill", ORIGIN, count=2)
        for origin in (ORIGIN + DAY, ORIGIN - DAY):
            delivery, collector = Fake(), Fake()
            result = self.execute(delivery, collector, origin=origin)
            self.assertEqual(result, RunResult(False, True, True, FAILED))
            self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))
        self.assertEqual(self.checkpoint(), ORIGIN + 2 * DAY)

    def test_pending_delivery_is_retried_before_advancing(self):
        self.commit("daily", ORIGIN + 3 * DAY)
        self.commit("backfill", ORIGIN, pending=PAYLOAD)
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))
        self.assertEqual(self.checkpoint(), ORIGIN + DAY)
        # A failed retry is a health failure and still does not advance.
        self.commit("backfill", ORIGIN + DAY, pending=PAYLOAD)
        failing, collector = Fake(error=True), Fake()
        result = self.execute(failing, collector)
        self.assertFalse(result.completed); self.assertTrue(result.health_failure)
        self.assertEqual(collector.calls, 0)
        self.assertEqual(self.checkpoint(), ORIGIN + 2 * DAY)

    def test_final_pending_delivery_is_retried_before_complete(self):
        self.commit("daily", ORIGIN + DAY)
        self.commit("backfill", ORIGIN, pending=PAYLOAD)
        delivery = Fake()
        self.assertEqual(self.execute(delivery, Fake()).status, "pending delivery acknowledged")
        self.assertEqual(self.execute(Fake(), Fake()).status, COMPLETE)

    def test_oldest_of_multiple_pending_reports_is_drained_before_collection(self):
        self.commit("daily", ORIGIN + 4 * DAY)
        self.commit("backfill", ORIGIN, pending=PAYLOAD)
        self.commit("backfill", ORIGIN + DAY, pending=SECOND_PAYLOAD)
        first_delivery, first_collector = Fake(), Fake()
        result = self.execute(first_delivery, first_collector)
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((first_collector.calls, len(first_delivery.payloads)), (0, 1))
        self.assertEqual(first_delivery.payloads[0].payloads[0]["content"], "synthetic")
        with StateStore(self.state) as store:
            self.assertEqual(store.oldest_pending_delivery(self.backfill_token).start, ORIGIN + DAY)
            self.assertEqual(store.checkpoint(self.backfill_token), ORIGIN + 2 * DAY)
        second_delivery, second_collector = Fake(), Fake()
        result = self.execute(second_delivery, second_collector)
        self.assertEqual(result, RunResult(True, True, False, "pending delivery acknowledged"))
        self.assertEqual((second_collector.calls, len(second_delivery.payloads)), (0, 1))
        self.assertEqual(second_delivery.payloads[0].payloads[0]["content"], "synthetic two")
        collector = Fake()
        self.assertEqual(self.execute(Fake(), collector).status, "window completed; no delivery required")
        self.assertEqual(collector.windows, [(ORIGIN + 2 * DAY, ORIGIN + 3 * DAY)])

    def test_failed_oldest_of_multiple_pending_reports_stays_pending_without_collection(self):
        self.commit("daily", ORIGIN + 4 * DAY)
        self.commit("backfill", ORIGIN, pending=PAYLOAD)
        self.commit("backfill", ORIGIN + DAY, pending=SECOND_PAYLOAD)
        delivery, collector = Fake(error=True), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(False, False, True, "window failed; health report could not be delivered"))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 2))
        with StateStore(self.state) as store:
            self.assertEqual(store.oldest_pending_delivery(self.backfill_token).payload, PAYLOAD)
            self.assertEqual(store.checkpoint(self.backfill_token), ORIGIN + 2 * DAY)

    def test_window_exceeding_daily_origin_is_never_produced(self):
        # A manually run daily window may start at a non-08:00 instant; backfill never crosses it.
        with StateStore(self.state) as store:
            start = ORIGIN + DAY + timedelta(hours=6)
            store.commit_window(opaque_key(self.key, "stream", "daily"), start, start + timedelta(hours=1), [], [],
                                recorded_at=start + timedelta(hours=1))
        self.commit("backfill", ORIGIN)
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector)
        self.assertEqual(result, RunResult(False, True, True, FAILED))
        self.assertEqual((collector.calls, len(delivery.payloads)), (0, 1))
        self.assertEqual(self.checkpoint(), ORIGIN + DAY)

    def test_dst_length_windows_are_collected(self):
        start = datetime(2026, 4, 2, 21, tzinfo=timezone.utc)  # 2026-04-03 08:00 AEDT
        self.commit("daily", datetime(2026, 4, 5, 22, tzinfo=timezone.utc))  # 2026-04-06 08:00 AEST
        lengths = []
        for _ in range(3):
            collector = Fake()
            self.assertEqual(self.execute(Fake(), collector, origin=start).status, "window completed; no delivery required")
            (window,) = collector.windows
            lengths.append(window[1] - window[0])
        self.assertEqual(lengths, [timedelta(hours=24), timedelta(hours=25), timedelta(hours=24)])
        self.assertEqual(self.execute(Fake(), Fake(), origin=start).status, COMPLETE)

    def test_tuning_is_loaded_and_passed_to_run_window(self):
        self.commit("daily", ORIGIN + 3 * DAY)
        path = Path(self.temp.name) / "tuning"
        cases = (('{"version":1,"entries":[{"rule_id":"100","action":"low","agent_id":"001"}]}', 0o600,
                  Tuning((TuningEntry("100", "low", "001", None),)), False),
                 ('{"version":1,"entries":[]}', 0o640, Tuning(), True),
                 (None, None, Tuning(), False))
        for value, mode, expected, failure in cases:
            with self.subTest(value=value, mode=mode):
                self.env.pop("SOC_THIEF_TUNING_FILE", None)
                if value is not None:
                    path.write_text(value); path.chmod(mode)
                    self.env["SOC_THIEF_TUNING_FILE"] = str(path)
                calls = []
                def run_window(**kwargs):
                    calls.append(kwargs)
                    return RunResult(True, False, False, "window completed; no delivery required")
                with patch("soc_thief.backfill.run_window", side_effect=run_window):
                    self.execute(Fake(), Fake())
                self.assertEqual(len(calls), 1)
                self.assertEqual((calls[0]["tuning"], calls[0]["tuning_failure"]), (expected, failure))

    def test_configuration_failures_fail_closed(self):
        self.commit("daily", ORIGIN + DAY)
        result = self.execute(Fake(), Fake(), delivery_factory=lambda env: (_ for _ in ()).throw(ValueError("secret")))
        self.assertEqual(result, RunResult(False, False, True, "window failed; health report could not be delivered"))
        delivery, collector = Fake(), Fake()
        result = self.execute(delivery, collector, model_factory=lambda env: (_ for _ in ()).throw(ValueError("secret")))
        self.assertEqual(result, RunResult(False, True, True, FAILED))
        self.assertEqual(collector.calls, 0)
        self.assertNotIn("secret", json.dumps(delivery.payloads[0].payloads))
        self.key_file.write_text("short")
        self.assertEqual(self.execute(Fake(), Fake()).status, FAILED)


if __name__ == "__main__":
    unittest.main()
