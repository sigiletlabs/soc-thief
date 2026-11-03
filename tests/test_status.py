"""Synthetic host status evidence; no service, source, model or delivery is contacted."""

import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from soc_thief import status


NOW = datetime(2026, 10, 8, 1, tzinfo=timezone.utc)


def row(message, instant=NOW):
    return json.dumps({"MESSAGE": message, "__REALTIME_TIMESTAMP": str(int(instant.timestamp() * 1_000_000))})


class StatusTests(unittest.TestCase):
    def inspect(self, messages, service="LoadState=loaded\nActiveState=inactive\nResult=success",
                timer="LoadState=loaded\nActiveState=active", approval=None,
                fastpath_timer="LoadState=not-found\nActiveState=inactive\nUnitFileState=",
                fastpath_messages=(), expect_fastpath=False):
        calls = []
        def command(args):
            calls.append(args)
            if args[0] == "journalctl":
                return "\n".join(fastpath_messages if "--unit=" + status.FASTPATH in args else messages)
            return {status.RUNNER: service, status.TIMER: timer, status.FASTPATH_TIMER: fastpath_timer}[args[2]]
        result = status.inspect(now=NOW, command=command, approval=approval, expect_fastpath=expect_fastpath)
        runner = [args for args in calls if args[0] == "journalctl" and "--unit=" + status.RUNNER in args]
        self.assertEqual(len(runner), 1)
        self.assertIn("--lines=2000", runner[0])
        self.assertIn("--unit=" + status.CATCHUP, runner[0])
        self.assertEqual(len(calls), 5 if result["fastpath"]["expected"] else 4)
        return result

    def test_successful_oneshot_is_healthy_and_uses_sydney_timestamps(self):
        result = self.inspect([row("window completed and delivery acknowledged")])
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["last_acknowledged"], "2026-10-08T12:00:00+11:00")

    def test_expired_approval_after_acknowledgement_is_visible(self):
        result = self.inspect([row("window completed and delivery acknowledged", NOW - timedelta(days=2)),
                               row("Runner approval missing, invalid, or expired; no request made.")],
                              service="LoadState=loaded\nActiveState=failed\nResult=exit-code")
        self.assertEqual(result["status"], "attention_required")
        self.assertEqual(result["last_outcome"]["status"], "approval_refused")
        self.assertEqual(result["counts"]["approval_refused"], 1)
        self.assertIn("runner_unsuccessful", result["reasons"])

    def test_acknowledgement_with_health_review_is_not_healthy(self):
        result = self.inspect([row("window completed and delivery acknowledged; health review required")])
        self.assertEqual(result["status"], "attention_required")
        self.assertTrue(result["last_outcome"]["health_review"])
        self.assertEqual(result["counts"]["health_review"], 1)

    def test_health_notifications_are_classified_as_failures(self):
        for message, expected in [("window failed; health report delivered", "health_delivered"),
                                  ("Runner deadline exceeded; health report could not be delivered.", "health_undelivered")]:
            with self.subTest(message=message):
                result = self.inspect([row(message)])
                self.assertEqual(result["status"], "attention_required")
                self.assertEqual(result["last_outcome"]["status"], expected)

    def test_caught_up_missed_days_are_recognised_outcomes(self):
        result = self.inspect([row("window completed and delivery acknowledged", NOW - timedelta(hours=2)),
                               row("missed day: window failed; health report delivered")],
                              service="LoadState=loaded\nActiveState=failed\nResult=exit-code")
        self.assertEqual(result["last_outcome"]["status"], "health_delivered")
        result = self.inspect([row("missed day: window completed; no delivery required; health review required")])
        self.assertEqual((result["last_outcome"]["status"], result["counts"]["health_review"]),
                         ("no_delivery_required", 1))

    def test_stale_success_missing_evidence_and_disabled_timer_are_not_green(self):
        stale = self.inspect([row("window completed and delivery acknowledged", NOW - timedelta(hours=27))])
        self.assertIn("runner_outcome_stale", stale["reasons"])
        self.assertIn("no_runner_outcome_visible", self.inspect([])["reasons"])
        disabled = self.inspect([row("window completed; no delivery required")],
                                timer="LoadState=loaded\nActiveState=inactive")
        self.assertIn("timer_inactive", disabled["reasons"])
        # A 25-hour DST day plus timer jitter must not raise a false stale warning.
        recent = self.inspect([row("window completed; no delivery required", NOW - timedelta(hours=25, minutes=30))])
        self.assertEqual(recent["status"], "healthy")

    def test_untrusted_fields_never_reach_output(self):
        marker = "untrusted-marker"
        result = self.inspect([row(marker), row("window completed and delivery acknowledged " + marker),
                               row("window completed and delivery acknowledged")],
                              service="LoadState=loaded\nActiveState=inactive\nResult=" + marker + "\nExtra=" + marker)
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(result["service"]["Result"], "unknown")
        self.assertEqual(result["counts"]["acknowledged"], 1)

    def test_malformed_evidence_and_command_failures_have_fixed_diagnostics(self):
        for error in (status.StatusError("untrusted-marker"), ValueError("untrusted-marker")):
            output = io.StringIO()
            with patch.object(status, "inspect", side_effect=error), contextlib.redirect_stdout(output):
                code = status.main()
            self.assertEqual(code, 2)
            self.assertNotIn("untrusted-marker", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "unavailable")
        with self.assertRaises(status.StatusError):
            self.inspect(["not-json"])
        with self.assertRaises(status.StatusError):
            self.inspect([json.dumps({"MESSAGE": "window completed and delivery acknowledged", "__REALTIME_TIMESTAMP": "invalid"})])

    def test_command_timeout_and_stderr_are_not_exposed(self):
        with patch.object(status.subprocess, "run", side_effect=subprocess.TimeoutExpired("untrusted-marker", 15)):
            with self.assertRaises(status.StatusError) as error:
                status._command(["systemctl"])
        self.assertNotIn("untrusted-marker", str(error.exception))
        completed = subprocess.CompletedProcess(["systemctl"], 1, "untrusted-marker", "untrusted-marker")
        with patch.object(status.subprocess, "run", return_value=completed):
            with self.assertRaises(status.StatusError):
                status._command(["systemctl"])

    def test_commands_use_the_budgeted_timeout(self):
        completed = subprocess.CompletedProcess(["systemctl"], 0, "", "")
        with patch.object(status.subprocess, "run", return_value=completed) as run:
            status._command(["systemctl"])
        self.assertEqual(run.call_args.kwargs["timeout"], status.COMMAND_TIMEOUT_SECONDS)

    def test_future_and_out_of_range_entries_are_ignored(self):
        result = self.inspect([row("window completed and delivery acknowledged", NOW + timedelta(hours=1)),
                               row("window completed and delivery acknowledged", NOW - timedelta(days=15))])
        self.assertEqual(result["status"], "attention_required")
        self.assertIsNone(result["last_acknowledged"])


class ApprovalStatusTests(unittest.TestCase):
    inspect = StatusTests.inspect
    ok = [row("window completed and delivery acknowledged")]

    def test_unchecked_approval_does_not_change_status(self):
        result = self.inspect(self.ok)
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["approval"], {"checked": False, "expires": None})

    def test_approval_far_from_expiry_is_healthy(self):
        result = self.inspect(self.ok, approval=lambda now: now + timedelta(days=20))
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["approval"], {"checked": True, "expires": "2026-10-28T12:00:00+11:00"})

    def test_approval_near_expiry_warns_before_runs_stop(self):
        for remaining in (timedelta(days=3), timedelta(hours=1)):
            with self.subTest(remaining=remaining):
                result = self.inspect(self.ok, approval=lambda now: now + remaining)
                self.assertEqual(result["reasons"], ["approval_expires_soon"])
        result = self.inspect(self.ok, approval=lambda now: now + timedelta(days=3, seconds=1))
        self.assertEqual(result["status"], "healthy")

    def test_permanent_approval_is_healthy_and_reported_as_never(self):
        from soc_thief.runner import APPROVAL_PERMANENT
        result = self.inspect(self.ok, approval=lambda now: APPROVAL_PERMANENT)
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["approval"], {"checked": True, "expires": "never"})

    def test_missing_or_invalid_approval_requires_attention(self):
        result = self.inspect(self.ok, approval=lambda now: None)
        self.assertEqual(result["reasons"], ["approval_invalid_or_expired"])
        self.assertIsNone(result["approval"]["expires"])

    def test_main_checks_the_approval_file_only_when_one_is_configured(self):
        seen = []
        def inspect(*, now, approval, expect_fastpath):
            seen.append(approval)
            return {"status": "healthy"}
        with patch.object(status, "inspect", inspect), contextlib.redirect_stdout(io.StringIO()):
            with patch.dict(status.os.environ, {}, clear=True):
                self.assertEqual(status.main(), 0)
            with patch.dict(status.os.environ, {"SOC_THIEF_RUNNER_APPROVAL_FILE": "/nonexistent"}, clear=True):
                self.assertEqual(status.main(), 0)
        self.assertIsNone(seen[0])
        self.assertIsNone(seen[1](NOW))  # A missing file reads as no valid approval, never green.


class FastPathStatusTests(unittest.TestCase):
    """A quiet phone means safe only if the fast path proved it looked."""
    inspect = StatusTests.inspect
    ok = [row("window completed and delivery acknowledged")]
    enabled = "LoadState=loaded\nActiveState=active\nUnitFileState=enabled"

    def run_check(self, fastpath_messages, timer=None, **kwargs):
        return self.inspect(self.ok, fastpath_timer=timer or self.enabled,
                            fastpath_messages=fastpath_messages, **kwargs)

    def healthy_runs(self, end=NOW, count=12, silent=0):
        rows = []
        for n in range(count):
            at = end - timedelta(minutes=10 * n)
            rows += [row("fast path checked; 0 pairs paged", at),
                     row(f"agent liveness: 4 expected, {silent} silent", at)]
        return rows

    def test_healthy_fast_path_and_agents_are_green(self):
        result = self.run_check(self.healthy_runs())
        self.assertEqual(result["status"], "healthy", result["reasons"])
        self.assertEqual((result["fastpath"]["agents_expected"], result["fastpath"]["agents_silent"]), (4, 0))
        self.assertEqual(result["fastpath"]["last_checked"], "2026-10-08T12:00:00+11:00")

    def test_not_installed_fast_path_is_not_required(self):
        result = self.inspect(self.ok)
        self.assertEqual(result["status"], "healthy")
        self.assertFalse(result["fastpath"]["expected"])

    def test_stopped_fast_path_timer_fails_the_check(self):
        stopped = "LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled"
        result = self.run_check(self.healthy_runs(), timer=stopped)
        self.assertIn("fastpath_timer_inactive", result["reasons"])
        # Disabled as well as stopped still fails once the monitor declares the fast path live.
        disabled = "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled"
        result = self.run_check(self.healthy_runs(), timer=disabled, expect_fastpath=True)
        self.assertIn("fastpath_timer_inactive", result["reasons"])

    def test_stopped_fast_path_runs_go_stale_within_one_status_interval(self):
        # The timer looks fine but the last check is older than the freshness bound.
        late = NOW - status.FASTPATH_FRESHNESS - timedelta(minutes=1)
        result = self.run_check(self.healthy_runs(end=late, count=3))
        self.assertIn("fastpath_coverage_unproven", result["reasons"])
        self.assertIn("agent_liveness_unproven", result["reasons"])
        self.assertEqual(self.run_check([])["status"], "attention_required")

    def test_a_coverage_gap_since_the_last_status_check_fails(self):
        runs = self.healthy_runs()
        runs.append(row("fast path coverage gap; last day checked; 0 pairs paged", NOW - timedelta(minutes=65)))
        result = self.run_check(runs)
        self.assertEqual(result["reasons"], ["fastpath_coverage_gap"])

    def test_a_failed_latest_fast_path_run_fails(self):
        for message in ("fast path page failed; 1 pairs due; checkpoint not advanced",
                        "Fast path check failed; checkpoint not advanced.",
                        "Runner approval missing, invalid, or expired; no request made."):
            with self.subTest(message=message):
                result = self.run_check(self.healthy_runs()[2:] + [row(message)])
                self.assertIn("fastpath_coverage_unproven", result["reasons"])

    def test_a_silent_agent_fails_the_check(self):
        result = self.run_check(self.healthy_runs(silent=1))
        self.assertEqual(result["reasons"], ["agents_silent"])
        self.assertEqual(result["fastpath"]["agents_silent"], 1)

    def test_unavailable_liveness_or_failed_liveness_page_fails(self):
        for message in ("agent liveness unavailable: inventory is missing or invalid",
                        "agent liveness: 4 expected, 1 silent; page failed"):
            with self.subTest(message=message):
                result = self.run_check(self.healthy_runs()[2:] + [row(message)])
                self.assertIn("agent_liveness_unproven", result["reasons"])

    def test_journal_overflow_cannot_hide_a_gap(self):
        runs = [row("fast path checked; 0 pairs paged", NOW)] * status.FASTPATH_JOURNAL_LIMIT
        self.assertIn("fastpath_journal_limit_reached", self.run_check(runs)["reasons"])

    def test_untrusted_fast_path_lines_never_reach_output(self):
        marker = "untrusted-marker"
        result = self.run_check(self.healthy_runs() + [row("agent liveness: 4 expected, 0 silent " + marker),
                                                      row(marker)])
        self.assertEqual(result["status"], "healthy")
        self.assertNotIn(marker, json.dumps(result))

    def test_main_passes_the_fast_path_expectation_from_the_unit(self):
        seen = []
        def inspect(*, now, approval, expect_fastpath):
            seen.append(expect_fastpath)
            return {"status": "healthy"}
        with patch.object(status, "inspect", inspect), contextlib.redirect_stdout(io.StringIO()):
            for value in ({}, {"SOC_THIEF_EXPECT_FASTPATH": "1"}):
                with patch.dict(status.os.environ, value, clear=True):
                    status.main()
        self.assertEqual(seen, [False, True])
