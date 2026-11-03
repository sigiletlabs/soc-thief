"""Synthetic agent liveness checks; no Wazuh, ntfy or other endpoint is contacted."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest

from soc_thief import fastpath, liveness
from soc_thief.collector import CollectorError
from soc_thief.fastpath import FastPathError
from soc_thief.runner import APPROVED_ROUTE


NOW = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)
KEY = "ab" * 32


class Collector:
    """Answers the liveness aggregation from a fixed last-seen map, honouring the window."""
    def __init__(self, seen=None, fail=False):
        self.seen, self.fail, self.queries, self.windows = dict(seen or {}), fail, [], []

    def agent_last_seen(self, agent_ids, start, end):
        self.queries.append((list(agent_ids), start, end))
        if self.fail:
            raise CollectorError("indexer search failed")
        return {agent: at for agent, at in self.seen.items() if agent in agent_ids and start <= at < end}

    def collect(self, start, end):
        self.windows.append((start, end))
        return iter(())


class Pager:
    def __init__(self, fail=False):
        self.pages, self.fail = [], fail

    def send(self, page):
        if self.fail:
            raise FastPathError("ntfy page failed")
        self.pages.append(page)


class Fixture:
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        key = self.root / "identity_key"
        key.write_text(KEY)
        key.chmod(0o600)
        self.env = {"STATE_PATH": str(self.root), "SOC_THIEF_IDENTITY_KEY_FILE": str(key),
                    "SOC_THIEF_AGENT_INVENTORY_FILE": str(self.root / "inventory")}
        self.inventory([("001", 60), ("002", 180, "domain controller secret-hostname")])

    def inventory(self, entries, raw=None):
        path = self.root / "inventory"
        agents = [{"agent_id": e[0], "max_silence_minutes": e[1], **({"note": e[2]} if len(e) > 2 else {})}
                  for e in entries]
        path.write_text(raw if raw is not None else json.dumps({"version": 1, "agents": agents}))
        path.chmod(0o600)

    def check(self, seen, *, now=NOW, pager=None, collector=None):
        pager = pager or Pager()
        collector = collector or Collector(seen)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = liveness.check(env=self.env, now=now, collector=collector, pager=pager)
        return code, output.getvalue().strip(), pager, collector


class LivenessTest(Fixture, unittest.TestCase):
    def test_every_agent_inside_its_gap_is_ok_and_reads_one_bounded_window(self):
        code, line, pager, collector = self.check({"001": NOW - timedelta(minutes=59),
                                                   "002": NOW - timedelta(minutes=179)})
        self.assertEqual((code, line, pager.pages), (fastpath.OK, "agent liveness: 2 expected, 0 silent", []))
        self.assertEqual(collector.queries, [(["001", "002"], NOW - timedelta(minutes=180), NOW)])

    def test_stopped_agent_pages_once_with_only_minimised_fields(self):
        code, line, pager, _ = self.check({"001": NOW - timedelta(minutes=61), "002": NOW - timedelta(minutes=1)})
        self.assertEqual((code, line), (fastpath.FAILED, "agent liveness: 2 expected, 1 silent"))
        self.assertEqual(len(pager.pages), 1)
        page = pager.pages[0]
        self.assertEqual((page.title, page.priority), ("Soc Thief breach: agent_silent", "urgent"))
        self.assertIn("Agent: 001\n", page.body)
        self.assertIn("Allowed silence: 1 hours", page.body)
        self.assertNotIn("secret", page.title + page.body)
        self.assertEqual(oct((self.root / liveness.STATE_NAME).stat().st_mode & 0o777), "0o600")
        # Still silent ten minutes later: no second page, but the run still fails.
        code, _, again, _ = self.check({"001": NOW - timedelta(minutes=61), "002": NOW - timedelta(minutes=1)},
                                       now=NOW + timedelta(minutes=10))
        self.assertEqual((code, again.pages), (fastpath.FAILED, []))

    def test_agent_never_seen_in_the_window_is_silent(self):
        _, line, pager, _ = self.check({"002": NOW - timedelta(minutes=1)})
        self.assertEqual(line, "agent liveness: 2 expected, 1 silent")
        self.assertIn("Last seen: not in the last 3 hours", pager.pages[0].body)

    def test_silent_agent_pages_again_after_the_repage_period_or_after_recovering(self):
        self.check({"002": NOW - timedelta(minutes=1)})
        later = NOW + fastpath.REPAGE_AFTER
        _, _, pager, _ = self.check({"002": later - timedelta(minutes=1)}, now=later)
        self.assertEqual(len(pager.pages), 1)
        # Back, then quiet again: pages at once rather than waiting out the repage period.
        back = later + timedelta(minutes=10)
        self.check({"001": back - timedelta(minutes=1), "002": back - timedelta(minutes=1)}, now=back)
        quiet = back + timedelta(minutes=70)
        _, _, pager, _ = self.check({"001": back - timedelta(minutes=1), "002": quiet - timedelta(minutes=1)}, now=quiet)
        self.assertEqual(len(pager.pages), 1)

    def test_failed_page_is_reported_and_retried(self):
        code, line, _, _ = self.check({"002": NOW - timedelta(minutes=1)}, pager=Pager(fail=True))
        self.assertEqual((code, line), (fastpath.FAILED, "agent liveness: 2 expected, 1 silent; page failed"))
        _, _, pager, _ = self.check({"002": NOW - timedelta(minutes=1)}, now=NOW + timedelta(minutes=10))
        self.assertEqual(len(pager.pages), 1)

    def test_many_silent_agents_send_one_summary(self):
        self.inventory([(f"{n:03}", 60) for n in range(fastpath.MAX_PAGES + 4)])
        _, line, pager, _ = self.check({})
        self.assertEqual(len(pager.pages), fastpath.MAX_PAGES + 1)
        self.assertIn("4 more expected agents", pager.pages[-1].body)
        _, _, again, _ = self.check({}, now=NOW + timedelta(minutes=10))
        self.assertEqual(again.pages, [])

    def test_missing_or_invalid_inventory_fails_closed_without_a_query(self):
        bad = [
            "{not json", json.dumps({"version": 1, "agents": []}),
            json.dumps({"version": 2, "agents": [{"agent_id": "001", "max_silence_minutes": 60}]}),
            json.dumps({"version": 1, "agents": [{"agent_id": "host-a", "max_silence_minutes": 60}]}),
            json.dumps({"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 10}]}),
            json.dumps({"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 60 * 24 * 8}]}),
            json.dumps({"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": "60"}]}),
            json.dumps({"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 60, "x": 1}]}),
            json.dumps({"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 60}] * 2}),
            '{"version": 1, "version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 60}]}',
        ]
        for raw in bad:
            with self.subTest(raw=raw):
                self.inventory([], raw=raw)
                code, line, pager, collector = self.check({})
                self.assertEqual((code, line), (fastpath.FAILED,
                                                "agent liveness unavailable: inventory is missing or invalid"))
                self.assertEqual((pager.pages, collector.queries), ([], []))
        del self.env["SOC_THIEF_AGENT_INVENTORY_FILE"]
        code, line, _, _ = self.check({})
        self.assertEqual(line, "agent liveness unavailable: inventory is missing or invalid")
        (self.root / "inventory").chmod(0o644)
        self.env["SOC_THIEF_AGENT_INVENTORY_FILE"] = str(self.root / "inventory")
        self.assertEqual(self.check({})[1], "agent liveness unavailable: inventory is missing or invalid")

    def test_indexer_failure_or_unreadable_state_fails_closed(self):
        code, line, _, _ = self.check({}, collector=Collector(fail=True))
        self.assertEqual((code, line), (fastpath.FAILED, "agent liveness unavailable: indexer check failed"))
        (self.root / liveness.STATE_NAME).write_text("{not json")
        code, line, _, _ = self.check({"001": NOW - timedelta(minutes=1), "002": NOW - timedelta(minutes=1)})
        self.assertEqual((code, line), (fastpath.FAILED, "agent liveness unavailable: state is unreadable"))

    def test_unexpected_error_still_prints_a_fixed_line(self):
        self.env["SOC_THIEF_IDENTITY_KEY_FILE"] = str(self.root / "missing")
        code, line, _, _ = self.check({"001": NOW - timedelta(minutes=1), "002": NOW - timedelta(minutes=1)})
        self.assertEqual((code, line), (fastpath.FAILED, "agent liveness unavailable: check failed"))


class FastPathHookTest(Fixture, unittest.TestCase):
    """The fast path runs the liveness check every run, after the breach check, and fails with it."""
    def run_main(self, seen, breach_fails=False):
        collector = Collector(seen)
        if breach_fails:
            collector.collect = lambda start, end: (_ for _ in ()).throw(CollectorError("indexer search failed"))
        pager = Pager()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = fastpath.main([], env=self.env, now=lambda: NOW, collector_factory=lambda env: collector,
                                 pager_factory=lambda env: pager)
        return code, output.getvalue().splitlines(), pager

    def setUp(self):
        super().setUp()
        approval = self.root / "approval"
        approval.write_text(json.dumps({"approved_route": APPROVED_ROUTE, "expires": "never"}))
        approval.chmod(0o600)
        self.env["SOC_THIEF_RUNNER_APPROVAL_FILE"] = str(approval)

    def test_silent_agent_fails_the_fast_path_run_and_pages(self):
        code, lines, pager = self.run_main({"002": NOW - timedelta(minutes=1)})
        self.assertEqual(code, fastpath.FAILED)
        self.assertEqual(lines, ["fast path checked; 0 pairs paged", "agent liveness: 2 expected, 1 silent"])
        self.assertEqual([p.title for p in pager.pages], ["Soc Thief breach: agent_silent"])

    def test_liveness_runs_even_when_the_breach_check_fails(self):
        code, lines, _ = self.run_main({"001": NOW - timedelta(minutes=1), "002": NOW - timedelta(minutes=1)}, breach_fails=True)
        self.assertEqual(code, fastpath.FAILED)
        self.assertEqual(lines, ["Fast path check failed; checkpoint not advanced.",
                                 "agent liveness: 2 expected, 0 silent"])

    def test_healthy_run_exits_ok(self):
        code, lines, _ = self.run_main({"001": NOW - timedelta(minutes=1), "002": NOW - timedelta(minutes=1)})
        self.assertEqual((code, lines[-1]), (fastpath.OK, "agent liveness: 2 expected, 0 silent"))


if __name__ == "__main__":
    unittest.main()
