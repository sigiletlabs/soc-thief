"""Tuned-spike paging and the stale-tuning report. Synthetic only: no network, no ntfy."""
from contextlib import closing, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
import io
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from soc_thief import tuning_watch
from soc_thief.fastpath import Page
from soc_thief.runner import run_window
from soc_thief.state import StateStore
from soc_thief.tuning import Tuning, TuningEntry
from soc_thief.tuning_watch import (Finding, Pager, REPAGE_AFTER, watch, MAX_PAGES, NEW, NEW_MIN_EVENTS, PAGE_MIN_EVENTS, PAGE_RATIO, SPIKE,
                                    find, notify, stale_entries)
from tests.test_runner import Collector, Delivery, Model, END, START, record

AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def history(events, days):
    return {("100", "001"): (events, days)}


class FindTests(unittest.TestCase):
    def test_spike_boundaries(self):
        # Baseline 300 events over 30 active days is 10 a day, so the ratio floor is 100 events.
        for count, expected in ((PAGE_MIN_EVENTS - 1, False), (99, False), (100, True), (101, True)):
            with self.subTest(count=count):
                found = find({("100", "001"): ("mute", count)}, history(300, 30))
                self.assertEqual([f.kind for f in found], [SPIKE] if expected else [])

    def test_minimum_events_applies_when_the_baseline_is_tiny(self):
        # The ratio alone (10x of 1 a day) is met at 10 events, but a page needs PAGE_MIN_EVENTS.
        self.assertEqual(find({("100", "001"): ("low", PAGE_MIN_EVENTS - 1)}, history(30, 30)), ())
        self.assertEqual(len(find({("100", "001"): ("low", PAGE_MIN_EVENTS)}, history(30, 30))), 1)
        self.assertEqual(PAGE_RATIO, 10)

    def test_ordinary_volume_does_not_page(self):
        self.assertEqual(find({("100", "001"): ("mute", 300)}, history(9000, 30)), ())

    def test_new_pair_boundary_and_zero_baseline(self):
        for hist in ({}, history(0, 0), {("100", "002"): (900, 30)}):
            with self.subTest(hist=hist):
                self.assertEqual(find({("100", "001"): ("mute", NEW_MIN_EVENTS - 1)}, hist), ())
                (found,) = find({("100", "001"): ("mute", NEW_MIN_EVENTS)}, hist)
                self.assertEqual((found.kind, found.daily_mean), (NEW, 0))


class NotifyTests(unittest.TestCase):
    @staticmethod
    def case(rule, agent):
        return "cccccccc"

    @staticmethod
    def finding(n=1, action="mute", kind=SPIKE):
        return Finding("SECRET-RULE", "001", action, kind, n, 7)

    def test_page_carries_only_the_minimised_fields(self):
        sent = []
        self.assertEqual(notify((self.finding(900),), sent.append, self.case), frozenset())
        (page,) = sent
        self.assertIsInstance(page, Page)
        self.assertEqual(page.title, "Soc Thief: muted rule spiking")
        self.assertEqual(page.body, "Tuning: mute\nAgent: 001\nEvents: 900 (baseline about 7 a day)\nCase: cccccccc")
        self.assertNotIn("SECRET-RULE", page.title + page.body)

    def test_low_and_new_agent_titles(self):
        sent = []
        notify((self.finding(action="low"), self.finding(kind=NEW)), sent.append, self.case)
        self.assertEqual([p.title for p in sent], ["Soc Thief: low-priority rule spiking",
                                                    "Soc Thief: muted rule on a new agent"])

    def test_no_route_or_failing_route_leaves_every_pair_unpaged(self):
        found = (Finding("1", "001", "mute", SPIKE, 99, 1), Finding("2", "001", "low", SPIKE, 98, 1))
        both = frozenset({("1", "001"), ("2", "001")})
        self.assertEqual(notify(found, None, self.case), both)

        def boom(page):
            raise RuntimeError("down")
        self.assertEqual(notify(found, boom, self.case), both)

    def test_one_failed_page_does_not_hide_the_others(self):
        found = (Finding("1", "001", "mute", SPIKE, 99, 1), Finding("2", "002", "mute", SPIKE, 98, 1))
        calls = []

        def flaky(page):
            calls.append(page)
            if len(calls) == 1:
                raise RuntimeError
        self.assertEqual(notify(found, flaky, self.case), frozenset({("1", "001")}))

    def test_more_than_the_cap_becomes_one_summary_and_a_failed_summary_is_unpaged(self):
        found = tuple(Finding(str(i), "001", "mute", SPIKE, 1000 - i, 1) for i in range(MAX_PAGES + 3))
        sent = []
        self.assertEqual(notify(found, sent.append, self.case), frozenset())
        self.assertEqual(len(sent), MAX_PAGES + 1)
        self.assertIn("3 more", sent[-1].body)

        def last_fails(page):
            if "more" in page.body:
                raise RuntimeError
        self.assertEqual(notify(found, last_fails, self.case),
                         frozenset((str(i), "001") for i in range(MAX_PAGES, MAX_PAGES + 3)))


class StaleTests(unittest.TestCase):
    def test_rule_only_and_agent_entries(self):
        tuning = Tuning((TuningEntry("1", "mute"), TuningEntry("2", "mute"), TuningEntry("3", "low", "001"),
                         TuningEntry("4", "low", "001"), TuningEntry("5", "low", "009")))
        groups = [{"rule_id": "1", "agent_id": "007"}, {"rule_id": "3", "agent_id": "001"},
                  {"rule_id": "5", "agent_id": "001"}]
        self.assertEqual([(e.rule_id, e.agent_id) for e in stale_entries(tuning, groups)],
                         [("2", None), ("4", "001"), ("5", "009")])

    def test_report_has_ids_and_actions_only(self):
        entry = TuningEntry("2", "mute", "001")
        text = tuning_watch.render_stale(AT - timedelta(days=90), AT, (entry,), 70)
        self.assertIn('{"rule_id": "2", "agent_id": "001", "action": "mute"}', text)
        self.assertIn("1 of 70", text)

    def test_cli_runs_the_worker_over_90_days_and_prints_counts_only(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                tuning_watch, "_run_worker", return_value=(0, (3, 70))) as run, redirect_stdout(io.StringIO()) as out:
            Path(directory).chmod(0o700)
            code = tuning_watch.main(["--output", str(Path(directory) / "stale.txt")], now=lambda: AT)
        self.assertEqual(code, 0)
        self.assertIn("3 of 70", out.getvalue())
        args, kwargs = run.call_args
        self.assertEqual(args[1] - args[0], timedelta(days=90))
        self.assertIs(kwargs["target"], tuning_watch._worker)

    def test_cli_failure_text_is_fixed_and_bad_output_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()) as out, patch.object(
                tuning_watch, "_run_worker", return_value=(1, None)):
            Path(directory).chmod(0o700)
            self.assertEqual(tuning_watch.main(["--output", str(Path(directory) / "s.txt")], now=lambda: AT), 1)
        self.assertIn("failed", out.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(tuning_watch.main(["--output", "/nonexistent-dir/x"], now=lambda: AT), 2)


def baseline():
    return {"total": 300, "groups": [{"rule_id": "100", "agent_id": "001", "events": 300, "days_active": 30}]}


class RunnerWatchTests(unittest.TestCase):
    """Through run_window: a spike on a muted rule pages and is delivered; tuning cannot stop it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "state"
        self.store = StateStore(self.directory)
        self.addCleanup(lambda: self.store.close())

    def run_with(self, count, pager, *, action="mute", base=baseline, agent=None):
        delivery = Delivery()
        entry = TuningEntry("100", action, agent, None)
        result = run_window(collector=Collector([record(str(i)) for i in range(count)]), model=Model(),
                            delivery=delivery, store=self.store, identity_key=b"k" * 32, stream="daily",
                            start=START, end=END, now=lambda: END, tuning=Tuning((entry,)),
                            baseline=base, pager=None if pager is None else Pager(
                                pager, Path(self.temp.name) / f"w-{action}-{count}.json"))
        return result, delivery

    def audit(self):
        with closing(sqlite3.connect(self.directory / "state.sqlite3")) as db:
            return [row[0] for row in db.execute("SELECT reason FROM audit ORDER BY ordinal")]

    def test_quiet_muted_rule_neither_pages_nor_delivers(self):
        pages = []
        _, delivery = self.run_with(99, pages.append)
        self.assertEqual((pages, delivery.payloads, self.audit()), ([], [], ["tuned_mute"]))

    def test_spike_on_a_muted_or_low_rule_pages_and_is_delivered_despite_tuning(self):
        for action in ("mute", "low"):
            with self.subTest(action=action):
                self.directory = Path(self.temp.name) / action
                self.store = StateStore(self.directory)
                pages = []
                result, delivery = self.run_with(100, pages.append, action=action)
                self.assertEqual(len(pages), 1)
                self.assertIn(f"Tuning: {action}", pages[0].body)
                self.assertEqual((result.delivered, result.health_failure, len(delivery.payloads)), (True, False, 1))
                self.assertEqual(self.audit(), ["tuned_spike"])

    def test_agent_specific_entry_spikes_too(self):
        pages = []
        result, _ = self.run_with(100, pages.append, agent="001")
        self.assertEqual((len(pages), result.delivered), (1, True))

    def test_failed_page_delivers_with_a_health_failure(self):
        def down(page):
            raise RuntimeError("ntfy down")
        result, _ = self.run_with(100, down)
        self.assertEqual((result.delivered, result.health_failure), (True, True))
        self.assertEqual(self.audit(), ["tuned_spike_unpaged"])

    def test_no_baseline_means_no_watch(self):
        pages = []

        def broken():
            raise RuntimeError
        result, _ = self.run_with(500, pages.append, base=broken)
        self.assertEqual(pages, [])
        self.assertTrue(result.health_failure)  # The existing baseline-failure health failure.

    def test_watch_is_off_without_a_pager(self):
        _, delivery = self.run_with(500, None)
        self.assertEqual((delivery.payloads, self.audit()), ([], ["tuned_mute"]))

    def test_a_continuing_spike_pages_once_but_is_delivered_every_day(self):
        group = {"rule_id": "100", "agent_id": "001", "rule_level": 3, "rule_description": "routine synthetic",
                 "timestamp": AT.isoformat(), "count": 500}
        tuning = Tuning((TuningEntry("100", "mute"),))
        pages = []
        pager = Pager(pages.append, Path(self.temp.name) / "w.json")
        call = lambda at: watch([group], tuning, at, {("100", "001"): (300, 30)}, pager, b"k" * 32, lambda r, a: "c")
        self.assertEqual(call(AT), (frozenset({("100", "001")}), frozenset()))
        self.assertEqual(len(pages), 1)
        self.assertEqual(call(AT + timedelta(days=1))[0], frozenset({("100", "001")}))  # Still delivered.
        self.assertEqual(len(pages), 1)  # Not paged again.
        call(AT + REPAGE_AFTER)
        self.assertEqual(len(pages), 2)

    def test_a_failed_page_is_not_recorded_so_the_next_run_pages_again(self):
        group = {"rule_id": "100", "agent_id": "001", "rule_level": 3, "rule_description": "routine synthetic",
                 "timestamp": AT.isoformat(), "count": 500}
        tuning, state, pages = Tuning((TuningEntry("100", "mute"),)), Path(self.temp.name) / "w.json", []

        def down(page):
            raise RuntimeError
        args = ([group], tuning, AT, {("100", "001"): (300, 30)})
        self.assertEqual(watch(*args, Pager(down, state), b"k" * 32, lambda r, a: "c")[1], frozenset({("100", "001")}))
        self.assertEqual(watch(*args, Pager(pages.append, state), b"k" * 32, lambda r, a: "c")[1], frozenset())
        self.assertEqual(len(pages), 1)

    def test_protected_group_is_not_counted_as_tuned(self):
        group = {"rule_id": "100", "agent_id": "001", "rule_level": 12, "rule_description": "routine synthetic",
                 "timestamp": AT.isoformat(), "count": 500}
        pages = []
        out = watch([group], Tuning((TuningEntry("100", "mute"),)), AT, {("100", "001"): (300, 30)},
                    Pager(pages.append, Path(self.temp.name) / "w.json"), b"k" * 32, lambda r, a: "c")
        self.assertEqual((out, pages), ((frozenset(), frozenset()), []))

    def test_new_agent_pages(self):
        pages = []
        other = lambda: {"total": 1, "groups": [{"rule_id": "100", "agent_id": "009", "events": 1, "days_active": 1}]}
        result, _ = self.run_with(NEW_MIN_EVENTS, pages.append, base=other)
        self.assertEqual((len(pages), result.delivered), (1, True))


if __name__ == "__main__":
    unittest.main()
