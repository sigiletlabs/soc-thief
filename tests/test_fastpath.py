"""Synthetic fast-path checks; no Wazuh, ntfy or other endpoint is contacted."""
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError

from soc_thief import fastpath
from soc_thief.fastpath import FastPathError, NtfyConfig, NtfyPager, Page, main, run, window


NOW = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)
KEY = "ab" * 32


def record(identifier, *, at, rule="100", agent="001", level=3, description="routine", **extra):
    fields = {
        "@timestamp": at.isoformat(), "rule.id": rule, "rule.level": level,
        "rule.description": description, "agent.id": agent, "agent.name": "secret-hostname",
        "decoder.name": "test", "manager.name": "test", "location": "/var/log/secret-path",
        "rule.groups": None, "data.srcip": None, "syscheck.path": None, "syscheck.event": None,
        "syscheck.changed_attributes": None,
    }
    fields.update({name.replace("__", "."): value for name, value in extra.items()})
    return {"source_key": {"index": "wazuh-alerts-synthetic", "id": identifier}, "fields": fields}


class Collector:
    def __init__(self, records=()):
        self.records, self.windows = list(records), []

    def collect(self, start, end):
        self.windows.append((start, end))
        return iter([r for r in self.records
                     if start <= datetime.fromisoformat(r["fields"]["@timestamp"]) < end])


class Pager:
    """Breach pages in ``pages``; #62 investigation follow-ups (tests/test_autoinvestigate.py) apart."""
    def __init__(self, fail=False):
        self.pages, self.follow_ups, self.fail = [], [], fail

    def send(self, page):
        if self.fail:
            raise FastPathError("ntfy page failed")
        (self.follow_ups if page.title.startswith("Soc Thief investigation") else self.pages).append(page)


class FastPathTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [p.unlink() for p in self.root.iterdir()] and None or self.root.rmdir())
        key = self.root / "identity_key"
        key.write_text(KEY)
        key.chmod(0o600)
        self.env = {"STATE_PATH": str(self.root), "SOC_THIEF_IDENTITY_KEY_FILE": str(key)}

    def check(self, records, *, now=NOW, pager=None):
        pager = pager or Pager()
        collector = Collector(records)
        code, status = run(env=self.env, now=now, collector=collector, pager=pager)
        return code, status, pager, collector

    def state(self):
        return json.loads((self.root / fastpath.STATE_NAME).read_text())

    def test_breach_pages_once_with_only_minimised_fields(self):
        malware = record("m", at=NOW - timedelta(minutes=10), rule="513", agent="042",
                         description="Windows malware detected secret-description")
        code, _, pager, _ = self.check([malware, record("r", at=NOW - timedelta(minutes=9))])
        self.assertEqual(code, fastpath.OK)
        self.assertEqual(len(pager.pages), 1)
        page = pager.pages[0]
        self.assertEqual(page.title, "Soc Thief breach: malware")
        self.assertEqual(page.priority, "urgent")
        self.assertIn("Agent: 042", page.body)
        self.assertIn("Events: 1", page.body)
        for leaked in ("secret", "513", "Windows"):
            self.assertNotIn(leaked, page.body + page.title)
        self.assertEqual(oct((self.root / fastpath.STATE_NAME).stat().st_mode & 0o777), "0o600")

    def test_ongoing_incident_does_not_page_again_and_checkpoint_advances(self):
        first = record("m1", at=NOW - timedelta(minutes=10), rule="513")
        self.check([first])
        later = NOW + timedelta(minutes=10)
        code, _, pager, collector = self.check(
            [first, record("m2", at=later - timedelta(minutes=5), rule="513")], now=later)
        self.assertEqual((code, pager.pages), (fastpath.OK, []))
        # The second run re-reads LOOKBACK before the first run's end.
        self.assertEqual(collector.windows[0], (NOW - fastpath.LAG - fastpath.LOOKBACK, later - fastpath.LAG))
        self.assertEqual(self.state()["checkpoint"], (later - fastpath.LAG).isoformat())

    def test_same_signal_pages_again_after_the_repage_period(self):
        self.check([record("m1", at=NOW - timedelta(minutes=10), rule="513")])
        later = NOW + fastpath.REPAGE_AFTER
        _, _, pager, _ = self.check([record("m2", at=later - timedelta(minutes=5), rule="513")], now=later)
        self.assertEqual(len(pager.pages), 1)

    def test_a_different_agent_or_signal_pages_separately(self):
        _, _, pager, _ = self.check([
            record("a", at=NOW - timedelta(minutes=10), rule="513", agent="001"),
            record("b", at=NOW - timedelta(minutes=10), rule="513", agent="002"),
            record("c", at=NOW - timedelta(minutes=10), rule="5902", agent="001"),
        ])
        self.assertEqual(sorted(p.title for p in pager.pages),
                         ["Soc Thief breach: account_created", "Soc Thief breach: malware",
                          "Soc Thief breach: malware"])

    def test_failed_page_keeps_the_checkpoint_and_the_next_run_pages(self):
        malware = record("m", at=NOW - timedelta(minutes=10), rule="513")
        self.check([record("r", at=NOW - timedelta(minutes=30))])
        before = self.state()["checkpoint"]
        later = NOW + timedelta(minutes=10)
        code, status, _, _ = self.check([malware], now=later, pager=Pager(fail=True))
        self.assertEqual(code, fastpath.FAILED)
        self.assertIn("checkpoint not advanced", status)
        self.assertEqual(self.state()["checkpoint"], before)
        code, _, pager, _ = self.check([malware], now=later + timedelta(minutes=10))
        self.assertEqual((code, len(pager.pages)), (fastpath.OK, 1))

    def test_ordinary_and_critical_alerts_without_a_breach_signal_do_not_page(self):
        code, _, pager, _ = self.check([record("c", at=NOW - timedelta(minutes=10), level=15),
                                        record("r", at=NOW - timedelta(minutes=10))])
        self.assertEqual((code, pager.pages), (fastpath.OK, []))

    def test_brute_force_then_success_correlates_across_runs_within_the_lookback(self):
        brute = record("b", at=NOW - timedelta(minutes=20), rule="5712", data__srcip="198.51.100.7",
                       rule__groups=["authentication_failures"])
        self.check([brute])
        later = NOW + timedelta(minutes=10)
        success = record("s", at=later - timedelta(minutes=5), rule="5715", data__srcip="198.51.100.7",
                         rule__groups=["authentication_success"])
        _, _, pager, _ = self.check([brute, success], now=later)
        self.assertEqual([p.title for p in pager.pages], ["Soc Thief breach: brute_force_success"])
        self.assertNotIn("198.51.100.7", pager.pages[0].body)

    def test_more_pairs_than_the_cap_send_one_summary_and_are_all_recorded(self):
        records = [record(str(n), at=NOW - timedelta(minutes=10), rule="513", agent=f"{n:03}")
                   for n in range(fastpath.MAX_PAGES + 3)]
        _, _, pager, _ = self.check(records)
        self.assertEqual(len(pager.pages), fastpath.MAX_PAGES + 1)
        self.assertIn("3 more breach signals", pager.pages[-1].body)
        _, _, again, _ = self.check(records, now=NOW + timedelta(minutes=10))
        self.assertEqual(again.pages, [])

    def test_gap_beyond_max_span_checks_the_last_day_and_reports_the_gap(self):
        self.check([])
        later = NOW + fastpath.MAX_SPAN + timedelta(hours=2)
        code, status, pager, collector = self.check([], now=later)
        self.assertEqual(code, fastpath.FAILED)
        self.assertIn("coverage gap", status)
        self.assertEqual(collector.windows[0], (later - fastpath.LAG - fastpath.MAX_SPAN, later - fastpath.LAG))
        self.assertEqual([p.title for p in pager.pages], ["Soc Thief fast path gap"])

    def test_first_run_checks_only_the_lookback(self):
        start, end, gap = window(NOW, None)
        self.assertEqual((start, end, gap), (NOW - fastpath.LAG - fastpath.LOOKBACK, NOW - fastpath.LAG, False))

    def test_window_bounds_are_whole_seconds(self):
        now = NOW + timedelta(microseconds=123456)
        for checkpoint in (None, NOW - timedelta(minutes=10, microseconds=7)):
            start, end, _ = window(now, checkpoint.replace(microsecond=0) if checkpoint else None)
            self.assertEqual((start.microsecond, end.microsecond), (0, 0))

    def test_unreadable_state_fails_without_paging(self):
        (self.root / fastpath.STATE_NAME).write_text("{not json")
        with self.assertRaises(FastPathError):
            self.check([record("m", at=NOW - timedelta(minutes=10), rule="513")])


class MainTest(unittest.TestCase):
    def test_no_approval_constructs_nothing(self):
        calls = []
        code = main([], env={}, now=lambda: NOW,
                    collector_factory=lambda env: calls.append("collector"),
                    pager_factory=lambda env: calls.append("pager"))
        self.assertEqual((code, calls), (fastpath.REFUSED, []))


class NtfyTest(unittest.TestCase):
    def config(self, value):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(json.dumps(value))
        handle.close()
        os.chmod(handle.name, 0o600)
        return NtfyConfig(Path(handle.name))

    def test_accepts_https_topic_and_token(self):
        self.assertEqual(self.config({"url": "https://ntfy.example/alerts_1", "token": "tk_abc"}).target(),
                         ("https://ntfy.example/alerts_1", "tk_abc"))

    def test_rejects_unsafe_routes(self):
        for value in ({"url": "http://ntfy.example/alerts"}, {"url": "https://u:p@ntfy.example/alerts"},
                      {"url": "https://ntfy.example/alerts?x=1"}, {"url": "https://ntfy.example/a/b"},
                      {"url": "https://ntfy.example/"}, {"url": "https://ntfy.example/alerts", "token": "a\r\nX: y"},
                      {"url": "https://ntfy.example/alerts", "extra": 1}, ["https://ntfy.example/alerts"]):
            with self.subTest(value=value), self.assertRaises(FastPathError):
                self.config(value).target()

    def test_sends_headers_and_retries_only_server_errors(self):
        class Response(io.BytesIO):
            status = 200
            def getcode(self): return 200

        class Opener:
            def __init__(self, errors): self.errors, self.requests = list(errors), []
            def open(self, request, timeout):
                self.requests.append(request)
                if self.errors:
                    raise HTTPError(request.full_url, self.errors.pop(0), "", {}, io.BytesIO())
                return Response()

        config = self.config({"url": "https://ntfy.example/alerts", "token": "tk_abc"})
        opener = Opener([503])
        NtfyPager(config, opener, sleep=lambda s: None).send(Page("T", "B", "urgent", "warning"))
        request = opener.requests[-1]
        self.assertEqual((len(opener.requests), request.get_header("Priority"), request.get_header("Authorization")),
                         (2, "urgent", "Bearer tk_abc"))
        refused = Opener([403, 403])
        with self.assertRaises(FastPathError):
            NtfyPager(config, refused, sleep=lambda s: None).send(Page("T", "B", "urgent", "warning"))
        self.assertEqual(len(refused.requests), 1)


if __name__ == "__main__":
    unittest.main()
