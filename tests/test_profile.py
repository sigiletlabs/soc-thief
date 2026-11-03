"""Synthetic noise-profile aggregation, report, and CLI safety tests; no live services."""

import contextlib
import io
import json
import os
import re
import stat
import tempfile
import time
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from soc_thief.collector import (
    PROFILE_MAX_DAYS, CollectorConfig, CollectorError, WazuhIndexerCollector, _RESPONSE_LIMIT,
)
from soc_thief.profile import (
    OutputError, _INVALID_OUTPUT, _run_worker, _worker, check_output, main, render_report, write_private,
)
from tests.test_collector import ORIGIN, Response, responses

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = datetime(2026, 1, 3, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 13, tzinfo=timezone.utc)
DAY_MS = 86_400_000
HOSTILE = "evil|pipe `tick` [link](http://x) *b* <i>\n# head @everyone \x1b[31m‮ zz"


def shards():
    return {"total": 2, "successful": 2, "skipped": 0, "failed": 0}


def terms(value, count, other=0):
    return {"doc_count_error_upper_bound": 0, "sum_other_doc_count": other,
            "buckets": [] if value is None else [{"key": value, "doc_count": count - other}]}


def group(rule="100", agent="001", count=10, level=3, days=None,
          description="Synthetic noise", agent_name="synthetic-host", other=0):
    days = [count] if days is None else days
    return {
        "key": {"rule_id": rule, "agent_id": agent}, "doc_count": count,
        "max_level": {"value": float(level)},
        "days": {"buckets": [{"key_as_string": "synthetic", "key": 1767225600000 + i * DAY_MS, "doc_count": n}
                             for i, n in enumerate(days)]},
        "description": terms(description, count, other),
        "agent_name": terms(agent_name, count),
    }


def agg(buckets, total=None):
    total = sum(b["doc_count"] for b in buckets) if total is None else total
    groups = {"buckets": buckets}
    if buckets:
        groups["after_key"] = dict(buckets[-1]["key"])
    return {"took": 1, "timed_out": False, "_shards": shards(),
            "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": []},
            "aggregations": {"groups": groups}}


class ProfileCollectorTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        user, password = root / "user", root / "password"
        for path in (user, password):
            path.write_text("synthetic-value")
            path.chmod(0o600)
        self.config = CollectorConfig(ORIGIN, user, password, max_attempts=1)
        self.opener = Mock()

    def profile(self, *pages, start=START, end=END, now=NOW):
        self.opener.side_effect = responses(*pages)
        return WazuhIndexerCollector(self.config, self.opener, Mock()).profile(start, end, now=now)

    def test_request_is_size_zero_composite_paginated_aggregation(self):
        first, second = group(count=12, days=[5, 7]), group("200", "002", count=8)
        result = self.profile(agg([first], 20), agg([second], 20))
        self.assertEqual(result["total"], 20)
        requests = [c.args[0] for c in self.opener.call_args_list]
        self.assertEqual(len(requests), 2)
        payloads = []
        for request in requests:
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.full_url, ORIGIN + "/wazuh-alerts-*/_search?allow_partial_search_results=false"
                             "&allow_no_indices=false&ignore_unavailable=false")
            text = request.data.decode()
            for forbidden in ('"_source"', "top_hits", '"script"', '"fields"', "docvalue", '"pit"', "stored_fields"):
                self.assertNotIn(forbidden, text)
            payloads.append(json.loads(text))
        for payload in payloads:
            self.assertEqual(payload["size"], 0)
            self.assertIs(payload["track_total_hits"], True)
            self.assertEqual(payload["query"], {"range": {"@timestamp": {
                "gte": START.isoformat(), "lt": END.isoformat()}}})
            composite = payload["aggs"]["groups"]["composite"]
            self.assertEqual(composite["sources"], [{"rule_id": {"terms": {"field": "rule.id"}}},
                                                    {"agent_id": {"terms": {"field": "agent.id"}}}])
            self.assertEqual(payload["aggs"]["groups"]["aggs"], {
                "max_level": {"max": {"field": "rule.level"}},
                "days": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day",
                                            "time_zone": "Australia/Sydney", "min_doc_count": 1}},
                "description": {"terms": {"field": "rule.description", "size": 1}},
                "agent_name": {"terms": {"field": "agent.name", "size": 1}},
            })
        self.assertNotIn("after", payloads[0]["aggs"]["groups"]["composite"])
        self.assertEqual(payloads[1]["aggs"]["groups"]["composite"]["after"], {"rule_id": "100", "agent_id": "001"})
        rows = result["groups"]
        self.assertEqual(rows[0], {"rule_id": "100", "agent_id": "001", "events": 12, "max_level": 3,
                                   "days_active": 2, "rule_description": "Synthetic noise",
                                   "description_complete": True, "agent_name": "synthetic-host",
                                   "agent_name_complete": True})
        self.assertEqual(rows[1]["events"], 8)

    def test_query_range_matches_collection_semantics(self):
        sydney = timezone(timedelta(hours=11))
        self.profile(agg([]), start=START.astimezone(sydney), end=END.astimezone(sydney))
        collector = WazuhIndexerCollector(self.config, self.opener)
        expected = collector._payload(START, END)["query"]
        self.assertEqual(json.loads(self.opener.call_args.args[0].data)["query"], expected)

    def test_empty_window_and_label_variants(self):
        self.assertEqual(self.profile(agg([], 0)), {"total": 0, "groups": []})
        row = self.profile(agg([group(count=5, description=None, agent_name=None)]))["groups"][0]
        self.assertEqual((row["rule_description"], row["description_complete"]), (None, False))
        row = self.profile(agg([group(count=5, other=2)]))["groups"][0]
        self.assertEqual((row["rule_description"], row["description_complete"]), ("Synthetic noise", False))

    def test_strict_validation_failures(self):
        cases = []
        def add(mutate, buckets=None, total=None):
            page = agg(buckets or [group()], total)
            mutate(page)
            cases.append(page)
        add(lambda p: p["_shards"].update(failed=1, successful=1))
        add(lambda p: p["_shards"].update(total=0))
        add(lambda p: p.update(timed_out=True))
        add(lambda p: p.pop("timed_out"))
        add(lambda p: p.update(terminated_early=True))
        add(lambda p: p.update(error="synthetic"))
        add(lambda p: p["hits"]["total"].update(relation="gte"))
        add(lambda p: p["hits"]["total"].update(value=True))
        add(lambda p: p["hits"].update(hits=[{"_source": {}}]))
        add(lambda p: p.pop("aggregations"))
        add(lambda p: p["aggregations"].update(extra={}))
        add(lambda p: p["aggregations"]["groups"].update(buckets=None))
        add(lambda p: p["aggregations"]["groups"].update(after_key={"rule_id": "999", "agent_id": "001"}))
        add(lambda p: None, total=9)                      # sum exceeds total
        add(lambda p: None, buckets=[group(), group()], total=20)  # duplicate key
        bucket_mutations = [
            lambda b: b.pop("key"), lambda b: b["key"].update(rule_id=""), lambda b: b["key"].update(agent_id=1),
            lambda b: b["key"].update(extra="x"), lambda b: b.update(doc_count=True),
            lambda b: b.update(doc_count=0), lambda b: b.update(doc_count=-1),
            lambda b: b["max_level"].update(value=None), lambda b: b["max_level"].update(value=3.5),
            lambda b: b["max_level"].update(value=17.0), lambda b: b["max_level"].update(value=True),
            lambda b: b["days"]["buckets"][0].update(doc_count=9),
            lambda b: b["days"].update(buckets=[]),
            lambda b: b["days"]["buckets"][0].update(key="x"),
            lambda b: b["description"]["buckets"].append({"key": "b", "doc_count": 1}),
            lambda b: b["description"]["buckets"][0].update(key=7),
            lambda b: b["description"]["buckets"][0].update(key=""),
            lambda b: b["description"]["buckets"][0].update(doc_count=11),
            lambda b: b["agent_name"].update(sum_other_doc_count=-1),
            lambda b: b.pop("agent_name"),
            lambda b: b["key"].update(rule_id="x" * 257),
        ]
        for mutate in bucket_mutations:
            bucket = group()
            mutate(bucket)
            page = agg([group("1", "1", count=10)], 20)
            page["aggregations"]["groups"]["buckets"].append(bucket)
            page["aggregations"]["groups"]["after_key"] = bucket.get("key")
            cases.append(page)
        for i, page in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(CollectorError):
                self.profile(page)

    def test_count_shortfall_and_changed_total_fail_closed(self):
        with self.assertRaisesRegex(CollectorError, "count"):
            self.profile(agg([group()], 20), agg([], 20))
        with self.assertRaises(CollectorError):
            self.profile(agg([group()], 20), agg([group("2", count=10)], 21))

    def test_page_size_bound_and_budget_exhaustion(self):
        with patch("soc_thief.collector._PROFILE_PAGE_SIZE", 1):
            with self.assertRaises(CollectorError):
                self.profile(agg([group("1"), group("2")]))
            with patch("soc_thief.collector._PROFILE_MAX_PAGES", 2):
                self.opener.reset_mock()
                with self.assertRaisesRegex(CollectorError, "budget"):
                    self.profile(agg([group("1")], 30), agg([group("2")], 30), agg([group("3")], 30))
                self.assertEqual(self.opener.call_count, 2)

    def test_oversized_response_fails(self):
        self.opener.side_effect = [Response(b" " * (_RESPONSE_LIMIT + 1))]
        with self.assertRaisesRegex(CollectorError, "size limit"):
            WazuhIndexerCollector(self.config, self.opener).profile(START, END, now=NOW)

    def test_errors_do_not_expose_labels(self):
        bad = agg([group(description=HOSTILE)], 5)
        try:
            self.profile(bad)
        except CollectorError:
            self.assertNotIn("evil", traceback.format_exc())
        else:
            self.fail("Count mismatch accepted")

    def test_window_limits_checked_before_network(self):
        naive = START.replace(tzinfo=None)
        cases = [(START, START), (END, START), (naive, END), (START, END.replace(tzinfo=None)),
                 (NOW - timedelta(days=1), NOW + timedelta(seconds=1)),
                 (END - timedelta(days=PROFILE_MAX_DAYS, seconds=1), END)]
        collector = WazuhIndexerCollector(self.config, self.opener)
        for start, end in cases:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                collector.profile(start, end, now=NOW)
        self.opener.assert_not_called()
        self.opener.side_effect = responses(agg([]))
        collector.profile(END - timedelta(days=PROFILE_MAX_DAYS), END, now=NOW)


def row(rule, agent, events, level=3, description="Synthetic noise", days=1, complete=True, name="host"):
    return {"rule_id": rule, "agent_id": agent, "events": events, "max_level": level, "days_active": days,
            "rule_description": description, "description_complete": complete,
            "agent_name": name, "agent_name_complete": True}


def table_rows(report):
    return [line for line in report.splitlines() if line.startswith("| ") and line[2:3].isdigit()]


def cells(line):
    # Label pipes are backslash-escaped; only unescaped pipes separate cells.
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip("|"))]


def candidates(report):
    section = report.split("## Top candidates", 1)[1]
    return [json.loads(line) for line in section.splitlines() if line.startswith("{")]


class ReportTest(unittest.TestCase):
    def test_ranking_share_cumulative_and_candidate_cutoff(self):
        profile = {"total": 1000, "groups": [
            row("5", "001", 50), row("1", "001", 500), row("2", "002", 200),
            row("3", "003", 150, level=12), row("4", "004", 100),
        ]}
        report = render_report(START, END, profile)
        rows = table_rows(report)
        self.assertEqual(len(rows), 5)
        cells = [[c.strip() for c in r.strip("|").split("|")] for r in rows]
        self.assertEqual([c[1] for c in cells], ["500", "200", "150", "100", "50"])
        self.assertEqual([c[2] for c in cells], ["50.00", "20.00", "15.00", "10.00", "5.00"])
        self.assertEqual([c[3] for c in cells], ["50.00", "70.00", "85.00", "95.00", "100.00"])
        self.assertEqual(cells[2][10], "no (protected)")
        self.assertEqual(cells[0][10], "yes")
        # Rows 1-3 reach 80%; the protected row is excluded, row 4 starts past the cut-off.
        self.assertEqual(candidates(report), [{"rule_id": "1", "agent_id": "001"},
                                              {"rule_id": "2", "agent_id": "002"}])
        self.assertIn("1000", report.split("|", 1)[0])
        self.assertIn("nothing is muted automatically", report.lower())
        self.assertIn("not recommendations to mute", report.lower())

    def test_candidate_cutoff_is_exclusive_at_eighty_percent(self):
        profile = {"total": 10, "groups": [row("1", "1", 8), row("2", "2", 1), row("3", "3", 1)]}
        self.assertEqual(candidates(render_report(START, END, profile)), [{"rule_id": "1", "agent_id": "1"}])

    def test_protected_rows_reuse_policy(self):
        profile = {"total": 40, "groups": [
            row("1", "1", 10, description="sshd: Authentication failure"),
            row("2", "2", 10, description="Possible ransomware activity"),
            row("3", "3", 10, level=15), row("4", "4", 5, description=None, complete=False),
            row("5", "5", 3, complete=False), row("6", "6", 2, description=HOSTILE),
        ]}
        report = render_report(START, END, profile)
        verdicts = [cells(r)[10] for r in table_rows(report)]
        self.assertEqual(verdicts[:3], ["no (protected)"] * 3)
        self.assertEqual(verdicts[3:], ["no (review)"] * 3)
        self.assertEqual(candidates(report), [])

    def test_hostile_labels_are_neutralised(self):
        printable = "Printable | `tick` [link](http://x) @everyone " + "x" * 300
        profile = {"total": 4, "groups": [
            row("r|`1", "a@everyone", 3, description=printable, name="@here `x` | y\r\n"),
            row("9", "9\n@here", 1, description=HOSTILE),
        ]}
        report = render_report(START, END, profile)
        for bad in ("\x1b", "\r", "‮", "@everyone", "@here", "`tick`", "](http"):
            self.assertNotIn(bad, report)
        self.assertTrue(all(ch == "\n" or ch.isprintable() for ch in report))
        lines = table_rows(report)
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertEqual(line.count("|") - line.count("\\|"), 12)
            self.assertLess(len(line), 700)
        self.assertEqual(sum("evil" in line for line in report.splitlines()), 1)
        self.assertTrue(lines[1].endswith("| no (review) |"))
        section = report.split("## Top candidates", 1)[1]
        self.assertNotIn("`", section.replace("```", ""))
        self.assertEqual(candidates(report), [{"rule_id": "r|`1", "agent_id": "a@everyone"}])


def _slow_worker(*args):
    time.sleep(30)


class OutputAndCliTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.output = self.root / "profile.md"

    def test_write_private_creates_exclusive_0600_file(self):
        old = os.umask(0)
        try:
            write_private(str(self.output), "synthetic report\n")
        finally:
            os.umask(old)
        info = os.lstat(self.output)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(self.output.read_text(), "synthetic report\n")
        with self.assertRaises(OutputError):
            write_private(str(self.output), "replacement")
        self.assertEqual(self.output.read_text(), "synthetic report\n")

    def test_unsafe_outputs_are_refused(self):
        target = self.root / "target"
        target.write_text("original")
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "missing")
        linked = self.root / "linked"
        linked.symlink_to(target)
        loose = self.root / "loose"
        loose.mkdir(mode=0o700)
        loose.chmod(0o770)
        other = self.root / "other"
        other.mkdir(mode=0o700)
        other.chmod(0o702)
        dirlink = self.root / "dirlink"
        dirlink.symlink_to(self.root, target_is_directory=True)
        cases = [str(target), str(dangling), str(linked), str(loose / "x"), str(other / "x"),
                 str(dirlink / "x"), str(target / "x"), str(self.root / "missing" / "x"),
                 str(self.root) + "/", str(self.root / ".."), ""]
        for path in cases:
            with self.subTest(path=path):
                with self.assertRaises(OutputError):
                    check_output(path)
                with self.assertRaises(OutputError):
                    write_private(path, "synthetic")
        self.assertEqual(target.read_text(), "original")
        self.assertFalse((self.root / "missing").exists())
        check_output(str(self.output))
        self.assertFalse(self.output.exists())

    def test_error_text_hides_path(self):
        for function in (check_output, lambda p: write_private(p, "x")):
            with self.assertRaises(OutputError) as caught:
                function(str(self.root / "missing" / "synthetic-private-marker"))
            exc = caught.exception
            self.assertNotIn("synthetic-private-marker", "".join(traceback.format_exception_only(exc)))
            self.assertNotIn(str(self.root), str(exc))
            self.assertTrue(exc.__suppress_context__)

    def args(self, start=START, end=END, output=None, propose_tuning=None):
        argv = ["--start", start.isoformat(), "--end", end.isoformat(), "--output", str(output or self.output)]
        if propose_tuning is not None:
            argv += ["--propose-tuning", str(propose_tuning)]
        return argv

    def run_main(self, argv, **worker):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                patch("soc_thief.profile._run_worker", **worker) as run:
            try:
                code = main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue(), run

    def test_success_prints_only_fixed_text_and_integers(self):
        code, out, err, run = self.run_main(self.args(), return_value=(0, (7, 12345)))
        self.assertEqual(code, 0)
        self.assertEqual(out, "Noise profile written: 7 groups, 12345 events. Review before writing tuning rules.\n")
        self.assertEqual(err, "")
        run.assert_called_once_with(START, END, str(self.output), None)

    def test_propose_tuning_flag_is_wired_through_and_message_says_review(self):
        proposal_path = self.root / "proposal.json"
        code, out, err, run = self.run_main(self.args(propose_tuning=proposal_path),
                                            return_value=(0, (7, 12345)))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("Review before writing tuning rules.", out)
        self.assertIn("not installed", out)
        self.assertIn("nothing is muted automatically", out)
        run.assert_called_once_with(START, END, str(self.output), str(proposal_path))

    def test_propose_tuning_path_must_be_new_and_distinct_from_output(self):
        existing = self.root / "existing-proposal.json"
        existing.write_text("existing")
        cases = [self.args(propose_tuning=self.output),           # same path as --output
                 self.args(propose_tuning=existing),               # already exists
                 self.args(propose_tuning=self.root / "missing-dir" / "x")]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err, run = self.run_main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, _INVALID_OUTPUT + "\n")
                run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_failure_and_deadline_messages(self):
        for code, text in [(1, "Noise profile failed; review required. Details withheld.\n"),
                           (3, "Noise profile deadline exceeded; review required.\n")]:
            result, out, _, _ = self.run_main(self.args(), return_value=(code, None))
            self.assertEqual((result, out), (code, text))

    def test_invalid_arguments_exit_two_without_echo_or_worker(self):
        future = datetime.now(timezone.utc) + timedelta(days=1)
        self.output.write_text("existing")
        cases = [["--private-marker"], ["--start", "private-marker", "--end", END.isoformat(), "--output", "x"],
                 self.args(output=self.output), self.args(end=future, output=self.root / "new"),
                 self.args(start=END, end=START, output=self.root / "new"),
                 self.args(start=END - timedelta(days=121), output=self.root / "new"),
                 self.args(output=self.root / "private-marker-dir" / "x")]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err, run = self.run_main(argv)
                self.assertEqual(code, 2)
                self.assertNotIn("private-marker", out + err)
                run.assert_not_called()

    def test_worker_writes_report_and_sends_only_counts(self):
        profile = {"total": 5, "groups": [row("100", "001", 5, description=HOSTILE, name="synthetic-name-marker")]}
        conn = Mock()
        stdout = io.StringIO()
        with patch("soc_thief.profile.CollectorConfig.from_environment"), \
                patch("soc_thief.profile.WazuhIndexerCollector") as collector, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            collector.return_value.profile.return_value = profile
            with self.assertRaises(SystemExit) as result:
                _worker(START, END, str(self.output), conn)
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(stdout.getvalue(), "")
        conn.send.assert_called_once_with((1, 5))
        collector.return_value.profile.assert_called_once_with(START, END)
        self.assertIn("synthetic\\-name\\-marker", self.output.read_text())
        self.assertEqual(stat.S_IMODE(os.lstat(self.output).st_mode), 0o600)

    def test_worker_writes_tuning_proposal_when_requested(self):
        profile = {"total": 1005, "groups": [
            row("100", "001", 1000, days=99), row("200", "002", 5, days=2),
        ]}
        conn = Mock()
        proposal_path = self.root / "proposal.json"
        stdout = io.StringIO()
        with patch("soc_thief.profile.CollectorConfig.from_environment"), \
                patch("soc_thief.profile.WazuhIndexerCollector") as collector, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            collector.return_value.profile.return_value = profile
            with self.assertRaises(SystemExit) as result:
                _worker(START, END, str(self.output), conn, str(proposal_path))
        self.assertEqual(result.exception.code, 0)
        document = json.loads(proposal_path.read_text())
        self.assertEqual(document["version"], 1)
        rule_ids = [entry["rule_id"] for entry in document["entries"]]
        self.assertIn("100", rule_ids)              # 99 days active clears the history bar
        self.assertNotIn("200", rule_ids)            # 2 days active does not
        self.assertEqual(stat.S_IMODE(os.lstat(proposal_path).st_mode), 0o600)

    def test_worker_omits_tuning_proposal_when_not_requested(self):
        profile = {"total": 5, "groups": [row("100", "001", 5, days=99)]}
        conn = Mock()
        proposal_path = self.root / "unwritten-proposal.json"
        stdout = io.StringIO()
        with patch("soc_thief.profile.CollectorConfig.from_environment"), \
                patch("soc_thief.profile.WazuhIndexerCollector") as collector, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            collector.return_value.profile.return_value = profile
            with self.assertRaises(SystemExit) as result:
                _worker(START, END, str(self.output), conn)
        self.assertEqual(result.exception.code, 0)
        self.assertFalse(proposal_path.exists())

    def test_worker_failure_is_silent_and_writes_nothing(self):
        conn = Mock()
        stdout = io.StringIO()
        with patch("soc_thief.profile.CollectorConfig.from_environment",
                   side_effect=RuntimeError("synthetic-private-marker")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            with self.assertRaises(SystemExit) as result:
                _worker(START, END, str(self.output), conn)
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "")
        conn.send.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_hard_deadline_stops_child(self):
        before = time.monotonic()
        self.assertEqual(_run_worker(START, END, str(self.output), timeout=0.2, target=_slow_worker), (3, None))
        self.assertLess(time.monotonic() - before, 8)


if __name__ == "__main__":
    unittest.main()
