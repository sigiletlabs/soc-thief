"""Synthetic checks of the detection measurement. No Wazuh, network or host is touched, and
the simulation scripts are never executed: they are only read as text and syntax-checked."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

from soc_thief import detection
from soc_thief.collector import CollectorError
from soc_thief.detection import (EXPECTATIONS, MISS, NOT_RUN, PASS, SUPPRESSED, DetectionError,
                                 Scenario, evaluate, main, measure, parse_run_log, write_report)
from soc_thief.tuning import Tuning, TuningEntry

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 11, 1, 1, 0, 0, tzinfo=timezone.utc)
END = START + timedelta(minutes=1)
LATER = END + timedelta(hours=2)
GRACE = timedelta(minutes=30)
KEY = b"k" * 32


def record(identifier, *, rule, level=5, description="routine event", agent="001", offset=10,
           groups=None, srcip=None, path=None, event=None, changed=None):
    return {"source_key": {"index": "wazuh-alerts-synthetic", "id": identifier}, "fields": {
        "@timestamp": (START + timedelta(seconds=offset)).isoformat(), "rule.id": rule,
        "rule.level": level, "rule.description": description, "agent.id": agent,
        "agent.name": "secret-hostname", "decoder.name": "test", "manager.name": "test",
        "location": "test", "rule.groups": groups, "data.srcip": srcip, "syscheck.path": path,
        "syscheck.event": event, "syscheck.changed_attributes": changed}}


def scenario(name, platform="linux", status="ok"):
    return Scenario("sim-test", platform, name, START, END, status)


def check(name, records, *, platform="linux", tuning=Tuning(), status="ok"):
    return evaluate(scenario(name, platform, status), records, key=KEY, tuning=tuning, grace=GRACE)


class Collector:
    def __init__(self, records=(), error=None):
        self.records, self.error, self.windows = list(records), error, []

    def collect(self, start, end):
        self.windows.append((start, end))
        if self.error:
            raise self.error
        return iter([r for r in self.records
                     if start <= datetime.fromisoformat(r["fields"]["@timestamp"]) < end])


class VerdictTest(unittest.TestCase):
    def test_present_breach_passes_and_would_page(self):
        result = check("account_created", [record("a", rule="5902", description="New user added")])
        self.assertEqual((result["verdict"], result["detail"]), (PASS, "detected"))
        self.assertEqual(result["groups"][0]["decision"], "breach_account_created")
        self.assertEqual(result["groups"][0]["digest_section"], "breach")
        self.assertEqual(result["fastpath_pages"], ["account_created"])
        self.assertTrue(result["fastpath_would_page_expected"])
        self.assertEqual(result["raised"], [{"rule_id": "5902", "rule_level": 5, "events": 1}])

    def test_absent_alerts_miss(self):
        result = check("account_created", [])
        self.assertEqual((result["verdict"], result["detail"]), (MISS, "no_matching_alert"))
        self.assertEqual(result["fastpath_pages"], [])

    def test_unrelated_alerts_still_miss(self):
        result = check("account_created", [record("a", rule="1002", description="other")])
        self.assertEqual(result["verdict"], MISS)
        self.assertFalse(result["groups"][0]["matched_expectation"])

    def test_raised_without_breach_signal_is_a_miss_not_a_pass(self):
        # Wazuh raised syscheck "file added" but on a path breach.py does not treat as critical.
        result = check("persistence", [record(
            "a", rule="554", groups=["syscheck"], path="/home/x/file", event="added",
            description="File added to the system")])
        self.assertEqual((result["verdict"], result["detail"]),
                         (MISS, "raised_without_expected_breach_signal"))
        self.assertEqual(result["fastpath_pages"], [])

    def test_critical_path_persistence_passes(self):
        result = check("persistence", [record(
            "a", rule="554", groups=["syscheck"], path="/etc/cron.d/soc-thief-sim", event="added",
            description="File added to the system")])
        self.assertEqual(result["verdict"], PASS)
        self.assertEqual(result["groups"][0]["breach_signal"], "critical_file_change")

    def test_brute_force_then_success_correlates(self):
        records = [record("f", rule="5712", groups=["authentication_failures"], srcip="127.0.0.1", offset=5),
                   record("s", rule="5715", groups=["authentication_success"], srcip="127.0.0.1", offset=20,
                          description="sshd: authentication success")]
        self.assertEqual(check("brute_force_success", records)["verdict"], PASS)
        # The same alerts in the wrong order (success first) are not a brute-force success.
        wrong = [dict(records[0], fields=dict(records[0]["fields"], **{
                     "@timestamp": (START + timedelta(seconds=40)).isoformat()})), records[1]]
        self.assertEqual(check("brute_force_success", wrong)["verdict"], MISS)

    def test_tuned_away_alert_only_group_is_suppressed(self):
        records = [record("a", rule="9999", groups=["syscheck_registry"],
                          description="Registry entry added")]
        tuning = Tuning((TuningEntry("9999", "mute"),))
        result = check("persistence", records, platform="windows", tuning=tuning)
        self.assertEqual((result["verdict"], result["detail"]), (SUPPRESSED, "raised_but_not_delivered"))
        self.assertEqual(result["groups"][0]["decision"], "tuned_mute")
        self.assertEqual(result["groups"][0]["digest_section"], "suppressed")
        # Untuned, the same alert is delivered (a model can only deliver) and passes.
        untuned = check("persistence", records, platform="windows")
        self.assertEqual((untuned["verdict"], untuned["groups"][0]["decision"]),
                         (PASS, "model_requires_review"))

    def test_tuning_cannot_hide_a_breach(self):
        tuning = Tuning((TuningEntry("5902", "mute"),))
        result = check("account_created", [record("a", rule="5902", description="New user added")],
                       tuning=tuning)
        self.assertEqual(result["verdict"], PASS)
        self.assertTrue(result["groups"][0]["delivered"])

    def test_scenario_not_run_is_neither_pass_nor_miss(self):
        result = check("account_created", [], status="failed")
        self.assertEqual((result["verdict"], result["detail"]), (NOT_RUN, "scenario_failed"))

    def test_known_gap_is_carried_into_the_report(self):
        result = check("log_cleared", [])
        self.assertEqual(result["verdict"], MISS)
        self.assertIn("logs_cleared", result["known_gap"])

    def test_report_carries_no_alert_text(self):
        result = check("account_created", [record("a", rule="5902", description="SECRET-DESCRIPTION")])
        text = json.dumps(result)
        for forbidden in ("SECRET-DESCRIPTION", "secret-hostname"):
            self.assertNotIn(forbidden, text)


class MeasureTest(unittest.TestCase):
    def test_only_the_named_agent_is_measured(self):
        collector = Collector([record("a", rule="5902", agent="002")])
        (result,) = measure([scenario("account_created")], collector=collector, agent_id="001",
                            key=KEY, tuning=Tuning(), grace=GRACE, now=LATER)
        self.assertEqual(result["verdict"], MISS)

    def test_window_is_widened_to_whole_seconds_plus_grace(self):
        scn = Scenario("r", "linux", "account_created", START + timedelta(microseconds=5),
                       END + timedelta(microseconds=5), "ok")
        collector = Collector()
        measure([scn], collector=collector, agent_id="001", key=KEY, tuning=Tuning(), grace=GRACE, now=LATER)
        start, end = collector.windows[0]
        self.assertEqual((start.microsecond, end.microsecond), (0, 0))
        self.assertGreaterEqual(end, scn.end + GRACE)

    def test_grace_stops_at_the_next_scenario_so_alerts_are_not_borrowed(self):
        # Measured: with an uncapped grace, a later scenario's breach alert credited
        # an earlier scenario. Here the account is created only inside the second scenario.
        first = Scenario("r", "linux", "persistence", START, END, "ok")
        second = Scenario("r", "linux", "account_created", END + timedelta(minutes=1),
                          END + timedelta(minutes=2), "ok")
        created = record("c", rule="5902", offset=150)  # START + 150s: inside the second scenario.
        collector = Collector([created])
        results = measure([first, second], collector=collector, agent_id="001", key=KEY,
                          tuning=Tuning(), grace=GRACE, now=LATER)
        self.assertEqual(collector.windows[0][1], second.start)
        self.assertEqual([r["groups"] for r in results][0], [])
        self.assertEqual(results[1]["verdict"], PASS)

    def test_the_last_scenario_keeps_its_full_grace(self):
        collector = Collector()
        measure([scenario("account_created")], collector=collector, agent_id="001", key=KEY,
                tuning=Tuning(), grace=GRACE, now=LATER)
        self.assertGreaterEqual(collector.windows[0][1], END + GRACE)

    def test_collector_error_fails_closed(self):
        with self.assertRaises(CollectorError):
            measure([scenario("account_created")], collector=Collector(error=CollectorError("x")),
                    agent_id="001", key=KEY, tuning=Tuning(), grace=GRACE, now=LATER)

    def test_open_window_is_refused_not_scored_as_a_miss(self):
        with self.assertRaises(DetectionError):
            measure([scenario("account_created")], collector=Collector(), agent_id="001", key=KEY,
                    tuning=Tuning(), grace=GRACE, now=END + timedelta(minutes=5))


class RunLogTest(unittest.TestCase):
    LINE = {"run": "r", "platform": "linux", "scenario": "account_created",
            "start": "2026-11-01T01:00:00Z", "end": "2026-11-01T01:01:00Z", "status": "ok"}

    def test_valid_line_parses(self):
        (parsed,) = parse_run_log(json.dumps(self.LINE) + "\n")
        self.assertEqual((parsed.scenario, parsed.start, parsed.status), ("account_created", START, "ok"))

    def test_invalid_logs_fail_closed(self):
        for bad in ("", "not json", json.dumps({**self.LINE, "scenario": "nope"}),
                    json.dumps({**self.LINE, "extra": 1}), json.dumps({**self.LINE, "start": "2026-11-01T01:00:00"}),
                    json.dumps({**self.LINE, "end": "2026-11-01T00:00:00Z"}),
                    json.dumps(self.LINE) + "\n" + json.dumps(self.LINE)):
            with self.subTest(bad=bad[:40]), self.assertRaises(DetectionError):
                parse_run_log(bad)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(lambda: [p.unlink() for p in self.dir.iterdir()] and None or self.dir.rmdir())
        self.log = self.dir / "run.jsonl"
        self.log.write_text(json.dumps(RunLogTest.LINE) + "\n")

    def run_main(self, collector):
        return main(["--run-log", str(self.log), "--agent-id", "001"], env={},
                    now=lambda: LATER, collector_factory=lambda env: collector)

    def test_report_is_private_and_exit_code_reflects_verdict(self):
        code = self.run_main(Collector([record("a", rule="5902", description="New user added")]))
        report = Path(str(self.log) + ".report.json")
        self.assertEqual(code, detection.OK)
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(json.loads(report.read_text())["summary"]["PASS"], 1)
        report.unlink()
        self.assertEqual(self.run_main(Collector()), detection.NOT_ALL_PASSED)
        Path(str(self.log) + ".report.json").unlink()

    def test_collector_error_writes_no_report(self):
        self.assertEqual(self.run_main(Collector(error=CollectorError("x"))), detection.FAILED)
        self.assertFalse(Path(str(self.log) + ".report.json").exists())

    def test_existing_report_is_never_overwritten(self):
        report = Path(str(self.log) + ".report.json")
        report.write_text("keep")
        self.assertEqual(self.run_main(Collector()), detection.FAILED)
        self.assertEqual(report.read_text(), "keep")
        with self.assertRaises(FileExistsError):
            write_report(report, [], agent_id="001", now=LATER)
        report.unlink()

    def test_bad_agent_id_is_a_usage_error(self):
        self.assertEqual(main(["--run-log", str(self.log), "--agent-id", "../x"], env={},
                              now=lambda: LATER, collector_factory=lambda env: Collector()), detection.USAGE)


class ScriptTest(unittest.TestCase):
    """The scripts are never run here; these checks only read them."""

    def text(self, name):
        return (ROOT / "simulations" / name).read_text()

    def test_bash_syntax(self):
        subprocess.run(["bash", "-n", str(ROOT / "simulations" / "run-linux.sh")], check=True)

    def test_hostname_guard_and_cleanup_exist(self):
        linux, windows = self.text("run-linux.sh"), self.text("run-windows.ps1")
        self.assertIn("--i-am-on-the-disposable-test-host", linux)
        self.assertRegex(linux, r'\[ "\$host_ok" != "\$\(hostname\)" \]')
        self.assertRegex(linux, r"(?m)^trap cleanup EXIT")
        self.assertIn("--i-am-on-the-disposable-test-host", windows)
        self.assertIn("$env:COMPUTERNAME", windows)
        self.assertRegex(windows, r"(?s)\bfinally\s*\{\s*Remove-Artefacts")
        # The guard comes before any scenario can run.
        self.assertLess(linux.index('"$host_ok" != "$(hostname)"'), linux.index("run_scenario "))
        self.assertLess(windows.index("$env:COMPUTERNAME"), windows.index("Invoke-Scenario "))

    def test_scripts_make_no_calls_beyond_the_host(self):
        for name in ("run-linux.sh", "run-windows.ps1"):
            body = "\n".join(line for line in self.text(name).splitlines() if not line.lstrip().startswith("#"))
            for forbidden in ("curl", "wget", "Invoke-WebRequest", "Invoke-RestMethod", "DownloadString",
                              "http://", "https://", "Install-Module"):
                self.assertNotIn(forbidden, body, (name, forbidden))
            for address in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", body):
                self.assertEqual(address, "127.0.0.1", name)

    def test_scenario_ids_match_the_expectation_table(self):
        for name, platform in (("run-linux.sh", "linux"), ("run-windows.ps1", "windows")):
            used = set(re.findall(r"(?:run_scenario|Invoke-Scenario|Write-Entry) +'?([a-z_]+)'?", self.text(name)))
            used -= {"ID", "Id"}
            expected = {scenario for (p, scenario) in EXPECTATIONS if p == platform}
            self.assertEqual(used, expected, name)

    def test_run_log_line_the_bash_script_writes_parses(self):
        line = ('{"run":"%s","platform":"linux","scenario":"%s","start":"%s","end":"%s","status":"%s"}'
                % ("sim-20261101T010000Z", "eicar", "2026-11-01T01:00:00Z", "2026-11-01T01:01:00Z", "ok"))
        self.assertIn('"platform":"linux","scenario":"%s","start":"%s","end":"%s","status":"%s"}',
                      self.text("run-linux.sh").replace("\\n", ""))
        self.assertEqual(parse_run_log(line)[0].scenario, "eicar")


if __name__ == "__main__":
    unittest.main()
