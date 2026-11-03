"""Synthetic local brief checks; no production state, indexer or alerts."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from soc_thief.investigate import InvestigationError, make_brief, main, resolve_case


NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
CASE = "a" * 64


def record(rule="100", description="Synthetic check"):
    return {"fields": {"@timestamp": (NOW - timedelta(minutes=5)).isoformat(),
                       "rule.id": rule, "rule.level": 3,
                       "rule.description": description, "agent.id": "001"}}


class Collector:
    def __init__(self): self.calls = []
    def sample_case(self, **kwargs):
        self.calls.append(kwargs)
        return (2, (record(),)) if kwargs.get("rule_id") else (1, (record("200", "Nearby synthetic alert"),))


class InvestigationTests(unittest.TestCase):
    def test_case_lookup_uses_service_account_and_accepts_only_identifiers(self):
        result = Mock(stdout='{"rule_id":"100","agent_id":"001"}')
        with patch("soc_thief.investigate.subprocess.run", return_value=result) as run:
            self.assertEqual(resolve_case(CASE), ("100", "001"))
            self.assertEqual(run.call_args.kwargs["cwd"], "/")
            self.assertEqual(run.call_args.args[0][-1], CASE)
        with patch("soc_thief.investigate.subprocess.run", return_value=Mock(stdout='{"rule_id":"100","agent_id":"001","extra":"x"}')):
            with self.assertRaises(InvestigationError):
                resolve_case(CASE)

    def test_brief_uses_two_scoped_queries_and_caps_rows(self):
        collector = Collector()
        brief = make_brief(collector, case_id=CASE, rule_id="100", agent_id="001", now=NOW)
        self.assertEqual(len(collector.calls), 2)
        self.assertEqual((collector.calls[0]["rule_id"], collector.calls[0]["limit"]), ("100", 20))
        self.assertEqual((collector.calls[1]["exclude_rule"], collector.calls[1]["limit"]), ("100", 10))
        self.assertIn("Matching alerts: 2; newest 1 shown", brief)
        self.assertIn("Nearby synthetic alert", brief)

    def test_cli_writes_private_file_and_prints_no_alert_text(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "brief.txt"
            collector = Collector()
            with patch("soc_thief.investigate.CollectorConfig.from_environment", return_value=None), \
                 patch("builtins.print") as printing:
                status = main(["--case-id", CASE, "--output", str(output)],
                              resolver=lambda _: ("100", "001"), collector_factory=lambda _: collector)
            self.assertEqual(status, 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn("Synthetic check", output.read_text())
            self.assertNotIn("Synthetic check", str(printing.call_args_list))

    def test_unsafe_output_fails_before_any_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "public"
            parent.mkdir(mode=0o755)
            resolver = Mock()
            self.assertEqual(main(["--case-id", CASE, "--output", str(parent / "brief.txt")],
                                  resolver=resolver), 2)
            resolver.assert_not_called()
            self.assertFalse((parent / "brief.txt").exists())

    def test_invalid_case_id_fails_before_any_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            resolver = Mock()
            self.assertEqual(main(["--case-id", "not-a-case", "--output", str(Path(directory) / "brief.txt")],
                                  resolver=resolver), 2)
            resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
