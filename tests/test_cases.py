"""Synthetic analyst feedback checks; no live state or service is opened."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from soc_thief.baseline import serialize
from soc_thief.cases import _private_output, candidates, main
from soc_thief.policy import Decision
from soc_thief.state import StateStore
from soc_thief.tuning import load_tuning


NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
START = NOW - timedelta(hours=1)
CASE = "a" * 64
STREAM = "b" * 64
GROUP = "c" * 64


class CaseReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state"
        with StateStore(self.path) as store:
            store.commit_window(STREAM, START, NOW, (), ((GROUP, Decision(True, False, "model_requires_review")),),
                                recorded_at=NOW, cases=((CASE, "100", "001", 3, True),))

    def test_routine_feedback_exports_only_an_expiring_candidate(self):
        with StateStore(self.path) as store:
            self.assertEqual(candidates(store, now=NOW), ())
            store.mark_case(CASE, "routine", now=NOW)
            result = candidates(store, now=NOW)
            self.assertEqual(len(result), 1)
            self.assertEqual((result[0].rule_id, result[0].agent_id, result[0].action), ("100", "001", "low"))
            self.assertEqual(candidates(store, now=NOW + timedelta(days=30)), ())
        valid_output = Path(self.temp.name) / "valid-proposal.json"
        _private_output(valid_output, serialize(result))
        loaded = load_tuning({"SOC_THIEF_TUNING_FILE": str(valid_output)})
        self.assertEqual(loaded.action("100", "001", NOW), "low")
        output = Path(self.temp.name) / "proposal.json"
        self.assertEqual(main(["--state", str(self.path), "propose", "--output", str(output)]), 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        document = json.loads(output.read_text())
        self.assertEqual(document["version"], 1)
        self.assertEqual({"version", "entries"}, set(document))
        self.assertEqual(main(["--state", str(self.path), "propose", "--output", str(output)]), 2)

    def test_review_and_uncertain_do_not_propose(self):
        with StateStore(self.path) as store:
            for status in ("review", "uncertain"):
                store.mark_case(CASE, status, now=NOW)
                self.assertEqual(candidates(store, now=NOW), ())


if __name__ == "__main__":
    unittest.main()
