"""Synthetic hosted Jev trial boundary tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.error import URLError

from soc_thief.model import JevConfig, JevTriage, ModelError
from soc_thief.policy import decide


GROUP = {"timestamp": "2026-01-01T00:00:00+00:00", "rule_id": "100", "rule_level": 3,
         "rule_description": "routine LabNode event from 192.0.2.1 at https://example.invalid",
         "agent_id": "001", "agent_name": "LabNode", "manager_name": "LabManager",
         "decoder_name": "test", "location": "LabNode log", "count": 4}


class Response:
    status = 200
    def __init__(self, value):
        self.value, self.headers = value, {"Content-Length": str(len(value))}
    def getcode(self): return self.status
    def read(self, amount): return self.value
    def __enter__(self): return self
    def __exit__(self, *args): return False


class JevTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        path = Path(self.scratch.name) / "key"
        path.write_text("synthetic-key")
        os.chmod(path, 0o600)
        self.opener = Mock()
        self.adapter = JevTriage(JevConfig(str(path)), self.opener, sleep=lambda _: None)
        self.adapter.prepare([GROUP])

    def test_pseudonymised_score_and_threat_are_display_only(self):
        self.opener.open.return_value = Response(json.dumps({"answers": {"suspicious": {
            "type": "boolean", "probability": 0.87}, "threat": {
            "type": "choice", "choice": "other_concern"}}}).encode())
        review = self.adapter.review(GROUP)
        request = self.opener.open.call_args.args[0]
        body = request.data.decode()
        self.assertEqual(review.attention_probability, 0.87)
        self.assertEqual(review.threat_label, "other_concern")
        self.assertEqual(set(json.loads(body)["questions"]), {"suspicious", "threat"})
        self.assertNotIn("LabNode", body)
        self.assertNotIn("LabManager", body)
        self.assertNotIn("192.0.2.1", body)
        self.assertNotIn("example.invalid", body)
        self.assertNotIn(GROUP["timestamp"], body)
        self.assertEqual(json.loads(body)["state"]["group"]["agent"], "host-01")
        self.assertTrue(decide(GROUP, review.result).delivery_required)

    def test_bad_answer_fails_closed(self):
        for answer in ({"type": "boolean", "probability": 1.2},
                       {"type": "boolean", "probability": True},
                       {"type": "boolean", "probability": "0.8"}):
            self.opener.open.return_value = Response(json.dumps({"answers": {"suspicious": answer,
                "threat": {"type": "choice", "choice": "routine"}}}).encode())
            with self.subTest(answer=answer), self.assertRaises(ModelError):
                self.adapter.review(GROUP)

    def test_bad_threat_answer_fails_closed(self):
        for threat in ({"type": "choice", "choice": "cold"},
                       {"type": "choice", "choice": True},
                       {"type": "boolean", "choice": "routine"},
                       {"type": "choice"}):
            self.opener.open.return_value = Response(json.dumps({"answers": {"suspicious": {
                "type": "boolean", "probability": 0.87}, "threat": threat}}).encode())
            with self.subTest(threat=threat), self.assertRaises(ModelError):
                self.adapter.review(GROUP)

    def test_duplicate_or_oversized_response_fails_closed(self):
        for raw in (b'{"answers":{"suspicious":{"type":"boolean","probability":0.8,"probability":0.1}}}',
                    b"x" * (64 * 1024 + 1)):
            self.opener.open.return_value = Response(raw)
            with self.assertRaises(ModelError):
                self.adapter.review(GROUP)

    def test_protected_group_cannot_leave_host(self):
        with self.assertRaises(ModelError):
            self.adapter.review({**GROUP, "rule_description": "password spray"})
        self.opener.open.assert_not_called()

    def test_repeated_failures_open_circuit_to_preserve_runner_budget(self):
        self.opener.open.side_effect = URLError("synthetic")
        for _ in range(4):
            with self.assertRaises(ModelError):
                self.adapter.review(GROUP)
        self.assertEqual(self.opener.open.call_count, 3)


if __name__ == "__main__":
    unittest.main()
