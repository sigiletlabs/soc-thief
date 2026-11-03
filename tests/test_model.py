"""Synthetic contract tests for bounded local-model triage."""

import json
import unittest
from unittest.mock import Mock

from soc_thief.model import ModelConfig, ModelError, OllamaTriage
from soc_thief.policy import decide

GROUP = {"timestamp": "2026-01-01T00:00:00+00:00", "rule_id": "100", "rule_level": 3,
         "rule_description": "routine synthetic heartbeat", "agent_id": "001", "count": 4}


class Response:
    status = 200
    def __init__(self, value, length=True): self._value, self.headers = value, ({"Content-Length": str(len(value))} if length else {})
    def getcode(self): return self.status
    def read(self, amount): return self._value
    def __enter__(self): return self
    def __exit__(self, *args): return False


def response(content): return json.dumps({"model": "qwen3:4b", "message": {"role": "assistant", "content": content}}).encode()


class ModelTest(unittest.TestCase):
    def setUp(self):
        self.opener = Mock(); self.adapter = OllamaTriage(ModelConfig(timeout_seconds=2), self.opener)

    def test_request_is_local_json_schema_non_streaming_and_no_thinking(self):
        self.opener.open.return_value = Response(response(json.dumps({"classification": "benign", "confidence": 0.99, "rationale": "routine", "analyst_action": "none"})))
        review = self.adapter.review(GROUP); body = json.loads(self.opener.open.call_args.args[0].data)
        self.assertEqual(review.model_version, "qwen3:4b"); self.assertFalse(body["stream"]); self.assertFalse(body["think"])
        self.assertEqual(body["format"]["required"], ["classification", "confidence", "rationale", "analyst_action"])
        self.assertEqual(body["options"], {"temperature": 0}); self.assertEqual(json.loads(body["messages"][1]["content"]), GROUP)
        # Even benign at 0.99 requires delivery: the model cannot suppress.
        self.assertEqual(decide(GROUP, review.result).reason, "model_requires_review")
        self.assertTrue(decide(GROUP, review.result).delivery_required)

    def test_protected_group_never_reaches_model(self):
        with self.assertRaises(ModelError): self.adapter.review({**GROUP, "rule_description": "password spray"})
        self.opener.open.assert_not_called()

    def test_bad_endpoint_and_environment_fail_closed(self):
        for endpoint in ("https://127.0.0.1", "http://localhost:11434", "http://10.0.0.1", "http://127.0.0.1/x"):
            with self.assertRaises(ValueError): ModelConfig(endpoint)
        with self.assertRaises(ModelError): ModelConfig.from_environment({"MODEL_TIMEOUT_SECONDS": "0"})

    def test_malformed_duplicate_and_oversized_responses_fail_closed(self):
        for raw in (b"not json", response('{"classification":"benign","classification":"unknown"}'), b"x" * (64 * 1024 + 1)):
            self.opener.open.return_value = Response(raw, length=False)
            with self.assertRaises(ModelError): self.adapter.review(GROUP)

    def test_invalid_model_schema_is_preserved_for_policy_health_fallback(self):
        self.opener.open.return_value = Response(response('{"classification":"benign"}'))
        self.assertEqual(decide(GROUP, self.adapter.review(GROUP).result).reason, "invalid_model_result")

    def test_model_identity_is_bounded_and_sanitized_before_audit(self):
        content = json.dumps({"classification": "benign", "confidence": 0.99,
                              "rationale": "routine", "analyst_action": "none"})
        for identity in ("qwen3:4b\nleak", " qwen3:4b", "qwen3:4b?token=value", "x" * 257):
            raw = json.dumps({"model": identity,
                              "message": {"role": "assistant", "content": content}}).encode()
            self.opener.open.return_value = Response(raw)
            with self.subTest(identity=identity), self.assertRaises(ModelError):
                self.adapter.review(GROUP)
