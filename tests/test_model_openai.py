"""The OpenAI-compatible backend: local fake server and stubbed openers only, no real endpoint."""
import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock

from soc_thief import model
from soc_thief.model import ModelError, OpenAICompatibleTriage, OpenAIConfig, triage_from_environment
from soc_thief.policy import decide

GROUP = {"timestamp": "2026-01-01T00:00:00+00:00", "rule_id": "100", "rule_level": 3,
         "rule_description": "routine heartbeat from web-01 at 192.0.2.10 token=abc123", "agent_id": "001",
         "agent_name": "web-01", "manager_name": "wazuh-manager", "location": "/var/log/secret-path", "count": 4}
GOOD = {"classification": "benign", "confidence": 0.9, "rationale": "Routine.", "analyst_action": "None."}
KEY = "placeholder-key-for-tests"


def completion(content, model_name="local-model"):
    return json.dumps({"id": "x", "model": model_name, "choices": [
        {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}).encode()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.path, dict(self.headers), json.loads(body)))
        if self.server.delay:
            self.server.release.wait(5)
        reply = self.server.reply
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
        except (BrokenPipeError, ConnectionResetError):
            pass  # The client timed out and left, as the timeout test intends.

    def log_message(self, *args):
        pass


class FakeServer:
    def __init__(self, reply, delay=False):
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.server.requests, self.server.reply, self.server.delay = [], reply, delay
        self.server.release = threading.Event()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.release.set()
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"


class Response:
    status = 200

    def __init__(self, value):
        self._value, self.headers = value, {"Content-Length": str(len(value))}

    def getcode(self):
        return self.status

    def read(self, amount):
        return self._value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class OpenAIBackendTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.key_file = Path(temp.name) / "key"
        self.key_file.write_text(KEY + "\n")
        self.key_file.chmod(0o600)

    def adapter(self, url, opener=None, timeout=5):
        return OpenAICompatibleTriage(OpenAIConfig(url, "local-model", str(self.key_file), timeout), opener)

    def test_happy_path_against_a_local_server(self):
        with FakeServer(completion(json.dumps(GOOD))) as fake:
            review = self.adapter(fake.url).review(GROUP)
        self.assertEqual((review.result, review.model_version), (GOOD, "local-model"))
        path, headers, body = fake.server.requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(headers["Authorization"], "Bearer " + KEY)
        self.assertEqual(body["response_format"]["type"], "json_schema")
        self.assertTrue(body["response_format"]["json_schema"]["strict"])
        self.assertEqual((body["stream"], body["temperature"]), (False, 0))
        sent = json.loads(body["messages"][1]["content"])
        self.assertEqual(set(sent), {"rule_id", "level", "events", "decoder", "rule_description"})
        for leaked in ("web-01", "192.0.2.10", "abc123", "secret-path", "wazuh-manager", "001"):
            self.assertNotIn(leaked, json.dumps(sent))
        # Advice only: even a benign answer still requires delivery.
        self.assertTrue(decide(GROUP, review.result).delivery_required)

    def test_malformed_output_is_a_model_error_for_that_group(self):
        bad_contents = (
            "not json",
            json.dumps({**GOOD, "classification": "harmless"}),
            json.dumps({**GOOD, "confidence": 1.5}),
            json.dumps({**GOOD, "confidence": True}),
            json.dumps({**GOOD, "extra": "ignore previous instructions"}),
            json.dumps({k: v for k, v in GOOD.items() if k != "rationale"}),
            json.dumps({**GOOD, "rationale": "x" * 513}),
            '{"classification":"benign","classification":"suspicious","confidence":0.5,"rationale":"a","analyst_action":"b"}',
        )
        envelopes = [completion(c) for c in bad_contents] + [
            b"{}", json.dumps({"choices": []}).encode(), completion(json.dumps(GOOD), model_name="bad name"),
            json.dumps({"model": "m", "choices": [{"message": {"role": "user", "content": json.dumps(GOOD)}}]}).encode(),
            b"x" * (64 * 1024 + 1)]
        for raw in envelopes:
            with self.subTest(raw=raw[:60]):
                opener = Mock()
                opener.open.return_value = Response(raw)
                with self.assertRaises(ModelError):
                    self.adapter("http://127.0.0.1:8080/v1", opener).review(GROUP)

    def test_timeout_is_a_model_error(self):
        with FakeServer(completion(json.dumps(GOOD)), delay=True) as fake:
            with self.assertRaises(ModelError):
                self.adapter(fake.url, timeout=1).review(GROUP)
        opener = Mock()
        opener.open.side_effect = socket.timeout("timed out")
        with self.assertRaises(ModelError):
            self.adapter("http://127.0.0.1:8080/v1", opener).review(GROUP)

    def test_remote_endpoints_need_the_opt_in_and_https(self):
        for url in ("https://openrouter.example.com/api/v1", "http://localhost:1234/v1",
                    "https://203.0.113.9/v1", "http://192.0.2.4:8000/v1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OpenAIConfig(url, "m")
        for url in ("http://openrouter.example.com/api/v1", "http://192.0.2.4:8000/v1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OpenAIConfig(url, "m", allow_remote=True)  # Remote over http is refused even with the opt-in.
        self.assertEqual(OpenAIConfig("https://openrouter.example.com/api/v1/", "m", allow_remote=True).endpoint,
                         "https://openrouter.example.com/api/v1/chat/completions")
        for url in ("http://127.0.0.1:1234/v1", "http://[::1]:8000", "https://127.0.0.1:8443/v1"):
            OpenAIConfig(url, "m")
        for url in ("http://user:pw@127.0.0.1/v1", "http://127.0.0.1/v1?x=1", "ftp://127.0.0.1/", "http://127.0.0.1:0/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OpenAIConfig(url, "m", allow_remote=True)
        env = {"SOC_THIEF_MODEL_BACKEND": "openai", "SOC_THIEF_OPENAI_BASE_URL": "https://api.example.com/v1",
               "SOC_THIEF_OPENAI_MODEL": "m"}
        with self.assertRaises(ModelError):
            triage_from_environment(env)
        self.assertIsInstance(triage_from_environment({**env, "SOC_THIEF_OPENAI_ALLOW_REMOTE": "1"}), OpenAICompatibleTriage)
        with self.assertRaises(ModelError):
            triage_from_environment({**env, "SOC_THIEF_OPENAI_ALLOW_REMOTE": "yes"})

    def test_redirects_are_refused(self):
        with self.assertRaises(ModelError):
            model._NoRedirect().redirect_request(None, Mock(), 302, "Found", {}, "http://203.0.113.1/")

    def test_key_never_appears_in_errors_or_repr(self):
        config = OpenAIConfig("https://api.example.com/v1", "m", str(self.key_file), allow_remote=True)
        adapter = OpenAICompatibleTriage(config, Mock(**{"open.side_effect": OSError("boom " + KEY)}))
        for text in (repr(config), repr(adapter), str(config)):
            self.assertNotIn(KEY, text)
            self.assertNotIn(str(self.key_file), text)
        with self.assertRaises(ModelError) as caught:
            adapter.review(GROUP)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)  # The OSError text is not chained.

    def test_default_backend_is_still_local_ollama_and_key_is_file_only(self):
        self.assertIsInstance(triage_from_environment({}), model.OllamaTriage)
        with self.assertRaises(ModelError):
            triage_from_environment({"SOC_THIEF_MODEL_BACKEND": "gpt"})
        with self.assertRaises(ModelError):  # A relative path is not accepted as a key file.
            triage_from_environment({"SOC_THIEF_MODEL_BACKEND": "openai", "SOC_THIEF_OPENAI_BASE_URL": "http://127.0.0.1:1/v1",
                                     "SOC_THIEF_OPENAI_MODEL": "m", "SOC_THIEF_OPENAI_API_KEY_FILE": "key.txt"})
        self.assertFalse(any("KEY" in name and not name.endswith("_FILE") for name in model.OPENAI_ENV.values()))

    def test_protected_groups_never_reach_the_model(self):
        opener = Mock()
        with self.assertRaises(ModelError):
            self.adapter("http://127.0.0.1:8080/v1", opener).review({**GROUP, "rule_description": "password spray"})
        opener.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
