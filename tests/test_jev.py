"""Synthetic hosted Jev trial boundary tests."""

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from io import BytesIO
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

from soc_thief.model import JevConfig, JevTriage, ModelError, triage_from_environment
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


def assert_fails_closed(case, adapter, opener, response):
    """Reset the repeated-failure cut-off first, or later cases would fail on the budget alone."""
    adapter._failures = 0
    opener.reset_mock()
    opener.open.return_value = response
    with case.assertRaises(ModelError) as caught:
        adapter.review(GROUP)
    case.assertEqual(str(caught.exception), "Jev review failed")
    opener.open.assert_called_once()


class JevVercelRouteTest(unittest.TestCase):
    """The older Vercel AI Gateway route, kept as an explicit option."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        path = Path(self.scratch.name) / "key"
        path.write_text("synthetic-key")
        os.chmod(path, 0o600)
        self.opener = Mock()
        self.adapter = JevTriage(JevConfig(str(path), endpoint="vercel"), self.opener, sleep=lambda _: None)
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
        self.assertEqual(request.full_url, "https://ai-gateway.vercel.sh/v4/ai/evaluation-model")
        self.assertEqual(request.get_header("Ai-model-id"), "typesafe-ai/jev")
        self.assertNotIn("model", json.loads(body))
        self.assertEqual(json.loads(body)["questions"]["suspicious"]["type"], "boolean")

    def test_bad_answer_fails_closed(self):
        for answer in ({"type": "boolean", "probability": 1.2},
                       {"type": "boolean", "probability": True},
                       {"type": "boolean", "probability": "0.8"}):
            with self.subTest(answer=answer):
                assert_fails_closed(self, self.adapter, self.opener, Response(json.dumps({"answers": {"suspicious": answer,
                "threat": {"type": "choice", "choice": "routine"}}}).encode()))

    def test_bad_threat_answer_fails_closed(self):
        for threat in ({"type": "choice", "choice": "cold"},
                       {"type": "choice", "choice": True},
                       {"type": "boolean", "choice": "routine"},
                       {"type": "choice"}):
            with self.subTest(threat=threat):
                assert_fails_closed(self, self.adapter, self.opener, Response(json.dumps({"answers": {"suspicious": {
                "type": "boolean", "probability": 0.87}, "threat": threat}}).encode()))

    def test_duplicate_or_oversized_response_fails_closed(self):
        for raw in (b'{"answers":{"suspicious":{"type":"boolean","probability":0.8,"probability":0.1}}}',
                    b"x" * (64 * 1024 + 1)):
            with self.subTest(size=len(raw)):
                assert_fails_closed(self, self.adapter, self.opener, Response(raw))

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



V1_OK = {"model": "jev-1.13.0", "usage": {"input_tokens": 360, "output_tokens": 39}, "answers": {
    "suspicious": {"type": "noul", "noul": 0.87},
    "threat": {"type": "choice", "choice": "other_concern", "confidence": 0.6,
               "probabilities": {"other_concern": 0.6, "routine": 0.4}}}}


def v1_with(**answers):
    return Response(json.dumps({**V1_OK, "answers": {**V1_OK["answers"], **answers}}).encode())


class JevTypeSafeRouteTest(unittest.TestCase):
    """TypeSafe's own System One API, the default route. No network: the opener is a mock.

    The OpenRouter preset speaks the same API and reruns every test below with its own URL and model.
    """

    ENDPOINT, URL, MODEL = None, "https://api.typesafe.ai/v1/systemone", "jev-latest"

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.key_path = Path(self.scratch.name) / "key"
        self.key_path.write_text("synthetic-key")
        os.chmod(self.key_path, 0o600)
        self.opener = Mock()
        self.config = (JevConfig(str(self.key_path)) if self.ENDPOINT is None
                       else JevConfig(str(self.key_path), endpoint=self.ENDPOINT))
        self.adapter = JevTriage(self.config, self.opener, sleep=lambda _: None)
        self.adapter.prepare([GROUP])

    def test_default_route_and_request_shape(self):
        self.opener.open.return_value = v1_with()
        review = self.adapter.review(GROUP)
        request = self.opener.open.call_args.args[0]
        body = json.loads(request.data.decode())
        self.assertEqual(request.full_url, self.URL)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-key")
        self.assertIsNone(request.get_header("Ai-model-id"))
        self.assertIsNone(request.get_header("Ai-gateway-auth-method"))
        self.assertEqual(list(body), ["model", "state", "questions"])
        self.assertEqual(body["model"], self.MODEL)
        self.assertEqual(body["questions"]["suspicious"]["type"], "noul")
        self.assertEqual(set(body["questions"]["suspicious"]["criteria"]), {"true", "false"})
        self.assertEqual(body["questions"]["threat"]["type"], "choice")
        self.assertIsInstance(body["questions"]["threat"]["criteria"], dict)
        self.assertEqual(body["state"]["group"]["agent"], "host-01")
        for raw in ("LabNode", "LabManager", "192.0.2.1", "example.invalid", GROUP["timestamp"]):
            self.assertNotIn(raw, request.data.decode())
        self.assertEqual(review.attention_probability, 0.87)
        self.assertEqual(review.threat_label, "other_concern")
        self.assertEqual(review.model_version, self.MODEL)
        self.assertTrue(decide(GROUP, review.result).delivery_required)

    def test_model_setting_is_sent(self):
        adapter = JevTriage(JevConfig(str(self.key_path), endpoint=self.config.endpoint, model="jev-1.13.0"), self.opener, sleep=lambda _: None)
        adapter.prepare([GROUP])
        self.opener.open.return_value = v1_with()
        adapter.review(GROUP)
        self.assertEqual(json.loads(self.opener.open.call_args.args[0].data)["model"], "jev-1.13.0")

    def test_malformed_noul_fails_closed(self):
        for answer in ({"type": "noul", "noul": 1.2}, {"type": "noul", "noul": -0.1},
                       {"type": "noul", "noul": True}, {"type": "noul", "noul": "0.8"},
                       {"type": "noul"}, {"type": "boolean", "probability": 0.8},
                       {"type": "noul", "probability": 0.8}, [0.8], None):
            with self.subTest(answer=answer):
                assert_fails_closed(self, self.adapter, self.opener, v1_with(suspicious=answer))

    def test_non_finite_noul_fails_closed(self):
        raw = json.dumps(V1_OK).replace('"noul": 0.87', '"noul": NaN').encode()
        assert_fails_closed(self, self.adapter, self.opener, Response(raw))

    def test_malformed_choice_fails_closed(self):
        good = V1_OK["answers"]["threat"]
        for threat in ({**good, "choice": "cold"}, {**good, "choice": True}, {**good, "type": "noul"},
                       {k: v for k, v in good.items() if k != "choice"},
                       {k: v for k, v in good.items() if k != "confidence"},
                       {k: v for k, v in good.items() if k != "probabilities"},
                       {**good, "confidence": 1.5}, {**good, "confidence": "high"},
                       {**good, "probabilities": {"cold": 1.0}},
                       {**good, "probabilities": {"routine": 2}}, {**good, "probabilities": [0.6]}):
            with self.subTest(threat=threat):
                assert_fails_closed(self, self.adapter, self.opener, v1_with(threat=threat))

    def test_extra_or_missing_answers_fail_closed(self):
        for answers in ({"suspicious": V1_OK["answers"]["suspicious"]},
                        {**V1_OK["answers"], "extra": {"type": "noul", "noul": 0.1}}, {}, []):
            with self.subTest(answers=answers):
                assert_fails_closed(self, self.adapter, self.opener, Response(json.dumps({**V1_OK, "answers": answers}).encode()))
        for document in ([], {"model": "jev"}, "answers"):
            assert_fails_closed(self, self.adapter, self.opener, Response(json.dumps(document).encode()))

    def test_error_body_and_key_never_leave_in_errors(self):
        for code, detail in ((400, b'{"detail":"LEAKED-DETAIL synthetic-key"}'),
                             (422, b'{"detail":[{"loc":["body"],"msg":"LEAKED-DETAIL","type":"x"}]}'),
                             (401, b'{"detail":"LEAKED-DETAIL"}'), (302, b"")):
            self.adapter._failures = 0  # Isolate each case from the repeated-failure cut-off.
            http_error = HTTPError(self.URL, code, "synthetic", {}, BytesIO(detail))
            self.addCleanup(http_error.close)
            self.opener.open.side_effect = http_error
            with self.subTest(code=code), self.assertRaises(ModelError) as caught:
                self.adapter.review(GROUP)
            error = caught.exception
            self.assertEqual(str(error), "Jev review failed")
            self.assertIsNone(error.__cause__)
            self.assertTrue(error.__suppress_context__)
            for text in (str(error), repr(error), repr(self.config), repr(self.adapter)):
                self.assertNotIn("synthetic-key", text)
                self.assertNotIn("LEAKED-DETAIL", text)
        self.assertEqual(self.opener.open.call_count, 4)  # Client errors are not retried.

    def test_timeout_fails_closed(self):
        self.opener.open.side_effect = TimeoutError()
        with self.assertRaises(ModelError):
            self.adapter.review(GROUP)

    def test_configuration(self):
        key = str(self.key_path)
        base = {"SOC_THIEF_JEV_KEY_FILE": key}
        cases = (({"SOC_THIEF_JEV_TRIAL": "1", **base}, "typesafe", "jev-latest"),
                 ({"SOC_THIEF_MODEL_BACKEND": "jev", **base, "SOC_THIEF_JEV_ENDPOINT": ""}, "typesafe", "jev-latest"),
                 ({"SOC_THIEF_JEV_TRIAL": "1", **base, "SOC_THIEF_JEV_ENDPOINT": "vercel"}, "vercel", "typesafe-ai/jev"),
                 ({"SOC_THIEF_MODEL_BACKEND": "jev", **base, "SOC_THIEF_JEV_ENDPOINT": "openrouter"},
                  "openrouter", "typesafe/jev-1.13"),
                 ({"SOC_THIEF_JEV_TRIAL": "1", **base, "SOC_THIEF_JEV_MODEL": "jev-1.13.0"}, "typesafe", "jev-1.13.0"))
        for env, endpoint, model in cases:
            config = triage_from_environment(env)._config
            self.assertEqual((config.endpoint, config.model), (endpoint, model))
        for bad in ({"SOC_THIEF_JEV_ENDPOINT": "https://evil.invalid"}, {"SOC_THIEF_JEV_ENDPOINT": "TypeSafe"},
                    {"SOC_THIEF_JEV_MODEL": "jev latest"}, {"SOC_THIEF_JEV_MODEL": "x" * 200},
                    {"SOC_THIEF_JEV_MODEL": "-jev"}):
            with self.subTest(bad=bad), self.assertRaises(ModelError):
                triage_from_environment({"SOC_THIEF_JEV_TRIAL": "1", **base, **bad})


class JevOpenRouterRouteTest(JevTypeSafeRouteTest):
    """OpenRouter's native System One route: same client and parser, different URL and model."""

    ENDPOINT, URL, MODEL = "openrouter", "https://openrouter.ai/api/v1/systemone", "typesafe/jev-1.13"

    def test_preset(self):
        self.assertEqual((self.config.url, self.config.model), (self.URL, self.MODEL))



class JevCustomServerTest(unittest.TestCase):
    """Any System One server by base URL, under the same guard as the OpenAI-compatible backend."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.key_path = Path(self.scratch.name) / "key"
        self.key_path.write_text("synthetic-key")
        os.chmod(self.key_path, 0o600)
        self.key = {"SOC_THIEF_JEV_KEY_FILE": str(self.key_path)}

    @staticmethod
    def config(**env):
        return triage_from_environment({"SOC_THIEF_MODEL_BACKEND": "jev", **env})._config

    def test_loopback_http_needs_no_key(self):
        config = self.config(SOC_THIEF_JEV_BASE_URL="http://127.0.0.1:8080/v1/", SOC_THIEF_JEV_MODEL="local-jev")
        self.assertEqual((config.endpoint, config.url, config.model, config.key_file),
                         ("custom", "http://127.0.0.1:8080/v1/systemone", "local-jev", None))
        opener = Mock()
        opener.open.return_value = v1_with()
        adapter = JevTriage(config, opener, sleep=lambda _: None)
        adapter.prepare([GROUP])
        review = adapter.review(GROUP)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8080/v1/systemone")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(json.loads(request.data)["model"], "local-jev")
        self.assertEqual(json.loads(request.data)["questions"]["suspicious"]["type"], "noul")
        self.assertNotIn("LabNode", request.data.decode())
        self.assertEqual((review.attention_probability, review.model_version), (0.87, "local-jev"))
        self.assertTrue(decide(GROUP, review.result).delivery_required)

    def test_loopback_with_key_sends_it(self):
        config = self.config(**self.key, SOC_THIEF_JEV_BASE_URL="http://[::1]:9000", SOC_THIEF_JEV_MODEL="jev")
        opener = Mock()
        opener.open.return_value = v1_with()
        adapter = JevTriage(config, opener, sleep=lambda _: None)
        adapter.prepare([GROUP])
        adapter.review(GROUP)
        self.assertEqual(opener.open.call_args.args[0].get_header("Authorization"), "Bearer synthetic-key")
        self.assertNotIn("synthetic-key", repr(config))

    def test_remote_needs_https_and_opt_in(self):
        remote = {**self.key, "SOC_THIEF_JEV_MODEL": "jev"}
        config = self.config(**remote, SOC_THIEF_JEV_BASE_URL="https://jev.example.invalid/api",
                             SOC_THIEF_JEV_ALLOW_REMOTE="1")
        self.assertEqual(config.url, "https://jev.example.invalid/api/systemone")
        for env in ({"SOC_THIEF_JEV_BASE_URL": "https://jev.example.invalid/api"},
                    {"SOC_THIEF_JEV_BASE_URL": "https://jev.example.invalid/api", "SOC_THIEF_JEV_ALLOW_REMOTE": "0"},
                    {"SOC_THIEF_JEV_BASE_URL": "http://jev.example.invalid/api", "SOC_THIEF_JEV_ALLOW_REMOTE": "1"},
                    {"SOC_THIEF_JEV_BASE_URL": "http://192.0.2.10:8080", "SOC_THIEF_JEV_ALLOW_REMOTE": "1"},
                    {"SOC_THIEF_JEV_BASE_URL": "https://jev.example.invalid", "SOC_THIEF_JEV_ALLOW_REMOTE": "yes"}):
            with self.subTest(env=env), self.assertRaises(ModelError):
                self.config(**remote, **env)

    def test_localhost_is_remote(self):
        for env in ({"SOC_THIEF_JEV_BASE_URL": "http://localhost:8080"},
                    {"SOC_THIEF_JEV_BASE_URL": "http://localhost:8080", "SOC_THIEF_JEV_ALLOW_REMOTE": "1"},
                    {"SOC_THIEF_JEV_BASE_URL": "https://localhost:8080"}):
            with self.subTest(env=env), self.assertRaises(ModelError):
                self.config(**self.key, SOC_THIEF_JEV_MODEL="jev", **env)
        # Accepted only as a remote: https, acknowledged, and with a key.
        self.config(**self.key, SOC_THIEF_JEV_MODEL="jev", SOC_THIEF_JEV_BASE_URL="https://localhost:8080",
                    SOC_THIEF_JEV_ALLOW_REMOTE="1")
        with self.assertRaises(ModelError):
            self.config(SOC_THIEF_JEV_MODEL="jev", SOC_THIEF_JEV_BASE_URL="https://localhost:8080",
                        SOC_THIEF_JEV_ALLOW_REMOTE="1")

    def test_custom_route_needs_model_and_no_preset(self):
        for env in ({"SOC_THIEF_JEV_BASE_URL": "http://127.0.0.1:8080"},
                    {"SOC_THIEF_JEV_BASE_URL": "http://127.0.0.1:8080", "SOC_THIEF_JEV_MODEL": "jev",
                     "SOC_THIEF_JEV_ENDPOINT": "typesafe"},
                    {"SOC_THIEF_JEV_BASE_URL": "http://user:pw@127.0.0.1:8080", "SOC_THIEF_JEV_MODEL": "jev"},
                    {"SOC_THIEF_JEV_BASE_URL": "http://127.0.0.1:8080/?x=1", "SOC_THIEF_JEV_MODEL": "jev"},
                    {"SOC_THIEF_JEV_ENDPOINT": "custom", "SOC_THIEF_JEV_MODEL": "jev"}):
            with self.subTest(env=env), self.assertRaises(ModelError):
                self.config(**self.key, **env)

    def test_presets_count_as_the_remote_opt_in_and_still_need_a_key(self):
        for endpoint, url in (("", "https://api.typesafe.ai/v1/systemone"),
                              ("openrouter", "https://openrouter.ai/api/v1/systemone")):
            config = self.config(**self.key, SOC_THIEF_JEV_ENDPOINT=endpoint, SOC_THIEF_JEV_ALLOW_REMOTE="0")
            self.assertEqual(config.url, url)
            with self.assertRaises(ModelError):
                self.config(SOC_THIEF_JEV_ENDPOINT=endpoint)

    def test_redirect_refused(self):
        hits = []

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(302 if self.path.endswith("/systemone") else 200)
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):  # Where a followed redirect would land: a valid answer.
                hits.append(self.path)
                body = json.dumps(V1_OK).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Redirect)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        config = self.config(SOC_THIEF_JEV_BASE_URL=f"http://127.0.0.1:{server.server_port}",
                             SOC_THIEF_JEV_MODEL="jev")
        adapter = JevTriage(config, sleep=lambda _: None)
        adapter.prepare([GROUP])
        with self.assertRaises(ModelError) as caught:
            adapter.review(GROUP)
        self.assertEqual(str(caught.exception), "Jev review failed")
        self.assertEqual(hits, ["/systemone"])


if __name__ == "__main__":
    unittest.main()
