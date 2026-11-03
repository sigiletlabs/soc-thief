"""Synthetic breach follow-up checks; no Wazuh, ntfy, Ollama or other endpoint is contacted."""
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from soc_thief import autoinvestigate, fastpath
from soc_thief.autoinvestigate import raise_only, validate
from soc_thief.fastpath import FastPathError, run

from tests.test_fastpath import KEY, NOW, Collector, record

# A fictional RMM product and its install path, as an operator would configure them.
RMM = r"ExampleRMM Agent, C:\Program Files\ExampleRMM\agent.exe"


def malware(agent="042", minutes=10, rule="513"):
    return record(f"m{agent}{rule}", at=NOW - timedelta(minutes=minutes), rule=rule, agent=agent,
                  description="Windows malware detected secret-description", data__srcip="198.51.100.7")


class SearchCollector(Collector):
    def __init__(self, records=(), fail=False):
        super().__init__(records)
        self.searches, self.fail = [], fail

    def sample_case(self, **kwargs):
        self.searches.append(kwargs)
        if self.fail:
            raise RuntimeError("synthetic search failure")
        row = record("s", at=NOW - timedelta(minutes=10), rule=kwargs.get("rule_id") or "999",
                     agent=kwargs["agent_id"], description="Nearby secret-description 10.0.0.9")
        return (12, (row,)) if kwargs.get("rule_id") else (3, (row,))


class Pager:
    def __init__(self, fail_breach=False, fail_follow_up=False):
        self.sent, self.fail_breach, self.fail_follow_up = [], fail_breach, fail_follow_up

    def send(self, page):
        follow = page.title.startswith("Soc Thief investigation")
        if (self.fail_follow_up and follow) or (self.fail_breach and not follow):
            raise FastPathError("ntfy page failed")
        self.sent.append(page)


class Model:
    def __init__(self, answer=None, error=False):
        self.answer = answer or {"assessment": "suspicious", "urgency": "high"}
        self.error, self.payloads, self.systems, self.schemas = error, [], [], []

    def ask(self, system, payload, schema):
        self.payloads.append(payload)
        self.systems.append(system)
        self.schemas.append(schema)
        if self.error:
            raise RuntimeError("synthetic model failure")
        return self.answer, "qwen3:4b"


# Everything a follow-up page body may contain: fixed text, signal names, agent ids, the
# 64-hex case token, closed-set values and count buckets.
_ALLOWED_LINE = re.compile(
    r"Signal: [a-z_]+|Agent: \d{3}|Case: [0-9a-f]{64}( \(\+\d+ more, not investigated\))?"
    r"|Assessment: (likely_benign_admin_tool|suspicious|likely_malicious|undetermined)"
    r"|RMM possible: (yes|no)|Same rule, last 7 days: (0|1-9|10-99|100\+) alerts"
    r"|Other rules within 15 minutes: (0|1-9|10-99|100\+) alerts|Local brief: (written|not written)"
    r"|Investigation failed: (evidence search failed|model review failed|model answer invalid|investigation error)\."
    r"|A benign assessment is not a dismissal; confirm in Wazuh\."
    r"|The breach page still stands\. Nothing was dismissed, retracted or downgraded\."
    r"|Investigation (skipped \(limit \d+ per check or time budget\)|not configured"
    r"|failed \(model configuration is invalid\)) for \d+ breach page\(s\) in this check:"
    r"|[a-z_]+ on agent \d{3}|\(\+\d+ more\)|The pages still stand\.")


class FollowUpTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        os.chmod(self.root, 0o700)
        key = self.root / "identity_key"
        key.write_text(KEY)
        key.chmod(0o600)
        self.env = {"STATE_PATH": str(self.root), "SOC_THIEF_IDENTITY_KEY_FILE": str(key),
                    "MODEL_BASE_URL": "http://127.0.0.1:11434"}

    def check(self, records, *, model=None, pager=None, collector=None, monotonic=lambda: 0.0, now=NOW):
        pager, model = pager or Pager(), model or Model()
        collector = collector or SearchCollector(records)
        with patch.object(autoinvestigate, "_model", lambda env: (model, 30)):
            code, status = run(env=self.env, now=now, collector=collector, pager=pager, monotonic=monotonic)
        return code, status, pager, model, collector

    def assert_fixed_vocabulary(self, page):
        for line in page.body.splitlines():
            self.assertRegex(line, _ALLOWED_LINE)
            self.assertIsNotNone(_ALLOWED_LINE.fullmatch(line), line)
        for leaked in ("secret", "198.51", "10.0.0", "Windows", "rationale"):
            self.assertNotIn(leaked, page.title + page.body)

    def test_breach_page_goes_first_unchanged_then_a_typed_follow_up(self):
        code, _, pager, model, collector = self.check([malware()])
        self.assertEqual(code, fastpath.OK)
        breach, follow = pager.sent
        self.assertEqual(breach.title, "Soc Thief breach: malware")
        self.assertEqual(breach.priority, "urgent")
        self.assertTrue(follow.title.startswith("Soc Thief investigation: malware"))
        case = re.search(r"Case: ([0-9a-f]{64})", breach.body).group(1)
        self.assertIn(f"Case: {case}", follow.body)
        self.assertIn("Assessment: suspicious", follow.body)
        self.assertIn("Same rule, last 7 days: 10-99 alerts", follow.body)
        self.assertIn("Other rules within 15 minutes: 1-9 alerts", follow.body)
        self.assert_fixed_vocabulary(follow)
        # The two case searches ran with the rule and agent from the group, no service lookup.
        self.assertEqual([(s.get("rule_id"), s.get("exclude_rule"), s["agent_id"]) for s in collector.searches],
                         [("513", None, "042"), (None, "513", "042")])
        # The model saw no hostname, path or address, though it is local.
        sent = json.dumps(model.payloads)
        for leaked in ("secret-hostname", "secret-path", "198.51.100.7", "10.0.0.9"):
            self.assertNotIn(leaked, sent)

    def test_same_page_and_state_with_or_without_investigation(self):
        _, _, with_model, _, _ = self.check([malware()])
        (self.root / fastpath.STATE_NAME).unlink()
        env = dict(self.env)
        del self.env["MODEL_BASE_URL"]
        _, _, without, _, collector = self.check([malware()])
        self.env = env
        self.assertEqual(with_model.sent[0], without.sent[0])
        self.assertEqual(collector.searches, [])
        self.assertEqual(len(without.sent), 1)  # Not configured: the page alone, no follow-up.

    def test_model_can_raise_but_never_lower_priority(self):
        self.assertEqual(raise_only("default", "urgent"), "urgent")
        self.assertEqual(raise_only("high", "low"), "high")
        self.assertEqual(raise_only("urgent", "min"), "urgent")
        self.assertEqual(raise_only("high", None), "high")
        _, _, pager, _, _ = self.check([malware()], model=Model(
            {"assessment": "likely_malicious", "urgency": "min"}))
        self.assertEqual(pager.sent[1].priority, "urgent")

    def test_benign_assessment_still_says_the_alert_stands_and_changes_nothing(self):
        self.env[autoinvestigate.RMM_ENV] = RMM
        benign = Model({"assessment": "likely_benign_admin_tool", "rmm_possible": True, "urgency": "min"})
        code, _, pager, _, _ = self.check([malware()], model=benign)
        breach, follow = pager.sent
        self.assertEqual(code, fastpath.OK)
        self.assertEqual((breach.title, breach.priority), ("Soc Thief breach: malware", "urgent"))
        self.assertIn("RMM possible: yes", follow.body)
        self.assertIn("The breach page still stands", follow.body)
        self.assertIn("not a dismissal", follow.body)
        self.assertEqual(follow.priority, "urgent")
        self.assert_fixed_vocabulary(follow)

    def test_invalid_model_output_is_an_investigation_failed_follow_up(self):
        # Without RMM markers configured, an rmm_possible key is an unexpected key.
        for answer in ({"assessment": "benign", "urgency": "high"},
                       {"assessment": "suspicious", "rmm_possible": False, "urgency": "high"},
                       {"assessment": "suspicious", "urgency": "max"},
                       {"assessment": "suspicious", "urgency": "high",
                        "rationale": "secret free text"}):
            with self.subTest(answer=answer):
                (self.root / fastpath.STATE_NAME).unlink(missing_ok=True)
                code, _, pager, _, _ = self.check([malware()], model=Model(answer))
                self.assertEqual(code, fastpath.OK)
                self.assertEqual(pager.sent[0].title, "Soc Thief breach: malware")
                self.assertEqual(pager.sent[1].title, "Soc Thief investigation failed: malware")
                self.assertIn("Investigation failed: model answer invalid.", pager.sent[1].body)
                self.assertEqual(pager.sent[1].priority, "urgent")
                self.assert_fixed_vocabulary(pager.sent[1])
        with self.assertRaises(ValueError):
            validate([])

    def test_model_or_search_failure_pages_anyway(self):
        _, _, pager, _, _ = self.check([malware()], model=Model(error=True))
        self.assertIn("Investigation failed: model review failed.", pager.sent[1].body)
        (self.root / fastpath.STATE_NAME).unlink()
        _, _, pager, _, _ = self.check([malware()], collector=SearchCollector([malware()], fail=True))
        self.assertEqual(pager.sent[0].title, "Soc Thief breach: malware")
        self.assertIn("Investigation failed: evidence search failed.", pager.sent[1].body)

    def test_over_the_cap_gets_one_skipped_follow_up_never_silence(self):
        records = [malware(agent=f"{n:03}") for n in range(autoinvestigate.MAX_INVESTIGATIONS + 2)]
        _, _, pager, model, _ = self.check(records)
        breaches = [p for p in pager.sent if p.title.startswith("Soc Thief breach")]
        follows = [p for p in pager.sent if p.title.startswith("Soc Thief investigation: ")]
        skipped = [p for p in pager.sent if p.title == "Soc Thief investigation skipped"]
        self.assertEqual((len(breaches), len(follows), len(skipped)),
                         (autoinvestigate.MAX_INVESTIGATIONS + 2, autoinvestigate.MAX_INVESTIGATIONS, 1))
        self.assertEqual(len(model.payloads), autoinvestigate.MAX_INVESTIGATIONS)
        self.assertIn("for 2 breach page(s)", skipped[0].body)
        self.assertEqual(skipped[0].priority, "urgent")
        self.assert_fixed_vocabulary(skipped[0])
        # Every breach page went out before any follow-up.
        self.assertEqual(pager.sent[:len(breaches)], breaches)

    def test_no_time_left_skips_investigation_but_still_follows_up(self):
        clock = iter([0.0] + [fastpath.DEADLINE_SECONDS - 10.0] * 50)
        _, _, pager, model, collector = self.check([malware()], monotonic=lambda: next(clock))
        self.assertEqual([p.title for p in pager.sent],
                         ["Soc Thief breach: malware", "Soc Thief investigation skipped"])
        self.assertEqual((model.payloads, collector.searches), ([], []))

    def test_lost_follow_up_is_a_health_failure_but_page_and_checkpoint_stand(self):
        code, status, pager, _, _ = self.check([malware()], pager=Pager(fail_follow_up=True))
        self.assertEqual(code, fastpath.FAILED)
        self.assertIn("investigation follow-up failed", status)
        self.assertEqual([p.title for p in pager.sent], ["Soc Thief breach: malware"])
        state = json.loads((self.root / fastpath.STATE_NAME).read_text())
        self.assertEqual(state["checkpoint"], (NOW - fastpath.LAG).isoformat())
        # The next run neither repeats the page nor the investigation.
        code, _, again, _, _ = self.check([malware()], now=NOW + timedelta(minutes=10))
        self.assertEqual((code, again.sent), (fastpath.OK, []))

    def test_only_pages_accepted_in_this_run_are_investigated(self):
        code, _, pager, model, _ = self.check([malware()], pager=Pager(fail_breach=True))
        self.assertEqual((code, pager.sent, model.payloads), (fastpath.FAILED, [], []))

    def test_unexpected_error_never_reaches_the_fast_path(self):
        self.assertFalse(autoinvestigate.follow_up(
            env={}, now=NOW, collector=None, pager=None, key=b"x", groups=[], breaches={},
            due=[("malware", "001", None)], paged=None, deadline=0, monotonic=lambda: 0))

    def test_invalid_model_configuration_still_follows_up(self):
        self.env["MODEL_BASE_URL"] = "http://198.51.100.1:11434"  # Not loopback: refused.
        pager = Pager()
        code, _ = run(env=self.env, now=NOW, collector=SearchCollector([malware()]), pager=pager)
        self.assertEqual(code, fastpath.OK)
        self.assertEqual([p.title for p in pager.sent],
                         ["Soc Thief breach: malware", "Soc Thief investigation failed"])
        self.assert_fixed_vocabulary(pager.sent[1])

    def test_brief_is_local_private_bounded_and_pruned(self):
        directory = self.root / autoinvestigate.BRIEF_DIR
        directory.mkdir(mode=0o700)
        for n in range(autoinvestigate.MAX_BRIEFS):
            (directory / f"20000101T0000{n:02}Z-old.txt").write_text("old")
        _, _, pager, _, _ = self.check([malware()])
        self.assertIn("Local brief: written", pager.sent[1].body)
        briefs = sorted(directory.iterdir())
        self.assertEqual(len(briefs), autoinvestigate.MAX_BRIEFS)
        self.assertFalse((directory / "20000101T000000Z-old.txt").exists())
        brief = briefs[-1]
        self.assertEqual(brief.stat().st_mode & 0o777, 0o600)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        text = brief.read_text()
        self.assertIn("Breach signal: malware", text)
        self.assertIn("Assessment: suspicious", text)
        self.assertLessEqual(len(text.encode()), autoinvestigate.BRIEF_LIMIT)

    def test_unsafe_brief_directory_is_not_written_and_the_follow_up_says_so(self):
        (self.root / autoinvestigate.BRIEF_DIR).mkdir(mode=0o755)
        os.chmod(self.root / autoinvestigate.BRIEF_DIR, 0o755)
        _, _, pager, _, _ = self.check([malware()])
        self.assertIn("Local brief: not written", pager.sent[1].body)
        self.assertEqual(list((self.root / autoinvestigate.BRIEF_DIR).iterdir()), [])


if __name__ == "__main__":
    unittest.main()


class RmmMarkersTest(unittest.TestCase):
    def test_unset_means_no_rmm_question_at_all(self):
        self.assertEqual(autoinvestigate.rmm_markers({}), ())
        self.assertEqual(autoinvestigate.rmm_markers({autoinvestigate.RMM_ENV: " , "}), ())
        schema = autoinvestigate._schema(())
        self.assertNotIn("rmm_possible", schema["properties"])
        self.assertNotIn("RMM", autoinvestigate._system(()))
        self.assertIsNone(validate({"assessment": "suspicious", "urgency": "high"}).rmm_possible)

    def test_configured_markers_reach_the_prompt_and_require_the_answer(self):
        markers = autoinvestigate.rmm_markers({autoinvestigate.RMM_ENV: RMM})
        self.assertEqual(markers, ("ExampleRMM Agent", r"C:\Program Files\ExampleRMM\agent.exe"))
        self.assertEqual(autoinvestigate._schema(markers)["required"], ["assessment", "rmm_possible", "urgency"])
        system = autoinvestigate._system(markers)
        self.assertIn('"ExampleRMM Agent"', system)
        self.assertIn("rmm_possible", system)
        self.assertTrue(validate({"assessment": "suspicious", "rmm_possible": False, "urgency": "high"},
                                 rmm=True).rmm_possible is False)
        for answer in ({"assessment": "suspicious", "urgency": "high"},
                       {"assessment": "suspicious", "rmm_possible": "no", "urgency": "high"}):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                validate(answer, rmm=True)

    def test_malformed_markers_are_refused(self):
        for raw in ("a\x00b", ",".join(["m"] * 17), "x" * 129):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                autoinvestigate.rmm_markers({autoinvestigate.RMM_ENV: raw})


class RmmFollowUpTest(unittest.TestCase):
    """The configured path end to end: prompt, schema and page line."""

    setUp, check, assert_fixed_vocabulary = FollowUpTest.setUp, FollowUpTest.check, FollowUpTest.assert_fixed_vocabulary

    def test_markers_flow_to_model_and_page(self):
        self.env[autoinvestigate.RMM_ENV] = RMM
        model = Model({"assessment": "suspicious", "rmm_possible": False, "urgency": "high"})
        _, _, pager, model, _ = self.check([malware()], model=model)
        self.assertIn("ExampleRMM Agent", model.systems[0])
        self.assertIn("rmm_possible", model.schemas[0]["properties"])
        self.assertIn("RMM possible: no", pager.sent[1].body)
        self.assert_fixed_vocabulary(pager.sent[1])

    def test_unset_markers_leave_rmm_out_of_the_page(self):
        _, _, pager, model, _ = self.check([malware()])
        self.assertNotIn("rmm_possible", model.schemas[0]["properties"])
        self.assertNotIn("RMM", pager.sent[1].body)

    def test_malformed_markers_fail_the_follow_up_not_the_page(self):
        self.env[autoinvestigate.RMM_ENV] = "bad\x07marker"
        code, _, pager, _, _ = self.check([malware()])
        self.assertEqual(pager.sent[0].title, "Soc Thief breach: malware")
        self.assertIn("model configuration is invalid", pager.sent[1].body)
