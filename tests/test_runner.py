"""Synthetic end-to-end runner checks; no Wazuh, model, or Discord endpoint is contacted."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from soc_thief.delivery import RenderedReport, render
from soc_thief.model import ModelError, ModelReview
from soc_thief.policy import Decision
from soc_thief.runner import RunnerLimits, RunResult, run_window
from soc_thief.state import StateError, StateStore, opaque_key
from soc_thief.tuning import Tuning, TuningEntry


START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(hours=1)
SUSPICIOUS = {"classification": "suspicious", "confidence": .5, "rationale": "review", "analyst_action": "review"}


def record(identifier="a", *, level=3, description="routine synthetic heartbeat", **breach_fields):
    fields = {
        "@timestamp": START.isoformat(), "rule.id": "100", "rule.level": level,
        "rule.description": description, "agent.id": "001", "agent.name": "synthetic",
        "decoder.name": "test", "manager.name": "test", "location": "synthetic",
        "rule.groups": None, "data.srcip": None, "syscheck.path": None, "syscheck.event": None,
        "syscheck.changed_attributes": None,
    }
    fields.update({name.replace("__", "."): value for name, value in breach_fields.items()})
    return {"source_key": {"index": "wazuh-alerts-synthetic", "id": identifier}, "fields": fields}


class Collector:
    def __init__(self, records=(), error=None): self.records, self.error, self.calls = records, error, 0
    def collect(self, start, end):
        self.calls += 1
        if self.error: raise self.error
        return iter(self.records)


class Model:
    def __init__(self, result=None, error=False): self.result, self.error, self.calls, self.groups = result or {"classification":"benign","confidence":.99,"rationale":"routine","analyst_action":"none"}, error, 0, []
    def review(self, group):
        self.calls += 1
        self.groups.append(dict(group))
        if self.error: raise ModelError("synthetic")
        return ModelReview(self.result, "synthetic")


class ScoringModel(Model):
    def prepare(self, groups):
        self.prepared = len(groups)
    def review(self, group):
        self.calls += 1
        return ModelReview(SUSPICIOUS, "synthetic-jev", 0.82, "other_concern")


class Delivery:
    def __init__(self, error=False): self.error, self.payloads = error, []
    def send(self, payload):
        self.payloads.append(payload)
        if self.error: raise Exception("synthetic")


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name) / "state"); self.addCleanup(lambda: self.store.close())
        self.key = b"k" * 32

    def execute(self, collector, model=None, delivery=None, start=START, end=END, **kwargs):
        now = kwargs.pop("now", lambda: end)
        return run_window(collector=collector, model=model or Model(), delivery=delivery or Delivery(), store=self.store,
                          identity_key=self.key, stream="daily", start=start, end=end,
                          now=now, **kwargs)

    def test_normal_delivery_and_benign_results_both_deliver(self):
        delivery = Delivery()
        result = self.execute(Collector([record()]), model=Model({"classification":"suspicious","confidence":.5,"rationale":"review","analyst_action":"review"}), delivery=delivery)
        self.assertTrue(result.completed); self.assertTrue(result.delivered); self.assertEqual(len(delivery.payloads), 1)
        self.store.close(); self.store = StateStore(Path(self.temp.name) / "state")
        later = END + timedelta(hours=1)
        second = record("b"); second["fields"]["@timestamp"] = END.isoformat()
        result = self.execute(Collector([second]), model=Model({"classification":"benign","confidence":.98,"rationale":"routine","analyst_action":"none"}), start=END, end=later)
        # Benign at the former 0.98 threshold is delivered like anything else.
        self.assertTrue(result.completed); self.assertTrue(result.delivered)

    def test_operator_verdict_appears_on_next_digest_without_suppressing(self):
        profile = lambda: {"total": 1, "groups": [{"rule_id": "100", "agent_id": "001",
                                                  "events": 1, "days_active": 1}]}
        first = Delivery()
        self.assertTrue(self.execute(Collector([record()]), delivery=first, baseline=profile).completed)
        case = self.store.cases(now=END)[0]
        self.assertEqual(case.status, "unreviewed")
        self.assertIn(case.token, first.payloads[0].attachment)
        self.store.mark_case(case.token, "routine", now=END)
        later = END + timedelta(hours=1)
        second_record = record("next")
        second_record["fields"]["@timestamp"] = END.isoformat()
        second = Delivery()
        result = self.execute(Collector([second_record]), delivery=second, start=END, end=later,
                              baseline=profile)
        self.assertTrue(result.delivered)
        self.assertIn("Prior analyst routine verdict: 1 groups", second.payloads[0].payloads[0]["content"])
        self.assertIn(f"{case.token} | routine", second.payloads[0].attachment)
        self.assertEqual(self.store.case(case.token, now=later).status, "routine")

    def test_protected_case_verdict_never_proposes_tuning(self):
        from soc_thief.cases import candidates
        self.assertTrue(self.execute(Collector([record(level=12)])).completed)
        case = self.store.cases(now=END)[0]
        self.assertFalse(case.tunable)
        self.store.mark_case(case.token, "routine", now=END)
        self.assertEqual(candidates(self.store, now=END), ())

    def test_model_identity_is_audited_without_model_prose(self):
        model = Model({"classification":"benign", "confidence":.99,
                       "rationale":"synthetic private rationale", "analyst_action":"private action"})
        self.assertTrue(self.execute(Collector([record()]), model=model).completed)
        with closing(sqlite3.connect(Path(self.temp.name) / "state" / "state.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT model_identity FROM audit").fetchone(), ("synthetic",))
        raw = (Path(self.temp.name) / "state" / "state.sqlite3").read_bytes()
        self.assertNotIn(b"synthetic private rationale", raw)
        self.assertNotIn(b"private action", raw)

    def test_protected_group_audit_has_no_model_identity(self):
        model = Model()
        self.assertTrue(self.execute(Collector([record(level=12)]), model=model).completed)
        self.assertEqual(model.calls, 0)
        with closing(sqlite3.connect(Path(self.temp.name) / "state" / "state.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT model_identity FROM audit").fetchone(), (None,))

    def test_protected_and_critical_bypass_model(self):
        for item in (record(level=12), record(description="password spray synthetic")):
            model, delivery = Model(), Delivery()
            self.assertTrue(self.execute(Collector([item]), model, delivery).delivered)
            self.assertEqual(model.calls, 0)

    def test_source_failure_fails_closed_with_safe_health_delivery(self):
        delivery = Delivery(); result = self.execute(Collector(error=RuntimeError("synthetic")), Model(), delivery)
        self.assertFalse(result.completed); self.assertTrue(result.health_failure); self.assertTrue(result.delivered)
        self.assertEqual(len(delivery.payloads), 1)

    def test_model_failure_delivers_the_window_instead_of_aborting_it(self):
        # A model result cannot change any delivery outcome, so a model
        # boundary failure must not abort a window it could not have influenced. The group
        # is delivered and the run reports a health failure, which delivers strictly more.
        model, delivery = Model(error=True), Delivery()
        result = self.execute(Collector([record()]), model, delivery)
        self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, True))
        self.assertEqual(model.calls, 1)
        self.assertEqual(self.audit(), ["invalid_model_result"])
        self.assertIn("health failures: 1", self.content(delivery))

    def test_multi_page_report_is_delivered_and_replayed_whole(self):
        # A day wider than one message becomes a page sequence. The outbox carries the
        # whole sequence, so a retry after a delivery failure replays every page, not page 1.
        records = [record(str(index), description="y" * 600) for index in range(40)]
        for index, item in enumerate(records):
            item["fields"]["rule.id"] = str(200 + index)
        first = Delivery(error=True)
        result = self.execute(Collector(records), model=Model(SUSPICIOUS), delivery=first)
        self.assertFalse(result.delivered)
        pages = len(first.payloads[0].payloads)
        self.assertGreater(pages, 1)
        retry = Delivery()
        result = self.execute(Collector(records), model=Model(SUSPICIOUS), delivery=retry)
        self.assertTrue(result.delivered)
        self.assertEqual(len(retry.payloads[0].payloads), pages)
        self.assertEqual(retry.payloads[0].payloads[0]["content"], first.payloads[0].payloads[0]["content"])
        self.assertIn("Remaining", retry.payloads[0].payloads[0]["content"])

    def test_baseline_makes_a_digest_whose_attachment_survives_a_retry(self):
        # With a baseline the report is one message plus an attached listing, and the outbox
        # replays both, so a delivery failure never loses the attachment.
        records = [record(str(index)) for index in range(3)]
        records[2]["fields"]["rule.id"] = "999"
        profile = lambda: {"total": 60, "groups": [{"rule_id": "100", "agent_id": "001", "events": 60, "days_active": 30}]}
        first = Delivery(error=True)
        result = self.execute(Collector(records), model=Model(SUSPICIOUS), delivery=first, baseline=profile)
        self.assertFalse(result.delivered)
        sent = first.payloads[0]
        self.assertEqual(len(sent.payloads), 1)
        self.assertIn("**NEW** sev 3 `999`", sent.payloads[0]["content"])
        self.assertIn("__Recurring — 1 groups across 1 rules, 2 events__", sent.payloads[0]["content"])
        self.assertIn("recurring | 3 | 100 | 2 |", sent.attachment)
        retry = Delivery()
        result = self.execute(Collector(records), model=Model(SUSPICIOUS), delivery=retry, baseline=profile)
        self.assertTrue(result.delivered)
        self.assertEqual(retry.payloads[0].attachment, sent.attachment)
        self.assertEqual(retry.payloads[0].payloads, sent.payloads)

    def test_jev_score_reaches_digest_without_changing_policy(self):
        model, delivery = ScoringModel(), Delivery()
        profile = lambda: {"total": 30, "groups": [{"rule_id": "100", "agent_id": "001",
                                                   "events": 30, "days_active": 30}]}
        result = self.execute(Collector([record()]), model=model, delivery=delivery, baseline=profile)
        self.assertEqual(model.prepared, 1)
        self.assertTrue(result.completed)
        self.assertIn("Jev 0.82", delivery.payloads[0].payloads[0]["content"])
        self.assertIn("Jev 0.82 [other concern]", delivery.payloads[0].payloads[0]["content"])
        self.assertIn(" | 0.82 | other_concern", delivery.payloads[0].attachment)
        self.assertEqual(self.audit(), ["model_requires_review"])

    def test_baseline_failure_lists_everything_and_raises_health(self):
        def broken(): raise RuntimeError("synthetic")
        for baseline in (broken, lambda: {"groups": [{"rule_id": "100"}]}, lambda: []):
            with self.subTest(baseline=baseline):
                self.store.close(); self.setUp()
                delivery = Delivery()
                result = self.execute(Collector([record()]), model=Model(SUSPICIOUS), delivery=delivery, baseline=baseline)
                self.assertTrue(result.delivered); self.assertTrue(result.health_failure)
                self.assertIsNone(delivery.payloads[0].attachment)
                self.assertIn("Soc Thief triage", delivery.payloads[0].payloads[0]["content"])

    def test_truncated_report_raises_the_run_health_failure(self):
        # RenderedReport.truncated was computed by the renderer and never read by the
        # runner, so a run delivering 10 of 150 groups reported the status of a complete one.
        def truncating(report):
            rendered = render(report)
            return RenderedReport(rendered.payloads, True, 3)

        with patch("soc_thief.runner.render", truncating):
            result = self.execute(Collector([record()]), model=Model(SUSPICIOUS))
        self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, True))

    def test_delivery_failure_leaves_pending_report_for_restart(self):
        first = Delivery(error=True)
        result = self.execute(Collector([record()]), model=Model({"classification":"suspicious","confidence":.5,"rationale":"review","analyst_action":"review"}), delivery=first)
        self.assertFalse(result.completed); self.assertFalse(result.delivered)
        self.store.close(); self.store = StateStore(Path(self.temp.name) / "state")
        collector, retry = Collector([record()]), Delivery()
        result = self.execute(collector, delivery=retry)
        self.assertTrue(result.completed); self.assertTrue(result.delivered); self.assertEqual(collector.calls, 0)

    def test_state_renderer_and_limit_failure_do_not_checkpoint(self):
        class BadStore:
            def pending_delivery(self, *args): return None
            def contains(self, *args): return False
            def commit_window(self, *args, **kwargs): raise Exception("synthetic")
        delivery = Delivery()
        result = run_window(collector=Collector([record()]), model=Model(), delivery=delivery, store=BadStore(),
                            identity_key=self.key, stream="daily", start=START, end=END, now=lambda: END)
        self.assertFalse(result.completed); self.assertTrue(result.delivered)
        self.assertFalse(self.execute(Collector([record(), record("b")]), limits=RunnerLimits(max_events=1)).completed)

    def reconcile(self, collector, model=None, delivery=None):
        return run_window(collector=collector, model=model or Model(), delivery=delivery or Delivery(), store=self.store,
                          identity_key=self.key, stream="reconcile", start=START, end=END, now=lambda: END,
                          exclude_committed=True)

    def test_reconcile_triages_only_late_arrivals(self):
        self.assertTrue(self.execute(Collector([record("a")])).completed)
        suspicious = Model({"classification":"suspicious","confidence":.5,"rationale":"review","analyst_action":"review"})
        delivery = Delivery()
        # "a" was committed by the daily stream; "b" arrived late and is repeated within the snapshot.
        result = self.reconcile(Collector([record("a"), record("b"), record("b")]), suspicious, delivery)
        self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, False))
        self.assertEqual(suspicious.calls, 1)
        self.assertEqual(suspicious.groups[0]["count"], 1)
        self.assertEqual(len(delivery.payloads), 1)
        self.assertEqual(self.store.checkpoint(opaque_key(self.key, "stream", "reconcile")), END)
        self.assertTrue(self.store.contains(opaque_key(self.key, "source", "wazuh-alerts-synthetic", "b")))

    def test_reconcile_without_late_arrivals_completes_without_delivery(self):
        self.assertTrue(self.execute(Collector([record("a"), record("b")])).completed)
        model, delivery = Model(), Delivery()
        result = self.reconcile(Collector([record("a"), record("b")]), model, delivery)
        self.assertEqual(result.status, "window completed; no delivery required")
        self.assertEqual((result.completed, result.delivered, model.calls, delivery.payloads), (True, False, 0, []))
        self.assertEqual(self.store.checkpoint(opaque_key(self.key, "stream", "reconcile")), END)

    def test_reconcile_protected_late_arrival_always_delivers(self):
        self.assertTrue(self.execute(Collector([record("a")])).completed)
        for identifier, item in (("b", record("b", level=12)), ("c", record("c", description="password spray synthetic"))):
            with self.subTest(identifier=identifier):
                self.store.close(); self.store = StateStore(Path(self.temp.name) / identifier)
                self.assertTrue(self.execute(Collector([record("a")])).completed)
                model, delivery = Model(), Delivery()
                result = self.reconcile(Collector([record("a"), item]), model, delivery)
                self.assertTrue(result.completed); self.assertTrue(result.delivered)
                self.assertEqual((model.calls, len(delivery.payloads)), (0, 1))

    def test_limits_cover_measured_daily_volume(self):
        # Measured on a real deployment: p95 99k, max 128.7k events/day; ~40s collection, 1.8-5.3s/model group.
        limits = RunnerLimits()
        self.assertEqual((limits.max_events, limits.max_groups, limits.deadline_seconds), (400_000, 2_000, 1500))
        self.assertEqual(RunnerLimits(deadline_seconds=3600).deadline_seconds, 3600)
        for bad in (dict(deadline_seconds=3601), dict(max_events=1_000_001), dict(max_groups=10_001), dict(max_events=0)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                RunnerLimits(**bad)
        # The collector's default page budget must never be the binding limit before max_events.
        from soc_thief.collector import CollectorConfig
        import dataclasses
        defaults = {field.name: field.default for field in dataclasses.fields(CollectorConfig)}
        self.assertGreaterEqual(defaults["page_size"] * defaults["max_pages"], limits.max_events)

    def tuning(self, *entries):
        return Tuning(tuple(TuningEntry(rule, action, agent, expires) for rule, action, agent, expires in entries))

    def audit(self):
        with closing(sqlite3.connect(Path(self.temp.name) / "state" / "state.sqlite3")) as db:
            return [row[0] for row in db.execute("SELECT reason FROM audit ORDER BY ordinal")]

    def content(self, delivery):
        (rendered,) = delivery.payloads
        return rendered.payloads[0]["content"]

    def test_breach_signal_ignores_tuning_and_model_and_is_named(self):
        # A muted rule that raises a breach signal is still delivered, as the signal.
        for action in ("mute", "low"):
            with self.subTest(action=action):
                self.store.close(); shutil.rmtree(Path(self.temp.name) / "state")
                self.store = StateStore(Path(self.temp.name) / "state")
                model, delivery = Model(), Delivery()
                result = self.execute(Collector([record(rule__id="521", level=11)]), model, delivery,
                                      tuning=self.tuning(("521", action, None, None)))
                self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, False))
                self.assertEqual(model.calls, 0)
                self.assertEqual(self.audit(), ["breach_malware"])
                self.assertIn("BREACH malware", self.content(delivery))
                self.assertNotIn("Low priority", self.content(delivery))

    def test_breach_variant_is_never_folded_into_a_description_summary(self):
        records = [record(str(index), description=f"synthetic variant {index}") for index in range(51)]
        records.append(record("cleared", description="synthetic other variant", rule__groups=["logs_cleared"]))
        delivery = Delivery()
        result = self.execute(Collector(records), Model(), delivery, limits=RunnerLimits(max_groups=3))
        self.assertTrue(result.completed)
        self.assertEqual(sorted(self.audit()), ["breach_log_cleared", "description_summary"])

    def test_success_after_brute_force_flags_only_the_success_group(self):
        brute = record("brute", rule__id="5720", data__srcip="198.51.100.7",
                       rule__groups=["sshd", "authentication_failures"], description="synthetic failures")
        success = record("success", rule__id="5715", data__srcip="198.51.100.7",
                         rule__groups=["sshd", "authentication_success"], description="synthetic success")
        success["fields"]["@timestamp"] = (START + timedelta(minutes=1)).isoformat()
        model = Model(SUSPICIOUS)
        result = self.execute(Collector([brute, success]), model, Delivery())
        self.assertTrue(result.completed)
        self.assertEqual(sorted(self.audit()), ["breach_brute_force_success", "model_requires_review"])
        self.assertEqual(model.calls, 1)

    def test_malformed_breach_field_fails_the_window_closed(self):
        for name, value in (("rule__groups", "logs_cleared"), ("rule__groups", [1]), ("data__srcip", ""),
                            ("syscheck__changed_attributes", "size")):
            with self.subTest(name=name, value=value):
                self.store.close(); self.store = StateStore(Path(self.temp.name) / f"bad-{name}-{value!r}")
                result = self.execute(Collector([record(**{name: value})]), Model(), Delivery())
                self.assertEqual((result.completed, result.health_failure), (False, True))

    def test_protected_groups_ignore_mute_and_low_entries(self):
        cases = ((record(level=12), "critical_severity", 0), (record(level=15), "critical_severity", 0),
                 (record(description="password spray synthetic"), "protected_indicator", 0),
                 (record(description="bad" + chr(0) + "control"), "invalid_group", 1))
        for action in ("mute", "low"):
            for index, (item, reason, health) in enumerate(cases):
                directory = Path(self.temp.name) / f"state-{action}-{index}"
                with self.subTest(action=action, reason=reason, index=index):
                    self.store.close(); self.store = StateStore(directory)
                    model, delivery = Model(), Delivery()
                    result = self.execute(Collector([item]), model, delivery,
                                          tuning=self.tuning(("100", action, None, None), ("100", action, "001", None)))
                    self.assertEqual(model.calls, 0)
                    self.assertTrue(result.delivered)
                    content = self.content(delivery)
                    self.assertNotIn("Low priority", content)
                    if health:
                        # An invalid group cannot be rendered either: the whole window fails closed.
                        self.assertEqual((result.completed, result.health_failure), (False, True))
                        self.assertIn("health failures: 1", content)
                        continue
                    self.assertEqual((result.completed, result.health_failure), (True, False))
                    self.assertIn("Delivery-required groups: 1;", content)
                    with closing(sqlite3.connect(directory / "state.sqlite3")) as db:
                        self.assertEqual([row[0] for row in db.execute("SELECT reason FROM audit")], [reason])

    def test_mute_and_low_skip_model_and_report_item_and_never_send_alone(self):
        for action, reason in (("mute", "tuned_mute"), ("low", "tuned_low")):
            with self.subTest(action=action):
                self.store.close()
                directory = Path(self.temp.name) / "state"
                for path in directory.glob("*"): path.unlink()
                self.store = StateStore(directory)
                model, delivery = Model({"classification":"suspicious","confidence":.5,"rationale":"review","analyst_action":"review"}), Delivery()
                result = self.execute(Collector([record("a"), record("b")]), model, delivery,
                                      tuning=self.tuning(("100", action, "001", None)))
                self.assertEqual(result.status, "window completed; no delivery required")
                self.assertEqual((result.completed, result.delivered, result.health_failure), (True, False, False))
                self.assertEqual((model.calls, delivery.payloads), (0, []))
                self.assertEqual(self.store.checkpoint(opaque_key(self.key, "stream", "daily")), END)
                self.assertEqual(self.audit(), [reason])

    def test_tuning_matches_rule_and_agent_and_expiry_reverts_to_model(self):
        suspicious = {"classification":"suspicious","confidence":.5,"rationale":"review","analyst_action":"review"}
        for tuning in (self.tuning(("100", "mute", "002", None)), self.tuning(("101", "mute", None, None)),
                       self.tuning(("100", "mute", None, END))):
            with self.subTest(tuning=tuning):
                self.store.close()
                directory = Path(self.temp.name) / "state"
                for path in directory.glob("*"): path.unlink()
                self.store = StateStore(directory)
                model, delivery = Model(suspicious), Delivery()
                result = self.execute(Collector([record()]), model, delivery, tuning=tuning)
                self.assertEqual((result.delivered, model.calls), (True, 1))
                self.assertEqual(self.audit(), ["model_requires_review"])

    def test_mixed_window_renders_summary_counts_without_tuned_text(self):
        def item(identifier, rule, description, level=3):
            value = record(identifier, level=level, description=description)
            value["fields"]["rule.id"] = rule
            return value
        hostile = "@everyone <b>TUNED-MARKER</b> https://evil.example/" + "y" * 1900
        records = [item("a", "200", "needs review"), item("b", "300", hostile), item("c", "300", hostile),
                   item("d", "300", hostile), item("e", "400", hostile + " low"), item("f", "500", "benign"),
                   item("g", "666", hostile, level=3)]
        records[6]["fields"]["agent.id"] = "002"
        class Mixed(Model):
            def review(self, group):
                self.calls += 1; self.groups.append(dict(group))
                benign = group["rule_id"] == "500"
                return ModelReview({"classification": "benign" if benign else "suspicious", "confidence": .99,
                                    "rationale": "r", "analyst_action": "a"}, "synthetic")
        model, delivery = Mixed(), Delivery()
        tuning = self.tuning(("300", "mute", None, None), ("400", "low", None, None), ("666", "low", "002", None))
        result = self.execute(Collector(records), model, delivery, tuning=tuning)
        self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, False))
        self.assertEqual(sorted(group["rule_id"] for group in model.groups), ["200", "500"])
        content = self.content(delivery)
        self.assertIn("Delivery-required groups: 2; suppressed benign groups: 0; health failures: 0", content)
        self.assertIn("Low priority: 2 events in 2 groups. Muted: 3 events in 1 groups.", content)
        for leaked in ("TUNED-MARKER", "evil.example", "@everyone", "`300`", "`400`", "`666`", "yyyy"):
            self.assertNotIn(leaked, content)
        self.assertEqual(sorted(self.audit()), ["model_requires_review", "model_requires_review",
                                                "tuned_low", "tuned_low", "tuned_mute"])

    def test_tuning_failure_applies_no_tuning_and_delivers_health(self):
        benign = {"classification":"benign","confidence":.99,"rationale":"routine","analyst_action":"none"}
        model, delivery = Model(benign), Delivery()
        result = self.execute(Collector([record()]), model, delivery, tuning=self.tuning(("100", "mute", None, None)),
                              tuning_failure=True)
        self.assertEqual(result, RunResult(True, True, True, "window completed and delivery acknowledged"))
        self.assertEqual(model.calls, 1)
        content = self.content(delivery)
        self.assertIn("Delivery-required groups: 1; suppressed benign groups: 0; health failures: 1", content)
        self.assertNotIn("Low priority", content)
        self.assertEqual(self.audit(), ["model_requires_review"])
        self.assertEqual(self.store.checkpoint(opaque_key(self.key, "stream", "daily")), END)

    def test_tuning_failure_with_empty_window_still_delivers_health(self):
        delivery = Delivery()
        result = self.execute(Collector([]), Model(), delivery, tuning_failure=True)
        self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, True))
        self.assertIn("health failures: 1", self.content(delivery))

    def test_reconcile_applies_tuning_to_late_arrivals(self):
        self.assertTrue(self.execute(Collector([record("a")])).completed)
        model, delivery = Model(), Delivery()
        result = run_window(collector=Collector([record("a"), record("b")]), model=model, delivery=delivery,
                            store=self.store, identity_key=self.key, stream="reconcile", start=START, end=END,
                            now=lambda: END, exclude_committed=True, tuning=self.tuning(("100", "low", None, None)))
        self.assertEqual((result.completed, result.delivered, model.calls, delivery.payloads), (True, False, 0, []))

    def labelled(self, identifier, *, level=3, **labels):
        value = record(identifier, level=level)
        names = {"description": "rule.description", "agent_name": "agent.name", "decoder": "decoder.name",
                 "manager": "manager.name", "location": "location"}
        for name, label in labels.items():
            value["fields"][names[name]] = label
        return value

    def tokens(self):
        with closing(sqlite3.connect(Path(self.temp.name) / "state" / "state.sqlite3")) as db:
            return [row[0] for row in db.execute("SELECT group_token FROM audit ORDER BY ordinal")]

    def test_varying_labels_form_separate_groups_with_counts_and_levels(self):
        records = [self.labelled("a", level=3, description="synthetic variant one"),
                   self.labelled("b", level=5, description="synthetic variant one"),
                   self.labelled("c", level=4, description="synthetic variant two"),
                   self.labelled("d", level=2, description="synthetic variant one", agent_name="synthetic-renamed"),
                   self.labelled("e", level=6, description="synthetic variant one", manager="other-manager")]
        model, delivery = Model(), Delivery()
        result = self.execute(Collector(records), model, delivery)
        self.assertEqual(result, RunResult(True, True, False, "window completed and delivery acknowledged"))
        summary = sorted((g["rule_description"], g["agent_name"], g["manager_name"], g["count"], g["rule_level"])
                         for g in model.groups)
        self.assertEqual(summary, [("synthetic variant one", "synthetic", "other-manager", 1, 6),
                                   ("synthetic variant one", "synthetic", "test", 2, 5),
                                   ("synthetic variant one", "synthetic-renamed", "test", 1, 2),
                                   ("synthetic variant two", "synthetic", "test", 1, 4)])
        self.assertEqual(self.audit(), ["model_requires_review"] * 4)
        self.assertEqual(len(set(self.tokens())), 4)

    def test_protected_variant_delivers_while_benign_variant_is_reviewed(self):
        records = [self.labelled("a", description="routine synthetic heartbeat"),
                   self.labelled("b", description="password spray synthetic"),
                   self.labelled("c", description="routine synthetic heartbeat")]
        model, delivery = Model(), Delivery()
        result = self.execute(Collector(records), model, delivery)
        self.assertEqual((result.completed, result.delivered, result.health_failure), (True, True, False))
        self.assertEqual([(g["rule_description"], g["count"]) for g in model.groups], [("routine synthetic heartbeat", 2)])
        self.assertIn("Delivery-required groups: 2; suppressed benign groups: 0; health failures: 0", self.content(delivery))
        self.assertEqual(sorted(self.audit()), ["model_requires_review", "protected_indicator"])

    def test_tuning_covers_every_label_variant_but_never_a_protected_variant(self):
        benign = [self.labelled(str(n), description=f"synthetic variant {n}") for n in range(3)]
        model, delivery = Model(), Delivery()
        result = self.execute(Collector(benign), model, delivery, tuning=self.tuning(("100", "mute", "001", None)))
        self.assertEqual((result.completed, result.delivered, model.calls, delivery.payloads), (True, False, 0, []))
        self.assertEqual(self.audit(), ["tuned_mute"] * 3)
        self.store.close(); self.store = StateStore(Path(self.temp.name) / "protected")
        model, delivery = Model(), Delivery()
        records = benign + [self.labelled("p", description="password spray synthetic")]
        result = self.execute(Collector(records), model, delivery, tuning=self.tuning(("100", "mute", None, None)))
        self.assertEqual((result.completed, result.delivered, result.health_failure, model.calls), (True, True, False, 0))
        self.assertIn("Delivery-required groups: 1;", self.content(delivery))
        self.assertIn("Muted: 3 events in 3 groups.", self.content(delivery))

    def test_absent_labels_do_not_collide_with_other_label_positions(self):
        records = [self.labelled("a", agent_name=None, manager="synthetic"),
                   self.labelled("b", agent_name="synthetic", manager=None),
                   self.labelled("c", agent_name=None, manager=None, decoder=None, location=None),
                   self.labelled("d", agent_name=None, manager=None, decoder=None, location=None)]
        model = Model()
        self.assertTrue(self.execute(Collector(records), model).completed)
        self.assertEqual(sorted(g["count"] for g in model.groups), [1, 1, 2])
        self.assertEqual(len(set(self.tokens())), 3)
        # Empty labels remain malformed rather than aliasing an absent label.
        delivery = Delivery()
        self.store.close(); self.store = StateStore(Path(self.temp.name) / "empty")
        result = self.execute(Collector([self.labelled("e", agent_name="")]), Model(), delivery)
        self.assertEqual((result.completed, result.health_failure), (False, True))

    def test_grouping_is_independent_of_input_order(self):
        from soc_thief.runner import _group
        records = [self.labelled("a", level=3, description="synthetic b", location=None),
                   self.labelled("b", level=7, description="synthetic a"),
                   self.labelled("c", level=5, description="synthetic b", location=None),
                   self.labelled("d", level=1, description="synthetic a", decoder=None)]
        records[2]["fields"]["@timestamp"] = (START + timedelta(minutes=1)).isoformat()
        records[0]["fields"]["@timestamp"] = (START + timedelta(minutes=2)).isoformat()
        def grouped(items):
            return _group(items, start=START, end=END, store=self.store, key=self.key, limits=RunnerLimits(),
                          expired=lambda: False)[1]
        expected = grouped(records)
        self.assertEqual([(g["rule_description"], g["decoder_name"], g["location"], g["count"], g["rule_level"])
                          for g in expected],
                         [("synthetic a", None, "synthetic", 1, 1), ("synthetic a", "test", "synthetic", 1, 7),
                          ("synthetic b", "test", None, 2, 5)])
        self.assertEqual(expected[-1]["timestamp"], (START + timedelta(minutes=1)).isoformat())
        for items in (list(reversed(records)), records[1:] + records[:1], records[2:] + records[:2]):
            self.assertEqual(grouped(items), expected)

    def test_many_ordinary_descriptions_become_one_explicit_summary(self):
        records = [self.labelled(str(index), description=f"synthetic variant {index}") for index in range(60)]
        model, delivery = Model(), Delivery()
        result = self.execute(Collector(records), model=model, delivery=delivery,
                              limits=RunnerLimits(max_groups=2))
        self.assertTrue(result.completed)
        self.assertFalse(result.health_failure)
        self.assertEqual(model.calls, 0)
        self.assertEqual(self.audit(), ["description_summary"])
        self.assertIn("60 variants", self.content(delivery))
        self.assertIn("60 events", self.content(delivery))

    def test_description_summary_threshold_and_source_order_are_deterministic(self):
        from soc_thief.runner import _group
        records = [self.labelled(str(index), description=f"synthetic variant {index}") for index in range(51)]
        def grouped(items):
            return _group(items, start=START, end=END, store=self.store, key=self.key,
                          limits=RunnerLimits(max_groups=51), expired=lambda: False)[1:3]
        exact, summary_indexes = grouped(records[:50])
        self.assertEqual((len(exact), summary_indexes), (50, frozenset()))
        summary, summary_indexes = grouped(records)
        self.assertEqual((len(summary), summary_indexes), (1, frozenset({0})))
        self.assertEqual(summary[0]["count"], 51)
        self.assertEqual(grouped(list(reversed(records))), (summary, summary_indexes))

    def test_critical_variant_remains_exact_when_ordinary_descriptions_collapse(self):
        records = [self.labelled(str(index), description=f"synthetic variant {index}") for index in range(51)]
        records.append(self.labelled("critical", level=12, description="synthetic high severity"))
        model, delivery = Model(), Delivery()
        result = self.execute(Collector(records), model=model, delivery=delivery,
                              limits=RunnerLimits(max_groups=2))
        self.assertTrue(result.completed)
        self.assertFalse(result.health_failure)
        self.assertEqual(model.calls, 0)
        self.assertEqual(sorted(self.audit()), ["critical_severity", "description_summary"])
        self.assertIn("synthetic high severity", self.content(delivery))
        self.assertIn("51 variants", self.content(delivery))

    def test_protected_variant_remains_exact_and_ignores_tuning_after_summary(self):
        records = [self.labelled(str(index), description=f"synthetic variant {index}") for index in range(60)]
        records.append(self.labelled("protected", description="password spray synthetic"))
        model, delivery = Model(), Delivery()
        result = self.execute(Collector(records), model=model, delivery=delivery,
                              limits=RunnerLimits(max_groups=2),
                              tuning=self.tuning(("100", "mute", None, None)))
        self.assertTrue(result.completed)
        self.assertFalse(result.health_failure)
        self.assertEqual(model.calls, 0)
        self.assertEqual(sorted(self.audit()), ["protected_indicator", "tuned_mute"])
        self.assertIn("password spray synthetic", self.content(delivery))
        self.assertNotIn("60 variants", self.content(delivery))

    def test_grouping_uses_one_sydney_report_window_across_midnight(self):
        # A report window runs 08:00--08:00 Sydney and crosses both UTC and local
        # midnight.  Neither boundary may create a second model review.
        start = datetime(2026, 1, 1, 21, tzinfo=timezone.utc)
        end = start + timedelta(hours=24)
        first = self.labelled("sydney-a", description="same local-day synthetic")
        second = self.labelled("sydney-b", description="same local-day synthetic")
        first["fields"]["@timestamp"] = datetime(2026, 1, 2, 12, 30, tzinfo=timezone.utc).isoformat()
        second["fields"]["@timestamp"] = datetime(2026, 1, 2, 13, 30, tzinfo=timezone.utc).isoformat()
        model = Model()
        result = self.execute(Collector([first, second]), model, start=start, end=end)
        self.assertEqual(result, RunResult(True, True, False, "window completed and delivery acknowledged"))
        self.assertEqual(len(model.groups), 1)
        self.assertEqual(model.groups[0]["count"], 2)
        self.assertEqual(len(self.tokens()), 1)

    def test_successful_window_prunes_expired_audit_but_keeps_dedupe_and_checkpoint(self):
        stale_event = opaque_key(self.key, "source", "wazuh-alerts-synthetic", "stale")
        stale_group = opaque_key(self.key, "group", "stale")
        stale_stream = opaque_key(self.key, "stream", "stale")
        self.store.commit_window(
            stale_stream, START, END, [stale_event],
            [(stale_group, Decision(False, False, "high_confidence_benign"))], recorded_at=END,
        )
        later = END + timedelta(hours=1)
        fresh = record("fresh")
        fresh["fields"]["@timestamp"] = END.isoformat()
        result = self.execute(Collector([fresh]), start=END, end=later,
                              now=lambda: END + timedelta(days=8))
        self.assertEqual(result, RunResult(True, True, False, "window completed and delivery acknowledged"))
        with closing(sqlite3.connect(Path(self.temp.name) / "state" / "state.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE stream=?", (stale_stream,)).fetchone(), (0,))
        self.assertTrue(self.store.contains(stale_event))
        self.assertEqual(self.store.checkpoint(opaque_key(self.key, "stream", "daily")), later)

    def test_audit_retention_failure_requires_a_health_report_after_commit(self):
        def failed_prune(*, now):
            raise StateError("synthetic")
        self.store.prune_audit = failed_prune
        delivery = Delivery()
        result = self.execute(Collector([record()]), delivery=delivery)
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertEqual(len(delivery.payloads), 1)
        self.assertEqual(self.store.checkpoint(opaque_key(self.key, "stream", "daily")), END)

    def test_audit_retention_failure_after_pending_acknowledgement_reports_health(self):
        pending_delivery = Delivery(error=True)
        suspicious = Model({"classification":"suspicious","confidence":.5,"rationale":"review","analyst_action":"review"})
        self.assertEqual(self.execute(Collector([record()]), suspicious, pending_delivery).completed, False)
        self.store.prune_audit = lambda *, now: (_ for _ in ()).throw(StateError("synthetic"))
        delivery = Delivery()
        result = self.execute(Collector([]), delivery=delivery)
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertTrue(self.store.delivery_acknowledged(opaque_key(self.key, "stream", "daily"), START))
        self.assertEqual(len(delivery.payloads), 2)

    def test_group_limit_counts_each_label_variant(self):
        records = [self.labelled(str(n), description=f"synthetic variant {n}") for n in range(3)]
        delivery = Delivery()
        result = self.execute(Collector(records), Model(), delivery, limits=RunnerLimits(max_groups=2))
        self.assertEqual(result, RunResult(False, True, True, "window failed; health report delivered"))
        self.assertEqual(self.tokens(), [])

    def test_exact_replay_without_delivery_is_idempotent(self):
        model = Model({"classification":"benign","confidence":.99,"rationale":"routine","analyst_action":"none"})
        self.assertTrue(self.execute(Collector([record()]), model=model).completed)
        # Exact source replay has no new events and is a completed no-op, not a second delivery.
        self.assertTrue(self.execute(Collector([record()]), model=model).completed)


if __name__ == "__main__": unittest.main()
