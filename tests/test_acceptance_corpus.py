"""Guard the synthetic acceptance corpus before policy implementation begins."""

from __future__ import annotations

import json
from pathlib import Path


ALLOWED_GROUP_FIELDS = {
    "timestamp",
    "rule_id",
    "rule_level",
    "rule_description",
    "agent_id",
    "agent_name",
    "decoder_name",
    "manager_name",
    "location",
    "count",
}

REQUIRED_CASES = {
    "repeated_benign_below_threshold_delivers",
    "benign_at_former_threshold_is_still_delivered",
    "benign_at_maximum_confidence_is_still_delivered",
    "critical_severity_is_delivery_required",
    "authentication_abuse_is_delivery_required",
    "malware_is_delivery_required",
    "privilege_escalation_is_delivery_required",
    "collection_is_delivery_required",
    "prompt_injection_text_is_not_instruction",
    "malformed_model_result_fails_closed",
    "model_timeout_fails_closed",
    "model_unavailable_fails_closed",
    "collector_failure_fails_closed",
    "state_failure_fails_closed",
    "renderer_failure_fails_closed",
    "delivery_failure_fails_closed",
    "duplicate_group_fails_closed",
    "out_of_order_group_fails_closed",
    "cursor_replay_fails_closed",
}


def test_acceptance_corpus_is_synthetic_and_allowlisted() -> None:
    fixture = Path(__file__).parent / "fixtures" / "triage_cases.json"
    cases = json.loads(fixture.read_text())

    assert cases
    # Every case now expects delivery. A model result can require delivery or fail closed,
    # but it can never suppress, so "suppressible" is no longer a reachable outcome
    # from model review. Deterministic operator tuning remains the only suppressor, and it
    # is exercised in tests/test_tuning.py rather than here.
    assert {case["expected"] for case in cases} == {"deliver"}
    assert all(set(case) <= {"name", "group", "model", "failures", "expected"}
               for case in cases)
    assert all(set(case["group"]) <= ALLOWED_GROUP_FIELDS for case in cases)
    assert all(type(case.get("failures", [])) is list for case in cases)
    assert all(not case.get("failures") or case["expected"] == "deliver" for case in cases)
    # Pin the invariant directly: no model object in the corpus, at any confidence, suppresses.
    assert all(case["expected"] == "deliver" for case in cases if "model" in case)
    assert len({case["name"] for case in cases}) == len(cases)
    assert {case["name"] for case in cases} >= REQUIRED_CASES
