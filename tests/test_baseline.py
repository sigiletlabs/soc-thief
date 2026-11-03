"""Synthetic frequency-baseline proposal tests; no live services, no operator data.

This suite is entirely synthetic. It does not and cannot show the proposer produces sensible
entries against the operator's real noise profile: that profile is private data and is not
read here or anywhere in this repository's tests.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_thief.baseline import (
    MIN_COVERAGE, MIN_HISTORY_DAYS, MUTE_MAX_LEVEL, NEVER_PROPOSE, PROPOSAL_EXPIRY_DAYS,
    Proposal, propose, serialize,
)
from soc_thief.tuning import MAX_ENTRIES, load_tuning

END = datetime(2026, 9, 22, tzinfo=timezone.utc)
WINDOW_DAYS = 99


def row(rule="100", agent="001", events=1000, level=3, days_active=WINDOW_DAYS,
        description="Synthetic noise", complete=True, agent_name="synthetic-host",
        agent_name_complete=True):
    return {"rule_id": rule, "agent_id": agent, "events": events, "max_level": level,
            "days_active": days_active, "rule_description": description,
            "description_complete": complete, "agent_name": agent_name,
            "agent_name_complete": agent_name_complete}


def write_tuning_file(document):
    temp = tempfile.TemporaryDirectory()
    path = Path(temp.name) / "tuning.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return temp, {"SOC_THIEF_TUNING_FILE": str(path)}


class ProposeSafetyInvariantTests(unittest.TestCase):
    """The tunable() gate (policy.preflight) must exclude these, even at full history."""

    def test_protected_description_is_never_proposed(self):
        rows = [row(rule="1", description="sshd: Authentication failure", days_active=WINDOW_DAYS)]
        self.assertEqual(propose(rows, end=END, window_days=WINDOW_DAYS), ())

    def test_level_twelve_and_above_is_never_proposed(self):
        rows = [row(rule="1", level=12, days_active=WINDOW_DAYS),
                row(rule="2", level=16, days_active=WINDOW_DAYS)]
        self.assertEqual(propose(rows, end=END, window_days=WINDOW_DAYS), ())

    def test_missing_or_incomplete_description_is_never_proposed(self):
        rows = [row(rule="1", description=None, complete=False, days_active=WINDOW_DAYS),
                row(rule="2", complete=False, days_active=WINDOW_DAYS)]
        self.assertEqual(propose(rows, end=END, window_days=WINDOW_DAYS), ())


class ProposeThresholdTests(unittest.TestCase):
    def test_row_below_min_history_days_is_never_proposed(self):
        # Coverage passes (28 >= 28 * 0.5) but absolute history does not (28 < 30).
        window_days = MIN_HISTORY_DAYS - 2
        rows = [row(rule="1", days_active=window_days)]
        self.assertEqual(propose(rows, end=END, window_days=window_days), ())

    def test_row_below_coverage_fraction_is_never_proposed(self):
        # Absolute history passes (30 >= 30) but coverage does not (30 < 120 * 0.5 = 60).
        window_days = MIN_HISTORY_DAYS * 4
        rows = [row(rule="1", days_active=MIN_HISTORY_DAYS)]
        self.assertEqual(propose(rows, end=END, window_days=window_days), ())

    def test_row_passing_one_threshold_but_failing_the_other_is_never_proposed(self):
        # This test pins both halves of the AND explicitly, in one place.
        history_only = row(rule="history-only", days_active=MIN_HISTORY_DAYS)
        result = propose([history_only], end=END, window_days=MIN_HISTORY_DAYS * 4)
        self.assertEqual(result, (), "history alone must not be sufficient without coverage")

        coverage_only = row(rule="coverage-only", days_active=MIN_HISTORY_DAYS - 2)
        result = propose([coverage_only], end=END, window_days=MIN_HISTORY_DAYS - 2)
        self.assertEqual(result, (), "coverage alone must not be sufficient without history")

    def test_row_passing_both_thresholds_is_proposed(self):
        rows = [row(rule="1", days_active=MIN_HISTORY_DAYS)]
        result = propose(rows, end=END, window_days=MIN_HISTORY_DAYS)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].rule_id, "1")


class ProposeActionTests(unittest.TestCase):
    def test_level_at_or_below_mute_max_level_is_muted(self):
        rows = [row(rule="1", level=MUTE_MAX_LEVEL, days_active=WINDOW_DAYS)]
        result = propose(rows, end=END, window_days=WINDOW_DAYS)
        self.assertEqual(result[0].action, "mute")

    def test_level_above_mute_max_level_is_downgraded_never_muted(self):
        # Levels 12+ are excluded entirely by the protected gate (see ProposeSafetyInvariantTests),
        # so this pins the remaining band: above MUTE_MAX_LEVEL but still below the level-12 cutoff.
        rows = [row(rule="1", level=MUTE_MAX_LEVEL + 1, days_active=WINDOW_DAYS),
                row(rule="2", level=11, days_active=WINDOW_DAYS)]
        result = propose(rows, end=END, window_days=WINDOW_DAYS)
        actions = {p.rule_id: p.action for p in result}
        self.assertEqual(actions["1"], "low")
        self.assertEqual(actions["2"], "low")
        self.assertNotIn("mute", actions.values())

    def test_expires_is_thirty_days_after_end_in_utc(self):
        rows = [row(rule="1", days_active=WINDOW_DAYS)]
        result = propose(rows, end=END, window_days=WINDOW_DAYS)
        self.assertEqual(result[0].expires, END + timedelta(days=PROPOSAL_EXPIRY_DAYS))
        self.assertEqual(result[0].expires.utcoffset(), timedelta(0))


class ProposeCapTests(unittest.TestCase):
    def test_proposals_are_capped_at_tuning_max_entries(self):
        rows = [row(rule=str(i), agent="001", days_active=WINDOW_DAYS) for i in range(MAX_ENTRIES + 5)]
        result = propose(rows, end=END, window_days=WINDOW_DAYS)
        self.assertEqual(len(result), MAX_ENTRIES)


class ProposeSerializationTests(unittest.TestCase):
    def test_hostile_printable_description_does_not_reach_the_serialized_output_unescaped(self):
        hostile = "evil `tick` @everyone # markdown *bold* [link](http://x)"
        rows = [row(rule="1", description=hostile, days_active=WINDOW_DAYS)]
        result = propose(rows, end=END, window_days=WINDOW_DAYS)
        self.assertEqual(len(result), 1)
        blob = json.dumps(serialize(result))
        for fragment in ("evil", "`tick`", "@everyone", "markdown", "*bold*", "](http"):
            self.assertNotIn(fragment, blob)

    def test_hostile_description_with_control_character_is_excluded_entirely(self):
        # policy.preflight treats any control character as a malformed group (health_failure),
        # so profile.tunable() returns "no (review)" and the row is never proposed at all --
        # a stronger guarantee than escaping, and it applies before this module ever builds a
        # note. This is the control-character half of the corpus requirement; the markdown/
        # mention/backtick half is exercised above with a description that clears preflight.
        hostile = "evil \x1b[31m escape sequence"
        rows = [row(rule="1", description=hostile, days_active=WINDOW_DAYS)]
        self.assertEqual(propose(rows, end=END, window_days=WINDOW_DAYS), ())

    def test_serialize_produces_the_tuning_file_shape(self):
        rows = [row(rule="1", agent="001", days_active=WINDOW_DAYS)]
        document = serialize(propose(rows, end=END, window_days=WINDOW_DAYS))
        self.assertEqual(document["version"], 1)
        self.assertEqual(document.keys(), {"version", "entries"})
        entry = document["entries"][0]
        self.assertEqual(entry["rule_id"], "1")
        self.assertEqual(entry["agent_id"], "001")
        self.assertIn(entry["action"], ("mute", "low"))
        self.assertLessEqual(len(entry["note"]), 200)

    def test_serialized_proposals_round_trip_through_tuning_load(self):
        rows = [row(rule="1", agent="001", events=5000, level=3, days_active=WINDOW_DAYS),
                row(rule="2", agent="002", events=40, level=8, days_active=60)]
        proposals = propose(rows, end=END, window_days=WINDOW_DAYS)
        self.assertEqual(len(proposals), 2)
        document = serialize(proposals)
        temp, env = write_tuning_file(document)
        try:
            tuning = load_tuning(env)
        finally:
            temp.cleanup()
        self.assertEqual(len(tuning.entries), len(proposals))
        by_key = {(e.rule_id, e.agent_id): e for e in tuning.entries}
        for proposal in proposals:
            entry = by_key[(proposal.rule_id, proposal.agent_id)]
            self.assertEqual(entry.action, proposal.action)
            self.assertEqual(entry.expires, proposal.expires)


class ProposeDenyListTests(unittest.TestCase):
    """Classes whose value is not their frequency are never proposed automatically.

    A base-rate proposer ranks by how normal a group is, and ``policy.preflight`` misses these
    classes on a word boundary, so nothing upstream of this list stops them.
    """

    def test_a_denied_rule_is_never_proposed_at_full_history(self):
        # Wiring: the module constant is the default, not just an argument this suite passes.
        denied = sorted(NEVER_PROPOSE)[0]
        rows = [row(rule=denied, days_active=WINDOW_DAYS, description="Synthetic noise")]
        self.assertEqual(propose(rows, end=END, window_days=WINDOW_DAYS), ())

    def test_every_denied_rule_is_excluded_and_an_identical_undenied_rule_is_not(self):
        # The control row is identical in every field but its rule id, so a proposal for the
        # control and none for the denied rules can only be the deny-list doing the work.
        rows = [row(rule=rule, days_active=WINDOW_DAYS) for rule in sorted(NEVER_PROPOSE)]
        control = row(rule="not-a-denied-rule", days_active=WINDOW_DAYS)
        result = propose([*rows, control], end=END, window_days=WINDOW_DAYS)
        self.assertEqual([p.rule_id for p in result], ["not-a-denied-rule"])

    def test_a_denied_rule_is_excluded_for_every_agent(self):
        denied = sorted(NEVER_PROPOSE)[0]
        rows = [row(rule=denied, agent=agent, days_active=WINDOW_DAYS)
                for agent in ("001", "002", "003")]
        self.assertEqual(propose(rows, end=END, window_days=WINDOW_DAYS), ())

    def test_an_empty_deny_list_proposes_the_same_rows(self):
        # Pins that exclusion is caused by membership, not by some other property of these rows.
        rows = [row(rule=rule, days_active=WINDOW_DAYS) for rule in sorted(NEVER_PROPOSE)]
        result = propose(rows, end=END, window_days=WINDOW_DAYS, never_propose=frozenset())
        self.assertEqual(len(result), len(NEVER_PROPOSE))

    def test_the_deny_list_removes_proposals_and_never_adds_one(self):
        # It can only ever shrink the proposal set: whatever it excludes stays delivered.
        rows = [row(rule=rule, days_active=WINDOW_DAYS) for rule in ("1", *sorted(NEVER_PROPOSE))]
        without = {(p.rule_id, p.agent_id) for p in
                   propose(rows, end=END, window_days=WINDOW_DAYS, never_propose=frozenset())}
        with_list = {(p.rule_id, p.agent_id) for p in propose(rows, end=END, window_days=WINDOW_DAYS)}
        self.assertTrue(with_list < without)

    def test_denied_rules_are_valid_tuning_identifiers_and_the_list_is_not_empty(self):
        self.assertTrue(NEVER_PROPOSE)
        self.assertIs(type(NEVER_PROPOSE), frozenset)
        for rule in NEVER_PROPOSE:
            self.assertIs(type(rule), str)
            self.assertTrue(0 < len(rule) <= 64 and rule.strip() == rule)

    def test_a_malformed_deny_list_is_rejected(self):
        rows = [row(rule="1", days_active=WINDOW_DAYS)]
        for bad in ({"504"}, ["504"], "504", None, frozenset({504})):
            with self.assertRaises(ValueError):
                propose(rows, end=END, window_days=WINDOW_DAYS, never_propose=bad)


if __name__ == "__main__":
    unittest.main()
