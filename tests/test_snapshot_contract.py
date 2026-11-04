"""Demo and state snapshots against the docs/SNAPSHOT.md contract. No network, no credentials."""
import contextlib
import hashlib
import io
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from soc_thief import demo, snapshot
from soc_thief.model import ModelReview
from soc_thief.policy import Decision
from soc_thief.state import StateStore, opaque_key

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "demo-snapshot.json"
EXAMPLE_NOW = datetime.fromisoformat("2026-11-07T08:00:04+11:00")
NOW = datetime(2026, 11, 6, 22, 0, 4, tzinfo=timezone.utc)
DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_STATUSES = {"ok", "attention", "failed"}


def _time(test, value):
    test.assertIsInstance(value, str)
    test.assertRegex(value, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?([+-]\d\d:\d\d|Z)$")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    test.assertIsNotNone(parsed.utcoffset())
    return parsed


def _keys(test, value, keys):
    test.assertIsInstance(value, dict)
    test.assertEqual(set(value), set(keys))


def validate(test, document, *, source):
    """Every field docs/SNAPSHOT.md names, with its type and closed vocabulary."""
    text = json.dumps(document, ensure_ascii=False)
    test.assertLessEqual(len(text.encode()), 8 * 1024 * 1024)
    required = ("schema", "generated_at", "source", "timezone", "window", "health", "groups",
                "breaches", "timeline", "history")
    _keys(test, document, required + (("attacks",) if "attacks" in document else ()))
    test.assertRegex(document["schema"], r"^soc-thief\.snapshot/1(\.\d+)?$")
    test.assertEqual(document["source"], source)
    _time(test, document["generated_at"])
    test.assertIsInstance(document["timezone"], str)
    window = document["window"]
    _keys(test, window, ("start", "end", "events", "groups", "duplicates", "muted_by_tuning"))
    test.assertLessEqual(_time(test, window["start"]), _time(test, window["end"]))
    for name in ("events", "groups", "duplicates", "muted_by_tuning"):
        test.assertIs(type(window[name]), int)
        test.assertGreaterEqual(window[name], 0)
    test.assertLessEqual(len(document["groups"]), 5000)
    test.assertEqual(len(document["groups"]), min(window["groups"], 5000))
    _keys(test, document["health"], ("status", "checks"))
    test.assertIn(document["health"]["status"], _STATUSES)
    for check in document["health"]["checks"]:
        _keys(test, check, ("name", "status", "detail"))
        test.assertIn(check["status"], _STATUSES)
        test.assertIsInstance(check["name"], str)
        test.assertIsInstance(check["detail"], str)
    order = ("failed", "new", "spike", "recurring")
    categories = []
    for group in document["groups"]:
        _keys(test, group, ("id", "rule_id", "rule_description", "level", "count", "agents", "first_seen",
                            "last_seen", "category", "protected", "tuning", "decision", "model", "breach_signals"))
        for name in ("id", "rule_id", "rule_description"):
            test.assertIsInstance(group[name], str)
        test.assertTrue(group["id"])
        test.assertIs(type(group["level"]), int)
        test.assertTrue(0 <= group["level"] <= 16)
        test.assertIs(type(group["count"]), int)
        test.assertTrue(all(isinstance(a, str) for a in group["agents"]))
        test.assertLessEqual(_time(test, group["first_seen"]), _time(test, group["last_seen"]))
        test.assertIn(group["category"], order)
        categories.append(order.index(group["category"]))
        test.assertIs(type(group["protected"]), bool)
        test.assertIn(group["tuning"], ("none", "low", "mute"))
        decision = group["decision"]
        _keys(test, decision, ("delivery_required", "health_failure", "reason"))
        test.assertIs(type(decision["delivery_required"]), bool)
        test.assertIs(type(decision["health_failure"]), bool)
        test.assertIsInstance(decision["reason"], str)
        if group["protected"]:
            test.assertTrue(decision["delivery_required"], group)  # Tuning never hides a protected group.
        if group["model"] is not None:
            _keys(test, group["model"], ("name", "verdict", "confidence", "tags", "summary"))
            test.assertIsInstance(group["model"]["confidence"], (int, float))
            test.assertTrue(0 <= group["model"]["confidence"] <= 1)
            test.assertTrue(all(isinstance(t, str) for t in group["model"]["tags"]))
            # The model only advises; it never leaves a group undelivered.
            test.assertTrue(decision["delivery_required"], group)
        test.assertTrue(all(isinstance(s, str) for s in group["breach_signals"]))
    test.assertEqual(categories, sorted(categories), "groups are not in digest category order")
    test.assertEqual(len({g["id"] for g in document["groups"]}), len(document["groups"]))
    for breach in document["breaches"]:
        _keys(test, breach, ("name", "signals", "agent", "at", "paged"))
        _time(test, breach["at"])
        test.assertIs(type(breach["paged"]), bool)
    starts = [_time(test, bucket["start"]) for bucket in document["timeline"]]
    test.assertEqual(starts, sorted(starts))
    for earlier, later in zip(starts, starts[1:]):
        test.assertEqual(later - earlier, timedelta(hours=1))
    for bucket in document["timeline"]:
        _keys(test, bucket, ("start", "events", "delivery_required"))
    test.assertLessEqual(len(document["history"]), 30)
    previous = None
    for row in document["history"]:
        _keys(test, row, ("start", "end", "events", "groups", "delivered", "health_failure"))
        start = _time(test, row["start"])
        test.assertLess(start, _time(test, row["end"]))
        if previous is not None:
            test.assertLess(start, previous, "history is not newest first")
        previous = start
        test.assertIs(type(row["delivered"]), bool)
        test.assertIs(type(row["health_failure"]), bool)
    if "attacks" in document:
        validate_attacks(test, document["attacks"], window)
    for forbidden in ("webhook", "/api/webhooks/", "password=", "token="):
        test.assertNotIn(forbidden, text.lower())


def validate_attacks(test, attacks, window):
    """The optional globe block: countries and kinds only, never an address or a host."""
    _keys(test, attacks, ("home", "start", "end", "no_source", "dropped", "shots"))
    test.assertRegex(attacks["home"], r"^[A-Z]{2}$")
    test.assertEqual((attacks["start"], attacks["end"]), (window["start"], window["end"]))
    span = (_time(test, attacks["end"]) - _time(test, attacks["start"])).total_seconds()
    for name in ("no_source", "dropped"):
        test.assertIs(type(attacks[name]), int)
        test.assertGreaterEqual(attacks[name], 0)
    test.assertLessEqual(len(attacks["shots"]), 20000)
    times = []
    for shot in attacks["shots"]:
        _keys(test, shot, ("t", "country", "level", "kind", "label"))
        test.assertIsInstance(shot["t"], (int, float))
        test.assertTrue(0 <= shot["t"] <= span, shot)
        times.append(shot["t"])
        test.assertRegex(shot["country"], r"^([A-Z]{2}|LAN)$")
        test.assertIs(type(shot["level"]), int)
        test.assertIn(shot["kind"], ("tuned", "reported", "breach"))
        test.assertIsInstance(shot["label"], str)
        test.assertLessEqual(len(shot["label"]), 48)
    test.assertEqual(times, sorted(times), "shots are not oldest first")


def _sydney():
    return patch.dict(os.environ, {"SOC_THIEF_TIMEZONE": "Australia/Sydney"})


class DemoSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with _sydney():
            cls.snap, cls.digest = demo.build(seed=demo.DEFAULT_SEED, now=EXAMPLE_NOW)

    def test_matches_the_contract(self):
        validate(self, self.snap, source="demo")
        window = self.snap["window"]
        self.assertTrue(10_000 <= window["events"] <= 50_000, window)
        self.assertTrue(150 <= window["groups"] <= 250, window)
        self.assertTrue(7 <= len(self.snap["history"]) <= 14)
        self.assertEqual(len(self.snap["timeline"]), 24)
        self.assertEqual(sum(b["events"] for b in self.snap["timeline"]), window["events"])
        self.assertEqual((window["start"], window["end"]), ("2026-11-06T08:00:00+11:00", "2026-11-07T08:00:00+11:00"))

    def test_seed_decides_the_alerts(self):
        # Same-seed determinism of the whole snapshot is proven by the CLI test, which builds it
        # again and compares; here a different seed must change the generated alerts.
        with _sydney():
            start, end = demo.report_window(EXAMPLE_NOW, demo.zone.report_zone())
            records = []
            for seed in (demo.DEFAULT_SEED, demo.DEFAULT_SEED, demo.DEFAULT_SEED + 1):
                generator = demo._Generator(seed, start, end, demo.zone.report_zone())
                generator.background()
                generator.story()
                generator.duplicates()
                records.append(json.dumps(generator.records))
        self.assertEqual(records[0], records[1])
        self.assertNotEqual(records[0], records[2])

    def test_committed_example_is_current(self):
        self.assertEqual(json.loads(EXAMPLE.read_text(encoding="utf-8")), self.snap,
                         "regenerate: SOC_THIEF_TIMEZONE=Australia/Sydney python -m soc_thief.demo "
                         "--out examples/demo-snapshot.json --seed 7 --now 2026-11-07T08:00:04+11:00")

    def test_tells_the_story(self):
        groups = self.snap["groups"]
        by = lambda rule, agent: [g for g in groups if g["rule_id"] == rule and g["agents"] == [agent]]
        self.assertEqual(by("5712", "vpn-01")[0]["category"], "spike")
        (ransomware,) = by("92213", "ws-07")
        self.assertEqual((ransomware["tuning"], ransomware["protected"]), ("mute", True))
        self.assertTrue(ransomware["decision"]["delivery_required"])
        failed = [g for g in groups if g["category"] == "failed"]
        self.assertEqual(len(failed), 2)
        self.assertTrue(all(g["decision"] == {"delivery_required": True, "health_failure": True,
                                              "reason": "invalid_model_result"} for g in failed))
        self.assertEqual(by("61138", "dc-01")[0]["category"], "new")
        signals = {(b["signals"][0], b["agent"]) for b in self.snap["breaches"]}
        self.assertEqual(signals, {("brute_force_success", "web-02"), ("account_created", "web-02"),
                                   ("critical_file_change", "web-01")})
        self.assertTrue(all(b["paged"] for b in self.snap["breaches"]))
        self.assertGreater(self.snap["window"]["muted_by_tuning"], 0)
        self.assertEqual(self.snap["health"]["status"], "attention")
        self.assertIsNotNone(self.digest.attachment)

    def test_globe_replays_the_demo_breaches_at_their_times(self):
        attacks = self.snap["attacks"]
        self.assertEqual(attacks["home"], "AU")
        start = datetime.fromisoformat(self.snap["window"]["start"])
        expected = sorted(round((datetime.fromisoformat(b["at"]) - start).total_seconds(), 1)
                          for b in self.snap["breaches"])
        self.assertEqual([shot["t"] for shot in attacks["shots"] if shot["kind"] == "breach"], expected)
        self.assertGreater(len(attacks["shots"]), 5000)

    def test_only_documentation_addresses(self):
        text = json.dumps(self.snap)
        with _sydney():
            start, end = demo.report_window(EXAMPLE_NOW, demo.zone.report_zone())
            generator = demo._Generator(demo.DEFAULT_SEED, start, end, demo.zone.report_zone())
            generator.background()
            generator.story()
        text += json.dumps(generator.records) + EXAMPLE.read_text(encoding="utf-8")
        found = set(_IPV4.findall(text))
        self.assertTrue(found)  # The generated alerts do carry addresses.
        for address in found:
            self.assertTrue(any(ipaddress.ip_address(address) in net for net in DOCUMENTATION_NETS), address)

    def test_no_deny_listed_term(self):
        # The list is private to the maintainer and never copied into the repository.
        path = Path.home() / ".config" / "soc-thief" / "public-denylist.txt"
        if not path.is_file():
            self.skipTest("no private deny-list on this machine")
        patterns = [re.compile(line, re.I) for line in path.read_text().splitlines()
                    if line.strip() and not line.startswith("#")]
        text = json.dumps(self.snap) + EXAMPLE.read_text(encoding="utf-8") + self.digest.attachment
        hits = [p.pattern for p in patterns if p.search(text)]
        self.assertFalse(hits, "a deny-listed term appears in demo output")

    def test_a_model_that_calls_everything_benign_changes_no_delivery(self):
        def benign(model, group):
            if demo.preflight(group).delivery_required:
                raise demo.ModelError("not permitted")
            return ModelReview({"classification": "benign", "confidence": 1.0, "rationale": "Benign.",
                                "analyst_action": "None."}, demo.STUB_MODEL)
        with _sydney(), patch.object(demo.StubModel, "review", benign):
            calm, _ = demo.build(seed=demo.DEFAULT_SEED, now=EXAMPLE_NOW)
        decisions = lambda snap: {g["id"]: g["decision"]["delivery_required"] for g in snap["groups"]}
        # The only differences: the two groups the stub failed now have advice. Delivery is unchanged.
        self.assertEqual(decisions(calm), decisions(self.snap))
        undelivered = [g for g in calm["groups"] if not g["decision"]["delivery_required"]]
        self.assertTrue(undelivered)
        self.assertTrue(all(g["decision"]["reason"] in ("tuned_mute", "tuned_low") for g in undelivered))

    def test_cli_writes_the_file_and_refuses_a_bad_zone(self):
        with tempfile.TemporaryDirectory() as temp, _sydney():
            out = Path(temp) / "s.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(demo.main(["--out", str(out), "--now", EXAMPLE_NOW.isoformat(),
                                            "--digest-out", str(Path(temp) / "d.txt")]), 0)
            # A second build with the same seed and time is identical: the demo is deterministic.
            self.assertEqual(out.read_text(), json.dumps(self.snap, ensure_ascii=False, indent=1) + "\n")
            self.assertIn("Soc Thief daily digest", (Path(temp) / "d.txt").read_text())
            with patch.dict(os.environ, {"SOC_THIEF_TIMEZONE": "Nowhere/Land"}), \
                    contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(demo.main(["--out", str(out)]), 2)
            self.assertIn("SOC_THIEF_TIMEZONE", printed.getvalue())


KEY = bytes(range(32))


class StateSnapshotTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name) / "state"
        stream = opaque_key(KEY, "stream", "daily")
        decisions = [Decision(True, False, "protected_indicator"), Decision(False, False, "tuned_mute"),
                     Decision(True, True, "invalid_model_result"), Decision(True, False, "breach_malware")]
        start = datetime(2026, 11, 4, 21, tzinfo=timezone.utc)
        with StateStore(self.dir) as store:
            for day in range(3):
                begin, end = start + timedelta(days=day), start + timedelta(days=day + 1)
                events = [opaque_key(KEY, "source", "i", f"{day}-{n}") for n in range(5)]
                assessments = [(opaque_key(KEY, "group", f"{day}-{n}"), d) for n, d in enumerate(decisions)]
                payload = b'[{"content":"x","allowed_mentions":{"parse":[]}}]'
                store.commit_window(stream, begin, end, events, assessments, recorded_at=end + timedelta(minutes=20),
                                    pending_delivery=payload)
                if day < 2:
                    store.acknowledge_delivery(stream, begin, payload)
        self.db_path = self.dir / "state.sqlite3"

    def _fingerprint(self):
        return sorted((p.name, hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
                      for p in self.dir.iterdir())

    def test_state_snapshot_matches_the_contract_and_holds_real_decisions(self):
        db = snapshot.connect(self.dir)
        try:
            with _sydney():
                snap = snapshot.build(db, now=datetime(2026, 11, 7, 22, tzinfo=timezone.utc), key=KEY)
        finally:
            db.close()
        validate(self, snap, source="state")
        self.assertEqual(snap["window"]["start"], "2026-11-07T08:00:00+11:00")
        self.assertEqual(snap["window"]["events"], 5)
        self.assertEqual(snap["window"]["muted_by_tuning"], 1)
        reasons = [g["decision"]["reason"] for g in snap["groups"]]
        # Failed first, then breach groups, as in the digest.
        self.assertEqual(reasons[:2], ["invalid_model_result", "breach_malware"])
        self.assertEqual(sorted(reasons[2:]), ["protected_indicator", "tuned_mute"])
        self.assertEqual(len(snap["history"]), 2)
        self.assertTrue(all(row["delivered"] and row["health_failure"] for row in snap["history"]))
        statuses = {c["name"]: c["status"] for c in snap["health"]["checks"]}
        self.assertEqual(statuses["delivery"], "attention")  # The newest report is still pending.
        self.assertEqual(statuses["window"], "attention")
        for group in snap["groups"]:
            self.assertEqual((group["rule_description"], group["agents"], group["model"]), ("", [], None))

    def test_without_the_identity_key_the_busiest_stream_is_used(self):
        db = snapshot.connect(self.db_path)
        try:
            with _sydney():
                snap = snapshot.build(db, now=datetime(2026, 11, 7, 22, tzinfo=timezone.utc))
        finally:
            db.close()
        self.assertEqual(snap["window"]["start"], "2026-11-07T08:00:00+11:00")

    def test_opens_read_only_and_never_writes(self):
        before = self._fingerprint()
        db = snapshot.connect(self.dir)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO checkpoints VALUES ('x', 'y')")
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("PRAGMA user_version=9")
        finally:
            db.close()
        with tempfile.TemporaryDirectory() as temp, _sydney(), patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SOC_THIEF_IDENTITY_KEY_FILE", None)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(snapshot.main(["--state", str(self.dir), "--out", str(Path(temp) / "s.json")]), 0)
            validate(self, json.loads((Path(temp) / "s.json").read_text()), source="state")
        self.assertEqual(self._fingerprint(), before)
        # The runner can still take its lock while a snapshot connection is open.
        db = snapshot.connect(self.dir)
        try:
            with StateStore(self.dir):
                pass
        finally:
            db.close()

    def test_read_only_holds_without_query_only(self):
        # Two layers: the mode=ro URI and PRAGMA query_only. Each must refuse a write alone.
        db = snapshot.connect(self.dir)
        try:
            db.execute("PRAGMA query_only=OFF")
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO checkpoints VALUES ('x', 'y')")
        finally:
            db.close()

    def test_group_list_is_capped_with_delivery_required_first(self):
        group = lambda n, delivered, category: {
            "id": f"g-{n:06d}", "category": category, "breach_signals": [], "level": 3, "count": 1,
            "decision": {"delivery_required": delivered}}
        groups = [group(n, n % 3 == 0, "recurring" if n % 2 else "new") for n in range(12_000)]
        kept = demo.order_groups(groups)
        self.assertEqual(len(kept), demo.MAX_GROUPS)
        self.assertEqual(sum(g["decision"]["delivery_required"] for g in kept), 4000)
        order = [("failed", "new", "spike", "recurring").index(g["category"]) for g in kept]
        self.assertEqual(order, sorted(order))
        self.assertEqual(len(demo.order_groups(groups[:10])), 10)

    def test_missing_state_is_a_fixed_error(self):
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.connect(self.dir / "absent")


if __name__ == "__main__":
    unittest.main()
