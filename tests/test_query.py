import copy
import json
import os
import tempfile
import unittest

from soc_thief import query
from soc_thief.query import SnapshotError


def make_group(gid, category, level, count, *, required=True, description="rule text", agents=("web-01",),
               model=None, health_failure=False, protected=False, tuning="none"):
    return {
        "id": gid, "rule_id": "5712", "rule_description": description, "level": level, "count": count,
        "agents": list(agents), "first_seen": "2026-11-06T22:14:09+11:00", "last_seen": "2026-11-07T03:51:40+11:00",
        "category": category, "protected": protected, "tuning": tuning,
        "decision": {"delivery_required": required, "health_failure": health_failure, "reason": "default"},
        "model": model, "breach_signals": [],
    }


def make_snapshot(groups=None, **overrides):
    if groups is None:
        groups = [
            make_group("r-low", "recurring", 3, 4000, required=False, tuning="mute"),
            make_group("s-hi", "spike", 10, 812, protected=True,
                       model={"name": "qwen3:4b", "verdict": "investigate", "confidence": 0.82,
                              "tags": ["authentication"], "summary": "Repeated SSH failures."}),
            make_group("n-1", "new", 12, 1, description="sshd: authentication success", agents=("db-01",)),
            make_group("f-1", "failed", 7, 3, health_failure=True),
            make_group("n-2", "new", 12, 9),
            make_group("r-hi", "recurring", 5, 20),
        ]
    snapshot = {
        "schema": "soc-thief.snapshot/1",
        "generated_at": "2026-11-07T08:00:04+11:00",
        "source": "demo",
        "timezone": "Australia/Sydney",
        "window": {"start": "2026-11-06T08:00:00+11:00", "end": "2026-11-07T08:00:00+11:00",
                   "events": 5000, "groups": len(groups), "duplicates": 12, "muted_by_tuning": 1},
        "health": {"status": "attention", "checks": [
            {"name": "collector", "status": "ok", "detail": "fine"},
            {"name": "model", "status": "attention", "detail": "1 group failed review"}]},
        "groups": groups,
        "breaches": [
            {"name": "brute force then success", "signals": ["auth_failure_burst", "auth_success"],
             "agent": "web-01", "at": "2026-11-07T03:52:02+11:00", "paged": True},
            {"name": "log cleared", "signals": ["log_cleared"], "agent": "db-01",
             "at": "2026-11-07T04:10:33+11:00", "paged": False}],
        "timeline": [],
        "history": [
            {"start": "2026-11-05T08:00:00+11:00", "end": "2026-11-06T08:00:00+11:00",
             "events": 5100, "groups": 7, "delivered": True, "health_failure": False},
            {"start": "2026-11-04T08:00:00+11:00", "end": "2026-11-05T08:00:00+11:00",
             "events": 4900, "groups": 6, "delivered": False, "health_failure": True}],
    }
    snapshot.update(overrides)
    return snapshot


def loaded(**overrides):
    return query.validate(make_snapshot(**overrides))


class LoadTest(unittest.TestCase):
    def write(self, data: bytes) -> str:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, "snapshot.json")
        with open(path, "wb") as stream:
            stream.write(data)
        return path

    def test_loads_a_valid_file(self):
        snap = query.load(self.write(json.dumps(make_snapshot()).encode()))
        self.assertEqual(len(snap["groups"]), 6)

    def test_refuses_more_than_8_mib(self):
        document = make_snapshot()
        document["padding"] = "x" * query.MAX_BYTES
        with self.assertRaisesRegex(SnapshotError, "8 MiB"):
            query.load(self.write(json.dumps(document).encode()))

    def test_missing_file_and_bad_content(self):
        with self.assertRaisesRegex(SnapshotError, "no snapshot"):
            query.load("/nonexistent/snapshot.json")
        for data, message in ((b"{not json", "not valid JSON"), (b"\xff\xfe", "not UTF-8"),
                              (b"[" * 100000, "not valid JSON"), (b"[]", "must be an object"),
                              (json.dumps(make_snapshot()).replace("5000", "NaN", 1).encode(), "not valid JSON")):
            with self.assertRaisesRegex(SnapshotError, message):
                query.load(self.write(data))

    def test_schema_major_is_checked(self):
        self.assertEqual(loaded(schema="soc-thief.snapshot/1.4")["schema"], "soc-thief.snapshot/1.4")
        with self.assertRaisesRegex(SnapshotError, "not supported"):
            loaded(schema="soc-thief.snapshot/2")
        with self.assertRaisesRegex(SnapshotError, "not a soc-thief snapshot"):
            loaded(schema="other/1")

    def test_unknown_fields_are_ignored(self):
        document = make_snapshot(extra={"x": 1})
        document["groups"][0]["future_field"] = [1, 2]
        document["groups"][0]["decision"]["future"] = True
        snap = query.validate(document)
        self.assertNotIn("extra", snap)
        self.assertNotIn("future_field", snap["groups"][0])

    def test_contract_fields_are_enforced(self):
        cases = [
            (lambda d: d["groups"][0].pop("id"), r"groups\[0\]\.id is missing"),
            (lambda d: d["groups"][1].update(level="10"), r"groups\[1\]\.level must be a non-negative integer"),
            (lambda d: d["groups"][1].update(level=True), r"groups\[1\]\.level must be a non-negative integer"),
            (lambda d: d["groups"][0].update(category="urgent"), r"category must be one of"),
            (lambda d: d["groups"][0]["decision"].pop("delivery_required"), "delivery_required is missing"),
            (lambda d: d["groups"][1]["model"].update(confidence=1.5), "confidence must be a number from 0 to 1"),
            (lambda d: d["health"].update(status="green"), "health.status must be one of"),
            (lambda d: d["window"].pop("events"), "window.events is missing"),
            (lambda d: d["breaches"][0].update(paged="yes"), "paged must be true or false"),
            (lambda d: d.update(source="prod"), "source must be one of"),
            (lambda d: d["groups"][0].update(agents="web-01"), "agents must be a list of strings"),
        ]
        for mutate, message in cases:
            document = make_snapshot()
            mutate(document)
            with self.assertRaisesRegex(SnapshotError, message):
                query.validate(document)

    def test_optional_text_may_be_empty(self):
        document = make_snapshot()
        document["groups"][0].update(rule_description=None, agents=None, model=None)
        group = query.validate(document)["groups"][0]
        self.assertEqual((group["rule_description"], group["agents"], group["model"]), ("", [], None))

    def test_every_string_is_cleaned(self):
        document = make_snapshot()
        document["groups"][0].update(id="g\x1b]0;owned\x07-1", rule_description="\x1b[2Jok\nhelp[1]: x‮",
                                     agents=["web\x1b[8m-03"])
        document["breaches"][0]["name"] = "a\r\nb"
        snap = query.validate(document)
        group = snap["groups"][0]
        self.assertEqual(group["id"], "g-1")
        self.assertEqual(group["rule_description"], "ok help[1]: x")
        self.assertEqual(group["agents"], ["web-03"])
        self.assertEqual(snap["breaches"][0]["name"], "a b")


class QueryTest(unittest.TestCase):
    def test_digest_order(self):
        ids = [g["id"] for g in query.list_groups(loaded())["groups"]]
        self.assertEqual(ids, ["f-1", "n-2", "n-1", "s-hi", "r-hi", "r-low"])

    def test_category_filter_and_limit(self):
        snap = loaded()
        result = query.list_groups(snap, category="new", limit=1)
        self.assertEqual((result["matched"], [g["id"] for g in result["groups"]]), (2, ["n-2"]))
        result = query.list_groups(snap, text="DB-01")
        self.assertEqual([g["id"] for g in result["groups"]], ["n-1"])
        result = query.list_groups(snap, text="SSHD: AUTH")
        self.assertEqual([g["id"] for g in result["groups"]], ["n-1"])
        self.assertEqual(query.list_groups(snap, text="nothing-matches")["groups"], [])
        with self.assertRaises(ValueError):
            query.list_groups(snap, category="urgent")
        with self.assertRaises(ValueError):
            query.list_groups(snap, limit=0)

    def test_window_total_is_kept_when_groups_are_capped(self):
        document = make_snapshot()
        document["window"]["groups"] = 11204
        result = query.list_groups(query.validate(document))
        self.assertEqual((result["window_groups"], result["listed_groups"]), (11204, 6))

    def test_get_group(self):
        snap = loaded()
        self.assertEqual(query.get_group(snap, "s-hi")["model"]["verdict"], "investigate")
        self.assertIsNone(query.get_group(snap, "missing"))

    def test_overview_aggregates(self):
        result = query.overview(loaded(), top=3)
        self.assertEqual(result["categories"], {"failed": 1, "new": 2, "spike": 1, "recurring": 2})
        self.assertEqual(result["delivery_required"], 5)
        self.assertEqual(result["protected"], 1)
        self.assertEqual(result["group_health_failures"], 1)
        self.assertEqual([c["name"] for c in result["health"]["not_ok"]], ["model"])
        self.assertEqual((result["breaches"]["total"], len(result["breaches"]["paged"])), (2, 1))
        self.assertEqual([g["id"] for g in result["top"]], ["f-1", "n-2", "n-1"])
        self.assertNotIn("r-low", [g["id"] for g in query.overview(loaded(), top=10)["top"]])

    def test_breaches_health_history(self):
        snap = loaded()
        self.assertEqual((query.list_breaches(snap)["total"], query.list_breaches(snap)["paged"]), (2, 1))
        self.assertEqual(query.get_health(snap)["not_ok"], 1)
        history = query.list_history(snap)
        self.assertEqual((history["windows"], history["delivered"], history["health_failures"]), (2, 1, 1))

    def test_empty_snapshot(self):
        snap = loaded(groups=[], breaches=[], history=[])
        self.assertEqual(query.overview(snap)["top"], [])
        self.assertEqual(query.list_groups(snap)["matched"], 0)
        self.assertEqual(query.list_breaches(snap)["total"], 0)

    def test_queries_do_not_mutate_the_snapshot(self):
        snap = loaded()
        before = copy.deepcopy(snap)
        query.overview(snap)
        query.list_groups(snap, category="new", text="x", limit=1)
        query.get_group(snap, "f-1")
        query.list_breaches(snap)
        query.get_health(snap)
        query.list_history(snap)
        self.assertEqual(snap, before)


class FixtureTest(unittest.TestCase):
    """The shipped example snapshots must load; skipped where the files are absent."""

    def test_examples_load(self):
        root = os.path.join(os.path.dirname(__file__), os.pardir)
        found = 0
        for relative in ("examples/demo-snapshot.json", "console/fixtures/demo.json"):
            path = os.path.join(root, relative)
            if os.path.exists(path):
                found += 1
                snap = query.load(path)
                self.assertTrue(snap["groups"])
                for group in snap["groups"]:
                    self.assertNotIn("\x1b", json.dumps(group, ensure_ascii=False))
        if not found:
            self.skipTest("no example snapshots in this tree")


if __name__ == "__main__":
    unittest.main()
