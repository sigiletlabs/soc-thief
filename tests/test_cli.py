import contextlib
import io
import json
import os
import tempfile
import unittest

from soc_thief import cli
from tests.test_query import make_group, make_snapshot
from tests.test_toon import split_row

FIXTURE = os.path.join(os.path.dirname(__file__), os.pardir, "console", "fixtures", "demo.json")


class CliCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        self.path = self.save(make_snapshot())

    def save(self, document, name="snapshot.json"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(document, stream)
        return path

    def run_cli(self, *argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv), environ=env if env is not None else {})
        return code, out.getvalue()

    def ok(self, *argv):
        code, out = self.run_cli("--snapshot", self.path, *argv)
        self.assertEqual(code, 0, out)
        return out


class OverviewTest(CliCase):
    def test_bare_command_shows_live_content(self):
        out = self.ok()
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("bin: "))
        self.assertTrue(lines[1].startswith("description: "))
        self.assertIn("health: attention", lines)
        self.assertIn("checks_not_ok[1]{name,status,detail}:", lines)
        self.assertIn("breaches: 2 in window (1 paged)", lines)
        self.assertIn("paged_breaches[1]{at,agent,name}:", lines)
        self.assertIn("top_delivery_required[5]{id,category,level,rule}:", lines)
        self.assertIn('  note: "demo data: generated alerts run through the real pipeline; nothing was sent"'
                      .strip(), [line.strip() for line in lines])
        self.assertTrue(any(line.startswith("help[") for line in lines))
        self.assertIn(f"--snapshot {self.path} group <id>", out)

    def test_status_drops_the_header(self):
        out = self.ok("status")
        self.assertFalse(out.startswith("bin:"))
        self.assertIn("delivery_required: 5", out)

    def test_snapshot_from_environment(self):
        code, out = self.run_cli("status", env={"SOC_THIEF_SNAPSHOT": self.path})
        self.assertEqual(code, 0)
        self.assertIn("Run `soc-thief group <id>`", out)

    def test_quiet_window(self):
        self.path = self.save(make_snapshot(groups=[], breaches=[]))
        out = self.ok()
        self.assertIn("top_delivery_required: []", out)
        self.assertIn("paged_breaches: []", out)
        self.assertIn("breaches: 0 in window (0 paged)", out)


class GroupsTest(CliCase):
    def table(self, out, name="groups"):
        lines = out.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith(name + "["))
        header = lines[start]
        fields = header[header.index("{") + 1:header.index("}")].split(",")
        rows = []
        for line in lines[start + 1:]:
            if not line.startswith("  "):
                break
            rows.append(dict(zip(fields, split_row(line[2:]))))
        return fields, rows

    def test_default_schema_is_small_and_in_digest_order(self):
        out = self.ok("groups")
        fields, rows = self.table(out)
        self.assertEqual(fields, ["id", "category", "level", "rule"])
        self.assertEqual([r["id"] for r in rows], ["f-1", "n-2", "n-1", "s-hi", "r-hi", "r-low"])
        self.assertIn("count: 6 of 6 matching (6 listed in window)", out)

    def test_limit_reports_the_total_and_how_to_see_all(self):
        out = self.ok("groups", "--category", "new", "--limit", "1")
        self.assertIn("count: 1 of 2 matching category new", out)
        self.assertIn("groups --category new --limit 2` for all 2", out)

    def test_empty_result_is_definitive(self):
        out = self.ok("groups", "--filter", "no-such-thing")
        self.assertIn("groups: []", out.splitlines())
        self.assertIn("count: 0 of 0 matching filter 'no-such-thing'", out)

    def test_fields(self):
        _, rows = self.table(self.ok("groups", "--fields", "count,advisory_verdict"))
        self.assertEqual(rows[3], {"id": "s-hi", "category": "spike", "level": "10", "rule": "rule text",
                                   "count": "812", "advisory_verdict": "investigate"})
        code, out = self.run_cli("--snapshot", self.path, "groups", "--fields", "count,secret")
        self.assertEqual(code, 2)
        self.assertIn('error: "unknown field secret;', out)

    def test_truncation_and_full(self):
        long_text = "word " * 100
        self.path = self.save(make_snapshot(groups=[make_group("g-1", "new", 9, 1, description=long_text)]))
        out = self.ok("groups")
        cleaned = long_text.strip()
        self.assertIn(f"…(+{len(cleaned) - cli.LIST_TEXT} chars)", out)
        self.assertIn("Add `--full`", out)
        out = self.ok("groups", "--full")
        self.assertIn(cleaned, out)
        self.assertNotIn("chars)", out)


class GroupTest(CliCase):
    def test_detail_labels_the_model_advisory(self):
        out = self.ok("group", "s-hi")
        self.assertIn("model_advisory:", out)
        self.assertIn("  verdict: investigate", out)
        self.assertIn("advisory only", out)
        self.assertIn("decision:\n  delivery_required: true", out)
        self.assertNotIn("help[", out)

    def test_no_model(self):
        out = self.ok("group", "f-1")
        self.assertIn("model_advisory:\n  ran: false", out)

    def test_unknown_group_fails_with_a_next_step(self):
        code, out = self.run_cli("--snapshot", self.path, "group", "nope")
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("error: no group with id nope\nhelp[2]:"))

    def test_json(self):
        code, out = self.run_cli("--snapshot", self.path, "group", "s-hi", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["model"]["confidence"], 0.82)


class OtherCommandsTest(CliCase):
    def test_breaches_health_history(self):
        self.assertIn("breaches[2]{at,agent,name,paged,signals}:", self.ok("breaches"))
        self.assertIn("count: 1 of 2 checks not ok", self.ok("health"))
        out = self.ok("history")
        self.assertIn("count: 2 earlier windows; 1 delivered; 1 with a health failure", out)
        self.assertIn("history[2]{start,events,groups,delivered,health_failure}:", out)

    def test_empty_states(self):
        self.path = self.save(make_snapshot(breaches=[], history=[]))
        out = self.ok("breaches")
        self.assertIn("count: 0 breaches detected in this window\nbreaches: []", out)
        self.assertIn("count: 0 earlier windows recorded\nhistory: []", self.ok("history"))


class ErrorTest(CliCase):
    def test_unknown_flag_exits_2_and_lists_valid_flags(self):
        code, out = self.run_cli("--snapshot", self.path, "groups", "--stat", "closed")
        self.assertEqual(code, 2)
        self.assertTrue(out.startswith("error: unknown flag --stat for groups\nusage: "))
        self.assertIn('"--category C"', out)
        self.assertIn("examples[", out)

    def test_abbreviated_flag_is_not_guessed(self):
        code, out = self.run_cli("--snapshot", self.path, "groups", "--lim", "5")
        self.assertEqual(code, 2)
        self.assertIn("unknown flag --lim", out)

    def test_flag_valid_elsewhere_is_rejected_here(self):
        code, out = self.run_cli("--snapshot", self.path, "health", "--category", "new")
        self.assertEqual(code, 2)
        self.assertIn("unknown flag --category for health", out)

    def test_unknown_command_and_missing_argument(self):
        code, out = self.run_cli("nosuch")
        self.assertEqual(code, 2)
        self.assertIn("unknown command nosuch", out)
        code, out = self.run_cli("group")
        self.assertEqual((code, out.splitlines()[0]), (2, "error: group needs an ID"))
        code, out = self.run_cli("groups", "--limit", "0")
        self.assertEqual(code, 2)

    def test_missing_snapshot_exits_1_on_stdout(self):
        code, out = self.run_cli("--snapshot", os.path.join(self.dir, "absent.json"))
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("error: no snapshot at "))
        self.assertIn("demo` to write a demo snapshot", out)

    def test_bad_snapshot(self):
        self.path = self.save(make_snapshot(schema="soc-thief.snapshot/2"))
        code, out = self.run_cli("--snapshot", self.path)
        self.assertEqual(code, 1)
        self.assertIn("is not supported", out)

    def test_json_errors(self):
        code, out = self.run_cli("--snapshot", os.path.join(self.dir, "absent.json"), "--json")
        self.assertEqual(code, 1)
        self.assertIn("no snapshot", json.loads(out)["error"])
        code, out = self.run_cli("groups", "--bogus", "--json")
        self.assertEqual(code, 2)
        self.assertIn("--limit", json.loads(out)["valid_flags"])

    def test_help_and_version(self):
        for flag in ("--version", "-v", "-V"):
            code, out = self.run_cli(flag)
            self.assertEqual(code, 0)
            self.assertRegex(out.strip(), r"^\S+$")
        code, out = self.run_cli("groups", "--help")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("usage: "))
        self.assertNotIn("history", out)
        code, out = self.run_cli("--help")
        self.assertIn("commands[8]{name,does}:", out)


class ReadOnlyTest(CliCase):
    def test_no_command_changes_the_snapshot_or_writes_files(self):
        def state():
            with open(self.path, "rb") as stream:
                return os.stat(self.path).st_mtime_ns, stream.read()

        before = state()
        for argv in ((), ("status",), ("groups",), ("group", "s-hi"), ("breaches",), ("health",), ("history",),
                     ("groups", "--json")):
            self.ok(*argv)
        self.assertEqual(state(), before)
        self.assertEqual(os.listdir(self.dir), ["snapshot.json"])


@unittest.skipUnless(os.path.exists(FIXTURE), "hostile console fixture absent")
class HostileFixtureTest(CliCase):
    def test_hostile_strings_cannot_break_structure(self):
        self.path = FIXTURE
        outputs = [self.ok(), self.ok("groups", "--fields", "agents,reason", "--full"), self.ok("breaches"),
                   self.ok("health", "--full")]
        outputs += [self.ok("group", gid, "--full") for gid in ("c-x", "c-8e8e41", "c-9e0c55")]
        for out in outputs:
            self.assertFalse(any(ord(ch) < 0x20 and ch != "\n" or 0x7F <= ord(ch) <= 0x9F for ch in out))
            self.assertNotIn("‮", out)
            lines = out.splitlines()
            self.assertEqual(sum(line.startswith("help[") for line in lines), int(any("help[" in l for l in lines)))
            self.assertFalse(any(line.startswith("error") for line in lines))
            for i, line in enumerate(lines):
                if "]{" in line and line.endswith(":") and not line.startswith(" "):
                    width = line.count(",", line.index("{")) + 1
                    for row in lines[i + 1:]:
                        if not row.startswith("  ") or row.startswith("  Run"):
                            break
                        self.assertEqual(len(split_row(row[2:])), width, row)

    def test_hostile_id_is_reachable_by_its_clean_form(self):
        self.path = FIXTURE
        out = self.ok("group", "c-x")
        self.assertIn("rule: ALL CLEAR nothing to see here", out)
        self.assertIn("reason: model response failed schema validation INJECTED LINE", out)


if __name__ == "__main__":
    unittest.main()
