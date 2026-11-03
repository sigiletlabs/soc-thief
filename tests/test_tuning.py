"""Synthetic operator tuning file checks; no production data or network is used."""
import dataclasses
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest

from soc_thief.tuning import MAX_ENTRIES, MAX_FILE_BYTES, Tuning, TuningError, load_tuning


NOW = datetime(2026, 9, 13, tzinfo=timezone.utc)


def entry(**changes):
    value = {"rule_id": "5715", "action": "mute"}
    value.update(changes)
    return value


class TuningFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "tuning"

    def write(self, value, mode=0o600):
        if self.path.exists(): self.path.chmod(0o600)
        self.path.write_text(value if type(value) is str else json.dumps(value, indent=2))
        self.path.chmod(mode)
        return {"SOC_THIEF_TUNING_FILE": str(self.path)}

    def load(self, value, mode=0o600):
        return load_tuning(self.write(value, mode))

    def assert_rejected(self, value, mode=0o600):
        with self.assertRaises(TuningError) as caught:
            self.load(value, mode)
        self.assertEqual(str(caught.exception), "tuning file is invalid")

    def test_unset_variable_is_empty_tuning(self):
        tuning = load_tuning({})
        self.assertEqual(tuning, Tuning())
        self.assertIsNone(tuning.action("5715", "001", NOW))

    def test_valid_multiline_file_loads(self):
        tuning = self.load({"version": 1, "entries": [
            entry(), entry(rule_id="31101", action="low", agent_id="004", expires="2026-12-01T00:00:00Z",
                           note="printer noise"),
            entry(rule_id="31102", expires="2026-12-01T00:00:00+00:00"),
        ]})
        self.assertEqual(tuning.action("5715", "anything", NOW), "mute")
        self.assertEqual(tuning.action("31101", "004", NOW), "low")
        self.assertIsNone(tuning.action("31101", "005", NOW))
        self.assertEqual(tuning.action("31102", "001", NOW), "mute")
        self.assertIsNone(tuning.action("9999", "001", NOW))
        self.assertEqual(self.load({"version": 1, "entries": []}), Tuning())

    def test_note_is_never_retained(self):
        tuning = self.load({"version": 1, "entries": [entry(note="SECRET-NOTE-MARKER")]})
        self.assertNotIn("SECRET-NOTE-MARKER", repr(tuning))
        self.assertNotIn("SECRET-NOTE-MARKER", repr(vars(tuning)))
        self.assertNotIn("SECRET-NOTE-MARKER", repr([vars(item) for item in tuning.entries]))

    def test_matcher_is_immutable(self):
        tuning = self.load({"version": 1, "entries": [entry()]})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            tuning.entries = ()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            tuning.entries[0].action = "low"
        with self.assertRaises(TypeError):
            tuning._index[("5715", None)] = "low"

    def test_specific_entry_wins_and_expiry_reverts(self):
        tuning = self.load({"version": 1, "entries": [
            entry(action="mute"), entry(action="low", agent_id="001", expires="2026-09-14T00:00:00Z"),
        ]})
        self.assertEqual(tuning.action("5715", "001", NOW), "low")
        self.assertEqual(tuning.action("5715", "002", NOW), "mute")
        # An expired specific entry falls back to the active rule-only entry.
        self.assertEqual(tuning.action("5715", "001", datetime(2026, 9, 14, tzinfo=timezone.utc)), "mute")
        expired = self.load({"version": 1, "entries": [entry(expires="2026-09-13T00:00:00Z")]})
        self.assertIsNone(expired.action("5715", "001", NOW))  # expiry instant is exclusive
        self.assertEqual(expired.action("5715", "001", NOW - timedelta(seconds=1)), "mute")
        with self.assertRaises(ValueError):
            tuning.action("5715", "001", NOW.replace(tzinfo=None))

    def test_rejected_shapes(self):
        long = "x" * 65
        cases = [
            [], "null", {"version": 1}, {"entries": []}, {"version": 2, "entries": []},
            {"version": "1", "entries": []}, {"version": True, "entries": []}, {"version": 1.0, "entries": []},
            {"version": 1, "entries": {}}, {"version": 1, "entries": [], "extra": 1},
            {"version": 1, "entries": ["5715"]},
            {"version": 1, "entries": [{"action": "mute"}]},
            {"version": 1, "entries": [{"rule_id": "5715"}]},
            {"version": 1, "entries": [entry(action="MUTE")]},
            {"version": 1, "entries": [entry(action="suppress")]},
            {"version": 1, "entries": [entry(rule_id="")]},
            {"version": 1, "entries": [entry(rule_id="   ")]},
            {"version": 1, "entries": [entry(rule_id=long)]},
            {"version": 1, "entries": [entry(rule_id=5715)]},
            {"version": 1, "entries": [entry(rule_id="57\n15")]},
            {"version": 1, "entries": [entry(agent_id="")]},
            {"version": 1, "entries": [entry(agent_id=None)]},
            {"version": 1, "entries": [entry(agent_id=long)]},
            {"version": 1, "entries": [entry(agent_id=1)]},
            {"version": 1, "entries": [entry(expires="2026-12-01T00:00:00")]},
            {"version": 1, "entries": [entry(expires="2026-12-01T11:00:00+11:00")]},
            {"version": 1, "entries": [entry(expires="tomorrow")]},
            {"version": 1, "entries": [entry(expires=1)]},
            {"version": 1, "entries": [entry(expires=None)]},
            {"version": 1, "entries": [entry(note="n" * 201)]},
            {"version": 1, "entries": [entry(note=3)]},
            {"version": 1, "entries": [entry(comment="unknown key")]},
            {"version": 1, "entries": [entry(), entry(action="low")]},
            {"version": 1, "entries": [entry(agent_id="001"), entry(agent_id="001", action="low")]},
            "not json", "", '{"version":1,"entries":[]} trailing',
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assert_rejected(value)
        # Maximum-length values are accepted.
        self.load({"version": 1, "entries": [entry(rule_id="r" * 64, agent_id="a" * 64, note="n" * 200)]})

    def test_duplicate_keys_and_constants_are_rejected(self):
        for text in ('{"version":1,"version":1,"entries":[]}',
                     '{"version":1,"entries":[{"rule_id":"1","rule_id":"2","action":"mute"}]}',
                     '{"version":1,"entries":[{"rule_id":"1","action":"mute","expires":NaN}]}',
                     '{"version":1,"entries":[{"rule_id":"1","action":"mute","note":Infinity}]}',
                     '{"version":NaN,"entries":[]}'):
            with self.subTest(text=text):
                self.assert_rejected(text)
        self.path.write_bytes(b'{"version":1,"entries":[{"rule_id":"\xff","action":"mute"}]}')
        with self.assertRaises(TuningError):
            load_tuning({"SOC_THIEF_TUNING_FILE": str(self.path)})
        self.assert_rejected("[" * 100_000 + "]" * 100_000)

    def test_entry_and_size_limits(self):
        many = [entry(rule_id=str(i)) for i in range(MAX_ENTRIES)]
        self.assertEqual(len(self.load({"version": 1, "entries": many}).entries), MAX_ENTRIES)
        self.assert_rejected({"version": 1, "entries": many + [entry(rule_id="extra")]})
        padding = " " * (MAX_FILE_BYTES - len('{"version":1,"entries":[]}'))
        self.load('{"version":1,"entries":[]}' + padding)
        self.assert_rejected('{"version":1,"entries":[]}' + padding + " ")
        self.assertEqual(MAX_FILE_BYTES, 256 * 1024)

    def test_systemd_credential_mode_is_accepted_on_a_read_only_mount(self):
        # The runner's tuning credential arrives as 0440 on the container's read-only bind mount.
        from unittest.mock import Mock, patch
        env = self.write({"version": 1, "entries": []}, 0o440)
        with patch("os.fstatvfs", Mock(return_value=Mock(f_flag=os.ST_RDONLY))):
            self.assertEqual(load_tuning(env).entries, ())

    def test_unsafe_files_are_rejected(self):
        for mode in (0o640, 0o604, 0o660, 0o644, 0o440):
            with self.subTest(mode=mode):
                self.assert_rejected({"version": 1, "entries": []}, mode)
        self.write({"version": 1, "entries": []})
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.path)
        for env in ({"SOC_THIEF_TUNING_FILE": str(link)}, {"SOC_THIEF_TUNING_FILE": self.temp.name},
                    {"SOC_THIEF_TUNING_FILE": str(self.path) + ".missing"}, {"SOC_THIEF_TUNING_FILE": ""}):
            with self.subTest(env=env), self.assertRaises(TuningError):
                load_tuning(env)
        fifo = Path(self.temp.name) / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(TuningError):
            load_tuning({"SOC_THIEF_TUNING_FILE": str(fifo)})


if __name__ == "__main__":
    unittest.main()
