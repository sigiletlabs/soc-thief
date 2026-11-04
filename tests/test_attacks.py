"""Globe attack shots from synthetic records; no indexer, no network, no production data."""

from datetime import datetime, timedelta, timezone
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from soc_thief import attacks
from soc_thief.attacks import AttacksError, GeoIP, Shot, block, demo_shots, label, main, shots_from_records
from soc_thief.tuning import Tuning, TuningEntry

START = datetime(2026, 1, 2, tzinfo=timezone.utc)
# DB-IP rows for documentation ranges would map to LAN (they are not global), so the table
# uses public-looking ranges that no test record is ever told is real.
GEOIP_ROWS = [("1.0.0.0", "1.0.0.255", "AU"), ("8.8.8.0", "8.8.8.255", "US"),
              ("9.9.9.0", "9.9.9.255", "ZZ"), ("2001:4860::", "2001:4860:ffff::", "US")]


def record(rule="5710", level=5, srcip="8.8.8.8", description="sshd: authentication failed.",
           seconds=0, agent="001", **extra):
    fields = {"@timestamp": (START + timedelta(seconds=seconds)).isoformat(), "rule.id": rule,
              "rule.level": level, "rule.description": description, "agent.id": agent,
              "agent.name": "web-01", **extra}
    if srcip is not None:
        fields["data.srcip"] = srcip
    return {"fields": fields}


class GeoIPTests(unittest.TestCase):
    def test_lookup_maps_ranges_private_space_and_unknowns(self):
        geoip = GeoIP(GEOIP_ROWS)
        self.assertEqual(geoip.country("1.0.0.7"), "AU")
        self.assertEqual(geoip.country("8.8.8.8"), "US")
        self.assertEqual(geoip.country("2001:4860::8888"), "US")
        self.assertIsNone(geoip.country("8.8.9.1"))
        self.assertIsNone(geoip.country("9.9.9.9"))  # ZZ is DB-IP's unknown
        for value in ("172.16.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "fe80::1", "203.0.113.5"):
            self.assertEqual(geoip.country(value), attacks.LAN, value)
        for value in (None, 17, "", "not-an-ip", "8.8.8.8; rm"):
            self.assertIsNone(geoip.country(value))

    def test_load_reads_plain_and_gzip_and_refuses_junk(self):
        text = "".join(",".join(row) + "\n" for row in GEOIP_ROWS)
        with tempfile.TemporaryDirectory() as folder:
            plain, packed, junk = (Path(folder) / name for name in ("a.csv", "b.csv.gz", "c.csv"))
            plain.write_text(text)
            packed.write_bytes(gzip.compress(text.encode()))
            junk.write_text("1.0.0.0,1.0.0.255,AUS\n")
            for path in (plain, packed):
                self.assertEqual(GeoIP.load(path).country("1.0.0.1"), "AU")
            with self.assertRaisesRegex(AttacksError, "start,end,country"):
                GeoIP.load(junk)
            with self.assertRaisesRegex(AttacksError, "could not be read"):
                GeoIP.load(Path(folder) / "missing.csv")


class ShotTests(unittest.TestCase):
    def test_shots_keep_country_kind_and_a_clean_label_never_ip_or_host(self):
        tuning = Tuning((TuningEntry("5710", "mute"),))
        shots = shots_from_records([
            record(seconds=30),
            record(rule="5902", srcip=None, description="New user added.", seconds=10),
            record(rule="31101", level=7, srcip="172.16.0.9", seconds=20,
                   description="Bad \x1b[31m request from 198.51.100.4 password=hunter2 " + "x" * 80),
        ], START, tuning, GeoIP(GEOIP_ROWS))
        self.assertEqual([shot.at for shot in shots], [10, 20, 30])
        found, reported, tuned = shots
        self.assertEqual((found.kind, found.country), ("breach", None))
        self.assertEqual((reported.kind, reported.country, reported.level), ("reported", attacks.LAN, 7))
        self.assertEqual((tuned.kind, tuned.country), ("tuned", "US"))
        self.assertLessEqual(len(reported.label), attacks.LABEL_LIMIT)
        for forbidden in ("\x1b", "198.51.100.4", "hunter2"):
            self.assertNotIn(forbidden, reported.label)
        self.assertEqual(set(vars(tuned)), {"at", "country", "level", "kind", "label"})

    def test_success_after_brute_force_from_one_source_is_a_breach_even_if_tuned(self):
        tuning = Tuning((TuningEntry("5715", "mute"),))
        shots = shots_from_records([
            record(rule="5712", level=10, seconds=1, **{"rule.groups": ["authentication_failures"]}),
            record(rule="5715", level=3, seconds=5, **{"rule.groups": ["authentication_success"]}),
        ], START, tuning, GeoIP(GEOIP_ROWS))
        self.assertEqual([shot.kind for shot in shots], ["reported", "breach"])

    def test_label_is_printable_and_capped(self):
        self.assertEqual(label(None), "?")
        self.assertEqual(label("a\nb"), "a?b")
        self.assertTrue(label("y" * 100).endswith("…"))

    def test_block_counts_no_source_and_keeps_breaches_over_the_cap(self):
        shots = [Shot(float(i), "CN", 3, "tuned", "noise") for i in range(10)]
        shots += [Shot(4.5, None, 3, "reported", "local"), Shot(9.5, "RU", 12, "breach", "pwned"),
                  Shot(0.5, "US", 7, "reported", "scan")]
        with patch.object(attacks, "MAX_SHOTS", 3):
            result = block(shots, home="au", start="a", end="b")
        self.assertEqual((result["home"], result["no_source"], result["dropped"]), ("AU", 1, 9))
        self.assertEqual([(s["t"], s["kind"]) for s in result["shots"]],
                         [(0, "tuned"), (0.5, "reported"), (9.5, "breach")])
        self.assertNotIn("LAN", json.dumps(block([], home="AU", start="a", end="b")))
        with self.assertRaises(AttacksError):
            block(shots, home="AUS", start="a", end="b")

    def test_demo_is_seeded_sorted_and_carries_each_breach(self):
        first = demo_shots(3600, [(100.0, "account created")], seed=7)
        self.assertEqual(first, demo_shots(3600, [(100.0, "account created")], seed=7))
        self.assertNotEqual(first, demo_shots(3600, seed=8))
        self.assertEqual(first, sorted(first, key=lambda shot: shot.at))
        self.assertEqual([(s.at, s.label) for s in first if s.kind == "breach"], [(100.0, "account created")])
        self.assertTrue(all(0 <= shot.at < 3600 and shot.country for shot in first))


class Collector:
    def __init__(self, records):
        self.records, self.calls = records, []

    def collect(self, start, end):
        self.calls.append((start, end))
        return iter(self.records)


class MainTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.geoip, self.snapshot = root / "geo.csv", root / "snapshot.json"
        self.geoip.write_text("8.8.8.0,8.8.8.255,US\n")
        self.snapshot.write_text(json.dumps({"schema": "soc-thief.snapshot/1.1", "window": {
            "start": "2026-01-02T11:00:00+11:00", "end": "2026-01-03T11:00:00+11:00"}}))

    def run_main(self, argv, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err), \
             patch("soc_thief.collector.CollectorConfig.from_environment", return_value=object()), \
             patch.dict("os.environ", {}, clear=True):
            return main(argv, **kwargs), out.getvalue() + err.getvalue()

    def test_adds_the_block_for_the_snapshots_own_window_and_prints_no_alert_content(self):
        collector = Collector([record(seconds=5), record(srcip=None, seconds=6)])
        code, output = self.run_main(["--snapshot", str(self.snapshot), "--geoip", str(self.geoip), "--home", "AU"],
                                     collector_factory=lambda config: collector)
        self.assertEqual(code, 0, output)
        self.assertEqual(collector.calls, [(START, START + timedelta(days=1))])
        written = json.loads(self.snapshot.read_text())
        self.assertEqual(written["attacks"]["start"], "2026-01-02T11:00:00+11:00")
        self.assertEqual([s["country"] for s in written["attacks"]["shots"]], ["US"])
        self.assertEqual(written["attacks"]["no_source"], 1)
        text = output + self.snapshot.read_text()
        for forbidden in ("8.8.8.8", "web-01"):
            self.assertNotIn(forbidden, text)

    def test_failures_are_fixed_text_and_leave_the_snapshot_alone(self):
        before = self.snapshot.read_text()

        def broken(config):
            raise RuntimeError("https://indexer.internal password=x")
        code, output = self.run_main(["--snapshot", str(self.snapshot), "--geoip", str(self.geoip), "--home", "AU"],
                                     collector_factory=broken)
        self.assertEqual(code, 2)
        self.assertNotIn("indexer.internal", output)
        self.assertNotIn("password", output)
        self.snapshot.write_text(json.dumps({"window": {"start": "2026-01-02", "end": "2026-01-01"}}))
        code, output = self.run_main(["--snapshot", str(self.snapshot), "--geoip", str(self.geoip), "--home", "AU"])
        self.assertEqual((code, output), (2, "Attacks failed: the snapshot has no usable window.\n"))
        self.assertNotEqual(self.snapshot.read_text(), before)  # the rewrite above, untouched since


if __name__ == "__main__":
    unittest.main()
