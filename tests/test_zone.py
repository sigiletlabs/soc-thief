"""The report timezone setting: UTC by default, any IANA zone by name, a clear error otherwise."""
import contextlib
import io
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from soc_thief import backfill, fastpath, profile, runner, zone
from soc_thief.collector import CollectorConfig, WazuhIndexerCollector

UNITS = Path(__file__).resolve().parents[1] / "deploy" / "systemd"


def _env(value=None):
    """Patch the process setting; None removes it so the default applies."""
    environ = {k: v for k, v in os.environ.items() if k != zone.ENV}
    if value is not None:
        environ[zone.ENV] = value
    return patch.dict(os.environ, environ, clear=True)


class ZoneSettingTest(unittest.TestCase):
    def test_default_is_utc(self):
        with _env():
            self.assertEqual(zone.name(), "UTC")
            self.assertEqual(zone.report_zone().key, "UTC")
            start, end = runner.daily_window(datetime(2026, 3, 10, 9, tzinfo=timezone.utc))
            self.assertEqual((start, end), (datetime(2026, 3, 9, 8, tzinfo=timezone.utc),
                                            datetime(2026, 3, 10, 8, tzinfo=timezone.utc)))

    def test_invalid_names_raise_fixed_text(self):
        for value in ("", "Mars/Olympus_Mons", "../../etc/passwd", "Europe/" + "x" * 80, "UTC\n"):
            with self.subTest(value=value[:20]), _env(value):
                with self.assertRaises(zone.TimezoneError) as caught:
                    zone.report_zone()
                self.assertNotIn(value or "\0", str(caught.exception))
                self.assertIn("SOC_THIEF_TIMEZONE", zone.check())

    def test_new_york_dst_days_are_23_and_25_hours(self):
        with _env("America/New_York"):
            # DST starts 2026-03-08 02:00 EST: the report day ending 08:00 EDT is 23 hours.
            start, end = runner.daily_window(datetime(2026, 3, 8, 18, tzinfo=timezone.utc))
            self.assertEqual((start, end), (datetime(2026, 3, 7, 13, tzinfo=timezone.utc),
                                            datetime(2026, 3, 8, 12, tzinfo=timezone.utc)))
            self.assertEqual(end - start, timedelta(hours=23))
            # DST ends 2026-11-01 02:00 EDT: the report day ending 08:00 EST is 25 hours.
            start, end = runner.daily_window(datetime(2026, 11, 1, 18, tzinfo=timezone.utc))
            self.assertEqual((start, end), (datetime(2026, 10, 31, 12, tzinfo=timezone.utc),
                                            datetime(2026, 11, 1, 13, tzinfo=timezone.utc)))
            self.assertEqual(end - start, timedelta(hours=25))
            self.assertEqual(backfill.window_starting(start), (start, end))
            self.assertEqual(runner.reconcile_window(datetime(2026, 11, 2, 18, tzinfo=timezone.utc)), (start, end))
            # The quiet period follows local time: 07:45 EST is 12:45Z after the change.
            self.assertTrue(backfill.in_quiet_period(datetime(2026, 11, 2, 12, 45, tzinfo=timezone.utc)))
            self.assertFalse(backfill.in_quiet_period(datetime(2026, 11, 2, 11, 45, tzinfo=timezone.utc)))

    def test_zone_follows_the_setting_in_pages_and_profile_queries(self):
        entry = {"first": datetime(2026, 7, 1, 12, tzinfo=timezone.utc), "count": 1, "cases": {"0" * 64}}
        with _env("Europe/Berlin"):
            self.assertIn("First seen: 2026-07-01 14:00 CEST", fastpath._page("malware", "001", entry).body)
            config = CollectorConfig("https://indexer.example.test:9200", Path("/nonexistent/u"), Path("/nonexistent/p"))
            payload = WazuhIndexerCollector(config)._profile_payload(
                datetime(2026, 6, 1, tzinfo=timezone.utc), datetime(2026, 7, 1, tzinfo=timezone.utc), None)
            days = payload["aggs"]["groups"]["aggs"]["days"]["date_histogram"]
            self.assertEqual(days["time_zone"], "Europe/Berlin")
        with _env():
            self.assertIn("First seen: 2026-07-01 12:00 UTC", fastpath._page("malware", "001", entry).body)

    def test_entrypoints_refuse_an_invalid_zone_before_anything_else(self):
        never = lambda *a, **k: self.fail("must not run")
        calls = (lambda: runner.main(["--daily"], env={}, run_worker=never, send_health=never),
                 lambda: backfill.main(["--from", "2026-01-01"], env={}, run_worker=never, send_health=never),
                 lambda: fastpath.main([], env={}, collector_factory=never, pager_factory=never),
                 lambda: profile.main(["--start", "2026-01-01T00:00:00Z", "--end", "2026-01-02T00:00:00Z",
                                       "--output", "/nonexistent/x"]))
        for call in calls:
            with self.subTest(call=call), _env("Not/AZone"):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = call()
                self.assertEqual(code, 2)
                self.assertIn("SOC_THIEF_TIMEZONE is not a valid IANA timezone name", out.getvalue())


class DeploymentZoneTest(unittest.TestCase):
    def test_timers_use_the_same_zone_the_units_default_to(self):
        defaults = set()
        for unit in UNITS.glob("*.service"):
            text = unit.read_text()
            if "-m soc_thief." in text or "${SOC_THIEF_IMAGE}" in text:
                found = re.findall(r"^Environment=SOC_THIEF_TIMEZONE=(\S+)$", text, re.M)
                self.assertEqual(len(found), 1, unit.name)
                defaults.update(found)
                if "podman" in text:
                    self.assertIn("--env SOC_THIEF_TIMEZONE=${SOC_THIEF_TIMEZONE} ", text, unit.name)
        self.assertEqual(defaults, {"UTC"})
        for timer in UNITS.glob("*.timer"):
            for spec in re.findall(r"^OnCalendar=(.*)$", timer.read_text(), re.M):
                if spec.startswith("*-*-*"):
                    with self.subTest(timer=timer.name):
                        self.assertTrue(spec.endswith(" UTC"), spec)


if __name__ == "__main__":
    unittest.main()
