"""Deployment invariants for the rate-limited all-history backfill units."""
from datetime import datetime, timedelta
from pathlib import Path
import re
import unittest

from soc_thief import backfill


ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy/systemd"


def _lines(text):
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def _timeout(text):
    (value,) = re.findall(r"^TimeoutStartSec=(\d+)s$", text, re.MULTILINE)
    return timedelta(seconds=int(value))


class BackfillDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.unit = (UNITS / "soc-thief-backfill.service").read_text()
        self.runner = (UNITS / "soc-thief-runner.service").read_text()
        self.timer = (UNITS / "soc-thief-backfill.timer").read_text()

    def test_unit_is_separately_gated(self):
        self.assertIn("ConditionPathExists=/etc/soc-thief/enable-backfill", self.unit)
        self.assertNotIn("enable-runner", self.unit)
        self.assertNotIn("enable-schedule", self.unit)
        self.assertIn("SyslogIdentifier=soc-thief-backfill", self.unit)
        self.assertIn("--name soc-thief-backfill ", self.unit)
        self.assertIn("EnvironmentFile=/etc/soc-thief/environment\n", self.unit)
        self.assertTrue(re.search(r" -m soc_thief\.backfill --from \$\{SOC_THIEF_BACKFILL_FROM\}$", self.unit, re.MULTILINE))

    def test_hardening_matches_runner_apart_from_expected_differences(self):
        def normalise(text, name):
            result = []
            for line in _lines(text):
                if line.startswith(("Description=", "ConditionPathExists=", "SyslogIdentifier=", "TimeoutStartSec=")):
                    continue
                if (line.startswith(("ExecStartPre=", "Environment=SOC_THIEF_NTFY_"))
                        or line == "LoadCredential=ntfy:/etc/soc-thief/secrets/ntfy"):
                    continue  # Only the daily runner pages, so only it has the ntfy credential.
                if line.startswith("ExecStart="):
                    line = line.replace("--exclusive --nonblock", "--exclusive")
                    line = line.replace("--env SOC_THIEF_NTFY_FILE=/run/secrets/ntfy ", "")
                    line = line.replace("--add-host ${SOC_THIEF_NTFY_ALIAS}:${SOC_THIEF_NTFY_ADDR} ", "")
                    line = line.replace(f"--name {name} ", "--name NAME ")
                    line = re.sub(r" -m soc_thief\.(runner --daily|backfill --from \$\{SOC_THIEF_BACKFILL_FROM\})$", " -m ENTRY", line)
                result.append(line)
            return result
        self.assertEqual(normalise(self.unit, "soc-thief-backfill"), normalise(self.runner, "soc-thief-runner"))

    def test_no_host_network_or_privilege(self):
        for forbidden in ("--network host", "--network=host", "docker.sock", "--privileged", "slirp4netns"):
            self.assertNotIn(forbidden, self.unit)
        for flag in ("User=soc-thief", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--userns=keep-id", "--network pasta:-T,${SOC_THIEF_INDEXER_PORT},-T,${SOC_THIEF_MODEL_PORT}",
                     "--mount type=bind,src=%d,dst=/run/secrets,ro=true", "ProtectSystem=strict",
                     "PrivateDevices=yes", "MemoryDenyWriteExecute=yes", "UMask=0077",
                     "--env SOC_THIEF_RUNNER_APPROVAL_FILE=/run/secrets/runner_approval",
                     "--env STATE_PATH=/var/lib/soc-thief/state ",
                     "LoadCredential=tuning:/etc/soc-thief/secrets/tuning\n",
                     "--env SOC_THIEF_TUNING_FILE=/run/secrets/tuning "):
            self.assertIn(flag, self.unit)
        # The origin date is the only new value and it is not a secret or a credential.
        self.assertNotIn("LoadCredential=backfill", self.unit)

    def test_daily_and_reconcile_preempt_backfill_but_backfill_cannot_preempt_them(self):
        lock = "/usr/bin/flock --exclusive /run/soc-thief/priority.lock"
        stop = "ExecStartPre=+/usr/bin/systemctl stop soc-thief-backfill.service\n"
        for name in ("soc-thief-runner", "soc-thief-reconcile"):
            with self.subTest(unit=name):
                unit = (UNITS / f"{name}.service").read_text()
                self.assertIn(stop, unit)
                self.assertIn(f"ExecStart={lock} /usr/bin/podman ", unit)
        self.assertIn("ExecStart=/usr/bin/flock --exclusive --nonblock "
                      "/run/soc-thief/priority.lock /usr/bin/podman ", self.unit)
        self.assertNotIn("systemctl", self.unit)
        self.assertNotIn("soc-thief-runner.service", self.unit)
        self.assertNotIn("soc-thief-reconcile.service", self.unit)

    def test_unit_timeout_bounds_worker_and_respects_quiet_period(self):
        timeout = _timeout(self.unit)
        self.assertEqual(timeout, timedelta(seconds=1800))
        self.assertEqual(timeout, backfill.UNIT_TIMEOUT)
        self.assertLess(timedelta(seconds=backfill.WORKER_TIMEOUT), timeout)
        day = datetime(2026, 9, 13)
        # Every other state-lock holder (daily runner, reconcile pass) must run entirely inside a
        # quiet period, and a backfill started just before that period must end before it fires.
        for name in ("soc-thief-runner", "soc-thief-reconcile"):
            with self.subTest(unit=name):
                timer = (UNITS / f"{name}.timer").read_text()
                (hour, minute) = re.findall(r"^OnCalendar=\*-\*-\* (\d\d):(\d\d):00 UTC$", timer, re.MULTILINE)[0]
                (delay,) = re.findall(r"^RandomizedDelaySec=(\d+)m$", timer, re.MULTILINE)
                fires = day.replace(hour=int(hour), minute=int(minute))
                latest_end = fires + timedelta(minutes=int(delay)) + _timeout((UNITS / f"{name}.service").read_text())
                self.assertTrue(any(
                    datetime.combine(day, start) + timeout <= fires and latest_end <= datetime.combine(day, end)
                    for start, end in backfill.QUIET_PERIODS))

    def test_timer_is_hourly_non_persistent_and_jittered(self):
        lines = _lines(self.timer)
        self.assertIn("OnCalendar=hourly", lines)
        self.assertIn("Persistent=false", lines)
        self.assertIn("RandomizedDelaySec=2m", lines)
        self.assertIn("Unit=soc-thief-backfill.service", lines)
        self.assertIn("WantedBy=timers.target", lines)
        self.assertNotIn("Persistent=true", self.timer)


if __name__ == "__main__":
    unittest.main()
