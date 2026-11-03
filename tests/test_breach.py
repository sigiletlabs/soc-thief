"""Breach signals: each named signal, its near misses, and the correlation."""

import unittest
from datetime import datetime, timedelta, timezone

from soc_thief import breach

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def fields(rule="100", groups=None, **extra):
    base = {"rule.id": rule, "agent.id": "001", "rule.groups": groups, "data.srcip": None,
            "syscheck.path": None, "syscheck.event": None, "syscheck.changed_attributes": None}
    base.update({name.replace("__", "."): value for name, value in extra.items()})
    return base


class EventSignalTests(unittest.TestCase):
    def test_each_signal_fires_on_its_rules_or_group(self):
        cases = {
            "malware": [fields("521"), fields("513"), fields("62113"), fields("62122"), fields("62123"),
                        fields("62126")],
            "log_cleared": [fields("60117", ["windows", "logs_cleared"]), fields("593", ["logs_cleared"])],
            "privileged_group_change": [fields(rule) for rule in ("60154", "60159", "60166", "60167",
                                                                  "18217", "18222", "18229", "18230")],
            "account_created": [fields("5902"), fields("60109")],
            "brute_force_success": [fields("40112")],
            "critical_file_change": [
                fields("550", ["ossec", "syscheck"], syscheck__path="/etc/shadow",
                       syscheck__event="modified", syscheck__changed_attributes=["size", "mtime", "sha256"]),
                fields("554", ["syscheck"], syscheck__path="/etc/sudoers.d/new", syscheck__event="added"),
                fields("553", ["syscheck"], syscheck__path="/root/.ssh/authorized_keys", syscheck__event="deleted"),
                fields("550", ["syscheck"], syscheck__path="/etc/passwd", syscheck__event="modified"),
            ],
        }
        self.assertEqual(set(cases), set(breach.SIGNALS))
        for signal, examples in cases.items():
            for example in examples:
                with self.subTest(signal=signal, rule=example["rule.id"]):
                    self.assertEqual(breach.event_signals(example), {signal})

    def test_near_misses_raise_nothing(self):
        misses = [
            fields("510", ["ossec", "rootcheck"]),            # generic rootcheck anomaly
            fields("62128", ["windows", "windows_defender"]),  # Defender healthy
            fields("5903", ["adduser"]),                       # user deleted
            fields("60204", ["authentication_failures"]),      # brute force alone
            fields("5501", ["pam", "authentication_success"]),  # login alone
            fields("100", ["logs"]),
            # The measured daily noise: an mtime-only change in /etc/sudoers.d.
            fields("550", ["syscheck"], syscheck__path="/etc/sudoers.d/tool", syscheck__event="modified",
                   syscheck__changed_attributes=["mtime"]),
            fields("550", ["syscheck"], syscheck__path="/etc/hosts", syscheck__event="modified",
                   syscheck__changed_attributes=["sha256"]),
            fields("550", ["syscheck"], syscheck__path="/etc/sudoers.d.bak", syscheck__event="added"),
            # A critical path outside syscheck is not a file-integrity signal.
            fields("100", ["audit"], syscheck__path="/etc/shadow"),
        ]
        for example in misses:
            with self.subTest(example=example):
                self.assertEqual(breach.event_signals(example), frozenset())

    def test_description_words_are_never_consulted(self):
        example = fields("100", ["local"])
        example["rule.description"] = "malware rootkit audit log cleared new admin"
        self.assertEqual(breach.event_signals(example), frozenset())

    def test_group_names_tolerate_wazuh_leading_spaces(self):
        # Real alerts carry groups such as " WEF" and " powershell".
        self.assertEqual(breach.event_signals(fields("1", [" logs_cleared"])), {"log_cleared"})

    def test_unknown_syscheck_shape_fails_towards_paging(self):
        for event, changed in ((None, None), ("modified", None), ("renamed", ["mtime"])):
            with self.subTest(event=event):
                example = fields("550", ["syscheck"], syscheck__path="/etc/shadow", syscheck__event=event,
                                 syscheck__changed_attributes=changed)
                self.assertEqual(breach.event_signals(example), {"critical_file_change"})


class BruteForceSuccessTests(unittest.TestCase):
    def observe(self, detector, rule, groups, at, reference, agent="001", source="198.51.100.7"):
        detector.observe(fields(rule, groups, agent__id=agent, data__srcip=source), at, reference)

    def test_success_after_brute_force_from_same_source_and_agent(self):
        detector = breach.BruteForceSuccess()
        self.observe(detector, "5501", ["authentication_success"], T0 + timedelta(minutes=5), "late")
        self.observe(detector, "5720", ["sshd", "authentication_failures"], T0, "brute")
        self.observe(detector, "5501", ["authentication_success"], T0 - timedelta(minutes=1), "early")
        self.assertEqual(detector.flagged(), {"late"})

    def test_a_later_brute_force_run_does_not_hide_an_earlier_success(self):
        detector = breach.BruteForceSuccess()
        self.observe(detector, "5720", ["authentication_failures"], T0, "first-run")
        self.observe(detector, "5501", ["authentication_success"], T0 + timedelta(minutes=2), "between")
        self.observe(detector, "5720", ["authentication_failures"], T0 + timedelta(minutes=9), "second-run")
        self.assertEqual(detector.flagged(), {"between"})

    def test_other_source_other_agent_single_failure_or_no_source_do_not_correlate(self):
        detector = breach.BruteForceSuccess()
        self.observe(detector, "5720", ["authentication_failures"], T0, "brute")
        self.observe(detector, "5501", ["authentication_success"], T0 + timedelta(1), "other-source",
                     source="203.0.113.9")
        self.observe(detector, "5501", ["authentication_success"], T0 + timedelta(1), "other-agent", agent="002")
        self.observe(detector, "5716", ["authentication_failed"], T0, "single", source="192.0.2.5")
        self.observe(detector, "5501", ["authentication_success"], T0 + timedelta(1), "after-single",
                     source="192.0.2.5")
        detector.observe(fields("5720", ["authentication_failures"]), T0, "no-source")
        detector.observe(fields("5501", ["authentication_success"]), T0 + timedelta(1), "no-source-success")
        self.assertEqual(detector.flagged(), set())


class NameTests(unittest.TestCase):
    def test_first_signal_in_fixed_order_names_the_group(self):
        self.assertEqual(breach.name({"critical_file_change", "malware"}), "breach_malware")
        self.assertEqual(breach.REASONS, tuple("breach_" + signal for signal in breach.SIGNALS))
        with self.assertRaises(ValueError):
            breach.name(set())


if __name__ == "__main__":
    unittest.main()
