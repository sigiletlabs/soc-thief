"""Deterministic breach signals. Pure functions over allowlisted collector fields.

A signal is a fixed name; nothing here returns or echoes alert text. A group carrying a signal is
always delivered, skips operator tuning and the model, and is never folded into a description
summary (see ``runner.run_window``). Signals match on Wazuh rule ids and rule groups, never on
description words.

Rule ids come from the stock Wazuh 4.14.5 ruleset. The firing rates in the comments are 90 days
of real alerts from one deployment, counted read-only as
distinct agent-days, which bounds how often each signal could page.

Left out on purpose, after measurement:

- **Three or more MITRE tactics on one agent within N hours.** Every successful PAM login carries
  four tactics (T1078), and 1,454 of 3,922 agent-hours in 30 days reached three. Excluding T1078
  still left 823. As specified it would page all day; it needs a baseline design first.
- **An expected agent going silent.** That needs an operator-owned agent inventory, so it
  lives in ``soc_thief.liveness``.
"""

from collections.abc import Mapping

# Fixed order: when a group carries several signals, the first one names it.
SIGNALS = ("malware", "log_cleared", "privileged_group_change", "account_created",
           "brute_force_success", "critical_file_change")

# 513 rootcheck "Windows malware detected"; 521 rootcheck "Possible kernel level rootkit"
# (34 agent-days, almost all one agent: likely rootcheck's known false
# positive, but a rootkit claim is exactly what must not be hidden); Defender 62113 found
# malware, 62122 suspicious behaviour, 62123 potentially unwanted software, 62126 critical
# error acting on a threat (0 in 90 days).
_MALWARE_RULES = frozenset({"513", "521", "62113", "62122", "62123", "62126"})
# Wazuh tags every log-clearing rule (593, 18118, 60117) with this group. 0 in 90 days.
_LOG_CLEARED_GROUP = "logs_cleared"
# Administrators, Domain Admins, Schema Admins, Enterprise Admins changed (two rule families).
# 1 agent-day in 90.
_PRIVILEGED_GROUP_RULES = frozenset({"60154", "60159", "60166", "60167",
                                     "18217", "18222", "18229", "18230"})
# 5902 Linux new user added; 60109 Windows user account enabled or created. 9 agent-days in 90.
_ACCOUNT_CREATED_RULES = frozenset({"5902", "60109"})
# Wazuh's own "multiple authentication failures followed by a success". 0 in 90 days.
_BRUTE_SUCCESS_RULES = frozenset({"40112"})
# Wazuh's brute-force rules (5712, 5720, 5763, 60204, ...) carry the plural group; a single
# failed login carries "authentication_failed" and does not count.
_BRUTE_GROUP = "authentication_failures"
_SUCCESS_GROUP = "authentication_success"
# Exact files and directory prefixes whose content change is a breach signal.
_CRITICAL_FILES = frozenset({"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                             "/etc/sudoers", "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
                             "/etc/ld.so.preload", "/etc/crontab"})
_CRITICAL_PREFIXES = ("/etc/sudoers.d/", "/etc/ssh/sshd_config.d/", "/root/.ssh/", "/etc/cron.d/")
# A modification counts only when content changed. One /etc/sudoers.d file had 258 mtime-only
# changes on 255 agent-days across three agents in 90 days; paging on that would page daily.
_CONTENT_ATTRIBUTES = frozenset({"size", "md5", "sha1", "sha256"})


def _groups(fields: Mapping[str, object]) -> frozenset[str]:
    value = fields.get("rule.groups")
    if type(value) is not list:
        return frozenset()
    return frozenset(group.strip() for group in value if type(group) is str)


def _critical_file_change(fields: Mapping[str, object], groups: frozenset[str]) -> bool:
    path = fields.get("syscheck.path")
    if "syscheck" not in groups or type(path) is not str:
        return False
    if path not in _CRITICAL_FILES and not path.startswith(_CRITICAL_PREFIXES):
        return False
    event = fields.get("syscheck.event")
    if event in ("added", "deleted"):
        return True
    if event != "modified":
        return True  # Unknown or absent event type: fail towards paging.
    changed = fields.get("syscheck.changed_attributes")
    if type(changed) is not list:
        return True  # Wazuh did not say what changed; assume content.
    return any(attribute in _CONTENT_ATTRIBUTES for attribute in changed)


def event_signals(fields: Mapping[str, object]) -> frozenset[str]:
    """Signals one alert raises on its own. Correlation is ``BruteForceSuccess``."""
    rule, groups = fields.get("rule.id"), _groups(fields)
    found = set()
    if rule in _MALWARE_RULES:
        found.add("malware")
    if _LOG_CLEARED_GROUP in groups:
        found.add("log_cleared")
    if rule in _PRIVILEGED_GROUP_RULES:
        found.add("privileged_group_change")
    if rule in _ACCOUNT_CREATED_RULES:
        found.add("account_created")
    if rule in _BRUTE_SUCCESS_RULES:
        found.add("brute_force_success")
    if _critical_file_change(fields, groups):
        found.add("critical_file_change")
    return frozenset(found)


class BruteForceSuccess:
    """A successful login after a brute-force alert from the same source on the same agent.

    Feed every alert with ``observe``; ``flagged`` returns the references of success alerts that
    came after the first brute-force alert for their (agent, source). Order of observation does
    not matter. Measured: no such pair in 90 days.
    """

    def __init__(self) -> None:
        self._first_brute: dict[tuple[str, str], object] = {}
        self._successes: dict[tuple[str, str], list[tuple[object, object]]] = {}

    def observe(self, fields: Mapping[str, object], instant: object, reference: object) -> None:
        agent, source = fields.get("agent.id"), fields.get("data.srcip")
        if type(agent) is not str or type(source) is not str or not source:
            return
        key, groups = (agent, source), _groups(fields)
        if _BRUTE_GROUP in groups:
            first = self._first_brute.get(key)
            if first is None or instant < first:
                self._first_brute[key] = instant
        if _SUCCESS_GROUP in groups:
            self._successes.setdefault(key, []).append((instant, reference))

    def flagged(self) -> set[object]:
        hits = set()
        for key, successes in self._successes.items():
            first = self._first_brute.get(key)
            if first is not None:
                hits.update(reference for instant, reference in successes if instant > first)
        return hits


def name(signals: frozenset[str] | set[str]) -> str:
    """The decision reason for a group carrying ``signals``: ``breach_<first signal>``."""
    for signal in SIGNALS:
        if signal in signals:
            return "breach_" + signal
    raise ValueError("no breach signal")


REASONS = tuple("breach_" + signal for signal in SIGNALS)
