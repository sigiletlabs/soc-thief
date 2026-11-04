"""Demo mode: one synthetic report window through the real pipeline, written as a snapshot.

    python -m soc_thief.demo --out snapshot.json [--seed N] [--now ISO] [--digest-out FILE]

Generates deterministic, Wazuh-shaped alerts for the most recent closed 08:00-to-08:00 window in
``SOC_THIEF_TIMEZONE`` and runs them through ``runner.run_window`` unchanged: the real grouping and
dedupe, breach signals, ``policy.preflight``/``tuned``/``decide``, a real tuning file, the 30-day
baseline, the state store and the digest renderer. Only the edges are replaced: the collector
yields generated records, the model is a deterministic stub (no network), Discord delivery and the
fast-path pager capture what they are given instead of sending it, and the state store lives in a
temporary directory that is removed afterwards.

All data is fictional: host names like ``web-01``, addresses only from the RFC 5737 documentation
ranges, user names like ``alice``. Rule ids and descriptions are stock Wazuh rules.

The scenario, for a projector: steady background noise (some muted or downgraded by the demo
tuning file), an SSH brute-force spike on the VPN host, a brute force followed by a successful
login and a new account on a web server (breach, paged), a ransomware-style file drop that the
tuning file tries and fails to mute, an encoded PowerShell command, a new Windows service, a
content change to a sudoers file (breach, paged), and two groups whose model review times out
(failed, delivered anyway).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import tempfile
from dataclasses import dataclass
from datetime import datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from soc_thief import attacks, fastpath, runner, zone
from soc_thief.delivery import ReportItem, _category
from soc_thief.model import ModelError, ModelReview
from soc_thief.policy import Decision, preflight
from soc_thief.state import StateStore
from soc_thief.tuning import load_tuning

SCHEMA = "soc-thief.snapshot/1.1"
STUB_MODEL = "demo-stub"
BASELINE_DAYS = 30
HISTORY_DAYS = 10
DEFAULT_SEED = 7
MANAGER = "wazuh-manager"

# (agent id, name, platform)
AGENTS = (
    ("001", "web-01", "linux"), ("002", "web-02", "linux"), ("003", "db-01", "linux"),
    ("004", "mail-01", "linux"), ("005", "vpn-01", "linux"), ("006", "files-01", "linux"),
    ("007", "build-01", "linux"), ("008", "proxy-01", "linux"),
    ("011", "dc-01", "windows"), ("012", "ws-03", "windows"), ("013", "ws-07", "windows"),
    ("014", "ws-12", "windows"),
)
_NAMES = {agent_id: name for agent_id, name, _ in AGENTS}
_LINUX = tuple(name for _, name, platform in AGENTS if platform == "linux")
_WINDOWS = tuple(name for _, name, platform in AGENTS if platform == "windows")
_IDS = {name: agent_id for agent_id, name, _ in AGENTS}

# RFC 5737 only. Admins log in from 198.51.100.0/24; scanners and attackers come from 203.0.113.0/24.
ADMIN_IPS = ("198.51.100.10", "198.51.100.11", "198.51.100.24")
SCANNER_IPS = tuple(f"203.0.113.{n}" for n in (7, 19, 33, 61, 88, 102, 150, 201))
ATTACKER_IP = "203.0.113.45"
USERS = ("alice", "bob", "carol", "svc-backup", "svc-deploy")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    level: int
    description: str
    groups: tuple[str, ...]
    decoder: str
    location: str


R = {rule.rule_id: rule for rule in (
    Rule("5501", 3, "PAM: Login session opened.", ("pam", "syslog", "authentication_success"), "pam", "journald"),
    Rule("5502", 3, "PAM: Login session closed.", ("pam", "syslog"), "pam", "journald"),
    Rule("5402", 3, "Successful sudo to ROOT executed.", ("syslog", "sudo"), "sudo", "journald"),
    Rule("2902", 7, "New dpkg (Debian Package) installed.", ("syslog", "dpkg", "config_changed"), "dpkg-decoder", "/var/log/dpkg.log"),
    Rule("2904", 7, "Dpkg (Debian Package) half configured.", ("syslog", "dpkg", "config_changed"), "dpkg-decoder", "/var/log/dpkg.log"),
    Rule("533", 7, "Listened ports status (netstat) changed (new port opened or closed).", ("ossec",), "ossec", "netstat listening ports"),
    Rule("550", 7, "Integrity checksum changed.", ("ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"), "syscheck_integrity_changed", "syscheck"),
    Rule("554", 5, "File added to the system.", ("ossec", "syscheck", "syscheck_entry_added", "syscheck_file"), "syscheck_new_entry", "syscheck"),
    Rule("1002", 2, "Unknown problem somewhere in the system.", ("syslog", "errors"), "systemd", "journald"),
    Rule("5710", 5, "sshd: Attempt to login using a non-existent user", ("syslog", "sshd", "authentication_failed", "invalid_login"), "sshd", "journald"),
    Rule("5716", 5, "sshd: authentication failed.", ("syslog", "sshd", "authentication_failed"), "sshd", "journald"),
    Rule("5712", 10, "sshd: brute force trying to get access to the system. Non existent user.", ("syslog", "sshd", "authentication_failures"), "sshd", "journald"),
    Rule("5715", 3, "sshd: authentication success.", ("syslog", "sshd", "authentication_success"), "sshd", "journald"),
    Rule("40112", 12, "Multiple authentication failures followed by a success.", ("authentication_success", "attack"), "sshd", "journald"),
    Rule("5902", 8, "New user added to the system.", ("syslog", "adduser"), "useradd", "journald"),
    Rule("31101", 5, "Web server 400 error code.", ("web", "accesslog", "attack"), "web-accesslog", "/var/log/nginx/access.log"),
    Rule("31151", 10, "Multiple web server 400 error codes from same source ip.", ("web", "accesslog", "web_scan", "recon"), "web-accesslog", "/var/log/nginx/access.log"),
    Rule("19004", 7, "SCA summary: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0: Score less than 50% ({score})", ("sca",), "sca", "sca"),
    Rule("19007", 7, "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0: {check}", ("sca",), "sca", "sca"),
    Rule("60106", 3, "Windows Logon Success", ("windows", "windows_security", "authentication_success"), "windows_eventchannel", "EventChannel"),
    Rule("60137", 3, "Windows User Logoff", ("windows", "windows_security"), "windows_eventchannel", "EventChannel"),
    Rule("60122", 5, "Logon Failure - Unknown user or bad password", ("windows", "windows_security", "authentication_failed"), "windows_eventchannel", "EventChannel"),
    Rule("61104", 3, "Service startup type was changed", ("windows", "windows_system"), "windows_eventchannel", "EventChannel"),
    Rule("60602", 9, "Windows application error event.", ("windows", "windows_application"), "windows_eventchannel", "EventChannel"),
    Rule("61138", 5, "New Windows Service Created", ("windows", "windows_system", "policy_changed"), "windows_eventchannel", "EventChannel"),
    Rule("92057", 12, "Powershell.exe spawned a powershell process which executed a base64 encoded command", ("sysmon", "sysmon_eid1_detections", "windows"), "windows_eventchannel", "EventChannel"),
    Rule("92213", 15, "Executable file dropped in folder commonly used by malware", ("sysmon", "sysmon_eid11_detections", "windows"), "windows_eventchannel", "EventChannel"),
)}

_SCA_CHECKS = (
    "Ensure mounting of cramfs filesystems is disabled.",
    "Ensure separate partition exists for /var/tmp.",
    "Ensure AIDE is installed.",
    "Ensure bootloader password is set.",
    "Ensure auditd service is enabled.",
    "Ensure SSH X11 forwarding is disabled.",
    "Ensure permissions on /etc/crontab are configured.",
    "Ensure core dumps are restricted.",
    "Ensure chrony is configured.",
    "Ensure rsyslog default file permissions are configured.",
)

# (rule, agents, mean events per day). Every pair here is in the 30-day baseline.
_BACKGROUND = (
    ("5501", _LINUX, 420), ("5502", _LINUX, 410), ("5402", ("web-01", "web-02", "db-01", "build-01", "files-01", "mail-01"), 16),
    ("2902", _LINUX, 4), ("2904", _LINUX, 3), ("533", _LINUX, 6),
    ("550", tuple(a for a in _LINUX if a != "web-01"), 24), ("554", tuple(a for a in _LINUX if a != "web-01"), 18),
    ("1002", _LINUX, 30),
    ("5710", ("web-01", "web-02", "vpn-01", "mail-01"), 45), ("5716", ("web-01", "web-02", "vpn-01", "mail-01"), 20),
    ("5712", ("vpn-01",), 3), ("5715", ("web-01", "vpn-01", "build-01"), 10),
    ("31101", ("web-01", "web-02", "proxy-01"), 3000), ("31151", ("web-01", "web-02"), 2),
    ("19004", _LINUX, 1),
    ("60106", _WINDOWS, 1500), ("60137", _WINDOWS, 1000), ("60122", _WINDOWS, 10),
    ("61104", _WINDOWS, 3), ("60602", _WINDOWS, 4),
)
# Busy hours, local time, as weights for 24 hourly buckets starting at 08:00.
SCA_PER_HOST = 5
_HOUR_WEIGHTS = (6, 8, 8, 8, 7, 8, 8, 8, 7, 5, 4, 3, 3, 2, 2, 2, 1, 1, 1, 1, 1, 2, 3, 4)

DEMO_TUNING = {"version": 1, "entries": [
    {"rule_id": "31101", "action": "mute", "note": "web 4xx noise from crawlers"},
    {"rule_id": "1002", "action": "mute", "note": "generic journald errors"},
    {"rule_id": "533", "action": "mute", "note": "port churn from container restarts"},
    {"rule_id": "2902", "action": "low", "note": "package installs during patching"},
    {"rule_id": "61104", "action": "low", "note": "service startup changes from updates"},
    # This one cannot work: a level 15 malware rule is protected, and tuning never reaches it.
    {"rule_id": "92213", "action": "mute", "note": "someone tried to silence this"},
]}

# Stub model advice per rule: (classification, confidence, tags, rationale, action).
_ADVICE = {
    "31151": ("suspicious", 0.85, ("web", "scanning"), "Many 4xx responses from one source look like a path scanner.",
              "Check the source against the WAF and block it if it persists."),
    "61138": ("suspicious", 0.8, ("persistence", "windows"), "A new service on a domain controller needs a matching change record.",
              "Confirm the service against change records today."),
    "2904": ("benign", 0.9, ("patching",), "Package configuration during the patch window.", "No action unless it repeats."),
    "60137": ("benign", 0.95, ("authentication",), "User logoffs at their usual volume.", "None."),
    "60602": ("unknown", 0.6, ("windows", "stability"), "Application crashes; not a security signal by themselves.",
              "Check whether one application crashes repeatedly."),
    "19004": ("benign", 0.9, ("compliance",), "Configuration assessment score; a hardening task, not an attack.",
              "Track in the hardening backlog."),
    "19007": ("benign", 0.9, ("compliance",), "Failed configuration check; a hardening task, not an attack.",
              "Track in the hardening backlog."),
    "550": ("benign", 0.8, ("fim",), "File changes under application paths during deploy hours.", "Spot-check one change."),
    "554": ("benign", 0.8, ("fim",), "New files under application paths during deploy hours.", "Spot-check one file."),
}
_DEFAULT_ADVICE = ("unknown", 0.6, ("triage",), "No indicator of compromise in the group summary.", "Spot-check one event in Wazuh.")
# Groups whose review the stub fails, as a model timeout would: (rule, agent name).
STUB_FAILURES = frozenset({("2904", "db-01"), ("60602", "ws-12")})

_SIGNAL_NAMES = {"brute_force_success": "brute force then success", "account_created": "account created",
                 "critical_file_change": "critical file changed", "malware": "malware detected",
                 "log_cleared": "audit log cleared", "privileged_group_change": "privileged group changed"}


class StubModel:
    """Deterministic advice, no network. Fails, like a timeout, for ``STUB_FAILURES``."""

    def __init__(self) -> None:
        self.tags: dict[tuple[str, str], tuple[str, ...]] = {}

    def review(self, group: dict[str, object]) -> ModelReview:
        if preflight(group).delivery_required:
            raise ModelError("model review is not permitted for this group")
        if (group["rule_id"], group.get("agent_name")) in STUB_FAILURES:
            raise ModelError("local model review failed")
        classification, confidence, tags, rationale, action = _ADVICE.get(str(group["rule_id"]), _DEFAULT_ADVICE)
        self.tags[(str(group["rule_id"]), str(group["agent_id"]))] = tags
        return ModelReview({"classification": classification, "confidence": confidence,
                            "rationale": rationale, "analyst_action": action}, STUB_MODEL)


class _Capture:
    """Stands in for Discord delivery and the ntfy pager: keeps what it is given, sends nothing."""

    def __init__(self) -> None:
        self.sent: list[Any] = []

    def send(self, item: Any) -> None:
        self.sent.append(item)


class _Records:
    def __init__(self, records: list[dict[str, Any]]):
        self.records = records

    def collect(self, start: datetime, end: datetime) -> Iterable[dict[str, Any]]:
        return iter(self.records)


def report_window(now: datetime, report_zone: Any) -> tuple[datetime, datetime]:
    """The latest 08:00-to-08:00 local window that has closed at ``now``."""
    local = now.astimezone(report_zone)
    day = local.date() if local.time() >= dt_time(8) else local.date() - timedelta(days=1)
    end = datetime.combine(day, dt_time(8), tzinfo=report_zone)
    start = datetime.combine(day - timedelta(days=1), dt_time(8), tzinfo=report_zone)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


class _Generator:
    def __init__(self, seed: int, start: datetime, end: datetime, report_zone: Any):
        self.rng = random.Random(seed)
        self.start, self.end, self.zone = start, end, report_zone
        self.records: list[dict[str, Any]] = []
        self.serial = 0

    def at_local(self, hour: int, minute: int, second: int = 0) -> datetime:
        """An instant at a local wall-clock time inside the window (hours from 08:00 wrap to the next day)."""
        local_start = self.start.astimezone(self.zone)
        day = local_start.date() + timedelta(days=1 if hour < 8 else 0)
        return datetime.combine(day, dt_time(hour, minute, second), tzinfo=self.zone).astimezone(timezone.utc)

    def random_instant(self) -> datetime:
        hours = max(1, int((self.end - self.start).total_seconds() // 3600))
        weights = [_HOUR_WEIGHTS[i % 24] for i in range(hours)]
        hour = self.rng.choices(range(hours), weights)[0]
        moment = self.start + timedelta(hours=hour, seconds=self.rng.randrange(3600))
        return min(moment, self.end - timedelta(seconds=1))

    def emit(self, rule: Rule, agent: str, instant: datetime, *, description: str | None = None,
             srcip: str | None = None, path: str | None = None, event: str | None = None,
             changed: list[str] | None = None) -> None:
        self.serial += 1
        utc = instant.astimezone(timezone.utc)
        fields = {
            "@timestamp": utc.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "rule.id": rule.rule_id, "rule.level": rule.level,
            "rule.description": description or rule.description,
            "agent.id": _IDS[agent], "agent.name": agent, "decoder.name": rule.decoder,
            "manager.name": MANAGER, "location": rule.location, "rule.groups": list(rule.groups),
            "data.srcip": srcip, "syscheck.path": path, "syscheck.event": event,
            "syscheck.changed_attributes": changed,
        }
        index = f"wazuh-alerts-4.x-{utc:%Y.%m.%d}"
        self.records.append({"source_key": {"index": index, "id": f"demo{self.serial:08d}"}, "fields": fields})

    def count(self, mean: float) -> int:
        return max(1, round(self.rng.gauss(mean, math.sqrt(mean) * 1.2)))

    def background(self) -> None:
        for rule_id, agents, mean in _BACKGROUND:
            rule = R[rule_id]
            for agent in agents:
                for _ in range(self.count(mean)):
                    extra: dict[str, Any] = {}
                    if rule_id in ("5710", "5716", "5712"):
                        extra["srcip"] = self.rng.choice(SCANNER_IPS)
                    elif rule_id == "5715":
                        extra["srcip"] = self.rng.choice(ADMIN_IPS)
                    elif rule_id in ("31101", "31151"):
                        extra["srcip"] = self.rng.choice(SCANNER_IPS + ADMIN_IPS)
                    elif rule_id == "550":
                        extra.update(path=f"/var/www/app/releases/current/lib/module{self.rng.randrange(40)}.py",
                                     event="modified", changed=["size", "mtime", "md5", "sha1", "sha256"])
                    elif rule_id == "554":
                        extra.update(path=f"/var/www/app/releases/current/static/asset{self.rng.randrange(400)}.js",
                                     event="added")
                    elif rule_id == "19004":
                        extra["description"] = rule.description.format(score=30 + int(agent.encode()[-1]) % 19)
                    self.emit(rule, agent, self.random_instant(), **extra)
        # A few failed configuration checks per Linux host, each its own group.
        for agent in _LINUX:
            for check in self.rng.sample(_SCA_CHECKS, SCA_PER_HOST):
                self.emit(R["19007"], agent, self.at_local(9, self.rng.randrange(60)),
                          description=R["19007"].description.format(check=check))

    def story(self) -> None:
        rng = self.rng
        # 1. SSH brute force against the VPN host, well above its baseline.
        first, last = self.at_local(22, 14, 9), self.at_local(3, 51, 40)
        span = (last - first).total_seconds()
        for n in range(812):
            self.emit(R["5712"], "vpn-01", first + timedelta(seconds=span * n / 811), srcip=rng.choice(SCANNER_IPS[:3]))
        for n in range(1400):
            self.emit(R["5710"], "vpn-01", first + timedelta(seconds=rng.uniform(0, span)), srcip=rng.choice(SCANNER_IPS[:3]))
        # 2. Brute force against web-02, then a successful login and a new account from the same source.
        for n in range(64):
            self.emit(R["5712"], "web-02", self.at_local(2, 10) + timedelta(seconds=28 * n), srcip=ATTACKER_IP)
        for n in range(40):
            self.emit(R["5716"], "web-02", self.at_local(2, 12) + timedelta(seconds=41 * n), srcip=ATTACKER_IP)
        self.emit(R["5715"], "web-02", self.at_local(3, 52, 2), srcip=ATTACKER_IP)
        self.emit(R["40112"], "web-02", self.at_local(3, 52, 3), srcip=ATTACKER_IP)
        self.emit(R["5402"], "web-02", self.at_local(3, 55, 30))
        self.emit(R["5902"], "web-02", self.at_local(3, 58, 11))
        # 3. Content change to a sudoers drop-in on web-01: a critical file.
        self.emit(R["550"], "web-01", self.at_local(4, 5, 47), path="/etc/sudoers.d/90-deploy", event="modified",
                  changed=["size", "mtime", "md5", "sha1", "sha256"])
        # 4. Encoded PowerShell on a workstation, then executables dropped where malware hides.
        for n in range(4):
            self.emit(R["92057"], "ws-07", self.at_local(1, 12, 5 + 9 * n))
        for n in range(3):
            self.emit(R["92213"], "ws-07", self.at_local(1, 14, 30 + 7 * n))
        # 5. A rule the baseline has never seen on this host.
        for n in range(2):
            self.emit(R["61138"], "dc-01", self.at_local(23, 40 + n))

    def duplicates(self) -> int:
        """Re-deliver about 2% of records with the same source identity, as an indexer retry would."""
        picks = sorted(self.rng.sample(range(len(self.records)), len(self.records) // 50))
        self.records.extend(self.records[i] for i in picks)
        self.rng.shuffle(self.records)
        return len(picks)


def _baseline_profile() -> dict[str, Any]:
    rows = [{"rule_id": rule_id, "agent_id": _IDS[agent], "events": mean * BASELINE_DAYS, "days_active": BASELINE_DAYS}
            for rule_id, agents, mean in _BACKGROUND for agent in agents]
    rows += [{"rule_id": "19007", "agent_id": _IDS[agent], "events": SCA_PER_HOST * BASELINE_DAYS, "days_active": BASELINE_DAYS}
             for agent in _LINUX]
    return {"groups": rows}


def _local(instant: datetime, report_zone: Any) -> str:
    return instant.astimezone(report_zone).isoformat(timespec="seconds")


def _parse_instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


MAX_GROUPS = 5000  # docs/SNAPSHOT.md: at most this many groups are listed.


def order_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Digest category order, capped at MAX_GROUPS. When capped, delivery-required groups are
    kept before the rest; ``window.groups`` must still carry the true total."""
    ranked = sorted(groups, key=lambda g: (_ORDER.index(g["category"]), not g["breach_signals"],
                                           -g["level"], -g["count"], g["id"]))
    if len(ranked) <= MAX_GROUPS:
        return ranked
    kept = sorted(ranked, key=lambda g: not g["decision"]["delivery_required"])[:MAX_GROUPS]
    chosen = {id(g) for g in kept}
    return [g for g in ranked if id(g) in chosen]


_CATEGORY = {"FAILED": "failed", "NEW": "new", "NEW AGENT": "new", "SPIKE": "spike", "recurring": "recurring"}
_ORDER = ("failed", "new", "spike", "recurring")


def build(*, seed: int = DEFAULT_SEED, now: datetime, workdir: Path | None = None) -> tuple[dict[str, Any], Any]:
    """Run the demo window and return (snapshot, rendered digest or None). Writes only to a temp dir."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("demo time must carry an offset")
    report_zone, zone_name = zone.report_zone(), zone.name()
    now = now.astimezone(timezone.utc)
    start, end = report_window(now, report_zone)
    generator = _Generator(seed, start, end, report_zone)
    generator.background()
    generator.story()
    duplicates = generator.duplicates()
    records = generator.records

    # Identity key: fixed per seed, so group ids are stable across runs.
    key = bytes(random.Random(f"identity-{seed}").getrandbits(8) for _ in range(32))
    observed: list[tuple[dict[str, object], Decision, Any]] = []
    model, delivery, pager = StubModel(), _Capture(), _Capture()
    with tempfile.TemporaryDirectory(prefix="soc-thief-demo-", dir=workdir) as temp:
        root = Path(temp)
        os.chmod(root, 0o700)
        tuning_path = root / "tuning.json"
        fd = os.open(tuning_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(DEMO_TUNING, stream)
        tuning = load_tuning({"SOC_THIEF_TUNING_FILE": str(tuning_path)})
        with StateStore(root / "state") as store:
            result = runner.run_window(
                collector=_Records(records), model=model, delivery=delivery, store=store,
                identity_key=key, stream=runner.STREAM, start=start, end=end,
                now=lambda: now, tuning=tuning, baseline=_baseline_profile,
                observe=lambda group, decision, review: observed.append((dict(group), decision, review)))

    history = runner._history(_baseline_profile())
    known_agents = frozenset(agent for (_, agent), (events, _) in history.items() if events)
    groups_by_index = [group for group, _, _ in observed]
    breach_index = {index: decision.reason for index, (_, decision, _) in enumerate(observed)
                    if decision.reason.startswith("breach_")}

    # The fast path's real page composition over the same groups, sent to a capturing pager.
    pages = fastpath._pages(groups_by_index, breach_index, key)
    breaches, breach_times = [], []
    for (signal, agent_id), entry in sorted(pages.items(), key=lambda item: item[1]["first"]):
        page = fastpath._page(signal, agent_id, entry)
        try:
            pager.send(page)
            paged = True
        except Exception:
            paged = False
        breach_times.append(((entry["first"] - start).total_seconds(),
                             _SIGNAL_NAMES.get(signal, signal.replace("_", " "))))
        breaches.append({"name": _SIGNAL_NAMES.get(signal, signal.replace("_", " ")), "signals": [signal],
                         "agent": _NAMES.get(agent_id, agent_id), "at": _local(entry["first"], report_zone),
                         "paged": paged})

    # first/last seen per group, from the generated records the group was made of.
    seen: dict[tuple[str, str, str], list[datetime]] = {}
    unique: dict[tuple[str, str], datetime] = {}
    for record in records:
        source = record["source_key"]
        instant = _parse_instant(record["fields"]["@timestamp"])
        unique[(source["index"], source["id"])] = instant
    for record in {(r["source_key"]["index"], r["source_key"]["id"]): r for r in records}.values():
        fields = record["fields"]
        instant = _parse_instant(fields["@timestamp"])
        span = seen.setdefault((fields["rule.id"], fields["agent.id"], fields["rule.description"]), [instant, instant])
        span[0], span[1] = min(span[0], instant), max(span[1], instant)

    groups = []
    muted = protected_tuned = model_failures = 0
    for group, decision, review in observed:
        rule_id, agent_id = str(group["rule_id"]), str(group["agent_id"])
        gate = preflight(group)
        breach = decision.reason.startswith("breach_")
        action = tuning.action(rule_id, agent_id, now) or "none"
        protected = breach or gate.reason in ("critical_severity", "protected_indicator")
        if decision.reason in ("tuned_mute", "tuned_low"):
            muted += 1
        if protected and action != "none":
            protected_tuned += 1
        if decision.reason == "invalid_model_result":
            model_failures += 1
        label = _category(ReportItem(group, decision), history, known_agents)
        if label not in _CATEGORY:  # BREACH or CRITICAL: categorise against the baseline alone.
            label = _category(ReportItem(group, Decision(True, False, "model_requires_review")), history, known_agents)
        first = _parse_instant(str(group["timestamp"]))
        last = seen.get((rule_id, agent_id, str(group["rule_description"])), [first, first])[1]
        advice = None
        if review is not None:
            answer = review.result
            advice = {"name": review.model_version, "verdict": answer["classification"],
                      "confidence": answer["confidence"], "tags": list(model.tags.get((rule_id, agent_id), ())),
                      "summary": answer["rationale"]}
        groups.append({
            "id": "g-" + runner._group_token(key, group, start)[:12],
            "rule_id": rule_id, "rule_description": group["rule_description"], "level": group["rule_level"],
            "count": group["count"], "agents": [group.get("agent_name") or agent_id],
            "first_seen": _local(first, report_zone), "last_seen": _local(max(first, last), report_zone),
            "category": _CATEGORY[label], "protected": protected, "tuning": action,
            "decision": {"delivery_required": decision.delivery_required,
                         "health_failure": decision.health_failure, "reason": decision.reason},
            "model": advice,
            "breach_signals": [decision.reason.removeprefix("breach_")] if breach else [],
        })
    total_groups = len(groups)

    # Hourly timeline: events by time, and delivery-required groups by first sighting.
    timeline = []
    bucket = start
    while bucket < end:
        upper = min(bucket + timedelta(hours=1), end)
        events = sum(1 for instant in unique.values() if bucket <= instant < upper)
        required = sum(1 for g in groups if g["decision"]["delivery_required"]
                       and bucket <= _parse_instant(g["first_seen"]) < upper)
        timeline.append({"start": _local(bucket, report_zone), "events": events, "delivery_required": required})
        bucket = upper

    history_rows = []
    local_start = start.astimezone(report_zone)
    background_groups = sum(len(agents) for _, agents, _ in _BACKGROUND) + SCA_PER_HOST * len(_LINUX)
    for days in range(1, HISTORY_DAYS + 1):
        day_rng = random.Random(f"history-{seed}-{days}")
        day = local_start.date() - timedelta(days=days)
        h_start = datetime.combine(day, dt_time(8), tzinfo=report_zone)
        h_end = datetime.combine(day + timedelta(days=1), dt_time(8), tzinfo=report_zone)
        events = sum(max(1, round(day_rng.gauss(mean, math.sqrt(mean) * 1.2))) * len(agents)
                     for _, agents, mean in _BACKGROUND) + SCA_PER_HOST * len(_LINUX)
        history_rows.append({"start": _local(h_start, report_zone), "end": _local(h_end, report_zone),
                             "events": events, "groups": background_groups - day_rng.randrange(6),
                             # One earlier day had a model outage: delivered, with a health failure.
                             "delivered": True, "health_failure": days == 4})

    indices = {index for index, _ in unique}
    digest = delivery.sent[0] if delivery.sent else None
    checks = [
        {"name": "collector", "status": "ok",
         "detail": f"{len(unique)} events in {len(indices)} indices; {duplicates} duplicates dropped"},
        {"name": "model", "status": "attention" if model_failures else "ok",
         "detail": (f"{model_failures} groups failed review; delivered anyway" if model_failures
                    else "every reviewed group answered")},
        {"name": "tuning", "status": "ok",
         "detail": f"{len(DEMO_TUNING['entries'])} entries; {muted} groups muted or low; "
                   f"{protected_tuned} protected groups ignored tuning"},
        {"name": "digest", "status": "ok" if result.delivered else "failed",
         "detail": (f"{len(digest.payloads)} messages and an attachment rendered; demo: captured, not sent"
                    if digest is not None and digest.attachment is not None else "no digest rendered")},
        {"name": "fast path", "status": "ok" if all(b["paged"] for b in breaches) else "failed",
         "detail": f"{len(pager.sent)} breach pages; demo: captured, not sent"},
    ]
    if not result.completed:
        checks.append({"name": "window", "status": "failed", "detail": "the window did not complete"})
    statuses = {check["status"] for check in checks}
    snapshot = {
        "schema": SCHEMA,
        "generated_at": _local(now, report_zone),
        "source": "demo",
        "timezone": zone_name,
        "window": {"start": _local(start, report_zone), "end": _local(end, report_zone),
                   "events": len(unique), "groups": total_groups, "duplicates": duplicates,
                   "muted_by_tuning": muted},
        "health": {"status": "failed" if "failed" in statuses else "attention" if "attention" in statuses else "ok",
                   "checks": checks},
        "groups": order_groups(groups),
        "breaches": breaches,
        "timeline": timeline,
        "history": history_rows,
        # The globe's shots are generated, not derived from the alerts above: the demo's
        # addresses are documentation ranges, which have no country. Its breaches are real.
        "attacks": attacks.block(
            attacks.demo_shots((end - start).total_seconds(), breach_times, seed=seed, rate=0.1),
            home=attacks.DEMO_HOME, start=_local(start, report_zone), end=_local(end, report_zone)),
    }
    return snapshot, digest


def write_json(path: str, document: object) -> None:
    """Write next to the target and rename, so a watching console never reads half a file."""
    target = Path(path)
    text = json.dumps(document, ensure_ascii=False, indent=1, allow_nan=False) + "\n"
    if len(text.encode()) > 8 * 1024 * 1024:
        raise ValueError("snapshot exceeds 8 MiB")
    fd, temp = tempfile.mkstemp(prefix=".snapshot-", dir=target.parent or Path("."))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temp, 0o644)
        os.replace(temp, target)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def _digest_text(digest: Any) -> str:
    parts = [payload["content"] for payload in digest.payloads]
    if digest.attachment is not None:
        parts.append("--- attachment ---\n" + digest.attachment)
    return "\n\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a demo snapshot from synthetic alerts run through the real pipeline.")
    parser.add_argument("--out", required=True, help="Snapshot JSON path")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"Generator seed (default {DEFAULT_SEED})")
    parser.add_argument("--now", help="ISO time with offset to run as (default: the current time)")
    parser.add_argument("--digest-out", help="Optional path for the rendered digest text (not sent anywhere)")
    args = parser.parse_args(argv)
    problem = zone.check()
    if problem:
        print(problem)
        return 2
    try:
        now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError
    except ValueError:
        print("--now must be an ISO time with an offset, for example 2026-11-07T08:00:04+11:00")
        return 2
    snapshot, digest = build(seed=args.seed, now=now)
    write_json(args.out, snapshot)
    if args.digest_out and digest is not None:
        Path(args.digest_out).write_text(_digest_text(digest), encoding="utf-8")
    window = snapshot["window"]
    print(f"Demo snapshot written: {window['events']} events, {window['groups']} groups, "
          f"{len(snapshot['breaches'])} breaches, health {snapshot['health']['status']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
