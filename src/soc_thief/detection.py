"""Read-only end-to-end detection measurement.

Given the run log of ``simulations/run-linux.sh`` or ``simulations/run-windows.ps1``, this reads
the alerts Wazuh raised on one agent during each scenario window, runs them through the real
grouping, policy and breach code (``runner._group`` with no store, the way ``fastpath`` does),
and writes a local report: per scenario, what was expected, which rule ids and levels Wazuh
raised, which Soc Thief group and decision resulted, whether the fast path would have paged, and
PASS, MISS, SUPPRESSED or NOT_RUN.

Nothing is sent anywhere. The only endpoint is the read-only Wazuh indexer, through the existing
collector. No model runs: ``decide()`` can never suppress, so a group that preflight and tuning
leave to model review is delivered, and is reported as such. A collector, tuning or run-log error
stops the run with no report: a measurement that cannot be trusted is not written.

The expectation table below is data, not a claim. Rule ids in ``breach.py`` are measured against
a live Wazuh 4.14.5 ruleset; the alert-only rows are the stock Wazuh ruleset from memory and are expected
to need correction after the first live run. That correction is the purpose of the measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc_thief import fastpath
from soc_thief.collector import CollectorConfig, CollectorError, WazuhIndexerCollector
from soc_thief.policy import Decision, preflight, tuned
from soc_thief.runner import RunnerError, RunnerLimits, _group
from soc_thief.tuning import Tuning, TuningError, load_tuning

PASS, MISS, SUPPRESSED, NOT_RUN = "PASS", "MISS", "SUPPRESSED", "NOT_RUN"
GRACE_MINUTES = 30
_AGENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
_RUN_KEYS = {"run", "platform", "scenario", "start", "end", "status"}
_STATUSES = ("ok", "failed", "skipped")
PLATFORMS = ("linux", "windows")
OK, FAILED, USAGE, NOT_ALL_PASSED = 0, 1, 2, 3


class DetectionError(RuntimeError):
    """A fixed-text failure. The measurement stops and writes no report."""


@dataclass(frozen=True)
class Expectation:
    """What a scenario should produce.

    ``signals``: breach signals; when non-empty, only one of these counts as a PASS.
    ``rule_ids`` / ``rule_groups``: an alert matching either counts as "Wazuh raised it".
    ``known_gap``: a fixed note on a scenario expected to MISS with the stock ruleset.
    """
    signals: frozenset[str] = frozenset()
    rule_ids: frozenset[str] = frozenset()
    rule_groups: frozenset[str] = frozenset()
    known_gap: str | None = None


def _e(signals=(), rule_ids=(), rule_groups=(), known_gap=None) -> Expectation:
    return Expectation(frozenset(signals), frozenset(rule_ids), frozenset(rule_groups), known_gap)


# Atomic Red Team equivalents are named in the scripts. Keys are (platform, scenario id).
EXPECTATIONS: Mapping[tuple[str, str], Expectation] = {
    ("linux", "brute_force_success"): _e(
        {"brute_force_success"}, {"40112", "5712", "5715"}, {"authentication_failures"}),
    ("linux", "account_created"): _e({"account_created"}, {"5902"}),
    ("linux", "log_cleared"): _e(
        {"log_cleared"}, (), {"logs_cleared"},
        known_gap="no stock Wazuh Linux rule carries the logs_cleared group"),
    ("linux", "persistence"): _e({"critical_file_change"}, {"550", "554"}, {"syscheck"}),
    ("linux", "eicar"): _e(
        {"malware"}, (), (),
        known_gap="stock Wazuh does not scan Linux files for malware signatures"),
    ("windows", "brute_force_success"): _e(
        {"brute_force_success"}, {"40112", "60204", "60106"}, {"authentication_failures"}),
    ("windows", "account_created"): _e({"account_created", "privileged_group_change"},
                                       {"60109", "60154", "60159"}),
    ("windows", "log_cleared"): _e({"log_cleared"}, {"60117"}, {"logs_cleared"}),
    ("windows", "persistence"): _e((), (), {"syscheck_registry", "windows_task"}),
    ("windows", "suspicious_powershell_child"): _e((), (), {"sysmon_event1", "powershell"}),
    ("windows", "eicar"): _e({"malware"}, {"62113", "62122", "62123"}),
}


@dataclass(frozen=True)
class Scenario:
    run: str
    platform: str
    scenario: str
    start: datetime
    end: datetime
    status: str


def _instant(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.utcoffset() is None:
        raise ValueError
    return instant.astimezone(timezone.utc)


def parse_run_log(text: str) -> list[Scenario]:
    """One JSON object per line: run, platform, scenario, start, end, status. Anything else fails."""
    scenarios: list[Scenario] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if type(value) is not dict or set(value) != _RUN_KEYS:
                raise ValueError
            if (value["platform"] not in PLATFORMS or value["status"] not in _STATUSES
                    or (value["platform"], value["scenario"]) not in EXPECTATIONS
                    or type(value["run"]) is not str or not 0 < len(value["run"]) <= 64):
                raise ValueError
            start, end = _instant(value["start"]), _instant(value["end"])
            if end < start:
                raise ValueError
        except (ValueError, TypeError, KeyError, RecursionError):
            raise DetectionError("run log is invalid") from None
        scenarios.append(Scenario(value["run"], value["platform"], value["scenario"], start, end,
                                  value["status"]))
    if not scenarios:
        raise DetectionError("run log is empty")
    if len({(s.run, s.scenario) for s in scenarios}) != len(scenarios):
        raise DetectionError("run log is invalid")
    return scenarios


def _bounds(scenario: Scenario, grace: timedelta, cap: datetime | None = None) -> tuple[datetime, datetime]:
    """Whole-second bounds, widened outward: the indexer compares dates in milliseconds.

    The grace period is for alerts the manager raises after the scenario ends (syscheck, log
    batching). It stops at ``cap``, the next scenario's start in the same run, so one scenario's
    window never takes credit for the next scenario's alerts (measured: uncapped, a
    30-minute grace put the persistence scenario's cron.d alerts into three earlier windows)."""
    start = scenario.start.replace(microsecond=0)
    end = scenario.end.replace(microsecond=0) + timedelta(seconds=1) + grace
    if cap is not None:
        end = max(min(end, cap.replace(microsecond=0)), start + timedelta(seconds=1))
    return start, end


def _caps(scenarios: list[Scenario]) -> list[datetime | None]:
    """For each scenario, the start of the next scenario in the same run, if any."""
    caps: list[datetime | None] = []
    for scenario in scenarios:
        later = [other.start for other in scenarios
                 if other.run == scenario.run and other.start > scenario.start]
        caps.append(min(later) if later else None)
    return caps


def _decision(group: Mapping[str, object], breach_reason: str | None, tuning: Tuning,
              at: datetime) -> Decision:
    """The decision ``run_window`` would reach, minus the model (which can only deliver)."""
    gate = preflight(group)
    if breach_reason is not None and not gate.health_failure:
        return Decision(True, False, breach_reason)
    if gate.delivery_required:
        return gate
    decision = tuned(group, tuning.action(str(group["rule_id"]), str(group["agent_id"]), at))
    if decision.delivery_required or decision.reason.startswith("tuned_"):
        return decision
    return Decision(True, False, "model_requires_review")


def evaluate(scenario: Scenario, records: list[dict[str, Any]], *, key: bytes, tuning: Tuning,
             grace: timedelta, limits: RunnerLimits = RunnerLimits(),
             cap: datetime | None = None) -> dict[str, Any]:
    """Pure measurement of one scenario over already-collected records for one agent."""
    expectation = EXPECTATIONS[(scenario.platform, scenario.scenario)]
    base = {"run": scenario.run, "platform": scenario.platform, "scenario": scenario.scenario,
            "start": scenario.start.isoformat(), "end": scenario.end.isoformat(),
            "expected_signals": sorted(expectation.signals),
            "expected_rule_ids": sorted(expectation.rule_ids),
            "expected_rule_groups": sorted(expectation.rule_groups),
            "known_gap": expectation.known_gap}
    if scenario.status != "ok":
        return {**base, "verdict": NOT_RUN, "detail": "scenario_" + scenario.status,
                "raised": [], "groups": [], "fastpath_pages": []}
    start, end = _bounds(scenario, grace, cap)
    _, groups, _, breaches = _group(iter(records), start=start, end=end, store=None, key=key,
                                    limits=limits, expired=lambda: False)
    # Rule ids that matched the expectation by id or by rule group (groups are read from the raw
    # records here, because a Soc Thief group does not carry them).
    matched_rules: set[str] = set()
    raised: dict[tuple[str, int], int] = {}
    for record in records:
        fields = record["fields"]
        raised[(fields["rule.id"], fields["rule.level"])] = raised.get(
            (fields["rule.id"], fields["rule.level"]), 0) + 1
        record_groups = fields.get("rule.groups")
        record_groups = set(record_groups) if type(record_groups) is list else set()
        if fields["rule.id"] in expectation.rule_ids or record_groups & expectation.rule_groups:
            matched_rules.add(fields["rule.id"])
    rows, delivered_match, any_match, signal_hit = [], False, False, False
    for index, group in enumerate(groups):
        reason = breaches.get(index)
        decision = _decision(group, reason, tuning, end)
        signal = None if reason is None else reason.removeprefix("breach_")
        matched = signal in expectation.signals or group["rule_id"] in matched_rules
        any_match |= matched
        if matched:
            delivered_match |= decision.delivery_required
            signal_hit |= signal in expectation.signals
        rows.append({"rule_id": group["rule_id"], "rule_level": group["rule_level"],
                     "count": group["count"], "decision": decision.reason,
                     "delivered": decision.delivery_required, "breach_signal": signal,
                     "matched_expectation": matched,
                     "digest_section": "breach" if signal else (
                         "delivered" if decision.delivery_required else "suppressed")})
    pages = sorted(f"{signal}" for signal, _ in fastpath._pages(groups, breaches, key))
    if expectation.signals:
        passed = signal_hit
    else:
        passed = delivered_match
    if passed:
        verdict, detail = PASS, "detected"
    elif any_match and not delivered_match:
        verdict, detail = SUPPRESSED, "raised_but_not_delivered"
    elif any_match:
        verdict, detail = MISS, "raised_without_expected_breach_signal"
    else:
        verdict, detail = MISS, "no_matching_alert"
    return {**base, "verdict": verdict, "detail": detail,
            "raised": [{"rule_id": rule, "rule_level": level, "events": count}
                       for (rule, level), count in sorted(raised.items())],
            "groups": rows, "fastpath_pages": pages,
            "fastpath_would_page_expected": bool(set(pages) & expectation.signals)}


def measure(scenarios: list[Scenario], *, collector: Any, agent_id: str, key: bytes, tuning: Tuning,
            grace: timedelta, now: datetime) -> list[dict[str, Any]]:
    """Collect each scenario window read-only and evaluate it. Any error aborts everything."""
    results = []
    for scenario, cap in zip(scenarios, _caps(scenarios)):
        if scenario.status != "ok":
            results.append(evaluate(scenario, [], key=key, tuning=tuning, grace=grace))
            continue
        # Wait out the full grace even when the window is capped: alerts arrive late, not early.
        if _bounds(scenario, grace)[1] + fastpath.LAG > now:
            raise DetectionError("scenario window is still open; wait for the grace period")
        start, end = _bounds(scenario, grace, cap)
        records = [r for r in collector.collect(start, end)
                   if type(r) is dict and type(r.get("fields")) is dict
                   and r["fields"].get("agent.id") == agent_id]
        results.append(evaluate(scenario, records, key=key, tuning=tuning, grace=grace, cap=cap))
    return results


def write_report(path: Path, results: list[dict[str, Any]], *, agent_id: str, now: datetime) -> None:
    """Local report, mode 0600, never overwriting an existing file."""
    body = json.dumps({"generated": now.isoformat(), "agent_id": agent_id,
                       "summary": {v: sum(r["verdict"] == v for r in results)
                                   for v in (PASS, MISS, SUPPRESSED, NOT_RUN)},
                       "results": results}, indent=2, sort_keys=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(body)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(USAGE, "Invalid detection arguments; use --help.\n")


def main(argv: list[str] | None = None, *, env: Mapping[str, str] | None = None,
         now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
         collector_factory: Callable = lambda env: WazuhIndexerCollector(CollectorConfig.from_environment(env))
         ) -> int:
    parser = _Parser(description="Measure what Wazuh and Soc Thief did with simulated attacks "
                                 "(read-only; sends nothing).")
    parser.add_argument("--run-log", type=Path, required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--report", type=Path, help="default: <run-log>.report.json (must not exist)")
    parser.add_argument("--grace-minutes", type=int, default=GRACE_MINUTES)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit:
        return exit.code if type(exit.code) is int else USAGE
    if _AGENT.fullmatch(args.agent_id) is None or not 0 <= args.grace_minutes <= 24 * 60:
        print("Invalid detection arguments; use --help.")
        return USAGE
    env = os.environ if env is None else env
    report = args.report or args.run_log.with_name(args.run_log.name + ".report.json")
    instant = now()
    try:
        scenarios = parse_run_log(args.run_log.read_text())
        if report.exists() or report.is_symlink():
            raise DetectionError("report file already exists")
        tuning = load_tuning(env)  # An unreadable file raises: no silent "no tuning".
        results = measure(scenarios, collector=collector_factory(env), agent_id=args.agent_id,
                          key=os.urandom(32), tuning=tuning, grace=timedelta(minutes=args.grace_minutes),
                          now=instant)
        write_report(report, results, agent_id=args.agent_id, now=instant)
    except (DetectionError, CollectorError, RunnerError, TuningError, OSError, ValueError) as error:
        text = str(error) if isinstance(error, (DetectionError, TuningError)) else type(error).__name__
        print(f"Detection measurement failed ({text}); no report written.", file=sys.stderr)
        return FAILED
    for result in results:
        print(f"{result['scenario']:<30} {result['verdict']:<10} {result['detail']}")
    return OK if all(r["verdict"] == PASS for r in results) else NOT_ALL_PASSED


if __name__ == "__main__":
    raise SystemExit(main())
