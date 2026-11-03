"""On-demand, read-only case brief written only to a private local file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Callable

from soc_thief.collector import CollectorConfig, WazuhIndexerCollector
from soc_thief.delivery import _plain
from soc_thief.profile import check_output, write_private


_CASE_ID = re.compile(r"[0-9a-f]{64}\Z")
_SERVICE_COMMAND = (
    "sudo", "-u", "soc-thief", "/usr/bin/env", "-i", "PYTHONPATH=/opt/soc-thief/src",
    "/usr/bin/python3", "-m", "soc_thief.cases", "--state", "/var/lib/soc-thief/state", "resolve",
)


class InvestigationError(RuntimeError):
    """A fixed-text local investigation failure."""


def resolve_case(case_id: str) -> tuple[str, str]:
    """Ask the service account for only the rule and agent IDs behind a case ID."""
    if type(case_id) is not str or _CASE_ID.fullmatch(case_id) is None:
        raise InvestigationError("case lookup failed")
    try:
        result = subprocess.run((*_SERVICE_COMMAND, case_id), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, timeout=120, check=True, cwd="/")
        value = json.loads(result.stdout)
        if (type(value) is not dict or set(value) != {"rule_id", "agent_id"}
                or any(type(value[key]) is not str or not 0 < len(value[key]) <= 64
                       or any(ord(char) < 32 or ord(char) == 127 for char in value[key])
                       for key in value)):
            raise ValueError
        return value["rule_id"], value["agent_id"]
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise InvestigationError("case lookup failed") from None


def _row(record: dict) -> str:
    fields = record["fields"]
    stamp = datetime.fromisoformat(fields["@timestamp"].replace("Z", "+00:00"))
    rule = _plain(fields["rule.id"], 1024)
    description = _plain(fields["rule.description"], 4096)[:220]
    return f"{stamp.astimezone(timezone.utc).isoformat(timespec='seconds')} | sev {fields['rule.level']} | rule {rule} | {description}"


@dataclass(frozen=True)
class CaseEvidence:
    """The two bounded searches behind a brief. Rows are allowlisted records; keep them local."""
    start: datetime
    end: datetime
    total: int
    matches: tuple[dict, ...]
    related_total: int
    related: tuple[dict, ...]


def search_case(collector: WazuhIndexerCollector, *, rule_id: str, agent_id: str,
                now: datetime, days: int = 7) -> CaseEvidence:
    """Two bounded queries: this rule/agent, then other rules near its latest event.

    Takes the rule and agent IDs directly, so a caller that already holds them (the fast
    path's follow-up) needs no service-account case lookup.
    """
    if (type(days) is not int or not 1 <= days <= 30
            or type(now) is not datetime or now.utcoffset() is None):
        raise InvestigationError("investigation request is invalid")
    end = now.astimezone(timezone.utc)
    start = end - timedelta(days=days)
    total, matches = collector.sample_case(agent_id=agent_id, rule_id=rule_id,
                                           start=start, end=end, limit=20)
    related_total, related = 0, ()
    if matches:
        latest = datetime.fromisoformat(matches[0]["fields"]["@timestamp"].replace("Z", "+00:00"))
        related_start = latest - timedelta(minutes=15)
        related_end = min(end, latest + timedelta(minutes=15))
        related_total, related = collector.sample_case(
            agent_id=agent_id, exclude_rule=rule_id, start=related_start,
            end=related_end, limit=10)
    return CaseEvidence(start, end, total, tuple(matches), related_total, tuple(related))


def brief_lines(*, case_id: str, rule_id: str, agent_id: str, evidence: CaseEvidence) -> list[str]:
    if type(case_id) is not str or _CASE_ID.fullmatch(case_id) is None:
        raise InvestigationError("investigation request is invalid")
    return [
        "Soc Thief local investigation brief", f"Case ID: {case_id}",
        f"Rule ID: {_plain(rule_id, 64)}", f"Agent ID: {_plain(agent_id, 64)}",
        f"Search window: {evidence.start.isoformat(timespec='seconds')} to "
        f"{evidence.end.isoformat(timespec='seconds')} UTC",
        f"Matching alerts: {evidence.total}; newest {len(evidence.matches)} shown", "",
        "Recent matching alerts:",
        *([_row(row) for row in evidence.matches] or ["none in this search window"]), "",
        f"Other rules on this agent within 15 minutes of the latest match: {evidence.related_total}; "
        f"newest {len(evidence.related)} shown",
        *([_row(row) for row in evidence.related] or ["none in this context window"]), "",
        "Counts are exact at each query; rows are capped samples from separate searches.",
    ]


def make_brief(collector: WazuhIndexerCollector, *, case_id: str, rule_id: str,
               agent_id: str, now: datetime, days: int = 7) -> str:
    """Two bounded queries: this rule/agent, then other rules near its latest event."""
    if type(case_id) is not str or _CASE_ID.fullmatch(case_id) is None:
        raise InvestigationError("investigation request is invalid")
    evidence = search_case(collector, rule_id=rule_id, agent_id=agent_id, now=now, days=days)
    lines = [*brief_lines(case_id=case_id, rule_id=rule_id, agent_id=agent_id, evidence=evidence),
             "Review source evidence in Wazuh before recording a verdict. No model or response action was used."]
    return "\n".join(lines) + "\n"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "invalid investigation arguments; use --help\n")


def main(argv: list[str] | None = None,
         *, resolver: Callable[[str], tuple[str, str]] = resolve_case,
         collector_factory: Callable = WazuhIndexerCollector) -> int:
    parser = _Parser(description="Write a private, read-only investigation brief")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--days", type=int, default=7)
    args = parser.parse_args(argv)
    try:
        if _CASE_ID.fullmatch(args.case_id) is None or not 1 <= args.days <= 30:
            raise InvestigationError("investigation request is invalid")
        parent = args.output.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or parent.st_mode & 0o077):
            raise InvestigationError("investigation output is unsafe")
        check_output(str(args.output))
        rule_id, agent_id = resolver(args.case_id)
        collector = collector_factory(CollectorConfig.from_environment())
        brief = make_brief(collector, case_id=args.case_id, rule_id=rule_id,
                           agent_id=agent_id, now=datetime.now(timezone.utc), days=args.days)
        if len(brief.encode()) > 32 * 1024:
            raise InvestigationError("investigation brief exceeds limit")
        write_private(str(args.output), brief)
        print("Investigation brief written to the private output file.")
        return 0
    except Exception:
        # Paths, credentials and alert fields must not surface through a traceback.
        print("Investigation brief failed; no alert content was printed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
