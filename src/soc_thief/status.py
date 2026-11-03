"""Read-only host health inspection; never reads credentials or report payloads."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable

from soc_thief.runner import APPROVAL_PERMANENT, approval_expiry
from soc_thief.zone import check as check_zone, report_zone

RUNNER = "soc-thief-runner.service"
CATCHUP = "soc-thief-catchup.service"  # The operator's temporary catch-up unit logs the same statuses.
TIMER = "soc-thief-runner.timer"
JOURNAL_LIMIT = 2000
# One journal read was measured at 54s on a deployment host whose root disk answered in ~100ms per
# I/O. A 15s limit turned that into "unavailable", hiding the reasons the check had found.
# Five commands at this limit, plus the heartbeat, must fit the unit's TimeoutStartSec.
COMMAND_TIMEOUT_SECONDS = 60
FRESHNESS = timedelta(hours=26)  # Covers a 25-hour DST day and timer jitter.
APPROVAL_WARNING = timedelta(days=3)  # An expired approval stops every run, health reports included.
_STATUSES = {
    "Runner approval missing, invalid, or expired; no request made.": "approval_refused",
    "pending delivery acknowledged": "acknowledged",
    "window completed and delivery acknowledged": "acknowledged",
    "window replay already acknowledged": "acknowledged",
    "window completed; no delivery required": "no_delivery_required",
    "window already completed; no collection performed": "already_completed",
    "window failed; health report delivered": "health_delivered",
    "window failed; health report could not be delivered": "health_undelivered",
    "Runner deadline exceeded; health report delivered.": "health_delivered",
    "Runner deadline exceeded; health report could not be delivered.": "health_undelivered",
    "Runner failed; health report delivered.": "health_delivered",
    "Runner failed; health report could not be delivered.": "health_undelivered",
}
# Fast path coverage and agent liveness. The fast path runs every 10 minutes and takes up
# to 9 minutes, so a healthy service always has a checked window within 30 minutes. The gap
# lookback is longer than one hourly status interval plus its 5-minute jitter, so a one-off gap
# line cannot fall between two checks.
FASTPATH = "soc-thief-fastpath.service"
FASTPATH_TIMER = "soc-thief-fastpath.timer"
FASTPATH_FRESHNESS = timedelta(minutes=30)
FASTPATH_LOOKBACK = timedelta(hours=2)
FASTPATH_JOURNAL_LIMIT = 500
_LIVENESS = re.compile(r"agent liveness: ([0-9]{1,4}) expected, ([0-9]{1,4}) silent(; page failed)?")
_FASTPATH_FAILED = ("fast path page failed", "Fast path ", "Runner approval missing")
_UNIT_FILE = {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked", "masked-runtime",
              "static", "disabled", "indirect", "generated", "transient", "bad"}
_ACTIVE = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance"}
_RESULTS = {"success", "exit-code", "timeout", "signal", "core-dump", "watchdog", "resources",
            "start-limit-hit", "oom-kill", "protocol", "dependency", "condition", "assert"}


class StatusError(Exception):
    """Inspection unavailable; exception details must never be printed."""


def _command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS, check=False)
        if result.returncode != 0:
            raise StatusError
        return result.stdout
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise StatusError from None


def _properties(raw: str, allowed: dict[str, set[str]]) -> dict[str, str]:
    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    return {key: fields.get(key, "unknown") if fields.get(key) in values else "unknown"
            for key, values in allowed.items()}


def _journal_rows(raw: str, now: datetime, since: datetime):
    """Yield (instant, message) for well-formed rows inside [since, now]; malformed rows raise."""
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            message = row.get("MESSAGE")
            if type(message) is not str:
                continue
            instant = datetime.fromtimestamp(int(row["__REALTIME_TIMESTAMP"]) / 1_000_000, timezone.utc)
        except (ValueError, TypeError, KeyError, OverflowError, AttributeError, OSError):
            raise StatusError from None
        if since <= instant <= now:
            yield instant, message


def _fastpath(now: datetime, command: Callable[[list[str]], str], expect: bool) -> tuple[dict[str, object], list[str]]:
    """Prove the fast path covered every interval and every expected agent reported.

    The fast path is expected when the monitor unit says so, or when its timer is enabled or
    running; a stopped but enabled timer is therefore a failure, not "not installed".
    Only fixed labels, counts and times are returned.
    """
    timer = _properties(command(["systemctl", "show", FASTPATH_TIMER,
                                 "--property=LoadState,ActiveState,UnitFileState"]),
                        {"LoadState": {"loaded", "not-found"}, "ActiveState": _ACTIVE, "UnitFileState": _UNIT_FILE})
    expected = (expect or timer["UnitFileState"] in {"enabled", "enabled-runtime"}
                or timer["ActiveState"] == "active")
    report: dict[str, object] = {"expected": expected, "timer": timer, "last_checked": None,
                                 "agents_expected": None, "agents_silent": None}
    if not expected:
        return report, []
    reasons = []
    if timer["ActiveState"] != "active":
        reasons.append("fastpath_timer_inactive")
    since = now - FASTPATH_LOOKBACK
    raw = command(["journalctl", "--unit=" + FASTPATH,
                   "--since=" + since.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                   "--lines=" + str(FASTPATH_JOURNAL_LIMIT), "--output=json", "--no-pager", "--quiet"])
    if len(raw.splitlines()) >= FASTPATH_JOURNAL_LIMIT:
        reasons.append("fastpath_journal_limit_reached")
    coverage: list[tuple[datetime, str]] = []
    liveness: list[tuple[datetime, int | None, int | None, bool]] = []
    for instant, message in _journal_rows(raw, now, since):
        match = _LIVENESS.fullmatch(message)
        if message.startswith("fast path checked; "):
            coverage.append((instant, "checked"))
        elif message.startswith("fast path coverage gap"):
            coverage.append((instant, "gap"))
        elif message.startswith(_FASTPATH_FAILED):
            coverage.append((instant, "failed"))
        elif match is not None:
            liveness.append((instant, int(match[1]), int(match[2]), match[3] is None))
        elif message.startswith("agent liveness unavailable"):
            liveness.append((instant, None, None, False))
    coverage.sort(key=lambda event: event[0])
    liveness.sort(key=lambda event: event[0])
    if any(kind == "gap" for _, kind in coverage):
        reasons.append("fastpath_coverage_gap")
    # The checkpoint advances only on a fully checked window, and each window starts before the
    # previous checkpoint, so a fresh "checked" as the latest outcome proves continuous coverage.
    if not coverage or coverage[-1][1] != "checked" or now - coverage[-1][0] > FASTPATH_FRESHNESS:
        reasons.append("fastpath_coverage_unproven")
    checked = [instant for instant, kind in coverage if kind == "checked"]
    report["last_checked"] = _local(checked[-1]) if checked else None
    if not liveness or now - liveness[-1][0] > FASTPATH_FRESHNESS or not liveness[-1][3]:
        reasons.append("agent_liveness_unproven")
    if liveness:
        report["agents_expected"], report["agents_silent"] = liveness[-1][1], liveness[-1][2]
        if liveness[-1][2]:
            reasons.append("agents_silent")
    return report, reasons


def _local(instant: datetime) -> str:
    return instant.astimezone(report_zone()).isoformat()


def inspect(*, now: datetime, command: Callable[[list[str]], str] = _command,
            approval: Callable[[datetime], datetime | None] | None = None,
            expect_fastpath: bool = False) -> dict[str, object]:
    """Return only fixed labels, counts and local (``SOC_THIEF_TIMEZONE``) timestamps from a bounded journal slice.

    Journal freshness describes runner outcomes, not daily window continuity or alert accuracy.
    Fast path coverage and agent liveness come from the fast path's own journal lines.
    Missing evidence and inaccessible host tools produce an unavailable status, never green.
    ``approval`` returns a valid approval's expiry or None; omitted, the approval is unchecked.
    """
    service = _properties(command(["systemctl", "show", RUNNER, "--property=LoadState,ActiveState,Result"]),
                          {"LoadState": {"loaded"}, "ActiveState": _ACTIVE, "Result": _RESULTS})
    timer = _properties(command(["systemctl", "show", TIMER, "--property=LoadState,ActiveState"]),
                        {"LoadState": {"loaded"}, "ActiveState": _ACTIVE})
    since = (now - timedelta(days=14)).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    raw = command(["journalctl", "--unit=" + RUNNER, "--unit=" + CATCHUP, "--since=" + since,
                   "--lines=" + str(JOURNAL_LIMIT), "--output=json", "--no-pager", "--quiet"])
    counts: Counter[str] = Counter()
    events: list[tuple[datetime, str, bool]] = []
    lines = raw.splitlines()
    for line in lines:
        try:
            row = json.loads(line)
            message = row.get("MESSAGE")
            if type(message) is not str:
                continue
            health = message.endswith("; health review required")
            # A missed day the runner caught up itself carries this prefix.
            status = _STATUSES.get(message.removeprefix("missed day: ").removesuffix("; health review required"))
            if status is None:
                continue
            instant = datetime.fromtimestamp(int(row["__REALTIME_TIMESTAMP"]) / 1_000_000, timezone.utc)
            if not now - timedelta(days=14) <= instant <= now:
                continue
            counts[status] += 1
            counts["health_review"] += int(health)
            events.append((instant, status, health))
        except (ValueError, TypeError, KeyError, OverflowError, AttributeError, OSError):
            raise StatusError from None
    events.sort(key=lambda event: event[0])
    last = events[-1] if events else None
    good = {"acknowledged", "no_delivery_required", "already_completed"}
    acknowledged = [event for event in events if event[1] == "acknowledged"]
    latest_ack = acknowledged[-1] if acknowledged else None
    reasons = []
    if service["LoadState"] != "loaded" or timer["LoadState"] != "loaded":
        reasons.append("units_unavailable")
    if service["ActiveState"] == "unknown":
        reasons.append("runner_state_unavailable")
    if timer["ActiveState"] != "active":
        reasons.append("timer_inactive")
    if service["Result"] != "success":
        reasons.append("runner_unsuccessful")
    if last is None:
        reasons.append("no_runner_outcome_visible")
    else:
        if last[1] not in good or last[2]:
            reasons.append("latest_outcome_requires_attention")
        if now - last[0] > FRESHNESS:
            reasons.append("runner_outcome_stale")
    expires = approval(now) if approval is not None else None
    if approval is not None:
        if expires is None:
            reasons.append("approval_invalid_or_expired")
        elif expires - now <= APPROVAL_WARNING:
            reasons.append("approval_expires_soon")
    fastpath, fastpath_reasons = _fastpath(now, command, expect_fastpath)
    reasons.extend(fastpath_reasons)
    local = _local
    stamp = lambda event: local(event[0]) if event else None
    return {"status": "attention_required" if reasons else "healthy",
            "reasons": reasons, "service": service, "timer": timer,
            "approval": {"checked": approval is not None,
                         "expires": "never" if expires == APPROVAL_PERMANENT
                         else local(expires) if expires is not None else None},
            "journal_limit_reached": len(lines) >= JOURNAL_LIMIT,
            "last_outcome": {"time": stamp(last), "status": last[1] if last else None,
                             "health_review": last[2] if last else None},
            "last_acknowledged": stamp(latest_ack), "counts": dict(counts), "fastpath": fastpath}


def main() -> int:
    try:
        # The approval is checked only where the monitor unit passes it in as a credential.
        approval = None
        if os.environ.get("SOC_THIEF_RUNNER_APPROVAL_FILE"):
            approval = lambda now: approval_expiry(os.environ, now)
        # Set by a drop-in once the fast path is live, so disabling its timer also fails the check.
        expect = os.environ.get("SOC_THIEF_EXPECT_FASTPATH") == "1"
        report = inspect(now=datetime.now(timezone.utc), approval=approval, expect_fastpath=expect)
    except (StatusError, ValueError, OSError):
        print('{"status":"unavailable","reason":"host inspection failed or journal evidence is invalid"}')
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
