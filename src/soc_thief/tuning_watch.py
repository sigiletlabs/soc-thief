"""Watch standing tuning for a changed rule, and list tuning entries that went stale.

Tuning entries may never expire, so a muted rule stays muted whatever it later
does, and a flood of "known noise" can hide an attack or be one. Two read-only helps live here.

1. **Spike watch**, called by the daily runner for tuned groups *before* tuning drops them. A
   tuned (rule, agent) pair is a finding when the window's count is well above that pair's
   30-day baseline (``PAGE_MIN_EVENTS`` and ``PAGE_RATIO`` times its daily mean on active days),
   or when the pair has no baseline at all (a new agent, or a rule that never fired there) and
   reaches ``NEW_MIN_EVENTS``. Every finding is paged and the runner then delivers that group in
   the digest, bypassing tuning. A page that cannot be sent makes the group delivery-required
   with a health failure. Tuning cannot suppress a finding: this runs ahead of it. The model is
   not involved.

   A pair pages once per ``REPAGE_AFTER`` (the next days' baseline absorbs a flood only slowly,
   so a multi-day flood would otherwise page every morning). The record is one private JSON file
   of opaque keys and times; an unreadable file means "nothing paged yet", so it errs towards
   paging. A deduped pair is still delivered in the digest, never suppressed.

2. **Stale report** (``python -m soc_thief.tuning_watch``): lists tuning entries whose rule (and
   agent, when the entry names one) fired no event in the last 90 days, as removal candidates.
   It reuses the collector's aggregation-only profile, writes one new private file of rule ids,
   agent ids and actions, and never edits the tuning file or sends anything anywhere.

A page carries a fixed title, the tuning action, the Wazuh agent id, counts and the opaque case id.
No rule id, description, hostname, path or alert text leaves the host.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from soc_thief.collector import CollectorConfig, WazuhIndexerCollector
from soc_thief.policy import preflight
from soc_thief.profile import OutputError, _Parser, _run_worker, check_output, write_private
from soc_thief.state import opaque_key
from soc_thief.tuning import Tuning, TuningEntry, load_tuning

# "Well above baseline" for a page. Deliberately stricter than the digest's SPIKE flag (10 events,
# 3x), which itemises; this one interrupts a person.
PAGE_MIN_EVENTS = 50
PAGE_RATIO = 10
# A tuned pair with no baseline at all pages from this many events.
NEW_MIN_EVENTS = 5
# More findings than this in one window become one summary page; all are still delivered.
MAX_PAGES = 10
STALE_DAYS = 90
REPAGE_AFTER = timedelta(days=7)
STATE_NAME = "tuning_watch.json"

SPIKE, NEW = "spike", "new"
_Pair = tuple[str, str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    agent_id: str
    action: str
    kind: str
    count: int
    daily_mean: int


def find(counts: Mapping[_Pair, tuple[str, int]], history: Mapping[_Pair, tuple[int, int]]
         ) -> tuple[Finding, ...]:
    """Findings for tuned pairs. ``counts`` is pair -> (tuning action, window events);
    ``history`` is pair -> (30-day events, active days), as the digest baseline."""
    found = []
    for (rule, agent), (action, count) in counts.items():
        seen = history.get((rule, agent))
        if seen is None or seen[0] == 0:
            if count >= NEW_MIN_EVENTS:
                found.append(Finding(rule, agent, action, NEW, count, 0))
            continue
        events, days = seen
        if count >= PAGE_MIN_EVENTS and count >= PAGE_RATIO * events / max(days, 1):
            found.append(Finding(rule, agent, action, SPIKE, count, events // max(days, 1)))
    return tuple(sorted(found, key=lambda f: (-f.count, f.rule_id, f.agent_id)))


def _page(finding: Finding, case: str) -> Any:
    from soc_thief.fastpath import Page  # Lazy: fastpath imports the runner, which imports this.
    noun = "muted" if finding.action == "mute" else "low-priority"
    if finding.kind == NEW:
        title, detail = f"Soc Thief: {noun} rule on a new agent", "no baseline on this agent"
    else:
        title, detail = f"Soc Thief: {noun} rule spiking", f"baseline about {finding.daily_mean} a day"
    body = (f"Tuning: {finding.action}\nAgent: {finding.agent_id}\nEvents: {finding.count} ({detail})\n"
            f"Case: {case}")
    return Page(title, body, "high", "warning")


def _summary(count: int) -> Any:
    from soc_thief.fastpath import Page
    return Page("Soc Thief: several tuned rules changed",
                f"{count} more tuned rules changed behaviour in this window. They are in the daily digest.",
                "high", "warning")


def notify(findings: tuple[Finding, ...], send: Callable[[Any], None] | None,
           case: Callable[[str, str], str]) -> frozenset[_Pair]:
    """Page the findings; return the pairs that could not be paged. Never raises.

    ``send`` of None means no page route: every finding is unpaged, so the caller fails closed.
    A summary page that fails leaves every pair it stood for unpaged.
    """
    unpaged: set[_Pair] = set()
    batches = [([f], False) for f in findings[:MAX_PAGES]]
    if len(findings) > MAX_PAGES:
        batches.append((list(findings[MAX_PAGES:]), True))
    for members, summary in batches:
        try:
            if send is None:
                raise ValueError
            first = members[0]
            send(_summary(len(members)) if summary else _page(first, case(first.rule_id, first.agent_id)))
        except Exception:
            unpaged.update((f.rule_id, f.agent_id) for f in members)
    return frozenset(unpaged)


@dataclass(frozen=True)
class Pager:
    """The page route and where the once-per-pair record lives."""
    send: Callable[[Any], None] | None
    state: Path


def _load_paged(path: Path, at: datetime) -> dict[str, datetime]:
    try:
        raw = json.loads(path.read_text())
        paged = {k: datetime.fromisoformat(v) for k, v in raw.items() if type(k) is str and type(v) is str}
        return {k: v for k, v in paged.items() if v.utcoffset() is not None and at - v < REPAGE_AFTER}
    except Exception:
        return {}


def _save_paged(path: Path, paged: Mapping[str, datetime]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({k: v.isoformat() for k, v in sorted(paged.items())}, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        pass  # A lost record only means an earlier re-page.


def watch(groups: list[dict[str, Any]], tuning: Tuning, at: datetime,
          history: Mapping[_Pair, tuple[int, int]], pager: Pager, key: bytes,
          case: Callable[[str, str], str]) -> tuple[frozenset[_Pair], frozenset[_Pair]]:
    """Runner entry point: (pairs to deliver despite tuning, the subset whose page failed).

    Only groups tuning would act on count: preflight-protected groups are delivered anyway.
    """
    counts: dict[_Pair, tuple[str, int]] = {}
    for group in groups:
        if preflight(group).delivery_required:
            continue
        action = tuning.action(group["rule_id"], group["agent_id"], at)
        if action is not None:
            pair = (group["rule_id"], group["agent_id"])
            counts[pair] = (action, counts.get(pair, (action, 0))[1] + int(group["count"]))
    findings = find(counts, history)
    if not findings:
        return frozenset(), frozenset()
    name = lambda pair: opaque_key(key, "watch", *pair)
    paged = _load_paged(pager.state, at)
    due = tuple(f for f in findings if name((f.rule_id, f.agent_id)) not in paged)
    unpaged = notify(due, pager.send, case)
    for f in due:
        if (f.rule_id, f.agent_id) not in unpaged:
            paged[name((f.rule_id, f.agent_id))] = at
    if due:
        _save_paged(pager.state, paged)
    return frozenset((f.rule_id, f.agent_id) for f in findings), unpaged


def stale_entries(tuning: Tuning, groups: list[dict[str, Any]]) -> tuple[TuningEntry, ...]:
    """Entries no profile row matches: same rule, and the same agent when the entry names one."""
    rules = {row["rule_id"] for row in groups}
    pairs = {(row["rule_id"], row["agent_id"]) for row in groups}
    return tuple(e for e in tuning.entries
                 if (e.rule_id not in rules if e.agent_id is None else (e.rule_id, e.agent_id) not in pairs))


def render_stale(start: datetime, end: datetime, entries: tuple[TuningEntry, ...], total: int) -> str:
    lines = [f"Stale tuning entries: no event in {start.date()} to {end.date()}. Removal candidates for "
             f"operator review; nothing has been changed. {len(entries)} of {total} entries.", ""]
    for entry in entries:
        lines.append(json.dumps({"rule_id": entry.rule_id, "agent_id": entry.agent_id, "action": entry.action},
                                ensure_ascii=True))
    return "\n".join(lines) + "\n"


def _worker(start: datetime, end: datetime, output: str, conn: Any, _unused: object = None) -> None:
    code = 1
    try:
        tuning = load_tuning(os.environ)
        profile = WazuhIndexerCollector(CollectorConfig.from_environment()).profile(start, end)
        stale = stale_entries(tuning, profile["groups"])
        write_private(output, render_stale(start, end, stale, len(tuning.entries)))
        conn.send((len(stale), len(tuning.entries)))
        code = 0
    except Exception:
        pass  # Never expose configuration, labels, paths or tracebacks.
    finally:
        try:
            conn.close()
        except Exception:
            pass
    raise SystemExit(code)


def main(argv: list[str] | None = None, *, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> int:
    parser = _Parser(description="List tuning entries with no event in the last 90 days (read-only).")
    parser.add_argument("--output", required=True, help="New report path in a private directory you own")
    args = parser.parse_args(argv)
    try:
        check_output(args.output)
    except OutputError:
        print("Invalid output path; use a new file in an existing private directory you own.")
        return 2
    end = now().replace(minute=0, second=0, microsecond=0)
    code, counts = _run_worker(end - timedelta(days=STALE_DAYS), end, args.output, target=_worker)
    if code == 0 and counts:
        print(f"Stale tuning report written: {counts[0]} of {counts[1]} entries are removal candidates. "
              "Review before editing the tuning file; nothing was changed.")
        return 0
    print("Stale tuning report deadline exceeded." if code == 3 else "Stale tuning report failed. Details withheld.")
    return 3 if code == 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
