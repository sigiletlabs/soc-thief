"""Snapshot from a real deployment's state store, opened read-only.

    python -m soc_thief.snapshot --state /var/lib/soc-thief/state --out snapshot.json

The state store keeps opaque tokens, decisions and counts, never alert text. So a ``state``
snapshot carries real windows, real per-group decisions (while the seven-day audit retention
still holds them), delivery and case status, and leaves the alert-text fields empty, as
docs/SNAPSHOT.md allows. What it cannot know, it leaves out rather than invents:

- ``groups[].rule_id``, ``rule_description``, ``agents``, ``level`` and ``count`` are not stored
  per group, so they are empty or zero; ``category`` is ``failed`` for a group with a health
  failure and ``recurring`` otherwise, because the baseline comparison is not stored.
- ``breaches`` and ``timeline`` are empty: the store keeps neither page targets nor event times.

The database is opened with SQLite's ``mode=ro`` URI and ``query_only``, and the store's lock file
is not touched, so this never writes to the state directory and can run beside the runner. A
store mid-transaction (a hot journal) is refused rather than recovered.

The daily stream is identified by its opaque token when ``SOC_THIEF_IDENTITY_KEY_FILE`` is set;
otherwise the stream with the most windows is taken as the daily one.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from soc_thief import zone
from soc_thief.demo import SCHEMA, order_groups, write_json
from soc_thief.state import _REASONS, opaque_key

MAX_HISTORY = 30
FRESHNESS = timedelta(hours=26)  # A 25-hour DST day plus timer jitter, as in soc_thief.status.
_BREACH = "breach_"
_PROTECTED = {"critical_severity", "protected_indicator"}


class SnapshotError(RuntimeError):
    """Fixed text: the state could not be read. Never echoes paths or database detail."""


def connect(state: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open the state database read-only. ``state`` is the state directory or the database file."""
    path = Path(state)
    if path.is_dir():
        path = path / "state.sqlite3"
    if not path.is_file():
        raise SnapshotError("state database not found")
    uri = "file:" + quote(str(path.resolve())) + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        return db
    except sqlite3.Error:
        raise SnapshotError("state database could not be opened read-only") from None


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _daily_stream(db: sqlite3.Connection, key: bytes | None) -> str | None:
    if key is not None:
        return opaque_key(key, "stream", "daily")
    row = db.execute("SELECT stream FROM windows GROUP BY stream ORDER BY count(*) DESC, max(end) DESC LIMIT 1").fetchone()
    return row[0] if row else None


def build(db: sqlite3.Connection, *, now: datetime, key: bytes | None = None) -> dict[str, Any]:
    report_zone, zone_name = zone.report_zone(), zone.name()
    local = lambda instant: instant.astimezone(report_zone).isoformat(timespec="seconds")
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (1, 2, 3, 4):
            raise SnapshotError("unsupported state schema")
        stream = _daily_stream(db, key)
        windows = [] if stream is None else db.execute(
            "SELECT start, end, added, duplicates FROM windows WHERE stream=? ORDER BY start DESC LIMIT ?",
            (stream, MAX_HISTORY + 1)).fetchall()
        outbox = {} if version < 2 or stream is None else {
            start: acknowledged for start, acknowledged in db.execute(
                "SELECT start, payload IS NULL FROM outbox WHERE stream=?", (stream,))}
        pending = sum(1 for acknowledged in outbox.values() if not acknowledged)

        def audit(start: str) -> list[tuple[Any, ...]]:
            columns = "group_token, delivery, health, reason" + (", model_identity" if version >= 3 else ", NULL")
            return db.execute(f"SELECT {columns} FROM audit WHERE stream=? AND start=? ORDER BY ordinal",
                              (stream, start)).fetchall()

        cases = dict(db.execute("SELECT status, count(*) FROM cases GROUP BY status").fetchall()) if version >= 4 else {}
    except sqlite3.Error:
        raise SnapshotError("state database could not be read") from None

    checks = [{"name": "state", "status": "ok", "detail": f"schema version {version}; read-only"}]
    groups: list[dict[str, Any]] = []
    window: dict[str, Any]
    if windows:
        start, end, added, duplicates = windows[0]
        rows = audit(start)
        first, last = local(_utc(start)), local(_utc(end))
        for token, delivery, health, reason, model_identity in rows:
            if reason not in _REASONS:
                raise SnapshotError("state holds an unknown decision")
            breach = reason.startswith(_BREACH)
            groups.append({
                "id": "g-" + token[:12], "rule_id": "", "rule_description": "", "level": 0, "count": 0,
                "agents": [], "first_seen": first, "last_seen": last,
                "category": "failed" if health else "recurring",
                "protected": breach or reason in _PROTECTED,
                "tuning": {"tuned_mute": "mute", "tuned_low": "low"}.get(reason, "none"),
                "decision": {"delivery_required": bool(delivery), "health_failure": bool(health), "reason": reason},
                "model": None,
                "breach_signals": [reason.removeprefix(_BREACH)] if breach else [],
            })
        window = {"start": first, "end": last, "events": added + duplicates, "groups": len(rows),
                  "duplicates": duplicates,
                  "muted_by_tuning": sum(1 for g in groups if g["tuning"] != "none")}
        age = now - _utc(end)
        checks.append({"name": "freshness", "status": "ok" if age <= FRESHNESS else "attention",
                       "detail": f"latest window ended {int(age.total_seconds() // 3600)} hours ago"})
        failures = sum(1 for g in groups if g["decision"]["health_failure"])
        checks.append({"name": "window", "status": "attention" if failures else "ok",
                       "detail": (f"{failures} groups with a health failure" if failures else
                                  f"{len(rows)} group decisions retained" if rows else
                                  "group decisions are past the seven-day audit retention")})
    else:
        moment = local(now)
        window = {"start": moment, "end": moment, "events": 0, "groups": 0, "duplicates": 0, "muted_by_tuning": 0}
        checks.append({"name": "freshness", "status": "attention", "detail": "no completed daily window"})
    checks.append({"name": "delivery", "status": "attention" if pending else "ok",
                   "detail": f"{pending} reports waiting for delivery" if pending else "no report waiting"})
    if version >= 4:
        checks.append({"name": "cases", "status": "ok",
                       "detail": f"{sum(cases.values())} cases: {cases.get('review', 0)} marked review, "
                                 f"{cases.get('routine', 0)} routine, {cases.get('unreviewed', 0)} unreviewed"})

    history = []
    for start, end, added, duplicates in windows[1:MAX_HISTORY + 1]:
        rows = audit(start)
        history.append({"start": local(_utc(start)), "end": local(_utc(end)), "events": added + duplicates,
                        "groups": len(rows), "delivered": bool(outbox.get(start, False)),
                        "health_failure": any(row[2] for row in rows)})
    statuses = {check["status"] for check in checks}
    return {
        "schema": SCHEMA, "generated_at": local(now), "source": "state", "timezone": zone_name,
        "window": window,
        "health": {"status": "failed" if "failed" in statuses else "attention" if "attention" in statuses else "ok",
                   "checks": checks},
        "groups": order_groups(groups), "breaches": [], "timeline": [], "history": history,
    }


def _key(env: Mapping[str, str]) -> bytes | None:
    if not env.get("SOC_THIEF_IDENTITY_KEY_FILE"):
        return None
    from soc_thief.runner import _identity_key
    return _identity_key(env)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a snapshot of a deployment's state, read-only.")
    parser.add_argument("--state", required=True, help="State directory (or its state.sqlite3)")
    parser.add_argument("--out", required=True, help="Snapshot JSON path")
    args = parser.parse_args(argv)
    problem = zone.check()
    if problem:
        print(problem)
        return 2
    try:
        key = _key(os.environ)
        db = connect(args.state)
        try:
            snapshot = build(db, now=datetime.now(timezone.utc), key=key)
        finally:
            db.close()
        write_json(args.out, snapshot)
    except (SnapshotError, ValueError, OSError) as error:
        print(f"Snapshot failed: {error if isinstance(error, SnapshotError) else 'state or output unusable'}.")
        return 1
    print(f"State snapshot written: {len(snapshot['history']) + bool(snapshot['window']['groups'])} windows, "
          f"{len(snapshot['groups'])} group decisions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
