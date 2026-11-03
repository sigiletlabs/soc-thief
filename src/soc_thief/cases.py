"""Local operator case review and candidate tuning export.

No network, model, Wazuh write, Discord send or automatic tuning installation.
Run as the owner of the private state directory, outside the runner's scheduled window.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import sys

from soc_thief.baseline import NEVER_PROPOSE, Proposal, serialize
from soc_thief.state import StateError, StateStore
from soc_thief.tuning import MAX_ENTRIES, _identifier


def candidates(store: StateStore, *, now: datetime) -> tuple[Proposal, ...]:
    """Human routine verdicts can suggest only short-lived, agent-scoped low entries."""
    expiry = now.astimezone(timezone.utc) + timedelta(days=30)
    selected = {}
    for case in store.routine_cases(now=now):
        if (case.status != "routine" or not case.tunable or case.rule_id in NEVER_PROPOSE
                or not _identifier(case.rule_id) or not _identifier(case.agent_id)):
            continue
        key = (case.rule_id, case.agent_id)
        selected[key] = Proposal(case.rule_id, "low", case.agent_id, expiry,
                                 "analyst routine verdict; verify before installing")
    return tuple(selected[key] for key in sorted(selected)[:MAX_ENTRIES])


def _private_output(path: Path, document: dict) -> None:
    parent = path.parent
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError
    data = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review delivered Soc Thief cases locally")
    parser.add_argument("--state", type=Path, required=True, help="private state directory")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="show recent case metadata")
    listing.add_argument("--limit", type=int, default=200)
    marking = commands.add_parser("mark", help="record one human verdict")
    marking.add_argument("case_id")
    marking.add_argument("status", choices=("review", "routine", "uncertain"))
    resolving = commands.add_parser("resolve", help="return one case's lookup IDs for a local tool")
    resolving.add_argument("case_id")
    proposal = commands.add_parser("propose", help="write review-only tuning candidates")
    proposal.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc)
    try:
        with StateStore(args.state) as store:
            if args.command == "list":
                for case in store.cases(now=now, limit=args.limit):
                    print(f"{case.token}  {case.status:10}  rule={case.rule_id} agent={case.agent_id} "
                          f"last={case.last_seen.date()}")
            elif args.command == "mark":
                store.mark_case(args.case_id, args.status, now=now)
                print("case verdict recorded")
            elif args.command == "resolve":
                case = store.case(args.case_id, now=now)
                if case is None or now - case.last_seen > timedelta(days=90):
                    raise StateError("case lookup failed")
                print(json.dumps({"rule_id": case.rule_id, "agent_id": case.agent_id}))
            else:
                rows = candidates(store, now=now)
                _private_output(args.output, serialize(rows))
                print(f"wrote {len(rows)} candidate entries; review before manual installation")
        return 0
    except (StateError, OSError, ValueError):
        print("case operation failed; state and output must be private and unlocked", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
