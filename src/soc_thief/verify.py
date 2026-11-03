"""Bounded, source-disabled connection verification; emits fixed status messages only."""

from __future__ import annotations

import argparse
import multiprocessing
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Callable

from soc_thief.collector import CollectorConfig, WazuhIndexerCollector

DEADLINE_SECONDS = 75
_MESSAGES = {
    0: "Metadata pagination verified; no source fields requested. Deployment gates remain open.",
    1: "Verification failed; review required. Connection details withheld.",
    2: "Verification inconclusive: fewer than two metadata records. Review required.",
    3: "Verification deadline exceeded; review required.",
}
_SNAPSHOT_SUCCESS = "Snapshot metadata pagination verified; no source fields requested. Deployment gates remain open."


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally repeats untrusted argument text in its diagnostics.
        self.exit(1, "Invalid verification arguments; use --help.\n")


def _worker(start: datetime, end: datetime, snapshot: bool = False) -> None:
    code = 1
    try:
        config = replace(CollectorConfig.from_environment(), page_size=1, max_attempts=1)
        passed = WazuhIndexerCollector(config).verify_metadata(start, end, snapshot=snapshot)
        code = 0 if passed else 2
    except Exception:
        # Includes unexpected errors: never expose configuration or response tracebacks.
        pass
    raise SystemExit(code)


def _run_worker(start: datetime, end: datetime, *, snapshot: bool = False,
                timeout: float = DEADLINE_SECONDS, target: Callable = _worker) -> int:
    process = multiprocessing.get_context("spawn").Process(target=target, args=(start, end, snapshot))
    try:
        process.start()
        process.join(timeout)
        if process.is_alive():
            return 3
        return process.exitcode if process.exitcode in (0, 1, 2) else 1
    except Exception:
        return 1
    finally:
        if process.pid is not None:
            if process.is_alive():
                process.kill()
                process.join(5)
            if not process.is_alive():
                process.close()


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--start", required=True, help="Timezone-aware ISO timestamp (inclusive)")
    parser.add_argument("--end", required=True, help="Timezone-aware ISO timestamp (exclusive)")
    parser.add_argument("--snapshot", action="store_true",
                        help="Use and release one point-in-time snapshot for both metadata pages")
    args = parser.parse_args(argv)
    try:
        start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
        if (start.utcoffset() is None or end.utcoffset() is None
                or not timedelta(0) < end - start <= timedelta(hours=1)):
            raise ValueError
    except ValueError:
        print("Invalid verification window; use aware timestamps at most one hour apart.")
        return 1
    code = _run_worker(start, end, snapshot=args.snapshot)
    print(_SNAPSHOT_SUCCESS if code == 0 and args.snapshot else _MESSAGES[code])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
