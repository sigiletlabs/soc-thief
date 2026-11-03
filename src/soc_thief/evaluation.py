"""Content-free delivery-evaluation accounting for controlled activation.

The input ledger deliberately contains only three analyst-reviewed booleans per case.
It is evidence for a human approval decision, never an automatic activation decision.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


_MAX_CASES = 100_000
_MAX_BYTES = 2 * 1024 * 1024
_FIELDS = {"expected_delivery", "observed_delivery", "protected"}


class EvaluationError(RuntimeError):
    """A fixed-text evaluation failure that cannot disclose ledger content."""


@dataclass(frozen=True)
class Evaluation:
    cases: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    protected_miss: bool

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    def as_dict(self) -> dict[str, int | float | bool]:
        return {
            "cases": self.cases,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "protected_miss": self.protected_miss,
        }


def evaluate(rows: Iterable[object]) -> Evaluation:
    """Calculate bounded aggregate evidence without retaining case identities or prose."""
    try:
        iterator = iter(rows)
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        protected_miss = False
        cases = 0
        for row in iterator:
            cases += 1
            if cases > _MAX_CASES or type(row) is not dict or set(row) != _FIELDS:
                raise ValueError
            expected, observed, protected = (row[name] for name in (
                "expected_delivery", "observed_delivery", "protected"))
            if any(type(value) is not bool for value in (expected, observed, protected)):
                raise ValueError
            # A protected case is policy-delivery-required, irrespective of analyst outcome.
            if protected and not expected:
                raise ValueError
            if expected and observed:
                counts["tp"] += 1
            elif expected:
                counts["fn"] += 1
                protected_miss |= protected
            elif observed:
                counts["fp"] += 1
            else:
                counts["tn"] += 1
        if cases == 0:
            raise ValueError
        return Evaluation(cases, counts["tp"], counts["fp"], counts["tn"], counts["fn"], protected_miss)
    except (TypeError, ValueError):
        raise EvaluationError("evaluation ledger is invalid") from None


def load(path: Path) -> Evaluation:
    """Read one bounded, owner-controlled JSON ledger without exposing its contents."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_uid not in (0, os.geteuid())):
                raise ValueError
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise ValueError
        return evaluate(json.loads(raw.decode("utf-8")))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, EvaluationError):
        raise EvaluationError("evaluation ledger is invalid") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(1, "Invalid evaluation arguments; use --help.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--ledger", required=True, help="Private, minimized evaluation JSON")
    args = parser.parse_args(argv)
    try:
        result = load(Path(args.ledger))
    except EvaluationError:
        print("Delivery evaluation failed; review required.")
        return 1
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    print("Evaluation complete; analyst approval and explicit activation remain required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
