"""Aggregate-only comparison of private analyst labels and Jev advisory tags.

This is measurement, never an activation or suppression decision. Input files may contain
real alert text; errors and output contain only fixed text and aggregate counts.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import stat
from pathlib import Path

from soc_thief.policy import JEV_THREAT_LABELS


class JevEvaluationError(RuntimeError):
    pass


def _read_private(path: Path, limit: int = 512 * 1024) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_uid not in (0, os.geteuid())):
                raise ValueError
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError
        return raw.decode("utf-8")
    except (OSError, ValueError, UnicodeError):
        raise JevEvaluationError("Jev evaluation input is invalid") from None


def evaluate(worksheet: object, predictions: object) -> dict[str, int | float | None]:
    """Count agreement and false-routine advice; require an exact sample join."""
    try:
        if (type(worksheet) is not list or type(predictions) is not list
                or not 0 < len(worksheet) == len(predictions) <= 1000):
            raise ValueError
        tagged = {}
        for row in predictions:
            if (type(row) is not dict or set(row) != {"sample", "i", "score", "tag"}
                    or type(row["sample"]) is not int or row["sample"] <= 0
                    or type(row["i"]) is not int or row["i"] < 0
                    or type(row["score"]) not in (int, float)
                    or not 0 <= row["score"] <= 1
                    or type(row["tag"]) is not str or row["tag"] not in JEV_THREAT_LABELS
                    or row["sample"] in tagged):
                raise ValueError
            tagged[row["sample"]] = row["tag"]
        seen = set()
        labeled = agreement = false_routine = false_concern = insufficient = 0
        for row in worksheet:
            if type(row) is not dict or not {"sample", "analyst_label"} <= row.keys():
                raise ValueError
            if type(row["sample"]) is not str or not row["sample"].isascii() or not row["sample"].isdigit():
                raise ValueError
            sample = int(row["sample"])
            if sample in seen or sample not in tagged:
                raise ValueError
            seen.add(sample)
            label = row["analyst_label"]
            if type(label) is not str:
                raise ValueError
            label = label.strip()
            if not label:
                continue
            if label not in JEV_THREAT_LABELS:
                raise ValueError
            predicted = tagged[sample]
            labeled += 1
            agreement += predicted == label
            insufficient += predicted == "insufficient_context"
            false_routine += predicted == "routine" and label not in ("routine", "insufficient_context")
            false_concern += (predicted not in ("routine", "insufficient_context") and label == "routine")
        if seen != set(tagged):
            raise ValueError
        return {"rows": len(worksheet), "labeled": labeled, "exact_agreement": agreement,
                "agreement_rate": round(agreement / labeled, 3) if labeled else None,
                "predicted_insufficient_context": insufficient,
                "possible_missed_concerns": false_routine,
                "possible_false_alarms": false_concern}
    except (KeyError, TypeError, ValueError, OverflowError):
        raise JevEvaluationError("Jev evaluation input is invalid") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(1, "Invalid Jev evaluation arguments; use --help.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--worksheet", required=True, help="Private analyst worksheet CSV")
    parser.add_argument("--predictions", required=True, help="Private worksheet-aligned Jev JSON")
    args = parser.parse_args(argv)
    try:
        worksheet = list(csv.DictReader(io.StringIO(_read_private(Path(args.worksheet)))))
        predictions = json.loads(_read_private(Path(args.predictions)))["rows"]
        result = evaluate(worksheet, predictions)
    except (JevEvaluationError, csv.Error, KeyError, TypeError, ValueError, json.JSONDecodeError):
        print("Jev evaluation failed; review private inputs.")
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
