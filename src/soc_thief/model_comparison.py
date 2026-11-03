"""Compare private human attention labels with Qwen and Jev, printing aggregates only."""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
from pathlib import Path

from soc_thief.jev_evaluation import JevEvaluationError, _read_private
from soc_thief.policy import JEV_THREAT_LABELS


class ComparisonError(RuntimeError):
    pass


def _id(value: object) -> int:
    if type(value) is int and value > 0:
        return value
    if type(value) is str and value.isascii() and value.isdigit() and int(value) > 0:
        return int(value)
    raise ValueError


def _metrics(labels: dict[int, bool], predictions: dict[int, bool | None]) -> dict[str, int | float | None]:
    correct = false_routine = false_review = abstained = 0
    for sample, expected in labels.items():
        predicted = predictions[sample]
        if predicted is None:
            abstained += 1
        elif predicted == expected:
            correct += 1
        elif expected:
            false_routine += 1
        else:
            false_review += 1
    covered = len(labels) - abstained
    return {"covered": covered, "abstained": abstained,
            "agreement_on_covered": round(correct / covered, 3) if covered else None,
            "false_routine": false_routine, "false_review": false_review}


def _auc(labels: dict[int, bool], scores: dict[int, float]) -> float | None:
    positive = [scores[sample] for sample, value in labels.items() if value]
    negative = [scores[sample] for sample, value in labels.items() if not value]
    if not positive or not negative:
        return None
    favorable = sum(1 if high > low else .5 if high == low else 0
                    for high in positive for low in negative)
    return round(favorable / (len(positive) * len(negative)), 3)


def compare(worksheet: object, jev: object, qwen: object) -> dict[str, object]:
    """Require one exact row alignment and return no row identity or alert text."""
    try:
        if (type(worksheet) is not list or type(jev) is not list or type(qwen) is not list
                or not 0 < len(worksheet) == len(jev) == len(qwen) <= 1000):
            raise ValueError
        rows: dict[int, dict[str, object]] = {}
        for row in worksheet:
            if type(row) is not dict or "sample" not in row or "attention_label" not in row:
                raise ValueError
            sample = _id(row["sample"])
            if sample in rows or type(row["attention_label"]) is not str:
                raise ValueError
            label = row["attention_label"].strip()
            if label not in ("", "review", "routine", "uncertain"):
                raise ValueError
            rows[sample] = {"label": label}
        scores: dict[int, float] = {}
        jev_predictions: dict[int, bool | None] = {}
        indices: dict[int, int] = {}
        for row in jev:
            if (type(row) is not dict or not {"sample", "i", "score", "tag"} <= row.keys()
                    or type(row["i"]) is not int or row["i"] < 0
                    or type(row["score"]) not in (int, float)
                    or not math.isfinite(row["score"]) or not 0 <= row["score"] <= 1
                    or type(row["tag"]) is not str or row["tag"] not in JEV_THREAT_LABELS):
                raise ValueError
            sample = _id(row["sample"])
            if sample in scores:
                raise ValueError
            scores[sample] = float(row["score"])
            indices[sample] = row["i"]
            jev_predictions[sample] = (None if row["tag"] == "insufficient_context"
                                       else row["tag"] != "routine")
        qwen_predictions: dict[int, bool | None] = {}
        for row in qwen:
            if (type(row) is not dict or not {"sample", "i", "classification"} <= row.keys()
                    or type(row["i"]) is not int or row["i"] < 0
                    or row["classification"] not in ("benign", "suspicious", "unknown")):
                raise ValueError
            sample = _id(row["sample"])
            if sample in qwen_predictions or sample not in indices or indices[sample] != row["i"]:
                raise ValueError
            qwen_predictions[sample] = (None if row["classification"] == "unknown"
                                        else row["classification"] == "suspicious")
        if set(rows) != set(scores) or set(rows) != set(qwen_predictions):
            raise ValueError
        labels = {sample: row["label"] == "review" for sample, row in rows.items()
                  if row["label"] in ("review", "routine")}
        return {"rows": len(rows), "labeled": len(labels),
                "uncertain_human_labels": sum(row["label"] == "uncertain" for row in rows.values()),
                "jev_tag": _metrics(labels, jev_predictions),
                "jev_score_auc": _auc(labels, scores),
                "qwen_classification": _metrics(labels, qwen_predictions)}
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ComparisonError("Model comparison input is invalid") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(1, "Invalid model comparison arguments; use --help.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--worksheet", required=True)
    parser.add_argument("--jev", required=True)
    parser.add_argument("--qwen", required=True)
    args = parser.parse_args(argv)
    try:
        worksheet = list(csv.DictReader(io.StringIO(_read_private(Path(args.worksheet)))))
        jev = json.loads(_read_private(Path(args.jev)))["rows"]
        qwen = json.loads(_read_private(Path(args.qwen)))["rows"]
        result = compare(worksheet, jev, qwen)
    except (ComparisonError, JevEvaluationError, csv.Error, KeyError, TypeError,
            ValueError, json.JSONDecodeError):
        print("Model comparison failed; review private inputs.")
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
