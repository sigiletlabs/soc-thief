"""Synthetic, aggregate-only Qwen versus Jev comparison tests."""

import unittest

from soc_thief.model_comparison import ComparisonError, compare


def row(sample, label):
    return {"sample": str(sample), "attention_label": label,
            "description": "private synthetic marker"}


def jev(sample, score, tag):
    return {"sample": sample, "i": sample - 1, "score": score, "tag": tag}


def qwen(sample, classification):
    return {"sample": sample, "i": sample - 1, "classification": classification}


class ModelComparisonTests(unittest.TestCase):
    def test_unlabeled_rows_produce_no_accuracy_claim(self):
        result = compare([row(1, ""), row(2, "")],
                         [jev(1, .9, "other_concern"), jev(2, .1, "routine")],
                         [qwen(1, "suspicious"), qwen(2, "benign")])
        self.assertEqual(result["labeled"], 0)
        self.assertIsNone(result["jev_score_auc"])
        self.assertIsNone(result["qwen_classification"]["agreement_on_covered"])
        self.assertNotIn("private synthetic marker", str(result))

    def test_comparison_counts_false_routine_and_abstention(self):
        result = compare([row(1, "review"), row(2, "routine"), row(3, "review")],
                         [jev(1, .9, "other_concern"), jev(2, .1, "routine"),
                          jev(3, .7, "insufficient_context")],
                         [qwen(1, "benign"), qwen(2, "benign"), qwen(3, "suspicious")])
        self.assertEqual(result["jev_score_auc"], 1.0)
        self.assertEqual(result["jev_tag"]["abstained"], 1)
        self.assertEqual(result["qwen_classification"]["false_routine"], 1)
        self.assertEqual(result["qwen_classification"]["agreement_on_covered"], .667)

    def test_mismatched_samples_or_bad_label_fail_without_echoing(self):
        for worksheet, j, q in (
            ([row(1, "secret label")], [jev(1, .5, "routine")], [qwen(1, "benign")]),
            ([row(1, "routine")], [jev(1, .5, "routine")],
             [{"sample": 1, "i": 9, "classification": "benign"}]),
            ([row(1, "routine")], [jev(1, float("nan"), "routine")], [qwen(1, "benign")]),
        ):
            with self.subTest(worksheet=worksheet), self.assertRaises(ComparisonError) as raised:
                compare(worksheet, j, q)
            self.assertNotIn("secret label", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
