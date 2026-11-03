"""Synthetic tests for the controlled-delivery evaluation ledger."""

import unittest

from soc_thief.evaluation import EvaluationError, evaluate


class EvaluationTests(unittest.TestCase):
    def test_confusion_matrix_and_rates_are_content_free(self):
        result = evaluate((
            {"expected_delivery": True, "observed_delivery": True, "protected": True},
            {"expected_delivery": True, "observed_delivery": False, "protected": False},
            {"expected_delivery": False, "observed_delivery": True, "protected": False},
            {"expected_delivery": False, "observed_delivery": False, "protected": False},
        ))
        self.assertEqual((result.true_positive, result.false_negative,
                          result.false_positive, result.true_negative), (1, 1, 1, 1))
        self.assertEqual(result.precision, 0.5)
        self.assertEqual(result.recall, 0.5)
        self.assertFalse(result.protected_miss)
        self.assertEqual(result.as_dict(), {
            "cases": 4, "true_positive": 1, "false_positive": 1,
            "true_negative": 1, "false_negative": 1,
            "precision": 0.5, "recall": 0.5, "protected_miss": False,
        })

    def test_protected_miss_is_never_hidden(self):
        result = evaluate((
            {"expected_delivery": True, "observed_delivery": False, "protected": True},
        ))
        self.assertTrue(result.protected_miss)

    def test_rejects_invalid_or_unminimized_ledger_rows(self):
        invalid = (
            (),
            ({"expected_delivery": True, "observed_delivery": True},),
            ({"expected_delivery": True, "observed_delivery": True, "protected": False,
              "description": "synthetic sensitive marker"},),
            ({"expected_delivery": True, "observed_delivery": 1, "protected": False},),
            ({"expected_delivery": False, "observed_delivery": False, "protected": True},),
        )
        for rows in invalid:
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(EvaluationError, "evaluation ledger is invalid") as raised:
                    evaluate(rows)
                self.assertNotIn("synthetic sensitive marker", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
