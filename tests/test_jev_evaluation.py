"""Content-free analyst comparison for the dormant Jev advisory trial."""

import unittest

from soc_thief.jev_evaluation import JevEvaluationError, evaluate


class JevEvaluationTests(unittest.TestCase):
    def test_unlabeled_worksheet_makes_no_accuracy_claim(self):
        result = evaluate([{"sample": "1", "analyst_label": "", "description": "private"}],
                          [{"sample": 1, "i": 4, "score": 0.8, "tag": "other_concern"}])
        self.assertEqual(result["labeled"], 0)
        self.assertIsNone(result["agreement_rate"])
        self.assertNotIn("private", str(result))

    def test_agreement_and_missed_concern_are_aggregate_only(self):
        worksheet = [{"sample": "1", "analyst_label": "routine", "description": "private"},
                     {"sample": "2", "analyst_label": "possible_malware", "description": "private"},
                     {"sample": "3", "analyst_label": "routine", "description": "private"}]
        predictions = [{"sample": 1, "i": 0, "score": .2, "tag": "routine"},
                       {"sample": 2, "i": 1, "score": .8, "tag": "routine"},
                       {"sample": 3, "i": 2, "score": .7, "tag": "other_concern"}]
        result = evaluate(worksheet, predictions)
        self.assertEqual((result["labeled"], result["exact_agreement"],
                          result["possible_missed_concerns"], result["possible_false_alarms"]),
                         (3, 1, 1, 1))
        self.assertNotIn("private", str(result))

    def test_bad_join_or_label_fails_without_echoing_input(self):
        for worksheet, predictions in (
            ([{"sample": "1", "analyst_label": "secret label"}],
             [{"sample": 1, "i": 0, "score": .5, "tag": "routine"}]),
            ([{"sample": "2", "analyst_label": "routine"}],
             [{"sample": 1, "i": 0, "score": .5, "tag": "routine"}]),
            ([{"sample": "1", "analyst_label": "routine"}],
             [{"sample": 1, "i": 0, "score": float("nan"), "tag": "routine"}]),
        ):
            with self.subTest(worksheet=worksheet), self.assertRaises(JevEvaluationError) as raised:
                evaluate(worksheet, predictions)
            self.assertNotIn("secret label", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
