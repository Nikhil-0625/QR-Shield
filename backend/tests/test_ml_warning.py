"""Synthetic-only tests: no application, models, or datasets imported."""

import importlib.util
import json
import math
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "experimental/ml_warning.py"
SPEC = importlib.util.spec_from_file_location("isolated_ml_warning", MODULE)
warning_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(warning_module)
separate_ml_warning = warning_module.separate_ml_warning


class SeparateWarningTests(unittest.TestCase):
    def test_exact_threshold(self):
        threshold = warning_module.WARNING_THRESHOLD
        self.assertEqual(threshold, 0.40144790130467084)
        for probability, expected in (
            (math.nextafter(threshold, 0), False),
            (threshold, True),
            (math.nextafter(threshold, 1), True),
            (0, False), (1, True),
        ):
            with self.subTest(probability=probability):
                self.assertIs(separate_ml_warning(0, probability)["experimental_ml_warning"], expected)

    def test_risk_boundaries_independent_of_warning(self):
        for score, expected in ((0, "SAFE"), (30, "SAFE"),
                                (31, "SUSPICIOUS"), (60, "SUSPICIOUS"),
                                (61, "UNSAFE"), (100, "UNSAFE")):
            for probability in (0, 1):
                with self.subTest(score=score, probability=probability):
                    result = separate_ml_warning(score, probability)
                    self.assertEqual(result["risk_score"], score)
                    self.assertEqual(result["risk_classification"], expected)

    def test_safe_high_probability_is_not_promoted(self):
        result = separate_ml_warning(10, 0.99)
        self.assertEqual(result["risk_classification"], "SAFE")
        self.assertTrue(result["experimental_ml_warning"])
        self.assertIn("does not confirm a malicious URL", result["warning_explanation"])

    def test_unsafe_low_probability_is_not_demoted(self):
        result = separate_ml_warning(90, 0.01)
        self.assertEqual(result["risk_classification"], "UNSAFE")
        self.assertFalse(result["experimental_ml_warning"])
        self.assertIn("does not prove the URL is safe", result["warning_explanation"])

    def test_invalid_scores(self):
        for score in (-1, 101, 30.5, 30.0, True, False, None, "30", [], {}, math.nan, math.inf):
            with self.subTest(input_type=type(score).__name__):
                with self.assertRaises(ValueError):
                    separate_ml_warning(score, 0.5)

    def test_invalid_probabilities(self):
        for probability in (-0.01, 1.01, math.nan, math.inf, -math.inf,
                            True, False, None, "0.5", [], {}, 10**1000):
            with self.subTest(input_type=type(probability).__name__):
                with self.assertRaises(ValueError):
                    separate_ml_warning(30, probability)

    def test_structured_output_and_generic_errors(self):
        result = separate_ml_warning(30, 0.5)
        self.assertEqual(json.loads(json.dumps(result)), result)
        with self.assertRaises(ValueError) as caught:
            separate_ml_warning(0, "synthetic-private-marker")
        self.assertNotIn("synthetic-private-marker", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
