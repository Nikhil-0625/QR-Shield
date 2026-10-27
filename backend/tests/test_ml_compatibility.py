"""Pure synthetic tests: no application imports, model files, data, or network."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from ml_probability import phishing_probability
    from legacy_ml_features import FEATURE_NAMES, extract_legacy_features, legacy_feature_vector
finally:
    sys.path.pop(0)


class ProbabilityTests(unittest.TestCase):
    def test_both_class_orders_and_multiple_rows(self):
        self.assertEqual(phishing_probability([-1, 1], [[0.9, 0.1], [0.2, 0.8]], phishing_label=-1), [0.9, 0.2])
        self.assertEqual(phishing_probability([1, -1], [[0.1, 0.9], [0.8, 0.2]], phishing_label=-1), [0.9, 0.2])

    def test_explicit_label_is_not_assumed(self):
        self.assertEqual(phishing_probability(["benign", "phishing"], [[0.3, 0.7]], phishing_label="phishing"), [0.7])
        with self.assertRaises(TypeError):
            phishing_probability([-1, 1], [[0.2, 0.8]])

    def test_missing_duplicate_and_invalid_classes(self):
        for classes in [[], [0, 1], [-1, -1], [-1, None], [-1, float("nan")], [[-1], [1]], "-1", None]:
            with self.subTest(classes=classes), self.assertRaises(ValueError):
                phishing_probability(classes, [[0.2, 0.8]], phishing_label=-1)

    def test_invalid_values(self):
        for row in [[-0.1, 1.1], [float("nan"), 0.5], [float("inf"), 0], ["0.2", 0.8], [True, 0], [0.2, 0.2], [None, 1]]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                phishing_probability([-1, 1], [row], phishing_label=-1)

    def test_incompatible_shapes(self):
        for output in [None, [], 0.5, [0.2, 0.8], [[0.2]], [[0.2, 0.3, 0.5]], [[[0.2, 0.8]]], [[0.2, 0.8], [1]], "invalid"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                phishing_probability([-1, 1], output, phishing_label=-1)


class LegacyFeatureTests(unittest.TestCase):
    def test_names_order_and_integer_types(self):
        self.assertEqual(FEATURE_NAMES, (
            "url_length", "has_https", "num_dots", "num_hyphens", "num_at",
            "num_question_marks", "num_equal", "num_underscore", "num_slash",
            "has_ip", "num_digits", "num_subdomains",
        ))
        features = extract_legacy_features("https://example.test")
        self.assertEqual(tuple(features), FEATURE_NAMES)
        self.assertTrue(all(type(value) is int for value in features.values()))

    def test_exact_synthetic_vectors(self):
        # Manually counted fixtures lock the original notebook's imperfect semantics.
        cases = {
            "http://192.0.2.1": [16, 0, 3, 0, 0, 0, 0, 0, 2, 1, 6, 2],
            "http://[2001:db8::1]": [20, 0, 0, 0, 0, 0, 0, 0, 2, 0, 6, 0],
            "https://a.test/192.0.2.1": [24, 1, 4, 0, 0, 0, 0, 0, 3, 1, 6, 3],
            "https://a-b.test/x_y?u=@&n=2": [28, 1, 1, 1, 1, 1, 2, 1, 3, 0, 1, 0],
            "HTTPS://a.test": [14, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0],
            "a.test": [6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(legacy_feature_vector(url), expected)

    def test_legacy_edge_cases_are_preserved(self):
        self.assertEqual(extract_legacy_features("http://999.999.999.999")["has_ip"], 1)
        self.assertEqual(extract_legacy_features("https-not-a-url")["has_https"], 1)
        self.assertEqual(extract_legacy_features("١٢")["num_digits"], 2)
        with self.assertRaises(TypeError):
            extract_legacy_features(None)


if __name__ == "__main__":
    unittest.main()
