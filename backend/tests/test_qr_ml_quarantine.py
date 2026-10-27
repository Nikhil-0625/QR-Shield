"""Regression tests verifying unreliable ML model exclusion from QR scanner risk scoring.

Audited root cause: The production ML model was trained on a dataset where 99.5%
of benign URLs lacked schemes, causing the model to learn that `has_https=1`
indicates phishing. When evaluated on legitimate HTTPS sites (e.g. google.com,
wikipedia.org), the model outputs ~100% phishing probability, injecting 30
artificial risk points into legitimate destinations.

Task 2 resolution:
1. QR scanner excludes the unreliable ML model by default.
2. Legitimate HTTPS URLs receive 0 artificial risk points.
3. Heuristic URL rules remain fully intact and active.
4. Model artifacts and experimental ML endpoints remain preserved.
"""
from contextlib import ExitStack
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PIL import Image

import test_api_security as api_harness
import test_history_authorization as auth_harness


class QrMlQuarantineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("dotenv.load_dotenv", return_value=False):
            auth_harness.HistoryAuthorizationTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    setUp = auth_harness.HistoryAuthorizationTests.setUp
    token = auth_harness.HistoryAuthorizationTests.token
    api = api_harness.ApiSecurityTests.api

    def scan_qr(self, url, mock_model=None):
        """Helper to scan a synthetic QR code pointing to `url`."""
        image = io.BytesIO()
        Image.new("RGB", (8, 8), "white").save(image, format="PNG")
        body = (
            b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="test.png"\r\n'
            b'Content-Type: image/png\r\n\r\n' + image.getvalue() + b'\r\n--boundary--\r\n'
        )
        if mock_model is None:
            mock_model = SimpleNamespace(
                classes_=[-1, 1],
                predict_proba=Mock(side_effect=AssertionError("ML model must not be called")),
            )
        with patch.object(self.main, "ml_model", mock_model), \
             patch.object(self.main, "decode_qr", return_value=url), \
             patch.object(self.main, "analyze_tampering", return_value={"tampering_score": 0, "tampering_reasons": []}), \
             patch.object(self.main, "validate_outbound_url", return_value=(False, "offline quarantine test")), \
             patch.object(self.main.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(self.main.requests, "get", side_effect=AssertionError("HTTP forbidden")), \
             patch.object(self.main.whois, "whois", side_effect=AssertionError("WHOIS forbidden")):
            code, raw, _ = self.api(
                "/scan", "POST", self.token("a@example.test"), body,
                [(b"content-type", b"multipart/form-data; boundary=boundary"),
                 (b"x-qr-shield-offline", b"1")]
            )
        self.assertEqual(code, 200, raw)
        return json.loads(raw), mock_model

    def test_audit_finding_confirmed_has_https_feature_extraction(self):
        """Verify the audit finding: extract_ml_features marks has_https=1 for legitimate sites."""
        legit_urls = [
            "https://www.google.com",
            "https://www.instagram.com",
            "https://en.wikipedia.org/wiki/Main_Page",
            "https://github.com",
        ]
        for url in legit_urls:
            with self.subTest(url=url):
                features = self.main.extract_ml_features(url)
                self.assertEqual(features["has_https"], 1, "HTTPS URLs must have has_https=1")

    def test_qr_scanner_excludes_ml_model_by_default(self):
        """Verify the unreliable ML model is not invoked during default QR scan."""
        result, model = self.scan_qr("https://www.google.com")
        # Model predict_proba must NOT have been called.
        model.predict_proba.assert_not_called()
        # ML status must be explicitly marked as excluded.
        self.assertEqual(result.get("ml_status"), "excluded")
        self.assertIn("excluded from QR", result.get("ml_note", ""))
        self.assertIsNone(result.get("ml_phishing_probability"))

    def test_legitimate_urls_receive_zero_artificial_ml_risk_points(self):
        """Verify legitimate URLs no longer receive 30 artificial ML risk points."""
        legit_urls = [
            "https://www.google.com",
            "https://en.wikipedia.org/wiki/Main_Page",
            "https://github.com/project",
            "https://python.org",
        ]
        for url in legit_urls:
            with self.subTest(url=url):
                result, _ = self.scan_qr(url)
                # With ML excluded, no hybrid risk score adding 30 points is computed.
                self.assertIsNone(result.get("risk_score"), "Risk score must be None (no artificial points)")
                self.assertEqual(result.get("rule_score"), 0, "Legitimate URLs must have rule_score=0")
                self.assertEqual(result.get("risk_breakdown"), [], "No rules should trigger on clean URLs")
                self.assertEqual(result.get("risk_label"), "unverified", "Clean URLs should be unverified, not suspicious")

    def test_suspicious_urls_retain_heuristic_detection_rules_without_ml(self):
        """Verify offline heuristic rules still catch suspicious URLs independently of ML."""
        suspicious_cases = [
            ("http://paypal-login.example.com/verify", "Possible Brand Impersonation"),
            ("https://paypal.com@evil.test/verify", "Embedded URL Credentials"),
            ("http://192.0.2.1/verify", "IP Address URL"),
        ]
        for url, expected_rule in suspicious_cases:
            with self.subTest(url=url, rule=expected_rule):
                result, _ = self.scan_qr(url)
                rule_names = {r["name"] for r in result.get("risk_breakdown", [])}
                self.assertIn(expected_rule, rule_names)
                self.assertGreater(result.get("rule_score", 0), 0)
                self.assertEqual(result.get("risk_label"), "suspicious")
                self.assertEqual(result.get("ml_status"), "excluded")

    def test_experimental_ml_artifacts_and_files_are_preserved(self):
        """Verify model files and experimental code remain intact on disk."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Model artifact
        model_path = os.path.join(base_dir, "ml", "phishing_model_v2.pkl")
        self.assertTrue(os.path.exists(model_path), f"Model file must exist at {model_path}")
        # Candidate API
        candidate_api = os.path.join(base_dir, "experimental", "candidate_api.py")
        self.assertTrue(os.path.exists(candidate_api), f"Candidate API must exist at {candidate_api}")


if __name__ == "__main__":
    unittest.main()
