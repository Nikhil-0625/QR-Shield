"""Regression tests for ML model lazy loading and deployment readiness.

Verifies:
- Test A: QR_SCANNER_ML_ENABLED=false + absent model file -> initialization succeeds without error.
- Test B: QR_SCANNER_ML_ENABLED=false -> zero model loading attempts (joblib.load not invoked).
- Test C: QR_SCANNER_ML_ENABLED=true -> model loading occurs normally when an artifact is provided.
- Test D: Deterministic risk classification remains completely intact.
"""
import importlib
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import joblib
from PIL import Image

import test_api_security as api_harness
import test_history_authorization as auth_harness


class MlLazyLoadingTests(unittest.TestCase):
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

    def scan_qr(self, url, headers=()):
        """Helper to scan a synthetic QR code pointing to `url`."""
        image = io.BytesIO()
        Image.new("RGB", (8, 8), "white").save(image, format="PNG")
        body = (
            b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="test.png"\r\n'
            b'Content-Type: image/png\r\n\r\n' + image.getvalue() + b'\r\n--boundary--\r\n'
        )
        with patch.object(self.main, "decode_qr", return_value=url), \
             patch.object(self.main, "analyze_tampering", return_value={"tampering_score": 0, "tampering_reasons": []}), \
             patch.object(self.main, "validate_outbound_url", return_value=(False, "offline test")), \
             patch.object(self.main.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(self.main.requests, "get", side_effect=AssertionError("HTTP forbidden")), \
             patch.object(self.main.whois, "whois", side_effect=AssertionError("WHOIS forbidden")):
            code, raw, _ = self.api(
                "/scan", "POST", self.token("a@example.test"), body,
                [(b"content-type", b"multipart/form-data; boundary=boundary"),
                 (b"x-qr-shield-offline", b"1"), *headers]
            )
        self.assertEqual(code, 200, raw)
        return json.loads(raw)

    def test_a_disabled_ml_initializes_without_model_file(self):
        """Test A: QR_SCANNER_ML_ENABLED=false + absent model file -> initialization succeeds."""
        nonexistent_path = os.path.join(os.path.dirname(__file__), "nonexistent_model_file_absent.pkl")
        self.assertFalse(os.path.exists(nonexistent_path), "Test prerequisite: file must not exist")

        with patch.dict(os.environ, {
            "QR_SCANNER_ML_ENABLED": "false",
            "MODEL_PATH": nonexistent_path,
        }):
            # Verify is_ml_enabled() reports False
            self.assertFalse(self.main.is_ml_enabled())
            # Verify get_ml_model() returns None without checking nonexistent_path
            model = self.main.get_ml_model()
            self.assertIsNone(model)

    def test_b_disabled_ml_zero_joblib_load_attempts(self):
        """Test B: QR_SCANNER_ML_ENABLED=false -> zero model loading attempts (joblib.load not invoked)."""
        forbidden_loader = Mock(side_effect=AssertionError("joblib.load must NEVER be invoked when ML is disabled"))

        with patch.dict(os.environ, {"QR_SCANNER_ML_ENABLED": "false"}), \
             patch.object(joblib, "load", forbidden_loader):

            # 1. get_ml_model directly
            model = self.main.get_ml_model()
            self.assertIsNone(model)
            forbidden_loader.assert_not_called()

            # 2. Scanning QR code
            result = self.scan_qr("https://www.google.com")
            forbidden_loader.assert_not_called()
            self.assertEqual(result.get("ml_status"), "excluded")
            self.assertIsNone(result.get("ml_phishing_probability"))
            self.assertIn("excluded from QR risk scoring", result.get("ml_note", ""))

            # 3. Direct _analyze_url call
            direct_result = self.main._analyze_url("https://www.google.com", include_ml=False)
            forbidden_loader.assert_not_called()
            self.assertIsNone(direct_result.get("ml_phishing_probability"))

    def test_c_enabled_ml_loads_normally_when_artifact_provided(self):
        """Test C: QR_SCANNER_ML_ENABLED=true -> model loading occurs normally when an artifact is provided."""
        mock_model = SimpleNamespace(
            classes_=[-1, 1],
            predict_proba=Mock(return_value=[[0.85, 0.15]]),
        )
        mock_loader = Mock(return_value=mock_model)

        with patch.dict(os.environ, {"QR_SCANNER_ML_ENABLED": "true"}), \
             patch.object(self.main, "ml_model", None):
            self.assertTrue(self.main.is_ml_enabled())

            # Lazy load via get_ml_model
            loaded = self.main.get_ml_model(loader=mock_loader)
            self.assertIs(loaded, mock_model)
            mock_loader.assert_called_once()

            # Inference test with loaded model
            result = self.scan_qr("https://example.com/verify")
            self.assertEqual(result.get("ml_phishing_probability"), 85.0)
            mock_model.predict_proba.assert_called()

    def test_d_deterministic_risk_classification_remains_intact_without_ml(self):
        """Test D: Deterministic risk classification remains completely intact without ML."""
        with patch.dict(os.environ, {"QR_SCANNER_ML_ENABLED": "false"}), \
             patch.object(joblib, "load", side_effect=AssertionError("joblib.load forbidden")):

            # 1. Legitimate HTTPS destination
            legit = self.scan_qr("https://www.google.com")
            self.assertEqual(legit.get("rule_score"), 0)
            self.assertEqual(legit.get("risk_breakdown"), [])
            self.assertEqual(legit.get("risk_label"), "unverified")
            self.assertIsNone(legit.get("risk_score"))
            self.assertEqual(legit.get("ml_status"), "excluded")

            # 2. Lookalike brand impersonation
            phish = self.scan_qr("http://paypal-login.example.com/verify")
            rule_names = {item["name"] for item in phish.get("risk_breakdown", [])}
            self.assertIn("Possible Brand Impersonation", rule_names)
            self.assertEqual(phish.get("lookalike_brand").lower(), "paypal")
            self.assertEqual(phish.get("risk_label"), "suspicious")
            self.assertGreater(phish.get("rule_score", 0), 0)

            # 3. Public IP address in URL
            ip_scan = self.scan_qr("http://192.0.2.1/login")
            ip_rules = {item["name"] for item in ip_scan.get("risk_breakdown", [])}
            self.assertIn("IP Address URL", ip_rules)
            self.assertEqual(ip_scan.get("risk_label"), "suspicious")

            # 4. Insecure transport (HTTP)
            http_scan = self.scan_qr("http://ordinary.example/")
            http_rules = {item["name"] for item in http_scan.get("risk_breakdown", [])}
            self.assertIn("HTTP Connection", http_rules)


if __name__ == "__main__":
    unittest.main()
