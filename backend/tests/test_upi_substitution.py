"""Synthetic UPI tests using the existing isolated authorization-test harness."""
import asyncio
import io
import unittest
from unittest.mock import patch

from fastapi import UploadFile
import test_history_authorization as authorization_harness


class UpiSubstitutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Harness redirects database initialization to memory and stubs joblib.load.
        authorization_harness.HistoryAuthorizationTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    setUp = authorization_harness.HistoryAuthorizationTests.setUp
    snapshot = authorization_harness.HistoryAuthorizationTests.snapshot

    def compare(self, uri, expected=None):
        details = self.main.parse_upi_payment_uri(uri)
        return details, self.main.compare_upi_payment(details, expected)

    def test_match_and_mismatch(self):
        for expected, status in [(" Merchant@Bank ", "match"), ("other@bank", "mismatch")]:
            details, result = self.compare("upi://pay?pa=merchant%40bank&pn=Synthetic&am=10&cu=INR", expected)
            self.assertEqual(result["status"], status)
            self.assertFalse(result["identity_verified"])
            self.assertEqual(details["payee_name"], "Synthetic")
            self.assertEqual(details["amount"], "10")

    def test_missing_and_malformed_vpas(self):
        for uri, expected, status in [
            ("upi://pay?pa=merchant@bank", None, "not_requested"),
            ("upi://pay?pa=merchant@bank", "  ", "not_requested"),
            ("upi://pay?pa=merchant@bank", "bad", "invalid_expected"),
            ("upi://pay?pn=Synthetic", "merchant@bank", "invalid_scanned"),
            ("upi://pay?pa=", "merchant@bank", "invalid_scanned"),
            ("upi://pay?pa=%3Cscript%3E", "merchant@bank", "invalid_scanned"),
        ]:
            with self.subTest(uri=uri, status=status):
                self.assertEqual(self.compare(uri, expected)[1]["status"], status)

    def test_conflicts_override_match_even_without_expected_vpa(self):
        for suffix in ["&PA=other%40bank", "&pa=", "&am=10&am=20", "&cu=INR&CU=USD", "&pn=One&pn=Two"]:
            for expected in ["merchant@bank", None]:
                details, result = self.compare("upi://pay?pa=merchant@bank" + suffix, expected)
                self.assertEqual(result["status"], "ambiguous")
                self.assertTrue(details["conflicting_parameters"])

    def test_identical_duplicates_are_reported_without_conflict(self):
        details, result = self.compare("upi://pay?pa=merchant@bank&PA=merchant%40bank&am=10&am=10", "merchant@bank")
        self.assertEqual(result["status"], "match")
        self.assertEqual(details["duplicate_parameters"], ["pa", "am"])
        self.assertEqual(details["conflicting_parameters"], {})

    def test_invalid_amounts_and_non_upi_content(self):
        for amount in ["NaN", "Infinity", "-1", "bad"]:
            details, _ = self.compare("upi://pay?pa=merchant@bank&am=" + amount)
            self.assertFalse(details["amount_valid"])
        for content in ["plain synthetic text", "https://example.test", "upi://other?pa=a@b"]:
            self.assertIsNone(self.main.parse_upi_payment_uri(content))

    @staticmethod
    def synthetic_image():
        from PIL import Image
        image = io.BytesIO()
        Image.new('RGB', (1, 1), 'white').save(image, format='PNG')
        image.seek(0)
        return image

    def scan(self, content, expected=None):
        with patch.object(self.main.cv2, "imdecode", return_value=object()), \
                patch.object(self.main, "decode_qr", return_value=content), \
                patch.object(self.main, "analyze_tampering", return_value={"tampering_score": 0, "tampering_reasons": []}):
            return asyncio.run(self.main.scan_qr(
                file=UploadFile(filename="synthetic.png", file=self.synthetic_image()),
                current_user="a@example.test", expected_vpa=expected,
            ))

    def test_scan_additive_response_and_transient_expected_vpa(self):
        before = self.snapshot()
        result = self.scan("upi://pay?pa=merchant@bank", "expected-only@bank")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["upi_comparison"]["status"], "mismatch")
        self.assertIn("scan_id", result)
        self.assertEqual(result["tampering_score"], 0)
        after = self.snapshot()
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(len(after), len(before) + 1)
        self.assertNotIn("expected-only@bank", str(after))
        self.assertNotIn("risk_score", result)

    def test_existing_scan_without_expected_and_plain_text_compatibility(self):
        result = self.scan("upi://pay?pa=merchant@bank")
        self.assertEqual(result["upi_details"]["payee_vpa"], "merchant@bank")
        self.assertEqual(result["upi_comparison"]["status"], "not_requested")
        text = self.scan("synthetic plain text", "merchant@bank")
        self.assertEqual(text["decoded_content"], "synthetic plain text")
        self.assertNotIn("upi_details", text)
        self.assertNotIn("upi_comparison", text)


if __name__ == "__main__":
    unittest.main()
