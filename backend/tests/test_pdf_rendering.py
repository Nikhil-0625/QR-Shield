"""PDF rendering with synthetic records, no real database or model loads."""
import unittest
import json
from pathlib import Path
from unittest.mock import patch

import dotenv
from reportlab.lib import colors
import test_history_authorization as harness


class PdfRenderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(dotenv, "load_dotenv", return_value=False):
            harness.HistoryAuthorizationTests.setUpClass()
        cls.fixture = harness.HistoryAuthorizationTests()

    @classmethod
    def tearDownClass(cls):
        harness.HistoryAuthorizationTests.tearDownClass()

    def test_synthetic_report_without_named_color_cache(self):
        self.fixture.setUp()
        database = self.fixture.database.SessionLocal()
        try:
            record = database.query(self.fixture.database.ScanRecord).filter_by(id=11).first()
            # Regression for the dependency's unavailable named black lookup.
            with patch.object(colors, "_namedColors", {}):
                result = self.fixture.main._build_report(record)
            self.assertTrue(result.getvalue().startswith(b"%PDF"))
        finally:
            database.close()

    def test_low_risk_summary_does_not_hide_elevated_ml(self):
        from types import SimpleNamespace
        record = SimpleNamespace(final_url="https://www.wikipedia.org/", https_valid=1,
            domain_age_days=1000, lookalike_brand=None, ml_phishing_probability="100",
            risk_label="safe")
        summary = self.fixture.main._report_summary(record, [], [])
        self.assertIn("uncalibrated ML estimate is elevated", summary)
        self.assertIn("not proof of phishing", summary)
        self.assertIn("does not guarantee safety", summary)
        self.assertNotIn("No suspicious indicators", summary)

    def test_low_risk_summary_disclaims_unavailable_checks(self):
        from types import SimpleNamespace
        record = SimpleNamespace(final_url="https://example.org/", https_valid=None,
            domain_age_days=None, lookalike_brand=None, ml_phishing_probability=None,
            risk_label="safe")
        summary = self.fixture.main._report_summary(record, [], [])
        self.assertIn("Unavailable checks have not passed", summary)
        self.assertIn("available checks", summary)

    def test_upi_banner_shared_fixtures(self):
        from upi_security import analyze_upi, upi_intent_banner
        fixtures = json.loads((Path(__file__).resolve().parents[2] / "frontend/tests/upi-intent-fixtures.json").read_text(encoding="utf-8"))
        for fixture in fixtures:
            with self.subTest(uri=fixture["uri"]):
                intent = upi_intent_banner(self.fixture.main.parse_upi_payment_uri(fixture["uri"]), analyze_upi(fixture["uri"]))
                self.assertEqual(intent["state"], fixture["state"])
                self.assertEqual(intent["title"], fixture["title"])

    def test_upi_pdf_header_matches_banner_and_escapes_recipient(self):
        from upi_security import analyze_upi, upi_intent_banner
        fixtures = json.loads((Path(__file__).resolve().parents[2] / "frontend/tests/upi-intent-fixtures.json").read_text(encoding="utf-8"))
        for fixture in fixtures:
            with self.subTest(uri=fixture["uri"]):
                record = self.fixture.database.ScanRecord(id=991, decoded_content=fixture["uri"], tampering_reasons="[]", redirect_chain="[]")
                expected = upi_intent_banner(self.fixture.main.parse_upi_payment_uri(fixture["uri"]), analyze_upi(fixture["uri"]))
                with patch.object(self.fixture.main.SimpleDocTemplate, "build") as build:
                    self.fixture.main._build_report(record)
                story = build.call_args.args[0]
                self.assertEqual(story[0].getPlainText(), expected["title"])
                self.assertEqual(story[1].getPlainText(), expected["body"])
                self.assertEqual(story[0].style.fontSize, 30 if expected["state"] in ("collect", "conflict") else 24)
                if "<script>" in expected["title"]:
                    self.assertIn("&lt;script&gt;", story[0].text)
                self.assertTrue(any("UPI QR Analysis" in str(getattr(item, "_cellvalues", "")) for item in story))

    def test_url_pdf_header_verdict_unchanged(self):
        for score, ml, rule, expected in [(20,"5",0,"Likely safe"),(55,"60",50,"Be careful"),(30,"100",0,"Can't tell")]:
            record = self.fixture.database.ScanRecord(id=991, decoded_content="https://example.test/", final_url="https://example.test/",
                risk_score=score, ml_phishing_probability=ml, rule_score=rule, tampering_reasons="[]", redirect_chain="[]")
            with patch.object(self.fixture.main.SimpleDocTemplate, "build") as build:
                self.fixture.main._build_report(record)
            self.assertEqual(build.call_args.args[0][0].getPlainText(), expected)


if __name__ == "__main__":
    unittest.main()
