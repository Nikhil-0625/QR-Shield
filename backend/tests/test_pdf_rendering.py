"""PDF rendering with synthetic records, no real database or model loads."""
import unittest
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
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

    def test_current_url_reports_use_the_persisted_deterministic_verdict(self):
        cases = [
            ("known_dangerous", "HIGH", "DANGEROUS"),
            ("suspicious", "MEDIUM", "SUSPICIOUS"),
            ("integrity_review", "REVIEW REQUIRED", "SUSPICIOUS"),
            ("inconclusive", "INCONCLUSIVE", "EVIDENCE UNAVAILABLE"),
            ("transport_warning", "CAUTION", "CONNECTION WARNING"),
            ("low", "LOW", "NO KNOWN THREATS"),
        ]
        now = datetime.now(timezone.utc)
        checked_at = now.isoformat().replace("+00:00", "Z")
        valid_until = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        human_titles = {
            "known_dangerous": "Known Dangerous", "suspicious": "Be careful",
            "integrity_review": "Be careful", "inconclusive": "Can't tell",
            "transport_warning": "Be careful", "low": "Likely safe",
        }
        for code, level, label in cases:
            with self.subTest(code=code):
                overall = {
                    "code": code, "level": level, "label": label, "tone": "neutral",
                    "explanation": "Synthetic persisted deterministic evidence.",
                    "action": "Verify the address independently.",
                }
                reputation_status = "threat" if code == "known_dangerous" else "clear" if code in {"low", "transport_warning"} else "disabled"
                reputation = {"status": reputation_status}
                if reputation_status in {"threat", "clear"}:
                    reputation.update({"checked_at": checked_at, "verdict_expires_at": valid_until})
                metadata = {
                    "analysis_source": "qr", "offline_risk_label": "unverified",
                    "live_reputation": reputation, "overall_risk": overall,
                    "ml_status": "excluded",
                }
                record = SimpleNamespace(
                    id=991, scanned_at=None, decoded_content="https://example.test/",
                    final_url="https://example.test/", risk_label="safe", risk_score=None,
                    ml_phishing_probability=None, rule_score=0, score_explanation=json.dumps(metadata),
                    redirect_chain="[]", tampering_reasons="[]", tampering_score=0,
                    https_valid=1, domain_age_days=None, lookalike_brand=None,
                    lookalike_score=None, domain="example.test", risk_breakdown="[]",
                )
                with patch.object(self.fixture.main.SimpleDocTemplate, "build") as build:
                    self.fixture.main._build_report(record)
                story = build.call_args.args[0]
                self.assertEqual(story[0].getPlainText(), human_titles[code])
                self.assertEqual(story[1].getPlainText(), overall["action"])
                self.assertIn(overall["explanation"], self.fixture.main._report_summary(record, [], []))

    def test_expired_reputation_cannot_leave_a_stale_pdf_verdict(self):
        expired = {
            "status": "clear", "checked_at": "2020-01-01T00:00:00Z",
            "verdict_expires_at": "2020-01-01T00:30:00Z",
        }
        for code in ("known_dangerous", "low", "transport_warning"):
            with self.subTest(code=code):
                metadata = {"live_reputation": expired, "overall_risk": {
                    "code": code, "explanation": "Stale explanation", "action": "Stale action",
                }}
                risk = self.fixture.main._report_overall_risk(metadata)
                self.assertEqual(risk["code"], "inconclusive")
                self.assertIn("no longer current", risk["explanation"])

    def test_pdf_discloses_excluded_ml_and_escapes_stored_verdict_evidence(self):
        injection = "<script>alert(1)</script> & <tag>"
        metadata = {
            "analysis_source": "qr", "offline_risk_label": "unverified",
            "live_reputation": {"status": "disabled"},
            "overall_risk": {
                "code": "integrity_review", "explanation": injection,
                "action": "Review the QR image before proceeding.",
            },
            "ml_status": "excluded",
            "ml_note": "Experimental ML was excluded from this assessment.",
        }
        record = SimpleNamespace(
            id=991, scanned_at=None, decoded_content="https://example.test/",
            final_url="https://example.test/", risk_label="safe", risk_score=None,
            ml_phishing_probability=None, rule_score=0, score_explanation=json.dumps(metadata),
            redirect_chain="[]", tampering_reasons='["Synthetic integrity warning"]', tampering_score=35,
            https_valid=1, domain_age_days=None, lookalike_brand=None,
            lookalike_score=None, domain="example.test", risk_breakdown="[]",
        )
        with patch.object(self.fixture.main.SimpleDocTemplate, "build") as build:
            self.fixture.main._build_report(record)
        story = build.call_args.args[0]
        rendered = []

        def collect(item):
            if isinstance(item, (list, tuple)):
                for child in item:
                    collect(child)
            elif hasattr(item, "text"):
                rendered.append(item.text)
            elif hasattr(item, "_cellvalues"):
                collect(item._cellvalues)

        collect(story)
        output = "\n".join(rendered)
        self.assertEqual(story[0].getPlainText(), "Be careful")
        self.assertIn("Experimental ML status", output)
        self.assertIn("Not used", output)
        self.assertIn("It was not used for this assessment", output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)
        self.assertNotIn("<script>alert(1)</script>", output)
        summary = self.fixture.main._report_summary(record, [], ["Synthetic integrity warning"])
        self.assertIn("REVIEW REQUIRED", summary)
        self.assertIn("QR integrity warning", summary)


if __name__ == "__main__":
    unittest.main()
