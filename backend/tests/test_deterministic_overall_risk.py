"""Deterministic classification tests; no URL or external service is contacted."""
from datetime import datetime, timedelta, timezone
import unittest

from safe_browsing import _result, deterministic_overall_risk


def reputation(status):
    now = datetime.now(timezone.utc)
    return _result(
        status,
        "Synthetic Safe Browsing result.",
        checked_at=now.isoformat().replace("+00:00", "Z"),
        verdict_expires_at=(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        threat_types=["SOCIAL_ENGINEERING"] if status == "threat" else [],
    )


class DeterministicOverallRiskTests(unittest.TestCase):
    def classify(self, *, status="clear", label="unverified", unavailable=("ML verdict",),
                 findings=(), tampering=False):
        return deterministic_overall_risk(label, reputation(status), list(unavailable),
                                          list(findings), tampering)

    def test_completed_clean_deterministic_evidence_is_low_without_ml(self):
        result = self.classify()
        self.assertEqual((result["code"], result["level"], result["label"]),
                         ("low", "LOW", "NO KNOWN THREATS"))
        self.assertIn("does not guarantee safety", result["explanation"])

    def test_confirmed_safe_browsing_threat_is_high(self):
        result = self.classify(status="threat", unavailable=("TLS certificate verification",))
        self.assertEqual((result["code"], result["level"]), ("known_dangerous", "HIGH"))

    def test_rule_findings_are_suspicious_even_if_optional_checks_are_missing(self):
        findings = [
            {"category": "phishing", "name": "Possible Brand Impersonation"},
            {"category": "phishing", "name": "Sensitive Action Pattern"},
        ]
        result = self.classify(label="suspicious", status="unavailable",
                               unavailable=("Live reputation",), findings=findings)
        self.assertEqual((result["code"], result["level"]), ("suspicious", "MEDIUM"))

    def test_genuinely_unavailable_evidence_is_inconclusive_not_low(self):
        result = self.classify(status="disabled", unavailable=(
            "TLS certificate verification", "Redirect destination", "Domain registration / RDAP", "Live reputation", "ML verdict"))
        self.assertEqual((result["code"], result["level"]), ("inconclusive", "INCONCLUSIVE"))

    def test_ml_unavailable_alone_does_not_block_deterministic_low_result(self):
        result = self.classify(unavailable=("ML verdict",))
        self.assertEqual(result["code"], "low")

    def test_qr_integrity_warning_is_review_required(self):
        result = self.classify(tampering=True)
        self.assertEqual((result["code"], result["level"]), ("integrity_review", "REVIEW REQUIRED"))
        self.assertIn("QR image", result["explanation"])

    def test_incomplete_rule_data_is_not_low(self):
        result = deterministic_overall_risk("unverified", reputation("clear"), [], None)
        self.assertEqual(result["code"], "inconclusive")

    def test_transport_only_warning_is_not_low_or_phishing(self):
        result = self.classify(findings=[{"category": "transport", "name": "HTTP Connection"}])
        self.assertEqual(result["code"], "transport_warning")
        self.assertIn("not proof of phishing", result["explanation"])


if __name__ == "__main__":
    unittest.main()
