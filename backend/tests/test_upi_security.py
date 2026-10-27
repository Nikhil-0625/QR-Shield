"""Phase D: synthetic offline UPI analysis, isolated scan integration and PDFs."""
import unittest
import json
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from upi_security import analyze_upi
import test_upi_substitution as harness


class UpiSecurityTests(unittest.TestCase):
    def analyze(self, **values):
        return analyze_upi("upi://pay?" + urlencode({"pa": "merchant@upi", "cu": "INR", **values}))

    def codes(self, result):
        return {item["code"] for item in result["warnings"]}

    def test_valid_payment_direction_and_no_identity_claim(self):
        result = self.analyze(pn="Synthetic Store", am="250.00", tn="Lunch", tr="SYNTHETIC-001")
        self.assertEqual(result["payment_direction"], "send_money")
        self.assertEqual(result["warnings"], [])
        self.assertFalse(result["identity_verified"])
        self.assertEqual(result["fields"]["amount"]["value"], "250.00")
        self.assertIn("Scanning alone does not send money", result["payment_explanation"])
        self.assertIn("Receiving an ordinary UPI transfer", " ".join(result["safety_notes"]))
        self.assertIn("not proof of fraud", result["warning_context"])

    def test_missing_optional_fields_are_not_invented(self):
        result = analyze_upi("upi://pay?pa=merchant@upi")
        for key in ["payee_name", "amount", "currency", "transaction_note", "transaction_reference"]:
            self.assertEqual(result["fields"][key], {"value": None, "status": "missing"})
        self.assertIn("missing_currency", self.codes(result))
        self.assertNotIn("invalid_amount", self.codes(result))

    def test_missing_and_invalid_payee(self):
        for value, code in [("", "missing_payee"), ("not-an-id", "invalid_payee"), ("<img src=x>", "invalid_payee")]:
            result = self.analyze(pa=value)
            self.assertIn(code, self.codes(result))
            self.assertFalse(result["parameters_reliable"])

    def test_amounts_are_decimal_safe_and_never_rounded(self):
        for value in ["0", "0.00", "-1", "-0.01", "bad", "NaN", "Infinity", "1e2", "1_000", "1.001", "1.000", "+10", " 10 ", ".5", "10."]:
            with self.subTest(value=value):
                result = self.analyze(am=value)
                self.assertIn("invalid_amount", self.codes(result))
                self.assertEqual(result["fields"]["amount"]["value"], value)
        for value in ["0.01", "250.00", "9007199254740993.01", "00025.00", "9" * 100]:
            result = self.analyze(am=value)
            self.assertNotIn("invalid_amount", self.codes(result))
            self.assertEqual(result["fields"]["amount"]["value"], value)

    def test_currency_is_explicit(self):
        for value in ["USD", "inr", " INR ", "<script>"]:
            self.assertIn("unexpected_currency", self.codes(self.analyze(cu=value)))

    def test_duplicate_and_conflicting_values(self):
        same = analyze_upi("upi://pay?pa=merchant@upi&PA=merchant%40upi&am=10&am=10&cu=INR")
        self.assertIn("duplicate_parameters", self.codes(same))
        self.assertNotIn("conflicting_parameters", self.codes(same))
        for suffix in ["&pa=other@upi", "&am=20", "&cu=USD", "&pn=Other"]:
            result = analyze_upi("upi://pay?pa=merchant@upi&pn=Store&am=10&cu=INR" + suffix)
            self.assertIn("conflicting_parameters", self.codes(result))
            self.assertFalse(result["parameters_reliable"])

    def test_malformed_encoding_structure_and_bounds(self):
        for uri, code in [
            ("upi://pay?pa=merchant@upi&tn=%ZZ", "invalid_encoding"),
            ("upi://pay?pa=merchant@upi&tn=%FF", "invalid_parameters"),
            ("upi://pay?pa=merchant@upi&tn", "invalid_parameters"),
            ("upi://pay?pa=merchant@upi&tn=%00", "malformed_value"),
            ("upi://pay?pa=merchant@upi&tn=" + "a" * 1025, "malformed_value"),
            ("upi://pay?" + "x=1&" * 129, "invalid_parameters"),
            ("upi://other?pa=merchant@upi", "invalid_structure"),
            ("upi://pay/path?pa=merchant@upi", "invalid_structure"),
            ("upi://pay?pa=merchant@upi#hidden", "invalid_structure"),
            ("upi://user@pay?pa=merchant@upi", "invalid_structure"),
            ("upi://[broken", "invalid_structure"),
            ("upi://pay?tn=" + "x" * 17000, "oversized_payload"),
        ]:
            with self.subTest(code=code):
                result = analyze_upi(uri)
                self.assertIn(code, self.codes(result))
                self.assertFalse(result["parameters_reliable"])

    def test_contextual_language_warnings(self):
        for note, expected in [
            ("Pay to receive refund", {"refund_language", "pay_to_receive"}),
            ("Refund verification", {"refund_language"}),
            ("Cashback verification charge", {"cashback_language"}),
            ("Cashback collection", {"cashback_language"}),
            ("Prize collection fee", {"prize_language"}),
            ("Account activation payment", {"activation_language"}),
            ("Pay for account activation", {"activation_language"}),
            ("KYC verification fee", {"kyc_language"}),
            ("Payment to receive money", {"pay_to_receive"}),
        ]:
            with self.subTest(note=note):
                self.assertTrue(expected <= self.codes(self.analyze(tn=note)))
        # Repeated notes are all examined, not only the first encoded value.
        result = analyze_upi("upi://pay?pa=merchant@upi&cu=INR&tn=Lunch&tn=Prize%20collection%20fee")
        self.assertIn("prize_language", self.codes(result))

    def test_benign_notes_and_non_upi_content(self):
        for note in ["Refund for returned item", "Cashback", "KYC", "Lunch payment", "Service account", "25% discount"]:
            self.assertEqual(self.analyze(tn=note)["warnings"], [], note)
        self.assertIsNone(analyze_upi("https://example.test/?tn=Pay+to+receive+refund"))
        self.assertIsNone(analyze_upi("ordinary text"))
        # Do not treat unsupported structures as supported payment instructions.
        result = analyze_upi("upi://other?tn=Prize%20collection%20fee")
        self.assertNotIn("prize_language", self.codes(result))


class UpiIntegrationTests(unittest.TestCase):
    setUpClass = classmethod(harness.UpiSubstitutionTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.UpiSubstitutionTests.tearDownClass.__func__)
    setUp = harness.UpiSubstitutionTests.setUp
    scan = harness.UpiSubstitutionTests.scan
    synthetic_image = staticmethod(harness.UpiSubstitutionTests.synthetic_image)
    request = harness.authorization_harness.HistoryAuthorizationTests.request
    token = harness.authorization_harness.HistoryAuthorizationTests.token

    def test_upi_pdf_download_and_history_remain_owner_scoped(self):
        result = self.scan("upi://pay?pa=merchant@upi&am=250.00&cu=INR&tn=Cashback%20verification%20charge")
        report_path = "/report/" + str(result["scan_id"])
        status, body = self.request(report_path, self.token("a@example.test"))
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"%PDF"))
        self.assertEqual(self.request(report_path, self.token("b@example.test"))[0], 404)
        self.assertIn(self.request(report_path)[0], (401, 403))
        status, history = self.request("/history", self.token("b@example.test"))
        self.assertEqual(status, 200)
        self.assertNotIn(result["scan_id"], [row["id"] for row in json.loads(history)])

    def test_scan_is_additive_and_no_model_or_network_calls(self):
        with patch.object(self.main, "ml_model", Mock(predict_proba=Mock(side_effect=AssertionError("No URL ML for UPI")))), \
             patch.object(self.main.requests, "get", side_effect=AssertionError("No HTTP")), \
             patch.object(self.main.socket, "getaddrinfo", side_effect=AssertionError("No DNS")), \
             patch.object(self.main.whois, "whois", side_effect=AssertionError("No WHOIS")):
            result = self.scan("upi://pay?pa=merchant@upi&am=10.001&tn=Prize%20collection%20fee&cu=INR", "merchant@upi")
        self.assertEqual(result["upi_comparison"]["status"], "match")
        self.assertTrue(result["upi_details"]["amount_valid"])  # legacy numeric field unchanged
        self.assertIn("invalid_amount", {w["code"] for w in result["upi_analysis"]["warnings"]})
        self.assertNotIn("risk_score", result)
        self.assertNotIn("ml_phishing_probability", result)

    def test_unsupported_upi_is_not_silently_ordinary_text(self):
        result = self.scan("upi://other?pa=merchant@upi")
        self.assertNotIn("upi_details", result)  # legacy compatibility
        self.assertEqual(result["upi_analysis"]["content_type"], "malformed_upi")

    def test_upi_report_content_escaping_and_long_values(self):
        for payload in ["upi://pay?pa=merchant@upi&pn=Synthetic&am=250.00&cu=INR&tn=Pay%20to%20receive%20refund&tr=SYNTHETIC",
                        "upi://pay?pa=merchant@upi&tn=" + "%3Cimg%3E" * 1400,
                        "upi://pay?pa=merchant@upi&tn=" + "%0A" * 1500,
                        "upi://other?tn=%FF"]:
            result = self.scan(payload)
            db = self.database.SessionLocal()
            try:
                record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).first()
                original_table = self.main._report_table
                captured = []
                def capture(title, rows, styles):
                    captured.extend(str(label) + " " + str(value) for label, value in rows)
                    return original_table(title, rows, styles)
                paragraph = self.main.Paragraph
                with patch.object(self.main, "_report_table", side_effect=capture), \
                     patch.object(self.main, "Paragraph", side_effect=paragraph) as paragraphs:
                    pdf = self.main._build_report(record).getvalue()
                self.assertTrue(pdf.startswith(b"%PDF"))
                self.assertIn("Payment direction", " ".join(captured))
                rendered_text = " ".join(str(call.args[0]) for call in paragraphs.call_args_list)
                self.assertIn("recipient unverified", rendered_text)
                self.assertIn("not independently verified", rendered_text)
                self.assertIn("not proof of fraud", rendered_text)
                for warning in analyze_upi(payload)["warnings"]:
                    self.assertIn(warning["message"], rendered_text)
                self.assertNotIn("<img>", rendered_text)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
