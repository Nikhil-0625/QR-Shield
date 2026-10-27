"""Actual isolated ASGI routes, in-memory accounts and mocked registration data."""
from datetime import datetime, timedelta, timezone
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from PIL import Image
import rdap
import safe_browsing
import test_history_authorization as harness
import test_api_security as api_harness

URL = "https://www.wikipedia.org/"


class RdapIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("dotenv.load_dotenv",return_value=False):
            harness.HistoryAuthorizationTests.setUpClass.__func__(cls)
    @classmethod
    def tearDownClass(cls):cls.engine.dispose()
    setUp=harness.HistoryAuthorizationTests.setUp
    token=harness.HistoryAuthorizationTests.token
    api=api_harness.ApiSecurityTests.api

    def _probe_fixtures(self, url, allow_network=True):
        permitted = allow_network and not self.main.restricted_demo()
        status = "unavailable" if permitted else "blocked"
        details = {
            "status": status, "original_url": url, "final_url": url,
            "redirect_count": None, "observed_redirects": 0, "chain": [url], "hops": [],
            "final_response_status": None,
            "reason": "Network responses are not fixture data." if permitted else "Network checks are disabled for this offline or restricted request.",
        }
        return [url], details

    def _tls_fixture(self, url, allow_network=True, include_details=False):
        permitted = allow_network and not self.main.restricted_demo()
        scheme = url.split(":", 1)[0].lower()
        details = {
            "status": "not_applicable" if scheme == "http" else "unavailable" if permitted else "blocked",
            "valid": None,
            "reason": "No TLS result is fabricated in the offline test fixture." if permitted else "Network checks are disabled for this offline or restricted request.",
            "hostname": "wikipedia.org",
        }
        return details if include_details else details["valid"]

    def registration(self, age=1000):
        now=datetime.now(timezone.utc)
        return rdap._result("available","wikipedia.org","A matching registration event was observed.",
            registration_date=(now-timedelta(days=age)).isoformat(),domain_age_days=age,checked_at=now.isoformat())

    def reputation(self,status="clear"):
        now=datetime.now(timezone.utc)
        return safe_browsing._result(status,"Synthetic provider observation.",
            checked_at=now.isoformat(),verdict_expires_at=(now+timedelta(minutes=5)).isoformat(),
            threat_types=["SOCIAL_ENGINEERING"] if status=="threat" else [])

    def scan(self,url=URL,private=False,headers=(),ml=False):
        image=io.BytesIO();Image.new("RGB",(8,8),"white").save(image,format="PNG")
        body=b'--local\r\nContent-Disposition: form-data; name="file"; filename="test.png"\r\nContent-Type: image/png\r\n\r\n'+image.getvalue()+b'\r\n'
        if private:body+=b'--local\r\nContent-Disposition: form-data; name="private_scan"\r\n\r\ntrue\r\n'
        body+=b'--local--\r\n'
        with patch.dict(os.environ,{"QR_SCANNER_ML_ENABLED":"true" if ml else "false"}), \
             patch.object(self.main,"decode_qr",return_value=url), \
             patch.object(self.main,"analyze_tampering",return_value={"tampering_score":0,"tampering_reasons":[]}), \
             patch.object(self.main,"trace_redirects",side_effect=self._probe_fixtures), \
             patch.object(self.main,"check_https_valid",side_effect=self._tls_fixture):
            code,raw,_=self.api("/scan","POST",self.token("a@example.test"),body,
                [(b"content-type",b"multipart/form-data; boundary=local"),*headers])
        self.assertEqual(code,200,raw)
        return json.loads(raw)

    def website(self,url=URL,headers=()):
        with patch.object(self.main,"trace_redirects",side_effect=self._probe_fixtures), \
             patch.object(self.main,"check_https_valid",side_effect=self._tls_fixture):
            code,raw,_=self.api("/website/check","POST",self.token("a@example.test"),
                json.dumps({"url":url}).encode(),[(b"content-type",b"application/json"),*headers])
        self.assertEqual(code,200,raw)
        return json.loads(raw)

    def test_same_url_uses_same_registration_and_rule_semantics(self):
        with patch.object(self.main.registration_client,"lookup",return_value=self.registration(10)), \
             patch.object(self.main.reputation_client,"lookup",return_value=self.reputation()):
            qr=self.scan();website=self.website()
        for data in (qr,website):
            self.assertEqual(data["domain_age_days"],10)
            self.assertEqual(data["domain_registration"]["status"],"available")
            self.assertEqual(data["domain_registration_status"],"available")
            self.assertEqual(data["https_check_status"],"unavailable")
            self.assertEqual(data["redirect_check_status"],"unavailable")
            self.assertIsNone(data["redirect_count"])
            self.assertEqual(data["rule_score"],20) # Existing new-domain rule, unchanged.
            self.assertIn("Newly Registered Domain",{x["name"] for x in data["risk_breakdown"]})
            self.assertIsNone(data["risk_score"])
            self.assertEqual(data["risk_score_status"],"unavailable")
            self.assertEqual(data["website_verdict"]["code"],"suspicious")
        self.assertEqual(qr["risk_breakdown"],website["risk_breakdown"])

    def test_missing_registration_does_not_invent_score_or_pass_network_checks(self):
        missing=rdap._result("unavailable","wikipedia.org","No reliable registration date.")
        with patch.object(self.main.registration_client,"lookup",return_value=missing), \
             patch.object(self.main.reputation_client,"lookup",return_value=self.reputation()):
            data=self.website()
        self.assertIsNone(data["domain_age_days"]);self.assertIsNone(data["risk_score"])
        self.assertEqual(data["rule_score"],0)
        self.assertIn("ML is excluded",data["risk_score_reason"])
        self.assertIn("Domain registration / RDAP",data["unavailable_checks"])
        self.assertIn("TLS certificate verification",data["unavailable_checks"])
        self.assertIsNone(data["https_valid"])
        self.assertEqual(data["redirect_check_status"],"unavailable")
        self.assertEqual(data["website_verdict"]["code"],"no_known_threats")
        self.assertIn("does not",data["website_verdict"]["explanation"])

    def test_known_threat_wins_with_old_domain_and_low_legacy_score(self):
        model=SimpleNamespace(classes_=[-1,1],predict_proba=Mock(return_value=[[0.01,0.99]]))
        with patch.object(self.main.registration_client,"lookup",return_value=self.registration()), \
             patch.object(self.main.reputation_client,"lookup",return_value=self.reputation("threat")), \
             patch.object(self.main,"ml_model",model):
            qr=self.scan(ml=True);website=self.website()
        self.assertEqual(qr["risk_score"],0) # round(0.7*0 + 0.3*1), existing formula.
        self.assertEqual(qr["risk_score_status"],"available")
        for data in (qr,website):self.assertEqual(data["website_verdict"]["code"],"known_dangerous")
        self.assertIsNone(website["risk_score"])

    def test_private_scan_retains_observation_without_saving_row(self):
        with self.database.SessionLocal() as db:before=db.query(self.database.ScanRecord).count()
        with patch.object(self.main.registration_client,"lookup",return_value=self.registration()), \
             patch.object(self.main.reputation_client,"lookup",return_value=self.reputation()):
            data=self.scan(private=True)
        self.assertIsNone(data["scan_id"]);self.assertEqual(data["domain_age_days"],1000)
        with self.database.SessionLocal() as db:self.assertEqual(db.query(self.database.ScanRecord).count(),before)

    def test_public_offline_header_disables_registration_even_if_enabled(self):
        with patch.dict(os.environ,{"RDAP_ENABLED":"true"}), \
             patch.object(self.main.registration_client,"lookup",side_effect=AssertionError("RDAP forbidden")) as lookup, \
             patch.object(self.main.reputation_client,"lookup",side_effect=AssertionError("Reputation forbidden")):
            for result in (self.scan(headers=[(b"x-qr-shield-offline",b"1")]),self.website(headers=[(b"x-qr-shield-offline",b"1")])):
                self.assertEqual(result["domain_registration"]["status"],"disabled")
                self.assertIsNone(result["domain_age_days"])
        lookup.assert_not_called()

    def test_restricted_mode_overrides_rdap_and_does_not_resolve_or_fetch(self):
        with patch.dict(os.environ,{"RDAP_ENABLED":"true","QR_SHIELD_MODE":"restricted-demo"}), \
             patch.object(rdap,"_fetch_json",side_effect=AssertionError("RDAP network forbidden")) as request, \
             patch.object(rdap.socket,"getaddrinfo",side_effect=AssertionError("DNS forbidden")), \
             patch.object(self.main.reputation_client,"lookup",return_value=safe_browsing._result("disabled","Restricted offline demo")):
            qr=self.scan();website=self.website()
        request.assert_not_called()
        for data in (qr,website):
            self.assertEqual(data["domain_registration"]["status"],"disabled")
            self.assertIsNone(data["domain_age_days"])

    def test_non_url_and_upi_never_reach_registration_or_reputation(self):
        with patch.object(self.main.registration_client,"lookup",side_effect=AssertionError("No URL")) as lookup, \
             patch.object(self.main.reputation_client,"lookup",side_effect=AssertionError("No URL")):
            text=self.scan("Synthetic text");upi=self.scan("upi://pay?pa=demo@upi&pn=Demo")
        lookup.assert_not_called()
        self.assertNotIn("domain_registration",text);self.assertNotIn("risk_score",upi)
        self.assertIn("upi_analysis",upi);self.assertIn("upi_comparison",upi)

    def test_metadata_persistence_pdf_isolation_and_no_requery(self):
        with patch.object(self.main.registration_client,"lookup",return_value=self.registration()), \
             patch.object(self.main.reputation_client,"lookup",return_value=self.reputation()):
            data=self.website()
        with self.database.SessionLocal() as db:
            record=db.query(self.database.ScanRecord).filter_by(id=data["scan_id"]).one()
            metadata=json.loads(record.score_explanation)
            self.assertEqual(metadata["domain_registration"]["status"],"available")
            self.assertEqual(metadata["risk_score_status"],"unavailable")
            self.assertEqual(record.user_id,1)
        with patch.object(self.main.registration_client,"lookup",side_effect=AssertionError("No report lookup")), \
             patch.object(self.main.reputation_client,"lookup",side_effect=AssertionError("No report lookup")):
            code,body,_=self.api("/report/"+str(data["scan_id"]),token=self.token("a@example.test"))
            self.assertEqual(code,200);self.assertTrue(body.startswith(b"%PDF"))
            code,_,_=self.api("/report/"+str(data["scan_id"]),token=self.token("b@example.test"))
            self.assertEqual(code,404)

    def test_pdf_registration_and_scoring_values_are_xml_escaped(self):
        injection="<script>alert(1)</script> & <tag>"
        record=self.database.ScanRecord(id=999,user_id=1,decoded_content=URL,final_url=URL,domain="wikipedia.org",
            risk_label="unverified",risk_score=None,domain_age_days=42,redirect_chain=json.dumps([URL]),risk_breakdown="[]",
            tampering_reasons="[]",score_explanation=json.dumps({"analysis_source":"website","ml_status":"excluded",
                "risk_score_status":"unavailable","rule_score":0,"risk_score_reason":injection,
                "domain_registration":{**self.registration(42),"registration_date":injection,"reason":injection}}))
        self.assertTrue(self.main._build_report(record).getvalue().startswith(b"%PDF"))
        with patch.object(self.main.SimpleDocTemplate,"build") as build:self.main._build_report(record)
        self.assertTrue(any("Optional RDAP registration status is reported separately" in str(getattr(item,"text","")) for item in build.call_args.args[0]))
        tables=[item for item in build.call_args.args[0] if hasattr(item,"_cellvalues")]
        texts=[cell.text for table in tables for row in table._cellvalues for cell in row if hasattr(cell,"text")]
        self.assertTrue(any("&lt;script&gt;" in value for value in texts))
        self.assertFalse(any("<script>" in value for value in texts))
        self.assertTrue(any("Domain Information" in value for value in texts))


if __name__=="__main__":unittest.main()
