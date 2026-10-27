"""Restricted-mode routes using memory SQLite, synthetic QR images and stub ML."""
import json
import os
import sys
import unittest
from unittest.mock import patch
from test_demo_security import ENV, BASIC
from test_url_detection import UrlDetectionTests
from demo_security import DemoBoundary


class RestrictedIntegrationTests(unittest.TestCase):
    setUpClass = classmethod(UrlDetectionTests.setUpClass.__func__)
    tearDownClass = classmethod(UrlDetectionTests.tearDownClass.__func__)
    setUp = UrlDetectionTests.setUp
    token = UrlDetectionTests.token
    api = UrlDetectionTests.api
    scan = UrlDetectionTests.scan

    def test_offline_scan_real_qr_decode_score_and_report(self):
        with patch.dict(os.environ, ENV), patch.object(self.main.socket,"getaddrinfo",side_effect=AssertionError("No DNS")) as dns:
            for url in ("https://www.wikipedia.org/", "http://paypal-login.example.com/verify", "http://127.0.0.1/", "http://169.254.169.254/"):
                result=self.scan(url,probability=.8,real_decode=True)
                self.assertIn("Restricted demo",result["network_analysis"])
                self.assertIsNone(result["https_valid"])
                self.assertAlmostEqual(result["score_explanation"]["ml_weight"],.3)
                self.assertAlmostEqual(result["score_explanation"]["rule_weight"],.7)
                self.assertEqual(result["risk_score"],round(.7*result["rule_score"]+24))
                code,body,headers=self.api("/report/"+str(result["scan_id"]),token=self.token("a@example.test"))
                self.assertEqual(code,200)
                self.assertTrue(body.startswith(b"%PDF"))
                self.assertEqual(headers[b"content-type"],b"application/pdf")
            dns.assert_not_called()
            self.assertEqual(self.main.trace_redirects("https://synthetic.example/")[0],["https://synthetic.example/"])
            self.assertFalse(self.main.validate_outbound_url("https://synthetic.example/")[0])

    def test_same_origin_factory_asset_allowlist_and_gate(self):
        from demo_app import create_app
        with patch.dict(os.environ,{**ENV,"JWT_SECRET_KEY":"synthetic-jwt-key-for-demo-tests-123456789","CORS_ALLOWED_ORIGINS":ENV["PUBLIC_ORIGIN"]}), patch.dict(sys.modules,{"main":self.main}):
            app=create_app()
            original=self.main.app
            self.main.app=app
            try:
                headers=[(b"host",b"demo.example"),(b"authorization",BASIC)]
                for path in ("/backend/main.py","/.env","/../backend/main.py","/experimental-warning.html","/tests/example.py"):
                    self.assertEqual(self.api(path,headers=headers)[0],404)
                for page in ("login.html","scan.html","dashboard.html","generate.html"):
                    code,body,_=self.api("/"+page,headers=headers)
                    self.assertEqual(code,200)
                    if page=="scan.html": self.assertIn(b"Restricted offline college demo",body)
                self.assertEqual(self.api("/api/register","POST",headers=headers)[0],403)
                self.assertEqual(self.api("/scan.html",headers=[(b"host",b"demo.example")])[0],401)
                # Gate cookie and application JWT are both necessary for private data.
                cookie=b"qr_demo_access="+app.cookie_value().encode()
                jwt_headers=[(b"host",b"demo.example"),(b"cookie",cookie)]
                code,body,_=self.api("/api/history",token=self.token("a@example.test"),headers=jwt_headers)
                self.assertEqual(code,200)
                self.assertEqual([r["id"] for r in json.loads(body)],[11])
                self.assertEqual(self.api("/api/report/22",token=self.token("a@example.test"),headers=jwt_headers)[0],404)
            finally: self.main.app=original

    def test_validation_error_omits_submitted_input(self):
        code,body,_=self.api("/login","POST",body=b'{"password":"sensitive-synthetic-input"}',headers=[(b"content-type",b"application/json")])
        self.assertEqual(code,422)
        self.assertNotIn(b"sensitive-synthetic-input",body)
        self.assertNotIn(b'"input"',body)

    def test_offline_helpers_never_invoke_network_libraries(self):
        with patch.dict(os.environ,ENV), patch.object(self.main.socket,"getaddrinfo") as dns, patch.object(self.main.requests,"get") as http, patch.object(self.main.whois,"whois") as whois:
            for url in ("https://wikipedia.org/","http://127.0.0.1/","http://169.254.169.254/","https://redirect.example/"):
                self.assertFalse(self.main.validate_outbound_url(url)[0])
                self.assertEqual(self.main.trace_redirects(url)[0],[url])
                self.assertIsNone(self.main.check_https_valid(url))
            self.assertIsNone(self.main.get_domain_age_days("wikipedia.org"))
            dns.assert_not_called()
            http.assert_not_called()
            whois.assert_not_called()

    def test_restricted_precreated_login_and_storage_quota(self):
        with self.database.SessionLocal() as db:
            user=db.query(self.database.User).filter_by(id=1).one()
            user.hashed_password=self.main.hash_password("Synthetic!Demo123")
            db.commit()
        with patch.dict(os.environ,ENV):
            code,body,_=self.api("/login","POST",body=b'{"email":"a@example.test","password":"Synthetic!Demo123"}',headers=[(b"content-type",b"application/json")])
            self.assertEqual(code,200)
            self.assertIn("access_token",json.loads(body))
            self.assertEqual(self.api("/register","POST",body=b'{"email":"new@example.test","password":"Synthetic!Demo123"}',headers=[(b"content-type",b"application/json")])[0],403)
            with self.database.SessionLocal() as db:
                db.add_all([self.database.ScanRecord(user_id=1,decoded_content="synthetic quota") for _ in range(199)])
                db.commit()
            with self.assertRaises(Exception) as error:
                self.main._analyze_scan(b"", "a@example.test", None)
            self.assertEqual(error.exception.status_code,429)
