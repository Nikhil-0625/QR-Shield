"""Website checker security/regression tests: memory SQLite and synthetic inputs only.

The shared authorization harness replaces the database engine and model loader
before main.py is imported. Submitted destinations are never contacted.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_api_security as api_harness
import test_history_authorization as auth_harness
import test_url_detection as url_harness


_DEFAULT_TOKEN = object()


class WebsiteCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("dotenv.load_dotenv", return_value=False), patch.dict(
            os.environ, {"QR_SHIELD_MODE": "development"}
        ):
            auth_harness.HistoryAuthorizationTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    token = auth_harness.HistoryAuthorizationTests.token
    snapshot = auth_harness.HistoryAuthorizationTests.snapshot
    api = api_harness.ApiSecurityTests.api
    scan = url_harness.UrlDetectionTests.scan

    def setUp(self):
        auth_harness.HistoryAuthorizationTests.setUp(self)
        # Each test starts fresh middleware rate buckets; limits remain enabled.
        self.main.app.middleware_stack = None
        guards = ExitStack()
        self.addCleanup(guards.close)
        guards.enter_context(patch.dict(os.environ, {"QR_SHIELD_MODE": "development"}))
        def redirect_fixture(url, max_hops=5, allow_network=True):
            permitted = allow_network and not self.main.restricted_demo()
            status = "unavailable" if permitted else "blocked"
            return [url], {
                "status": status, "original_url": url, "final_url": url,
                "redirect_count": None,
                "observed_redirects": 0, "chain": [url], "hops": [],
                "final_response_status": None,
                "reason": "Network responses are not fixture data." if permitted else "Network checks are disabled for this offline or restricted request.",
            }
        def tls_fixture(url, allow_network=True, include_details=False):
            permitted = allow_network and not self.main.restricted_demo()
            scheme = url.split(":", 1)[0].lower()
            details = {
                "status": "not_applicable" if scheme == "http" else "unavailable" if permitted else "blocked",
                "valid": None,
                "reason": "No TLS result is fabricated in the offline test fixture." if permitted else "Network checks are disabled for this offline or restricted request.",
                "hostname": "www.wikipedia.org",
            }
            return details if include_details else details["valid"]
        guards.enter_context(patch.object(self.main, "trace_redirects", side_effect=redirect_fixture))
        guards.enter_context(patch.object(self.main, "check_https_valid", side_effect=tls_fixture))
        self.dns = guards.enter_context(patch.object(
            self.main.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")
        ))
        self.http = guards.enter_context(patch.object(
            self.main.requests, "get", side_effect=AssertionError("HTTP forbidden")
        ))
        self.whois = guards.enter_context(patch.object(
            self.main.whois, "whois", side_effect=AssertionError("WHOIS forbidden")
        ))
        self.model = SimpleNamespace(
            classes_=[-1, 1],
            predict_proba=Mock(side_effect=AssertionError("Website ML must be excluded")),
        )
        guards.enter_context(patch.object(self.main, "ml_model", self.model))

    def check(self, value="https://www.wikipedia.org/", *, token=_DEFAULT_TOKEN, payload=None):
        if token is _DEFAULT_TOKEN:
            token = self.token("a@example.test")
        if payload is None:
            payload = {"url": value}
        code, raw, headers = self.api(
            "/website/check", "POST", token, json.dumps(payload).encode(),
            [(b"content-type", b"application/json")],
        )
        return code, json.loads(raw), headers

    def assert_offline(self):
        self.dns.assert_not_called()
        self.http.assert_not_called()
        self.whois.assert_not_called()
        self.model.predict_proba.assert_not_called()

    def test_checker_copy_describes_bounded_checks_without_claiming_no_visit(self):
        page = Path(__file__).resolve().parents[2] / "frontend" / "website-checker.html"
        source = page.read_text(encoding="utf-8")
        self.assertIn("does not open the page or download its body", source)
        self.assertIn("bounded redirect response headers", source)
        self.assertIn("Google Safe Browsing receives the full URL", source)
        self.assertIn("RDAP receives only the registered domain", source)
        self.assertNotIn("website is never visited or fetched", source)

    def test_ordinary_https_remains_unverified_without_fabricated_hybrid_score(self):
        code, result, headers = self.check()
        self.assertEqual(code, 200, result)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["analysis_source"], "website")
        self.assertEqual(result["normalized_url"], "https://www.wikipedia.org/")
        self.assertEqual(result["risk_label"], "unverified")
        self.assertEqual(result["overall_risk"]["code"], "inconclusive")
        self.assertEqual(result["rule_score"], 0)
        self.assertEqual(result["risk_breakdown"], [])
        self.assertIsNone(result["risk_score"])
        self.assertIsNone(result["ml_phishing_probability"])
        self.assertEqual(result["ml_status"], "excluded")
        self.assertTrue(result["ml_note"])
        self.assertFalse(result["final_url_verified"])
        self.assertEqual(result["redirect_check_status"], "unavailable")
        self.assertIsNone(result["domain_age_days"])
        self.assertIsNone(result["https_valid"])
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assert_offline()

    def test_existing_rule_engine_flags_reserved_brand_impersonation_example(self):
        url = "http://paypal-login.example.com/verify"
        code, result, _ = self.check(url)
        self.assertEqual(code, 200, result)
        self.assertEqual(result["risk_label"], "suspicious")
        self.assertEqual(result["overall_risk"]["code"], "suspicious")
        self.assertEqual(result["overall_risk"]["level"], "MEDIUM")
        self.assertEqual(result["lookalike_brand"], "PayPal")
        self.assertEqual(result["registered_domain"], "example.com")
        findings = {item["name"]: item for item in result["risk_breakdown"]}
        self.assertIn("HTTP Connection", findings)
        self.assertIn("Possible Brand Impersonation", findings)
        self.assertIn("Sensitive Action Pattern", findings)
        self.assertIn("example.com", findings["Possible Brand Impersonation"]["reason"])
        self.assertIn("indicator", findings["Possible Brand Impersonation"]["reason"])
        self.assertEqual(result["rule_score"], sum(item["points"] for item in findings.values()))
        self.assertIsNone(result["risk_score"])
        self.assert_offline()

    def test_qr_and_website_share_exact_rule_findings_for_same_urls(self):
        for url in (
            "https://www.wikipedia.org/",
            "http://paypal-login.example.com/verify",
            "https://paypa1.example/verify",
            "https://paypal.com.example.com/login",
            "http://8.8.8.8/verify",
        ):
            with self.subTest(url=url):
                with patch.dict(os.environ, {"QR_SCANNER_ML_ENABLED": "true"}):
                    qr = self.scan(url, probability=.5)
                code, website, _ = self.check(url)
                self.assertEqual(code, 200, website)
                for field in ("rule_score", "risk_breakdown", "lookalike_brand", "registered_domain", "domain"):
                    self.assertEqual(website[field], qr[field], field)
                self.assertEqual(qr["risk_score"], min(round(.7 * qr["rule_score"] + 15), 100))
                self.assertEqual(qr["score_explanation"]["ml_weight"], .3)
                self.assertEqual(qr["score_explanation"]["rule_weight"], .7)
                self.assertIsNone(website["risk_score"])
                self.assertEqual(qr["overall_risk"], website["overall_risk"])
        self.assert_offline()

    def test_missing_scheme_and_surrounding_space_normalize_without_visiting(self):
        code, result, _ = self.check("  www.wikipedia.org/  ")
        self.assertEqual(code, 200, result)
        self.assertEqual(result["normalized_url"], "https://www.wikipedia.org/")
        self.assertEqual(result["final_url"], result["normalized_url"])
        self.assertEqual(result["redirect_chain"], [result["normalized_url"]])
        self.assert_offline()

    def test_explicit_http_is_not_silently_upgraded(self):
        url = "http://ordinary.example/"
        code, result, _ = self.check(url)
        self.assertEqual(code, 200, result)
        self.assertEqual(result["normalized_url"], url)
        self.assertEqual(result["https_check_status"], "not_applicable")
        self.assertIn("HTTP Connection", {item["name"] for item in result["risk_breakdown"]})
        self.assert_offline()

    def test_private_local_metadata_multicast_and_reserved_targets_rejected(self):
        before = self.snapshot()
        for url in (
            "http://localhost/", "http://localhost./", "http://service.localhost/",
            "http://router.local/", "http://metadata.google.internal/",
            "http://127.0.0.1/", "http://127.1.2.3/", "http://10.0.0.1/",
            "http://172.16.0.1/", "http://192.168.0.1/", "http://169.254.169.254/",
            "http://100.64.0.1/", "http://0.0.0.0/", "http://224.0.0.1/",
            "http://192.0.2.1/", "http://[::1]/", "http://[::]/",
            "http://[::ffff:127.0.0.1]/", "http://[fd00::1]/", "http://[fe80::1]/",
            "http://[ff02::1]/", "http://[2001:db8::1]/",
            "http://2130706433/", "http://0177.0.0.1/", "http://0x7f000001/",
        ):
            with self.subTest(url=url):
                code, _, _ = self.check(url)
                self.assertEqual(code, 400)
        self.assertEqual(self.snapshot(), before)
        self.assert_offline()

    def test_public_ip_is_an_offline_warning_not_an_outbound_request(self):
        code, result, _ = self.check("http://8.8.8.8/verify")
        self.assertEqual(code, 200, result)
        self.assertEqual(result["risk_label"], "suspicious")
        self.assertIn("IP Address URL", {item["name"] for item in result["risk_breakdown"]})
        self.assert_offline()

    def test_unsupported_schemes_credentials_and_malformed_urls_rejected(self):
        before = self.snapshot()
        for url in (
            "", "   ", "not a website", "https://", "https://[broken/",
            "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd", "ftp://example.com/", "upi://pay?pa=test@upi",
            "https://user:password@example.com/", "https://google.com@evil.example/",
            "https://a..example/", "https://example.com/%ZZ", "https://example.com:bad/",
            "https://example.com/\nsecret", "https://example.com/\\private",
            "https://%65xample.com/", "https://" + "a." * 33 + "example/",
        ):
            with self.subTest(url=url):
                code, _, _ = self.check(url)
                self.assertIn(code, (400, 422))
        self.assertEqual(self.snapshot(), before)
        self.assert_offline()

    def test_url_length_and_request_body_limits_before_analysis(self):
        before = self.snapshot()
        code, _, _ = self.check("https://example.com/" + "a" * 8192)
        self.assertEqual(code, 413)
        code, _, _ = self.check("https://example.com/" + "a" * 20000)
        self.assertEqual(code, 413)
        self.assertEqual(self.snapshot(), before)
        self.assert_offline()

    def test_malformed_json_missing_and_wrong_typed_fields_fail_without_leakage(self):
        before = self.snapshot()
        for raw in (
            b'{bad-json', b'{}', b'{"url":null}', b'{"url":42}',
            b'{"url":{"sensitive-synthetic-input":"private"}}',
        ):
            with self.subTest(raw=raw):
                code, response, _ = self.api(
                    "/website/check", "POST", self.token("a@example.test"), raw,
                    [(b"content-type", b"application/json")],
                )
                self.assertEqual(code, 422)
                self.assertNotIn(b"sensitive-synthetic-input", response)
                self.assertNotIn(b"Traceback", response)
                self.assertNotIn(self.signing_key.encode(), response)
        self.assertEqual(self.snapshot(), before)
        self.assert_offline()

    def test_missing_invalid_expired_jwt_and_nonexistent_user_cannot_save(self):
        before = self.snapshot()
        for token in (None, "not.a.token", self.token("a@example.test", expired=True)):
            with self.subTest(token_kind="missing" if token is None else "invalid"):
                code, _, _ = self.check(token=token)
                self.assertIn(code, (401, 403))
        code, _, _ = self.check(token=self.token("missing@example.test"))
        self.assertEqual(code, 401)
        self.assertEqual(self.snapshot(), before)
        self.assert_offline()

    def test_saved_website_check_is_scoped_to_jwt_owner_and_old_history_unchanged(self):
        before = self.snapshot()
        code, result, _ = self.check(payload={
            "url": "https://ordinary.example/", "user_id": 2, "email": "b@example.test"
        })
        self.assertEqual(code, 200, result)
        with self.database.SessionLocal() as db:
            record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
            self.assertEqual(record.user_id, 1)
            self.assertEqual(record.decoded_content, "https://ordinary.example/")
            self.assertIsNone(record.risk_score)
            self.assertIsNone(record.ml_phishing_probability)
            self.assertIsNone(record.tampering_score)
            self.assertEqual(json.loads(record.score_explanation)["analysis_source"], "website")
        after = self.snapshot()
        self.assertEqual(after[:3], before)
        self.assertEqual(len(after), len(before) + 1)
        code, raw, _ = self.api("/history", token=self.token("a@example.test"))
        self.assertEqual(code, 200)
        rows = json.loads(raw)
        saved = next(row for row in rows if row["id"] == result["scan_id"])
        self.assertEqual(saved["score_explanation"]["analysis_source"], "website")
        code, raw, _ = self.api("/history", token=self.token("b@example.test"))
        self.assertEqual(code, 200)
        self.assertEqual([row["id"] for row in json.loads(raw)], [22])
        code, _, _ = self.api("/report/" + str(result["scan_id"]), token=self.token("b@example.test"))
        self.assertEqual(code, 404)
        self.assert_offline()

    def test_existing_history_summary_and_page_remain_compatible(self):
        code, result, _ = self.check("http://paypal-login.example.com/verify")
        self.assertEqual(code, 200, result)
        code, raw, _ = self.api("/history/summary", token=self.token("a@example.test"))
        self.assertEqual(code, 200, raw)
        summary = json.loads(raw)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"]["suspicious"], 1)
        self.assertEqual(sum(summary["counts"].values()), summary["total"])
        code, raw, _ = self.api("/history/page", token=self.token("a@example.test"))
        self.assertEqual(code, 200, raw)
        page = json.loads(raw)
        self.assertEqual(set(page), {"items", "has_more", "next_cursor", "snapshot_id", "timezone"})
        self.assertEqual({item["id"] for item in page["items"]}, {11, result["scan_id"]})
        self.assertEqual(set(page["items"][0]), {
            "id", "decoded_content", "final_url", "domain", "risk_score", "risk_label", "scanned_at"
        })
        self.assert_offline()

    def test_unverified_website_does_not_inflate_safe_counts_or_average_score(self):
        code, result, _ = self.check("https://ordinary.example/")
        self.assertEqual(code, 200, result)
        code, raw, _ = self.api("/history/summary", token=self.token("a@example.test"))
        self.assertEqual(code, 200, raw)
        summary = json.loads(raw)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"]["unclassified"], 1)
        self.assertEqual(summary["counts"]["safe"], 0)
        self.assertIsNone(summary["average_url_risk"])
        self.assert_offline()

    def test_restricted_demo_quota_applies_to_website_checks_without_cross_user_effect(self):
        with self.database.SessionLocal() as db:
            db.add_all([
                self.database.ScanRecord(user_id=1, decoded_content="synthetic quota")
                for _ in range(199)
            ])
            db.commit()
        before = self.snapshot()
        with patch.object(self.main, "restricted_demo", return_value=True):
            with self.assertRaises(Exception) as raised:
                self.main._analyze_website("https://ordinary.example/", "a@example.test")
            self.assertEqual(raised.exception.status_code, 429)
            self.assertEqual(self.snapshot(), before)
            result = self.main._analyze_website("https://ordinary.example/", "b@example.test")
        with self.database.SessionLocal() as db:
            record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
            self.assertEqual(record.user_id, 2)
        self.assert_offline()

    def test_redirect_parameter_never_triggers_lookup_or_connection(self):
        url = "https://ordinary.example/?next=http%3A%2F%2F169.254.169.254%2Fmetadata"
        code, result, _ = self.check(url)
        self.assertEqual(code, 200, result)
        self.assertEqual(result["redirect_chain"], [url])
        self.assertFalse(result["final_url_verified"])
        self.assertEqual(result["redirect_check_status"], "unavailable")
        self.assert_offline()

    def test_existing_pdf_endpoint_renders_website_report_without_new_analysis(self):
        code, result, _ = self.check("https://ordinary.example/")
        self.assertEqual(code, 200, result)
        with patch.object(self.main, "_analyze_url", side_effect=AssertionError("Report must not rerun analysis")):
            code, pdf, headers = self.api(
                "/report/" + str(result["scan_id"]), token=self.token("a@example.test")
            )
        self.assertEqual(code, 200)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertEqual(headers[b"content-type"], b"application/pdf")
        self.assertIn(b"attachment", headers[b"content-disposition"])
        self.assert_offline()

    def test_maximum_length_url_is_accepted_and_its_pdf_is_downloadable(self):
        prefix = "https://ordinary.example/"
        url = prefix + "a" * (8192 - len(prefix))
        code, result, _ = self.check(url)
        self.assertEqual(code, 200, result)
        self.assertEqual(result["normalized_url"], url)
        code, pdf, headers = self.api(
            "/report/" + str(result["scan_id"]), token=self.token("a@example.test")
        )
        self.assertEqual(code, 200, pdf[:200])
        self.assertEqual(headers[b"content-type"], b"application/pdf")
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assert_offline()

    def test_pdf_scanned_url_is_xml_escaped_and_web_has_no_fake_image_findings(self):
        url = "https://ordinary.example/<script>alert(1)</script>?a=1&b=2"
        code, result, _ = self.check(url)
        self.assertEqual(code, 200, result)
        with self.database.SessionLocal() as db:
            record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
            with patch.object(self.main.SimpleDocTemplate, "build") as build:
                self.main._build_report(record)
        story = build.call_args.args[0]

        def paragraphs(items):
            for item in items:
                if hasattr(item, "text"):
                    yield item.text
                for row in getattr(item, "_cellvalues", []):
                    for cell in row:
                        yield from paragraphs(cell if isinstance(cell, list) else [cell])

        text = "\n".join(paragraphs(story))
        self.assertIn("Website", text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertNotIn("No tampering detected", text)
        self.assert_offline()

    def test_unknown_model_shape_cannot_affect_website_verdict_or_trigger_inference(self):
        model = SimpleNamespace(
            classes_=["unexpected"], predict_proba=Mock(side_effect=AssertionError("No ML inference"))
        )
        with patch.object(self.main, "ml_model", model):
            code, result, _ = self.check("https://ordinary.example/")
        self.assertEqual(code, 200, result)
        self.assertEqual(result["risk_label"], "unverified")
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["ml_status"], "excluded")
        model.predict_proba.assert_not_called()
        self.assert_offline()

    def test_restricted_app_serves_explicit_assets_and_requires_gate_plus_jwt(self):
        from demo_app import create_app
        from test_demo_security import ENV, BASIC

        with patch.dict(os.environ, {
            **ENV, "JWT_SECRET_KEY": self.signing_key, "CORS_ALLOWED_ORIGINS": ENV["PUBLIC_ORIGIN"]
        }), patch.dict(sys.modules, {"main": self.main}):
            wrapped = create_app()
            original = self.main.app
            self.main.app = wrapped
            try:
                host = [(b"host", b"demo.example")]
                self.assertEqual(self.api("/website-checker.html", headers=host)[0], 401)
                code, html, _ = self.api(
                    "/website-checker.html", headers=host + [(b"authorization", BASIC)]
                )
                self.assertEqual(code, 200)
                self.assertIn(b'window.QR_SHIELD_API_BASE="/api"', html)
                self.assertNotIn(self.signing_key.encode(), html)
                for asset in ("website-checker.css", "website-checker.js"):
                    self.assertEqual(self.api("/" + asset, headers=host + [(b"authorization", BASIC)])[0], 200)
                cookie = b"qr_demo_access=" + wrapped.cookie_value().encode()
                body = b'{"url":"https://ordinary.example/"}'
                gated = host + [(b"cookie", cookie), (b"content-type", b"application/json")]
                # Passing the outer development/demo gate does not replace JWT auth.
                self.assertIn(self.api("/api/website/check", "POST", body=body, headers=gated)[0], (401, 403))
                code, raw, _ = self.api(
                    "/api/website/check", "POST", self.token("a@example.test"), body, gated
                )
                self.assertEqual(code, 200, raw)
                self.assertEqual(json.loads(raw)["analysis_source"], "website")
                for path in ("/backend/main.py", "/.env", "/experimental-warning.html", "/api/docs"):
                    self.assertEqual(self.api(path, headers=gated)[0], 404)
            finally:
                self.main.app = original
        self.assert_offline()


class WebsiteBoundaryTests(unittest.TestCase):
    def test_direct_website_route_uses_scan_rate_limit(self):
        from test_phase_c_security import ApiBoundaryTests
        fixture = ApiBoundaryTests()
        fixture.setUp()
        for _ in range(60):
            self.assertEqual(fixture.request("/website/check")[0], 200)
        self.assertEqual(fixture.request("/website/check")[0], 429)
        self.assertEqual(len(fixture.calls), 60)

    def test_qr_and_website_share_one_development_rate_bucket(self):
        from test_phase_c_security import ApiBoundaryTests
        fixture = ApiBoundaryTests()
        fixture.setUp()
        for _ in range(30):
            self.assertEqual(fixture.request("/scan")[0], 200)
            self.assertEqual(fixture.request("/website/check")[0], 200)
        self.assertEqual(fixture.request("/website/check")[0], 429)
        self.assertEqual(fixture.request("/scan")[0], 429)

    def test_website_json_limit_remains_small_with_and_without_content_length(self):
        from test_phase_c_security import ApiBoundaryTests
        fixture = ApiBoundaryTests()
        fixture.setUp()
        self.assertEqual(fixture.request(
            "/website/check", headers=[(b"host", b"localhost"), (b"content-length", b"16385")]
        )[0], 413)
        self.assertEqual(fixture.request("/website/check", body=b"x" * 16385)[0], 413)
        self.assertEqual(fixture.calls, [])

    def test_restricted_qr_and_website_share_rate_bucket_and_small_website_body_limit(self):
        from test_demo_security import DemoBoundaryTests
        fixture = DemoBoundaryTests()
        fixture.setUp()
        try:
            self.assertEqual(fixture.request("/api/website/check", body=b"x" * 16385)[0], 413)
            self.assertEqual(fixture.received, [])
            # Rate reservation precedes body validation, so the rejected body
            # already used one slot in the common ten-request demo bucket.
            for index in range(9):
                path = "/api/scan" if index % 2 else "/api/website/check"
                self.assertEqual(fixture.request(path)[0], 200)
            self.assertEqual(fixture.request("/api/website/check")[0], 429)
            self.assertEqual(fixture.request("/api/scan")[0], 429)
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
