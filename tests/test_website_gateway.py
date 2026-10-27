"""Website route integration with a synthetic HTTP upstream on loopback only.

No FastAPI application, model artifact or SQLite database is opened.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import unittest
from urllib.parse import parse_qs, urlsplit

from test_dev_gateway import ROOT, gateway, request, start


class WebsiteGatewayTests(unittest.TestCase):
    def setUp(self):
        class Upstream(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                observed = {
                    "method": self.command,
                    "path": self.path,
                    "body": body.hex(),
                    "authorization": self.headers.get("Authorization"),
                    "content_type": self.headers.get("Content-Type"),
                    "cookie": self.headers.get("Cookie"),
                    "tunnel": self.headers.get("X-Tunnel-Authorization"),
                    "offline_values": self.headers.get_all("X-QR-Shield-Offline", []),
                }
                self.server.calls.append(observed)
                payload = json.dumps(observed).encode()
                status = int(parse_qs(urlsplit(self.path).query).get("status", ["201"])[0])
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.upstream.calls = []
        start(self.upstream)
        self.server = gateway.make_server(
            0, self.upstream.server_port, public_test=True,
            allowed_hosts=("website-demo.example",),
        )
        start(self.server)
        self.headers = {
            "Host": "website-demo.example",
            "Authorization": "Bearer synthetic-website-token",
            "Content-Type": "application/json",
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()

    def test_explicit_post_preserves_json_authorization_status_and_response(self):
        body = json.dumps({"url": "https://ordinary.example/?x=1&y=2"}).encode()
        for status in (201, 400, 401, 422, 503):
            with self.subTest(status=status):
                code, raw, headers = request(
                    self.server, "/api/website/check?status=" + str(status), "POST", body,
                    {**self.headers, "Cookie": "private-tunnel-cookie",
                     "X-Tunnel-Authorization": "private-tunnel-token"},
                )
                observed = json.loads(raw)
                self.assertEqual(code, status)
                self.assertEqual(observed["method"], "POST")
                self.assertEqual(observed["path"], "/website/check?status=" + str(status))
                self.assertEqual(bytes.fromhex(observed["body"]), body)
                self.assertEqual(observed["authorization"], self.headers["Authorization"])
                self.assertEqual(observed["content_type"], "application/json")
                self.assertIsNone(observed["cookie"])
                self.assertIsNone(observed["tunnel"])
                self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
                self.assertEqual(int(headers["Content-Length"]), len(raw))
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(len(self.upstream.calls), 5)

    def test_public_testing_always_forces_one_offline_marker(self):
        for value in ("", "0", "false", "1"):
            with self.subTest(client_marker=value):
                code, raw, _ = request(self.server, "/api/website/check", "POST", b"{}", {
                    **self.headers, "x-qr-shield-offline": value,
                })
                self.assertEqual(code, 201)
                self.assertEqual(json.loads(raw)["offline_values"], ["1"])

    def test_wrong_methods_and_unknown_suffixes_never_reach_upstream(self):
        for method in ("GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                self.assertEqual(request(
                    self.server, "/api/website/check", method, headers=self.headers,
                )[0], 404)
        for path in (
            "/api/website", "/api/website/check/", "/api/website/check/extra",
            "/api/website/checkextra", "/api/docs", "/api/openapi.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(request(
                    self.server, path, "POST", b"{}", self.headers,
                )[0], 404)
        self.assertEqual(self.upstream.calls, [])

    def test_page_and_assets_use_same_origin_api_without_exposing_project_files(self):
        code, page, _ = request(self.server, "/website-checker.html", headers=self.headers)
        self.assertEqual(code, 200)
        self.assertIn(b'window.QR_SHIELD_API_BASE="/api";', page)
        self.assertEqual(page.count(b'window.QR_SHIELD_API_BASE="/api";'), 1)
        self.assertIn(b"Website Safety Checker", page)
        for asset in ("website-checker.css", "website-checker.js", "theme.js", "navigation.js"):
            with self.subTest(asset=asset):
                code, raw, _ = request(self.server, "/" + asset, headers=self.headers)
                self.assertEqual(code, 200)
                self.assertEqual(raw, (ROOT / "frontend" / asset).read_bytes())
        code, raw, _ = request(self.server, "/website-checker.html", "HEAD", headers=self.headers)
        self.assertEqual(code, 200)
        self.assertEqual(raw, b"")
        for path in ("/backend/website_input.py", "/backend/main.py", "/.env", "/tests/test_website_gateway.py"):
            with self.subTest(path=path):
                self.assertIn(request(self.server, path, headers=self.headers)[0], (400, 404))
        self.assertEqual(self.upstream.calls, [])

    def test_website_body_limit_is_16_kib_and_checked_before_forwarding(self):
        code, _, _ = request(
            self.server, "/api/website/check", "POST", headers={
                **self.headers, "Content-Length": str(16 * 1024 + 1),
            },
        )
        self.assertEqual(code, 413)
        self.assertEqual(self.upstream.calls, [])
        prefix, suffix = b'{"url":"https://ordinary.example/', b'"}'
        body = prefix + b"a" * (16 * 1024 - len(prefix) - len(suffix)) + suffix
        code, raw, _ = request(self.server, "/api/website/check", "POST", body, self.headers)
        self.assertEqual(code, 201)
        self.assertEqual(bytes.fromhex(json.loads(raw)["body"]), body)
        self.assertEqual(len(self.upstream.calls), 1)

    def test_website_and_qr_requests_share_the_scan_rate_limit(self):
        for index in range(10):
            path = "/api/website/check" if index % 2 else "/api/scan"
            self.assertEqual(request(self.server, path, "POST", b"{}", self.headers)[0], 201)
        self.assertEqual(len(self.upstream.calls), 10)
        for path in ("/api/scan", "/api/website/check"):
            code, raw, headers = request(self.server, path, "POST", b"{}", self.headers)
            self.assertEqual(code, 429)
            self.assertEqual(headers["Retry-After"], "60")
            self.assertIn("Testing request limit", json.loads(raw)["detail"])
        self.assertEqual(len(self.upstream.calls), 10)
        self.assertEqual(set(self.server.rate_events), {"/scan"})


if __name__ == "__main__":
    unittest.main()
