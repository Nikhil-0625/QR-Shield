"""Privacy API regressions using synthetic records in in-memory SQLite only."""
import asyncio
import io
import json
import unittest
from unittest.mock import patch

import test_history_authorization as harness


class HistoryPrivacyTests(unittest.TestCase):
    setUpClass = classmethod(harness.HistoryAuthorizationTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.HistoryAuthorizationTests.tearDownClass.__func__)
    setUp = harness.HistoryAuthorizationTests.setUp
    snapshot = harness.HistoryAuthorizationTests.snapshot
    token = harness.HistoryAuthorizationTests.token

    def request(self, method, path, token=None, body=b"", content_type=None, query=b""):
        async def run():
            messages = []
            delivered = False

            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}
                await asyncio.Event().wait()

            async def send(message):
                messages.append(message)

            headers = [(b"host", b"localhost:8000")]
            if token is not None:
                headers.append((b"authorization", ("Bearer " + token).encode()))
            if content_type:
                headers.extend([(b"content-type", content_type.encode()),
                                (b"content-length", str(len(body)).encode())])
            await self.main.app({
                "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1", "method": method, "scheme": "http",
                "path": path, "raw_path": path.encode(), "query_string": query,
                "root_path": "", "headers": headers,
                "client": ("127.0.0.1", 1234), "server": ("test", 80),
            }, receive, send)
            status = next(m["status"] for m in messages if m["type"] == "http.response.start")
            data = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
            return status, json.loads(data)
        return asyncio.run(run())

    def test_delete_requires_valid_authentication_and_preserves_records(self):
        before = self.snapshot()
        for token in (None, "invalid", self.token("a@example.test", expired=True),
                      self.token("missing@example.test")):
            status, _ = self.request("DELETE", "/history", token)
            self.assertIn(status, (401, 403))
            self.assertEqual(before, self.snapshot())

    def test_delete_is_user_scoped_and_ignores_client_user_id(self):
        others = [row for row in self.snapshot() if row[1] != 1]
        status, data = self.request("DELETE", "/history", self.token("a@example.test"), query=b"user_id=2")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"deleted_count": 1})
        self.assertEqual(others, self.snapshot())
        self.assertEqual(self.request("DELETE", "/history", self.token("a@example.test")),
                         (200, {"deleted_count": 0}))
        self.assertEqual(self.request("GET", "/history", self.token("a@example.test")), (200, []))
        status, data = self.request("GET", "/history", self.token("b@example.test"))
        self.assertEqual(status, 200)
        self.assertEqual([row["id"] for row in data], [22])

    def scan(self, private_value):
        from PIL import Image
        image = io.BytesIO()
        Image.new("RGB", (1, 1), "white").save(image, format="PNG")
        boundary = "privacy-test-boundary"
        body = b""
        if private_value is not None:
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"private_scan\"\r\n\r\n{private_value}\r\n").encode()
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"synthetic.png\"\r\nContent-Type: image/png\r\n\r\n").encode()
        body += image.getvalue() + f"\r\n--{boundary}--\r\n".encode()
        with patch.object(self.main.cv2, "imdecode", return_value=object()), \
                patch.object(self.main, "decode_qr", return_value="synthetic private content"), \
                patch.object(self.main, "analyze_tampering", return_value={"tampering_score": 0, "tampering_reasons": []}):
            return self.request("POST", "/scan", self.token("a@example.test"), body,
                                "multipart/form-data; boundary=" + boundary)

    def test_private_scan_creates_no_row_or_save_calls(self):
        before = self.snapshot()
        session_type = type(self.database.SessionLocal())
        with patch.object(session_type, "add", side_effect=AssertionError("Private scan must not add")), \
                patch.object(session_type, "commit", side_effect=AssertionError("Private scan must not commit")):
            status, result = self.scan("true")
        self.assertEqual(status, 200)
        self.assertEqual(result["decoded_content"], "synthetic private content")
        self.assertIsNone(result["scan_id"])
        self.assertEqual(before, self.snapshot())

    def test_default_and_false_scans_still_save(self):
        for value in (None, "false"):
            before = self.snapshot()
            status, result = self.scan(value)
            self.assertEqual(status, 200)
            self.assertIsInstance(result["scan_id"], int)
            after = self.snapshot()
            self.assertEqual(len(after), len(before) + 1)
            self.assertEqual([row for row in after if row[0] == result["scan_id"]][0][1], 1)

    def test_invalid_private_boolean_rejected_without_saving(self):
        before = self.snapshot()
        self.assertEqual(self.scan("not-a-boolean")[0], 422)
        self.assertEqual(before, self.snapshot())

    def test_localhost_delete_preflight_retains_explicit_origin_policy(self):
        from test_api_security import ApiSecurityTests
        origin = self.main.cors_origins[0]
        status, _, headers = ApiSecurityTests.api(self, "/history", "OPTIONS", headers=[
            (b"origin", origin.encode()), (b"access-control-request-method", b"DELETE"),
            (b"access-control-request-headers", b"authorization")])
        self.assertEqual(status, 200)
        self.assertEqual(headers[b"access-control-allow-origin"].decode(), origin)
        self.assertIn(b"DELETE", headers[b"access-control-allow-methods"])
        status, _, headers = ApiSecurityTests.api(self, "/history", "OPTIONS", headers=[
            (b"origin", b"https://untrusted.invalid"), (b"access-control-request-method", b"DELETE")])
        self.assertEqual(status, 400)
        self.assertNotIn(b"access-control-allow-origin", headers)
