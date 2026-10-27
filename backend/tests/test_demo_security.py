"""Synthetic ASGI boundary tests; no live model, database or network required."""
import asyncio
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from demo_security import DemoBoundary, COOKIE
from demo_runtime import BoundedJob, load_production_model

ENV = {"QR_SHIELD_MODE":"restricted-demo", "PUBLIC_ORIGIN":"https://demo.example",
       "DEMO_ACCESS_USER":"demo", "DEMO_ACCESS_PASSWORD":"synthetic-gate-password-123456", "DEMO_ALLOWED_HOSTS":""}
BASIC = b"Basic " + base64.b64encode(b"demo:synthetic-gate-password-123456")


class DemoBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, ENV)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.received = []
        async def app(scope, receive, send):
            self.received.append((scope, await receive()))
            await send({"type":"http.response.start", "status":200, "headers":[]})
            await send({"type":"http.response.body", "body":b"ok"})
        self.guard = DemoBoundary(app)

    def request(self, path="/scan.html", headers=None, body=b"", basic=True):
        async def run():
            messages=[]
            h=[(b"host",b"demo.example")]
            if basic: h.append((b"authorization",BASIC))
            h.extend(headers or [])
            async def receive(): return {"type":"http.request","body":body,"more_body":False}
            async def send(message): messages.append(message)
            await self.guard({"type":"http","path":path,"headers":h}, receive, send)
            start=next(m for m in messages if m["type"]=="http.response.start")
            return start["status"], dict(start["headers"]), b"".join(m.get("body",b"") for m in messages)
        return asyncio.run(run())

    def test_gate_cookie_keeps_bearer_header_and_security_headers(self):
        code, headers, _ = self.request()
        self.assertEqual(code,200)
        cookie=headers[b"set-cookie"]
        for required in (b"HttpOnly",b"Secure",b"SameSite=Strict"): self.assertIn(required,cookie)
        self.assertIn(b"frame-ancestors 'none'",headers[b"content-security-policy"])
        code, _, _=self.request("/api/history",basic=False,headers=[(b"cookie",cookie.split(b";")[0]),(b"authorization",b"Bearer synthetic-jwt")])
        self.assertEqual(code,200)
        self.assertIn((b"authorization",b"Bearer synthetic-jwt"),self.received[-1][0]["headers"])

    def test_unauthenticated_tampered_expired_and_malformed_cookies(self):
        for cookie in (b"", b"qr_demo_access=0.bad", b"qr_demo_access=bad",b"[=bad"):
            self.assertEqual(self.request(basic=False,headers=[(b"cookie",cookie)])[0],401)
        self.assertEqual(self.received,[])

    def test_host_origin_docs_registration_and_path_exposure(self):
        self.assertEqual(self.request(headers=[(b"host",b"evil.example")])[0],400)
        self.assertEqual(self.request(headers=[(b"origin",b"https://evil.example")])[0],403)
        for path in ("/api/docs","/api/redoc","/api/openapi.json"):
            self.assertEqual(self.request(path)[0],404)
        self.assertEqual(self.request("/api/register")[0],403)
        self.assertEqual(self.received,[])

    def test_body_limit_before_app_with_and_without_length(self):
        self.assertEqual(self.request("/api/scan",headers=[(b"content-length",b"7000000")])[0],413)
        self.assertEqual(self.request("/api/login",body=b"x"*16385)[0],413)
        self.assertEqual(self.request(headers=[(b"content-length",b"bad")])[0],400)
        self.assertEqual(self.request(headers=[(b"content-length",b"1"),(b"content-length",b"1")])[0],400)
        self.assertEqual(self.received,[])
        self.assertEqual(self.guard.active,0)

    def test_global_login_rate_limit_and_concurrency(self):
        for _ in range(20): self.assertEqual(self.request("/api/login")[0],200)
        self.assertEqual(self.request("/api/login")[0],429)
        self.guard.active=4
        self.assertEqual(self.request("/api/history")[0],503)

    def test_errors_redacted_and_active_slot_released(self):
        async def broken(*args): raise RuntimeError("synthetic secret must not escape")
        self.guard.app=broken
        code, _, body=self.request()
        self.assertEqual(code,500)
        self.assertNotIn(b"synthetic secret",body)
        self.assertEqual(self.guard.active,0)

    def test_body_timeout_and_processing_timeout(self):
        async def slow(*args): await asyncio.sleep(0.05)
        self.guard.app=slow
        self.guard.request_timeout=0.001
        self.assertEqual(self.request()[0],504)
        self.assertEqual(self.guard.active,0)
        async def test_read():
            self.guard.body_timeout=0.001
            messages=[]
            async def receive(): await asyncio.sleep(0.05)
            async def send(message): messages.append(message)
            await self.guard({"type":"http","path":"/api/scan","headers":[(b"host",b"demo.example"),(b"authorization",BASIC)]},receive,send)
            self.assertEqual(messages[0]["status"],408)
        asyncio.run(test_read())
        self.assertEqual(self.guard.active,0)

    def test_health_has_no_private_data(self):
        code, _, body=self.request("/healthz",basic=False)
        self.assertEqual((code,body),(200,b'{"status":"ok"}'))


class DemoRuntimeTests(unittest.TestCase):
    def test_artifact_hash_required_and_checked_before_deserialization(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"synthetic-model.pkl"
            path.write_bytes(b"synthetic artifact")
            loader=Mock(return_value="model")
            with patch.dict(os.environ,{**ENV,"MODEL_PATH":str(path),"MODEL_SHA256":"0"*64}):
                with self.assertRaises(RuntimeError): load_production_model(loader)
                loader.assert_not_called()
                with patch.dict(os.environ,{"MODEL_SHA256":hashlib.sha256(path.read_bytes()).hexdigest()}):
                    self.assertEqual(load_production_model(loader),"model")

    def test_timeout_holds_native_slot_until_work_really_finishes(self):
        release=threading.Event()
        job=BoundedJob("test-demo",0.01)
        async def run():
            with self.assertRaises(Exception) as timed: await job.run(release.wait)
            self.assertEqual(timed.exception.status_code,504)
            with self.assertRaises(Exception) as busy: await job.run(lambda: "must not execute")
            self.assertEqual(busy.exception.status_code,503)
        try: asyncio.run(run())
        finally:
            release.set()
            job.pool.shutdown(wait=True)


if __name__ == "__main__": unittest.main()
