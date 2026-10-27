"""Fail-closed network policy and resource checks; mock destinations, memory DB only."""
import asyncio
import io
import os
import threading
import unittest
from unittest.mock import Mock, patch
from PIL import Image
from api_security import ApiBoundary
from demo_runtime import BoundedJob
from url_policy import MAX_QR_BYTES, url_input_error
import test_url_detection as url_harness


class ApiBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        async def app(scope,receive,send):
            self.calls.append(await receive())
            await send({"type":"http.response.start","status":200,"headers":[]})
            await send({"type":"http.response.body","body":b"ok"})
        self.guard=ApiBoundary(app)

    def request(self,path="/",headers=None,body=b"",chunks=None,receive_delay=0):
        async def run():
            messages=[]
            events=iter(chunks if chunks is not None else [{"type":"http.request","body":body,"more_body":False}])
            async def receive():
                if receive_delay: await asyncio.sleep(receive_delay)
                return next(events)
            async def send(message): messages.append(message)
            await self.guard({"type":"http","path":path,"headers":headers if headers is not None else [(b"host",b"localhost:8000")]},receive,send)
            first=next(message for message in messages if message["type"]=="http.response.start")
            return first["status"],b"".join(message.get("body",b"") for message in messages),dict(first["headers"])
        return asyncio.run(run())

    def test_duplicate_headers_and_foreign_host_rejected(self):
        for host in (b"evil.test",b"localhost@evil.test",b"localhost:bad",b"localhost/evil",b""):
            self.assertEqual(self.request(headers=[(b"host",host)])[0],400)
        self.assertEqual(self.request(headers=[])[0],400)
        for key in (b"host",b"authorization",b"origin",b"content-length",b"content-type"):
            headers=[(b"host",b"localhost:8000")]
            if key!=b"host": headers.append((key,b"one"))
            headers.append((key,b"two"))
            self.assertEqual(self.request(headers=headers)[0],400)
        self.assertEqual(self.calls,[])

    def test_body_limits_before_application_including_chunked(self):
        for headers in [ [(b"host",b"localhost"),(b"content-length",b"7000000")],
                         [(b"host",b"localhost"),(b"content-length",b"1"),(b"transfer-encoding",b"chunked")],
                         [(b"host",b"localhost"),(b"content-length",b"99999999999999999999")]]:
            self.assertIn(self.request("/scan",headers=headers)[0],(400,413))
        chunks=[{"type":"http.request","body":b"x"*16000,"more_body":True},{"type":"http.request","body":b"x"*1000,"more_body":False}]
        self.assertEqual(self.request("/login",headers=[(b"host",b"localhost"),(b"transfer-encoding",b"chunked")],chunks=chunks)[0],413)
        self.assertEqual(self.request(headers=[(b"host",b"localhost"),(b"content-length",b"5")],body=b"x")[0],400)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.guard.active,0)

    def test_timeout_and_concurrency_are_released(self):
        self.guard.body_timeout=.001
        self.assertEqual(self.request(receive_delay=.02)[0],408)
        self.assertEqual(self.guard.active,0)
        async def slow(*_): await asyncio.sleep(.02)
        self.guard.app=slow;self.guard.request_timeout=.001
        self.assertEqual(self.request()[0],504)
        self.assertEqual(self.guard.active,0)
        self.guard.active=self.guard.max_active
        self.assertEqual(self.request()[0],503)

    def test_rate_limits_fixed_buckets_and_forwarded_headers_do_not_bypass(self):
        for _ in range(60): self.assertEqual(self.request("/login")[0],200)
        status,_,headers=self.request("/login",headers=[(b"host",b"localhost"),(b"x-forwarded-for",b"198.51.100.5"),(b"origin",b"http://localhost:5500")])
        self.assertEqual(status,429)
        self.assertEqual(headers[b"access-control-allow-origin"],b"http://localhost:5500")
        self.assertEqual(headers[b"retry-after"],b"60")

    def test_safe_errors_headers_and_body_forwarding(self):
        status,_,headers=self.request(body=b"synthetic bytes")
        self.assertEqual(status,200)
        self.assertEqual(self.calls[0]["body"],b"synthetic bytes")
        self.assertEqual(headers[b"cache-control"],b"no-store")
        async def broken(*_): raise RuntimeError("synthetic private secret")
        self.guard.app=broken
        status,body,_=self.request()
        self.assertEqual(status,500)
        self.assertNotIn(b"private secret",body)


class PhaseCIntegrationTests(unittest.TestCase):
    setUpClass=classmethod(url_harness.UrlDetectionTests.setUpClass.__func__)
    tearDownClass=classmethod(url_harness.UrlDetectionTests.tearDownClass.__func__)
    setUp=url_harness.UrlDetectionTests.setUp
    token=url_harness.UrlDetectionTests.token
    api=url_harness.UrlDetectionTests.api
    scan=url_harness.UrlDetectionTests.scan

    def test_no_network_even_rebinding_private_redirect_slow_or_large_responses(self):
        urls=["http://127.0.0.1/","http://localhost/","http://10.0.0.1/","http://172.16.1.1/","http://192.168.1.1/","http://169.254.169.254/","http://[::1]/","http://[fd00::1]/","http://[fe80::1]/","http://[ff02::1]/","http://224.0.0.1/","http://0.0.0.0/","http://2130706433/","http://0177.0.0.1/","http://0x7f000001/","https://public.example/"]
        # If any DNS or HTTP call occurs, these mocks represent failure/rebinding
        # and malicious response behaviors. Policy must stop before calling them.
        hostile=Mock(status_code=302,headers={"Location":"http://127.0.0.1/","Content-Length":"999999999"})
        hostile.iter_content.side_effect=TimeoutError("synthetic slow body")
        for mode in ("development","restricted-demo"):
            with patch.dict(os.environ,{"QR_SHIELD_MODE":mode,"HTTP_PROXY":"http://proxy.invalid"}),patch.object(self.main.socket,"getaddrinfo",side_effect=AssertionError("DNS rebinding or DNS failure")) as dns,patch.object(self.main.requests,"get",return_value=hostile) as http,patch.object(self.main.whois,"whois",side_effect=TimeoutError("slow WHOIS")) as whois:
                for url in urls:
                    self.assertFalse(self.main.validate_outbound_url(url)[0])
                    self.assertEqual(self.main.trace_redirects(url,max_hops=100000)[0],[url])
                    self.assertIsNone(self.main.check_https_valid(url))
                self.assertIsNone(self.main.get_domain_age_days("public.example"))
                dns.assert_not_called();http.assert_not_called();whois.assert_not_called();hostile.iter_content.assert_not_called()

    def test_scans_preserve_scores_and_mark_network_unknown(self):
        for url in ("https://www.wikipedia.org/","http://paypal-login.example.com/verify","http://192.0.2.1/verify","https://xn--bcher-kva.example/","https://bücher.example/"):
            result=self.scan(url,probability=.5,headers=((b"x-qr-shield-offline",b"1"),))
            self.assertIsNone(result["domain_age_days"])
            self.assertIsNone(result["https_valid"])
            self.assertFalse(result["final_url_verified"])
            self.assertEqual(result["redirect_check_status"],"blocked")
            self.assertIsNone(result["redirect_count"])
            normalized_url=self.main._normalize_qr_url_for_analysis(url)
            self.assertEqual(result["redirect_chain"],[normalized_url])
            self.assertEqual(result["final_url"],normalized_url)
            self.assertIn("offline or restricted request",result["network_analysis"])
            self.assertEqual(result["risk_score"],min(round(.7*result["rule_score"]+15),100))

    def test_payload_limits_and_malformed_inputs_fail_without_saving(self):
        for content,status in [("x"*(MAX_QR_BYTES+1),413),("https://example.test/"+"x"*8200,413),("https://[broken/",400),("https://example.test/\nsecret",400),("https://a..test/",400),("https://%65xample.test/",400),("https://"+"a."*33+"test/",400),("https://example.test/%ZZ",400)]:
            with self.subTest(status=status),patch.object(self.main,"decode_qr",return_value=content),patch.object(self.main,"analyze_tampering") as tamper:
                image=io.BytesIO();Image.new("RGB",(8,8),"white").save(image,format="PNG")
                with self.assertRaises(Exception) as raised:self.main._analyze_scan(image.getvalue(),"a@example.test",None)
                self.assertEqual(raised.exception.status_code,status)
                tamper.assert_not_called()
        with self.database.SessionLocal() as db:self.assertEqual(db.query(self.database.ScanRecord).count(),3)

    def test_upload_type_size_dimensions_and_invalid_text_encoding(self):
        for data,status in [(b"%PDF-not-image",400),(b"<svg></svg>",400),(b"not-image",400)]:
            with self.assertRaises(Exception) as error:self.main._analyze_scan(data,"a@example.test",None)
            self.assertEqual(error.exception.status_code,status)
        for size in ((4001,4000),):
            image=io.BytesIO();Image.new("1",size).save(image,format="PNG")
            with patch.object(self.main.cv2,"imdecode") as decode:
                with self.assertRaises(Exception) as error:self.main._analyze_scan(image.getvalue(),"a@example.test",None)
                self.assertEqual(error.exception.status_code,413);decode.assert_not_called()
        image=io.BytesIO();Image.new("RGB",(8,8)).save(image,format="PNG")
        with patch.object(self.main,"decode_qr",side_effect=UnicodeError("synthetic")):
            with self.assertRaises(Exception) as error:self.main._analyze_scan(image.getvalue(),"a@example.test",None)
            self.assertEqual(error.exception.status_code,400)

    def test_host_preflight_docs_and_legacy_hash_fail_safely(self):
        for method in ("GET","OPTIONS"):
            headers=[(b"host",b"evil.test"),(b"origin",b"http://localhost:5500"),(b"access-control-request-method",b"GET")]
            self.assertEqual(self.api("/history",method,headers=headers)[0],400)
        for path in ("/docs","/redoc","/openapi.json"):
            self.assertEqual(self.api(path)[0],404)
        self.assertFalse(self.main.verify_password("synthetic",None))
        self.assertFalse(self.main.verify_password("synthetic","not-a-hash"))

    def test_file_limit_is_enforced_before_decoder(self):
        body=b'--local\r\nContent-Disposition: form-data; name="file"; filename="synthetic.png"\r\nContent-Type: image/png\r\n\r\n'+b'x'*(5*1024*1024+1)+b'\r\n--local--\r\n'
        with patch.object(self.main,"decode_qr") as decoder:
            self.assertEqual(self.api("/scan","POST",self.token("a@example.test"),body,[(b"content-type",b"multipart/form-data; boundary=local")])[0],413)
            decoder.assert_not_called()

    def test_large_history_is_rejected_explicitly_without_truncating_other_users(self):
        with self.database.SessionLocal() as db:
            db.add_all([self.database.ScanRecord(user_id=1,decoded_content="synthetic history limit") for _ in range(5000)])
            db.commit()
        self.assertEqual(self.api("/history",token=self.token("a@example.test"))[0],413)
        code,body,_=self.api("/history",token=self.token("b@example.test"))
        self.assertEqual(code,200)
        self.assertIn(b"synthetic B",body)

    def test_history_timeout_holds_processing_slot_until_native_work_finishes(self):
        release=threading.Event()
        job=BoundedJob("synthetic-history",.005)
        try:
            with patch.object(self.main,"history_jobs",job),patch.object(self.main,"_get_history",side_effect=lambda _:release.wait()):
                self.assertEqual(self.api("/history",token=self.token("a@example.test"))[0],504)
                self.assertEqual(self.api("/history",token=self.token("a@example.test"))[0],503)
        finally:
            release.set();job.pool.shutdown(wait=True)

    def test_history_byte_budget_rejects_oversized_legacy_records(self):
        with self.database.SessionLocal() as db:
            db.query(self.database.ScanRecord).filter_by(id=11).one().decoded_content="x"*(1024*1024+1)
            db.commit()
        with patch.object(self.main,"MAX_HISTORY_BYTES",1024*1024):
            self.assertEqual(self.api("/history",token=self.token("a@example.test"))[0],413)
            self.assertEqual(self.api("/history",token=self.token("b@example.test"))[0],200)


class UrlInputTests(unittest.TestCase):
    def test_ambiguous_numeric_and_invalid_punycode_hosts(self):
        for url in ("http://2130706433/","http://0177.0.0.1/","http://0x7f000001/","https://xn--a.example/"):
            self.assertIsNotNone(url_input_error(url))
    def test_normal_ipv4_ipv6_idn_and_encoded_paths(self):
        for url in ("https://example.com/","https://example.com./","http://127.0.0.1/","https://[2001:db8::1]/","https://bücher.example/","https://xn--bcher-kva.example/%20path","https://paypal.com@evil.test/verify","https://paypal.example:bad/"):
            self.assertIsNone(url_input_error(url),url)
