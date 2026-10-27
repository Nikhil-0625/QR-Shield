"""Google Safe Browsing v5 checks with synthetic responses; no network or keys.

Response fixtures follow the v5 urls.search schema: threats[] plus a top-level
cacheDuration applying to both positive and negative results.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from email.utils import format_datetime
import io
import json
import gzip
import os
import threading
import unittest
from unittest.mock import MagicMock, Mock, call, patch

import requests
import safe_browsing
import test_website_checker as website_harness


KEY = "synthetic-safe-browsing-test-key-not-a-real-secret"
URL = "https://ordinary.example/"
ENDPOINT = "https://safebrowsing.googleapis.com/v5/urls:search"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def time(self):
        return 1_700_000_000.0 + self.now

    def advance(self, seconds):
        self.now += seconds


class Response:
    def __init__(self, payload=None, *, status=200, headers=None, chunks=None):
        self.status_code = status
        self.headers = {"Content-Type": "application/x-protobuf", **(headers or {})}
        if chunks is not None:
            self.chunks = chunks
        elif isinstance(payload, bytes):
            self.chunks = [payload]
        elif payload is not None:
            if isinstance(payload, dict):
                has_threats = "threats" in payload
                threats = payload.get("threats")
                has_duration = "cacheDuration" in payload
                duration_val = payload.get("cacheDuration")
                secs = None
                nanos = 0
                if has_duration and isinstance(duration_val, str) and duration_val.endswith("s"):
                    raw = duration_val[:-1]
                    parts = raw.split(".")
                    if len(parts) == 1 and parts[0].isdigit():
                        secs = int(parts[0])
                    elif len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        secs = int(parts[0])
                        nanos = int(parts[1].ljust(9, "0")[:9])
                force_entry = (has_threats and threats is None)
                self.chunks = [safe_browsing.encode_search_urls_response(
                    threats=threats if has_threats else [],
                    seconds=secs,
                    nanos=nanos,
                    force_threat_entry=force_entry,
                )]
            else:
                self.chunks = [safe_browsing.encode_search_urls_response([], 300, 0)]
        else:
            self.chunks = [safe_browsing.encode_search_urls_response([], 300, 0)]
        self.body = b"".join(self.chunks)
        self.closed = False
        self.reads = 0

    def iter_content(self, chunk_size=4096):
        chunks = self.chunks if self.chunks is not None else [self.body]
        for chunk in chunks:
            self.reads += 1
            yield chunk

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def paragraph_xml(items):
    for item in items:
        if hasattr(item, "text"):
            yield item.text
        for row in getattr(item, "_cellvalues", []):
            for cell in row:
                yield from paragraph_xml(cell if isinstance(cell, list) else [cell])


class SafeBrowsingTests(unittest.TestCase):
    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        guards.enter_context(patch.dict(os.environ, {
            "SAFE_BROWSING_ENABLED": "true", "GOOGLE_SAFE_BROWSING_API_KEY": KEY,
            "QR_SHIELD_MODE": "development",
        }))
        self.clock = Clock()
        guards.enter_context(patch.object(safe_browsing.time, "monotonic", self.clock.monotonic))
        guards.enter_context(patch.object(safe_browsing.time, "time", self.clock.time))
        self.session = MagicMock()
        self.session.__enter__.return_value = self.session
        self.session.trust_env = True
        self.response = Response()
        self.session.get.return_value = self.response
        guards.enter_context(patch.object(safe_browsing.requests, "Session", return_value=self.session))
        self.client = safe_browsing.SafeBrowsingClient()

    def threat(self, ttl="300s", *, matched_url=URL, threat_types=None):
        return Response({
            "threats": [{"url": matched_url, "threatTypes": threat_types or ["SOCIAL_ENGINEERING"]}],
            "cacheDuration": ttl,
        })

    def assert_unavailable(self, result):
        self.assertEqual(result["status"], "unavailable", result)
        self.assertNotIn(KEY, json.dumps(result))
        if "known_malicious" in result:
            self.assertFalse(result["known_malicious"])

    def test_enabled_clear_result_is_qualified_and_has_utc_metadata(self):
        result = self.client.lookup(URL)
        self.assertEqual(result["provider"], "Google Safe Browsing")
        self.assertEqual(result["status"], "clear")
        self.assertEqual(result["threat_types"], [])
        self.assertFalse(result["cached"])
        self.assertTrue(result["reason"])
        self.assertNotIn("guaranteed safe", result["reason"].lower())
        for field in ("checked_at", "cache_expires_at"):
            value = datetime.fromisoformat(result[field].replace("Z", "+00:00"))
            self.assertIsNotNone(value.tzinfo)
            self.assertEqual(value.utcoffset().total_seconds(), 0)
        if "known_malicious" in result:
            self.assertFalse(result["known_malicious"])
        self.assertTrue(self.response.closed)

    def test_google_threat_types_are_returned_without_model_or_numeric_scores(self):
        self.session.get.return_value = self.threat(threat_types=["SOCIAL_ENGINEERING", "MALWARE"])
        result = self.client.lookup(URL)
        self.assertEqual(result["status"], "threat", result)
        self.assertEqual(set(result["threat_types"]), {"SOCIAL_ENGINEERING", "MALWARE"})
        self.assertNotIn("risk_score", result)
        self.assertNotIn("ml_probability", result)
        if "known_malicious" in result:
            self.assertTrue(result["known_malicious"])

    def test_provider_host_suffix_or_path_prefix_match_is_not_discarded(self):
        self.session.get.return_value = self.threat(matched_url="https://ordinary.example/")
        result = self.client.lookup("https://shop.ordinary.example/login?synthetic=1")
        self.assertEqual(result["status"], "threat", result)

    def test_only_fixed_google_endpoint_is_called_without_proxy_redirect_or_retry(self):
        submitted = "https://ordinary.example/?next=http%3A%2F%2F169.254.169.254%2Fmetadata"
        with patch.dict(os.environ, {
            "HTTPS_PROXY": "http://untrusted-proxy.invalid/",
            "SAFE_BROWSING_URL": "http://127.0.0.1/internal",
        }):
            result = self.client.lookup(submitted)
        self.assertEqual(result["status"], "clear")
        self.assertFalse(self.session.trust_env)
        self.session.get.assert_called_once()
        args, kwargs = self.session.get.call_args
        self.assertEqual(args, (ENDPOINT,))
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["timeout"], (3, 5))
        self.assertTrue(kwargs["verify"])
        self.assertTrue(kwargs["stream"])
        params = kwargs["params"]
        pairs = list(params.items()) if isinstance(params, dict) else list(params)
        values = [value for key, value in pairs if key in ("urls", "urls[]")]
        self.assertEqual(len(values), 1)
        self.assertIn(values[0], (submitted, [submitted], (submitted,)))
        headers = {key.lower(): value for key, value in kwargs["headers"].items()}
        self.assertEqual(headers["x-goog-api-key"], KEY)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("key", dict(pairs))
        self.assertNotIn("data", kwargs)
        self.assertNotIn("json", kwargs)

    def test_request_explicitly_negotiates_protobuf_and_uncompressed_transport(self):
        self.assertEqual(self.client.lookup(URL)["status"], "clear")
        _, kwargs = self.session.get.call_args
        params = dict(kwargs["params"])
        self.assertNotIn("alt", params)
        headers = {key.lower(): value for key, value in kwargs["headers"].items()}
        self.assertEqual(headers.get("accept"), "application/x-protobuf")
        self.assertEqual(headers.get("accept-encoding"), "identity")
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["timeout"], (3, 5))
        self.session.get.assert_called_once()

    def test_normal_protobuf_content_types_and_explicit_identity_are_accepted(self):
        for index, content_type in enumerate((
            "application/x-protobuf", "application/x-protobuf; charset=utf-8",
            "application/octet-stream", "application/vnd.google.protobuf",
        )):
            with self.subTest(content_type=content_type):
                response = Response(
                    {"threats": [], "cacheDuration": "300s"},
                    headers={"Content-Type": content_type, "Content-Encoding": "identity"},
                )
                self.session.get.return_value = response
                result = safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/proto/{index}")
                self.assertEqual(result["status"], "clear", result)
                self.assertTrue(response.closed)

    def test_binary_protobuf_response_is_decoded_as_clear(self):
        # Synthetic protobuf wire bytes: field 2 contains a Duration of 300 seconds.
        # This models the observed application/x-protobuf response from Google API v5.
        protobuf = b"\x12\x03\x08\xac\x02"
        response = Response(
            chunks=[protobuf],
            headers={"Content-Type": "application/x-protobuf", "Content-Length": str(len(protobuf))},
        )
        self.session.get.return_value = response
        result = self.client.lookup(URL)
        self.assertEqual(result["status"], "clear")
        self.assertEqual(result["threat_types"], [])
        self.assertEqual(response.reads, 1)
        self.assertTrue(response.closed)

    def test_unexpected_content_types_and_non_utf8_charsets_are_rejected_before_read(self):
        for index, content_type in enumerate((
            "text/html", "text/plain", "application/json",
            "application/json; charset=utf-8", "application/json; charset=utf-16",
            "application/json; charset=iso-8859-1", "",
        )):
            with self.subTest(content_type=content_type):
                response = Response(headers={"Content-Type": content_type})
                self.session.get.return_value = response
                self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/type/{index}"))
                self.assertEqual(response.reads, 0)
                self.assertTrue(response.closed)
        response = Response()
        response.headers.pop("Content-Type")
        self.session.get.return_value = response
        self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup("https://ordinary.example/no-type"))
        self.assertEqual(response.reads, 0)

    def test_unsupported_content_encoding_is_rejected_before_http_client_decoding(self):
        # Only identity is negotiated. Even otherwise supported Requests encodings
        # must not be decoded if the provider ignores that explicit contract.
        for index, encoding in enumerate(("gzip", "deflate", "br", "zstd", "compress", "gzip, identity", "identity, gzip")):
            with self.subTest(encoding=encoding):
                response = Response(headers={"Content-Encoding": encoding})
                self.session.get.return_value = response
                self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/encoding/{index}"))
                self.assertEqual(response.reads, 0)
                self.assertTrue(response.closed)

    def test_invalid_protobuf_and_malformed_bytes_fail_without_replacement_or_fallback(self):
        for index, body in enumerate((
            b"\xff\xff",
            b"\xac",  # truncated varint
            b"\x12\x05\x08\xac",  # length exceeds buffer
            b"not-protobuf",
        )):
            with self.subTest(case=index):
                response = Response(chunks=[body])
                self.session.get.return_value = response
                client = safe_browsing.SafeBrowsingClient()
                self.assert_unavailable(client.lookup(f"https://ordinary.example/bad-proto/{index}"))
                self.assertEqual(client.cache, {})
                self.assertTrue(response.closed)

    def test_oversized_compressed_wire_body_is_rejected_without_reading_or_inflating(self):
        compressed = gzip.compress(os.urandom(safe_browsing.MAX_RESPONSE_BYTES + 1))
        self.assertGreater(len(compressed), safe_browsing.MAX_RESPONSE_BYTES)
        response = Response(
            chunks=[compressed],
            headers={"Content-Encoding": "gzip", "Content-Length": str(len(compressed))},
        )
        self.session.get.return_value = response
        self.assert_unavailable(self.client.lookup(URL))
        self.assertEqual(response.reads, 0)
        self.assertTrue(response.closed)

    def test_decompression_bomb_is_rejected_before_decoder_receives_any_bytes(self):
        compressed = gzip.compress(b"x" * (safe_browsing.MAX_RESPONSE_BYTES + 1))
        self.assertLess(len(compressed), safe_browsing.MAX_RESPONSE_BYTES)
        response = Response(chunks=[compressed], headers={
            "Content-Encoding": "gzip", "Content-Length": str(len(compressed)),
        })
        self.session.get.return_value = response
        self.assert_unavailable(self.client.lookup(URL))
        self.assertEqual(response.reads, 0)
        self.assertTrue(response.closed)

    def test_oversized_identity_without_content_length_is_bounded_and_not_cached(self):
        # No decompression is performed, so this is both the wire and output bound.
        response = Response(chunks=[b"x" * safe_browsing.MAX_RESPONSE_BYTES, b"x", b"must-not-be-read"])
        self.session.get.return_value = response
        self.assert_unavailable(self.client.lookup(URL))
        self.assertEqual(response.reads, 2)
        self.assertTrue(response.closed)
        self.assertEqual(self.client.cache, {})

    def test_api_errors_keep_existing_categories_without_reading_their_body(self):
        for index, (status, phrase) in enumerate((
            (400, "could not complete"), (403, "credentials were rejected"),
            (429, "quota or capacity"),
        )):
            with self.subTest(status=status):
                response = Response(status=status, headers={"Content-Type": "application/x-protobuf"})
                self.session.get.return_value = response
                result = safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/error-preserved/{index}")
                self.assert_unavailable(result)
                self.assertIn(phrase, result["reason"])
                self.assertEqual(response.reads, 0)
                self.assertTrue(response.closed)

    def test_default_disabled_and_non_true_config_never_contacts_google(self):
        for value in (None, "", "false", "FALSE", "1", "yes"):
            with self.subTest(setting=value), patch.dict(os.environ):
                if value is None:
                    os.environ.pop("SAFE_BROWSING_ENABLED", None)
                else:
                    os.environ["SAFE_BROWSING_ENABLED"] = value
                result = safe_browsing.SafeBrowsingClient().lookup(URL)
                self.assertEqual(result["status"], "disabled", result)
                self.assertIsNone(result["checked_at"])
        self.session.get.assert_not_called()

    def test_explicit_true_configuration_accepts_case_and_whitespace(self):
        for index, value in enumerate(("true", "TRUE", "True", " true ")):
            with self.subTest(setting=value), patch.dict(os.environ, {"SAFE_BROWSING_ENABLED": value}):
                result = safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/config/{index}")
                self.assertEqual(result["status"], "clear", result)

    def test_restricted_demo_forces_offline_even_when_enabled_and_key_present(self):
        with patch.dict(os.environ, {"QR_SHIELD_MODE": "restricted-demo"}):
            result = self.client.lookup(URL)
        self.assertEqual(result["status"], "disabled", result)
        self.session.get.assert_not_called()

    def test_missing_key_does_not_make_a_request_or_report_clear(self):
        with patch.dict(os.environ):
            os.environ.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
            result = safe_browsing.SafeBrowsingClient().lookup(URL)
        self.assertIn(result["status"], ("disabled", "unavailable"))
        self.assertNotEqual(result["status"], "clear")
        self.session.get.assert_not_called()

    def test_bad_key_header_values_and_invalid_destination_inputs_do_not_send_requests(self):
        for key in ("x" * 257, "synthetic\nkey", "synthetic\rkey", "not-ascii-\u20b9"):
            with self.subTest(key_kind="invalid-header"), patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": key}):
                self.assert_unavailable(self.client.lookup(URL))
        for url in (
            "javascript:alert(1)", "http://localhost/", "http://127.0.0.1/",
            "http://169.254.169.254/", "https://user:secret@ordinary.example/", "https://[broken/",
        ):
            with self.subTest(url=url):
                self.assert_unavailable(self.client.lookup(url))
        self.session.get.assert_not_called()

    def test_disabled_configuration_does_not_reuse_an_old_positive_cache(self):
        self.session.get.return_value = self.threat()
        self.assertEqual(self.client.lookup(URL)["status"], "threat")
        with patch.dict(os.environ, {"SAFE_BROWSING_ENABLED": "false"}):
            result = self.client.lookup(URL)
        self.assertEqual(result["status"], "disabled", result)
        self.assertEqual(self.session.get.call_count, 1)

    def test_invalid_key_http_errors_redirects_and_server_errors_never_become_clear(self):
        for index, status in enumerate((400, 401, 403, 404, 500, 502, 301, 302, 307, 308)):
            with self.subTest(status=status):
                self.session.get.return_value = Response(
                    {"error": {"message": KEY + " synthetic private provider detail"}},
                    status=status, headers={"Location": "http://127.0.0.1/private"},
                )
                result = safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/error/{index}")
                self.assert_unavailable(result)
                self.assertNotIn("synthetic private provider detail", json.dumps(result))
        self.assertEqual(self.session.get.call_count, 10)

    def test_timeouts_connection_errors_and_bad_json_are_redacted_without_retry(self):
        for index, error in enumerate((
            requests.Timeout(KEY + " URL=" + URL),
            requests.ConnectionError(KEY + " internal network detail"),
            requests.exceptions.SSLError(KEY + " certificate detail"),
        )):
            with self.subTest(kind=type(error).__name__):
                self.session.get.side_effect = error
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    result = safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/network/{index}")
                self.assert_unavailable(result)
                self.assertNotIn(KEY, output.getvalue())
        self.session.get.side_effect = None
        self.session.get.return_value = Response(chunks=[b'{"bad-json":'])
        self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup("https://ordinary.example/bad-json"))
        self.assertEqual(self.session.get.call_count, 4)

    def test_missing_malformed_or_unbounded_ttl_cannot_report_clear_or_threat(self):
        payloads = [
            {}, {"threats": []}, {"threats": [], "cacheDuration": None},
            {"threats": [], "cacheDuration": "not-duration"},
            {"threats": [], "cacheDuration": "-1s"},
            {"threats": [], "cacheDuration": "NaNs"},
            {"threats": [], "cacheDuration": "infs"},
            {"threats": [], "cacheDuration": "999999999999999999999999999s"},
            {"threats": [{"url": URL, "threatTypes": ["MALWARE"]}]},
        ]
        for index, payload in enumerate(payloads):
            with self.subTest(payload=payload):
                self.session.get.return_value = Response(payload)
                self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/ttl/{index}"))

    def test_malformed_threat_fields_are_not_misread_as_negative_matches(self):
        for index, threats in enumerate((
            None, "MALWARE", {}, [None], ["MALWARE"],
            [{"url": URL}], [{"url": URL, "threatTypes": "MALWARE"}],
            [{"url": URL, "threatTypes": [1]}],
        )):
            with self.subTest(threats=threats):
                self.session.get.return_value = Response({"cacheDuration": "300s", "threats": threats})
                self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup(f"https://ordinary.example/shape/{index}"))

    def test_deeply_nested_json_below_size_limit_fails_closed_without_recursion_crash(self):
        body = b'{"cacheDuration":"60s","extra":' + b'[' * 20000 + b'0' + b']' * 20000 + b'}'
        self.assertLess(len(body), 64 * 1024)
        response = Response(chunks=[body])
        self.session.get.return_value = response
        result = safe_browsing.SafeBrowsingClient().lookup(URL)
        self.assert_unavailable(result)
        self.assertTrue(response.closed)
        self.session.get.assert_called_once()

    def test_unknown_threat_type_does_not_turn_a_provider_match_into_clear(self):
        self.session.get.return_value = self.threat(threat_types=["UNRECOGNIZED_FUTURE_THREAT"])
        result = self.client.lookup(URL)
        self.assertIn(result["status"], ("threat", "unavailable"))
        self.assertNotEqual(result["status"], "clear")

    def test_positive_and_negative_cache_use_exact_fractional_provider_ttl(self):
        for matched in (False, True):
            with self.subTest(matched=matched):
                client = safe_browsing.SafeBrowsingClient()
                self.session.get.return_value = self.threat("2.5s") if matched else Response({
                    "threats": [], "cacheDuration": "2.5s"
                })
                before = self.session.get.call_count
                first = client.lookup(URL)
                self.assertEqual(first["status"], "threat" if matched else "clear")
                self.clock.advance(2.49)
                cached = client.lookup(URL)
                self.assertEqual(cached["status"], first["status"])
                self.assertTrue(cached["cached"])
                self.assertEqual(cached["checked_at"], first["checked_at"])
                self.assertEqual(cached["cache_expires_at"], first["cache_expires_at"])
                self.assertEqual(self.session.get.call_count, before + 1)
                self.clock.advance(.02)
                refreshed = client.lookup(URL)
                self.assertFalse(refreshed["cached"])
                self.assertEqual(self.session.get.call_count, before + 2)

    def test_positive_older_than_thirty_minutes_is_not_reused_or_requeried_before_ttl(self):
        self.session.get.return_value = self.threat("3600s")
        self.assertEqual(self.client.lookup(URL)["status"], "threat")
        self.clock.advance(1801)
        result = self.client.lookup(URL)
        self.assert_unavailable(result)
        self.assertEqual(self.session.get.call_count, 1)
        self.clock.advance(1800)
        self.session.get.return_value = Response()
        self.assertEqual(self.client.lookup(URL)["status"], "clear")
        self.assertEqual(self.session.get.call_count, 2)

    def test_cache_stores_no_raw_submitted_or_provider_returned_urls(self):
        submitted = "https://ordinary.example/private?synthetic-token=do-not-store"
        matched = "https://ordinary.example/"
        self.session.get.return_value = self.threat(matched_url=matched)
        self.assertEqual(self.client.lookup(submitted)["status"], "threat")
        caches = [value for name, value in vars(self.client).items()
                  if "cache" in name.lower() and isinstance(value, dict)]
        self.assertTrue(caches, "Expected an inspectable in-memory cache")
        stored = repr(caches)
        self.assertNotIn(submitted, stored)
        self.assertNotIn(matched, stored)
        self.assertNotIn("do-not-store", stored)
        self.assertNotIn(KEY, stored)

    def test_ten_per_minute_rate_limit_does_not_limit_cache_hits_or_retry_requests(self):
        for index in range(10):
            self.assertEqual(self.client.lookup(f"https://ordinary.example/rate/{index}")["status"], "clear")
        self.assert_unavailable(self.client.lookup("https://ordinary.example/rate/overflow"))
        self.assertEqual(self.session.get.call_count, 10)
        self.assertTrue(self.client.lookup("https://ordinary.example/rate/0")["cached"])
        self.assertEqual(self.session.get.call_count, 10)
        self.clock.advance(61)
        self.assertEqual(self.client.lookup("https://ordinary.example/rate/overflow")["status"], "clear")
        self.assertEqual(self.session.get.call_count, 11)

    def test_retry_after_backoff_blocks_more_requests_then_recovers(self):
        for status in (429, 503):
            with self.subTest(status=status):
                client = safe_browsing.SafeBrowsingClient()
                before = self.session.get.call_count
                self.session.get.return_value = Response(status=status, headers={"Retry-After": "120"})
                self.assert_unavailable(client.lookup(URL))
                self.session.get.return_value = Response()
                self.clock.advance(60)
                self.assert_unavailable(client.lookup("https://ordinary.example/other"))
                self.assertEqual(self.session.get.call_count, before + 1)
                self.clock.advance(61)
                self.assertEqual(client.lookup("https://ordinary.example/other")["status"], "clear")
                self.assertEqual(self.session.get.call_count, before + 2)

    def test_http_date_retry_after_is_honored_without_retries(self):
        date = format_datetime(datetime.fromtimestamp(self.clock.time() + 180, timezone.utc), usegmt=True)
        self.session.get.return_value = Response(status=429, headers={"Retry-After": date})
        self.assert_unavailable(self.client.lookup(URL))
        self.clock.advance(121)
        self.session.get.return_value = Response()
        self.assert_unavailable(self.client.lookup("https://ordinary.example/after-quota"))
        self.session.get.assert_called_once()
        self.clock.advance(60)
        self.assertEqual(self.client.lookup("https://ordinary.example/after-quota")["status"], "clear")
        self.assertEqual(self.session.get.call_count, 2)

    def test_cache_capacity_does_not_evict_unexpired_provider_entries(self):
        self.session.get.return_value = Response({"threats": [], "cacheDuration": "86400s"})
        for index in range(256):
            result = self.client.lookup(f"https://ordinary.example/cache/{index}")
            self.assertEqual(result["status"], "clear", (index, result))
            self.clock.advance(61)
        self.assert_unavailable(self.client.lookup("https://ordinary.example/cache/overflow"))
        self.assertEqual(self.session.get.call_count, 256)
        retained = self.client.lookup("https://ordinary.example/cache/0")
        self.assertEqual(retained["status"], "clear")
        self.assertTrue(retained["cached"])
        self.assertEqual(self.session.get.call_count, 256)

    def test_oversized_stream_is_closed_and_never_treated_as_clear(self):
        response = Response(chunks=[b"x" * 65537, b"must-not-be-read"])
        self.session.get.return_value = response
        self.assert_unavailable(self.client.lookup(URL))
        self.assertTrue(response.closed)
        self.assertEqual(response.reads, 1)

    def test_invalid_or_oversized_content_length_is_rejected_before_stream_read(self):
        for value in ("65537", "-1", "not-a-length"):
            with self.subTest(length=value):
                response = Response(headers={"Content-Length": value})
                self.session.get.return_value = response
                self.assert_unavailable(safe_browsing.SafeBrowsingClient().lookup(URL))
                self.assertEqual(response.reads, 0)
                self.assertTrue(response.closed)

    def test_zero_duration_observation_is_immediately_unavailable(self):
        self.session.get.return_value = Response({"threats": [], "cacheDuration": "0s"})
        self.assert_unavailable(self.client.lookup(URL))

    def test_stream_time_budget_is_bounded_without_artificial_retries(self):
        def slow_chunks():
            self.clock.advance(9)
            yield b'{"threats":[],"cacheDuration":"300s"}'
        response = Response(chunks=slow_chunks())
        self.session.get.return_value = response
        self.assert_unavailable(self.client.lookup(URL))
        self.assertTrue(response.closed)
        self.session.get.assert_called_once()

    def test_second_pending_lookup_returns_without_starting_another_request(self):
        entered = threading.Event()
        release = threading.Event()
        result = []

        def blocked_get(*_, **__):
            entered.set()
            if not release.wait(3):
                raise AssertionError("Test did not release synthetic provider response")
            return Response()

        self.session.get.side_effect = blocked_get
        worker = threading.Thread(target=lambda: result.append(self.client.lookup(URL)))
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assert_unavailable(self.client.lookup("https://ordinary.example/concurrent"))
            self.assertEqual(self.session.get.call_count, 1)
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0]["status"], "clear")

    def test_stored_observation_expiry_downgrades_without_another_network_request(self):
        result = self.client.lookup(URL)
        self.assertEqual(safe_browsing.current_reputation(result)["status"], "clear")
        self.clock.advance(301)
        self.assert_unavailable(safe_browsing.current_reputation(result))
        self.session.get.assert_called_once()

    def test_missing_invalid_or_future_observation_timestamps_are_not_current(self):
        result = self.client.lookup(URL)
        for changed in (
            {"verdict_expires_at": None}, {"checked_at": None},
            {"verdict_expires_at": "not-a-time"},
            {"checked_at": datetime.fromtimestamp(self.clock.time() + 60, timezone.utc).isoformat()},
        ):
            with self.subTest(fields=changed):
                self.assert_unavailable(safe_browsing.current_reputation({**result, **changed}))
        self.session.get.assert_called_once()

    def test_verdict_priority_keeps_offline_warnings_despite_a_negative_provider_result(self):
        clear = self.client.lookup(URL)
        display = safe_browsing.website_verdict("suspicious", clear)
        self.assertEqual(display["code"], "suspicious")
        self.assertEqual(display["tone"], "warning")
        display = safe_browsing.website_verdict("unverified", clear)
        self.assertEqual(display["code"], "no_known_threats")
        self.assertIn("does not", display["explanation"].lower())
        self.assertIn("guarantee", display["explanation"].lower())

    def test_current_threat_takes_priority_but_expired_threat_cannot_be_known_dangerous(self):
        self.session.get.return_value = self.threat("3600s")
        threat = self.client.lookup(URL)
        display = safe_browsing.website_verdict("unverified", threat)
        self.assertEqual(display["code"], "known_dangerous")
        self.assertEqual(display["tone"], "danger")
        self.assertIn("mistakes", display["explanation"])
        self.clock.advance(1801)
        self.assertEqual(safe_browsing.website_verdict("unverified", threat)["code"], "unable_to_verify")
        self.assertEqual(safe_browsing.website_verdict("suspicious", threat)["code"], "suspicious")
        self.session.get.assert_called_once()

    def test_unavailable_or_disabled_provider_never_means_no_known_threats(self):
        for status in ("disabled", "unavailable"):
            with self.subTest(status=status):
                display = safe_browsing.website_verdict("unverified", {"status": status})
                self.assertEqual(display["code"], "unable_to_verify")
                self.assertEqual(display["tone"], "neutral")


class SafeBrowsingWebsiteIntegrationTests(unittest.TestCase):
    """Real ASGI routes, SQLAlchemy, ReportLab; only provider replies are mocked."""
    setUpClass = classmethod(website_harness.WebsiteCheckerTests.setUpClass.__func__)
    tearDownClass = classmethod(website_harness.WebsiteCheckerTests.tearDownClass.__func__)
    token = website_harness.WebsiteCheckerTests.token
    snapshot = website_harness.WebsiteCheckerTests.snapshot
    api = website_harness.WebsiteCheckerTests.api
    scan = website_harness.WebsiteCheckerTests.scan
    check = website_harness.WebsiteCheckerTests.check
    assert_offline = website_harness.WebsiteCheckerTests.assert_offline

    def setUp(self):
        website_harness.WebsiteCheckerTests.setUp(self)
        disabled = patch.dict(os.environ, {"SAFE_BROWSING_ENABLED": "false"})
        disabled.start()
        self.addCleanup(disabled.stop)

    def reputation(self, status, *, age=0, ttl=300):
        now = safe_browsing.time.time()
        iso = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
        return {
            "provider": "Google Safe Browsing", "status": status, "reason": "Synthetic provider fixture",
            "threat_types": ["SOCIAL_ENGINEERING"] if status == "threat" else [],
            "checked_at": iso(now - age) if status in ("threat", "clear") else None,
            "cached": False, "cache_expires_at": iso(now - age + ttl),
            "verdict_expires_at": iso(now - age + min(ttl, 1800) if status == "threat" else now - age + ttl),
        }

    def test_live_match_changes_display_verdict_without_changing_stored_offline_score(self):
        reply = self.reputation("threat")
        with patch.object(self.main.reputation_client, "lookup", return_value=reply) as lookup:
            code, result, _ = self.check(URL)
        self.assertEqual(code, 200, result)
        lookup.assert_called_once_with(URL)
        self.assertEqual(result["live_reputation"]["status"], "threat")
        self.assertEqual(result["website_verdict"]["code"], "known_dangerous")
        self.assertEqual(result["risk_label"], "unverified")
        self.assertIsNone(result["risk_score"])
        self.assertIsNone(result["ml_phishing_probability"])
        with self.database.SessionLocal() as db:
            record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
            self.assertEqual(record.user_id, 1)
            self.assertEqual(record.risk_label, "unverified")
            self.assertIsNone(record.risk_score)
            self.assertEqual(json.loads(record.score_explanation)["live_reputation"]["status"], "threat")
        code, raw, _ = self.api("/history/summary", token=self.token("a@example.test"))
        self.assertEqual(code, 200, raw)
        summary = json.loads(raw)
        self.assertEqual(summary["counts"]["unclassified"], 1)
        self.assertEqual(summary["counts"]["unsafe"], 0)
        self.assert_offline()

    def test_clear_provider_result_cannot_override_existing_impersonation_findings(self):
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("clear")):
            code, result, _ = self.check("http://paypal-login.example.com/verify")
        self.assertEqual(code, 200, result)
        self.assertEqual(result["website_verdict"]["code"], "suspicious")
        self.assertEqual(result["risk_label"], "suspicious")
        self.assertIn("Possible Brand Impersonation", {item["name"] for item in result["risk_breakdown"]})
        self.assert_offline()

    def test_provider_unavailability_is_disclosed_without_a_safe_result(self):
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("unavailable")):
            code, result, _ = self.check(URL)
        self.assertEqual(code, 200, result)
        self.assertEqual(result["website_verdict"]["code"], "unable_to_verify")
        self.assertEqual(result["live_reputation"]["status"], "unavailable")
        self.assertIsNone(result["risk_score"])
        self.assert_offline()

    def test_unauthenticated_and_private_destinations_never_reach_provider(self):
        before = self.snapshot()
        with patch.object(self.main.reputation_client, "lookup", side_effect=AssertionError("Provider must not be called")) as lookup:
            for url in ("http://127.0.0.1/", "http://169.254.169.254/", "file:///etc/passwd"):
                self.assertEqual(self.check(url)[0], 400)
            self.assertIn(self.check(URL, token=None)[0], (401, 403))
        lookup.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assert_offline()

    def test_qr_and_website_checker_share_completed_no_match_semantics_for_normalized_url(self):
        url = "https://www.wikipedia.org"
        clear = self.reputation("clear")
        with patch.object(self.main.reputation_client, "lookup", return_value=clear) as lookup:
            qr = self.scan(url, probability=.5)
            code, website, _ = self.check(url)
        self.assertEqual(code, 200, website)
        self.assertEqual(lookup.call_args_list, [call("https://www.wikipedia.org"), call("https://www.wikipedia.org")])
        for result in (qr, website):
            self.assertEqual(result["live_reputation"]["status"], "clear")
            self.assertEqual(result["website_verdict"]["code"], "no_known_threats")
            self.assertIn("does not", result["website_verdict"]["explanation"])
        self.assertEqual(qr["decoded_content"], url)
        self.assertEqual(qr["final_url"], website["normalized_url"])
        self.assertEqual(qr["offline_verdict"]["code"], "unable_to_verify")
        self.assertEqual(qr["risk_score"], 15)
        self.assertIsNone(website["risk_score"])
        self.assert_offline()

    def test_qr_reputation_is_persisted_and_pdf_uses_current_evidence(self):
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("clear")):
            qr = self.scan("https://www.wikipedia.org", probability=.5)
        with self.database.SessionLocal() as db:
            record = db.query(self.database.ScanRecord).filter_by(id=qr["scan_id"]).one()
            metadata = json.loads(record.score_explanation)
            self.assertEqual(metadata["analysis_source"], "qr")
            self.assertEqual(metadata["offline_risk_label"], "unverified")
            self.assertEqual(metadata["live_reputation"]["status"], "clear")
            with patch.object(self.main.SimpleDocTemplate, "build") as build:
                self.main._build_report(record)
            story = build.call_args.args[0]
            self.assertEqual(story[0].getPlainText(), "No Known Threats Detected")
            report_text = "\n".join(paragraph_xml(story))
            self.assertIn("does not prove a website is safe", report_text)
            self.assertIn("Google Safe Browsing", report_text)

            metadata["live_reputation"] = self.reputation("clear", age=301, ttl=300)
            record.score_explanation = json.dumps(metadata)
            with patch.object(self.main.SimpleDocTemplate, "build") as build:
                self.main._build_report(record)
            self.assertEqual(build.call_args.args[0][0].getPlainText(), "Unable to Verify")
        self.assert_offline()

    def test_known_threat_and_offline_warnings_are_never_downgraded(self):
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("threat")):
            qr = self.scan(URL, probability=.5)
            code, website, _ = self.check(URL)
        self.assertEqual(code, 200, website)
        self.assertEqual(qr["website_verdict"]["code"], "known_dangerous")
        self.assertEqual(website["website_verdict"]["code"], "known_dangerous")
        self.assertEqual(qr["live_reputation"]["threat_types"], ["SOCIAL_ENGINEERING"])

        url = "http://paypal-login.example.com/verify"
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("unavailable")):
            qr = self.scan(url, probability=.5)
            code, website, _ = self.check(url)
        self.assertEqual(code, 200, website)
        self.assertEqual(qr["website_verdict"]["code"], "suspicious")
        self.assertEqual(website["website_verdict"]["code"], "suspicious")
        self.assertEqual(qr["live_reputation"]["status"], "unavailable")
        self.assert_offline()

    def test_qr_disabled_and_unavailable_reputation_never_claims_no_known_threats(self):
        with patch.dict(os.environ, {"SAFE_BROWSING_ENABLED": "false", "GOOGLE_SAFE_BROWSING_API_KEY": KEY}):
            with patch.object(self.main.reputation_client, "_request", side_effect=AssertionError("Disabled checks must not make requests")) as request:
                qr = self.scan(URL, probability=.5)
                code, website, _ = self.check(URL)
        self.assertEqual(code, 200, website)
        self.assertEqual(qr["live_reputation"]["status"], "disabled")
        self.assertEqual(qr["website_verdict"]["code"], "unable_to_verify")
        self.assertEqual(website["website_verdict"]["code"], "unable_to_verify")
        request.assert_not_called()
        self.assert_offline()

        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("unavailable")):
            qr = self.scan(URL, probability=.5)
        self.assertEqual(qr["live_reputation"]["status"], "unavailable")
        self.assertEqual(qr["website_verdict"]["code"], "unable_to_verify")
        self.assert_offline()

    def test_qr_non_url_upi_malformed_and_redirect_services_do_not_trigger_extra_fetches(self):
        with patch.object(self.main.reputation_client, "lookup", side_effect=AssertionError("Non-URL content must not be sent to reputation")) as lookup:
            text = self.scan("private arbitrary QR text")
            upi = self.scan("upi://pay?pa=merchant@upi&pn=Test", real_decode=True)
            malformed = self.scan("https://", expected_status=400)
        lookup.assert_not_called()
        self.assertNotIn("live_reputation", text)
        self.assertNotIn("live_reputation", upi)
        self.assertIn("upi_analysis", upi)
        self.assertIn("detail", malformed)

        redirect_url = "https://q.me-qr.com/synthetic-code"
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("clear")) as lookup:
            qr = self.scan(redirect_url, probability=.5)
        lookup.assert_called_once_with(redirect_url)
        self.assertEqual(qr["final_url"], redirect_url)
        self.assertEqual(qr["redirect_chain"], [redirect_url])
        self.assertFalse(qr["final_url_verified"])
        self.assert_offline()

    def test_qr_embedded_credentials_keep_offline_warning_but_are_rejected_by_reputation_validation(self):
        url = "https://paypal.com@evil.test/verify"
        with patch.dict(os.environ, {"SAFE_BROWSING_ENABLED": "true", "GOOGLE_SAFE_BROWSING_API_KEY": KEY}):
            with patch.object(self.main.reputation_client, "_request", side_effect=AssertionError("Credential URL must not reach Google")) as request:
                qr = self.scan(url, probability=.5)
        request.assert_not_called()
        self.assertEqual(qr["decoded_content"], url)
        self.assertIn("Embedded URL Credentials", {item["name"] for item in qr["risk_breakdown"]})
        self.assertEqual(qr["live_reputation"]["status"], "unavailable")
        self.assertEqual(qr["website_verdict"]["code"], "suspicious")
        self.assert_offline()

    def test_restricted_demo_and_offline_gateway_never_query_reputation_provider(self):
        with patch.dict(os.environ, {
            "QR_SHIELD_MODE": "restricted-demo", "SAFE_BROWSING_ENABLED": "true",
            "GOOGLE_SAFE_BROWSING_API_KEY": KEY,
        }), patch.object(self.main.reputation_client, "_request", side_effect=AssertionError("Restricted demo must remain offline")) as request:
            qr = self.scan(URL, probability=.5)
        self.assertEqual(qr["live_reputation"]["status"], "disabled")
        self.assertIn("Restricted offline demo", qr["live_reputation"]["reason"])
        request.assert_not_called()

        with patch.object(self.main.reputation_client, "lookup", side_effect=AssertionError("Offline gateway must not query Google")) as lookup:
            qr = self.scan(URL, probability=.5, headers=[(b"x-qr-shield-offline", b"1")])
        self.assertEqual(qr["live_reputation"]["status"], "disabled")
        self.assertIn("Public-test gateway", qr["live_reputation"]["reason"])
        lookup.assert_not_called()
        self.assert_offline()

    def test_authenticated_offline_gateway_marker_bypasses_provider_completely(self):
        with patch.object(self.main.reputation_client, "lookup", side_effect=AssertionError("Offline gateway must not query Google")) as lookup:
            code, raw, _ = self.api(
                "/website/check", "POST", self.token("a@example.test"),
                json.dumps({"url": URL}).encode(),
                [(b"content-type", b"application/json"), (b"x-qr-shield-offline", b"1")],
            )
        self.assertEqual(code, 200, raw)
        result = json.loads(raw)
        self.assertEqual(result["live_reputation"]["status"], "disabled")
        self.assertEqual(result["website_verdict"]["code"], "unable_to_verify")
        lookup.assert_not_called()
        self.assert_offline()

    def test_report_uses_current_stored_reputation_then_downgrades_expired_header_without_network(self):
        with patch.object(self.main.reputation_client, "lookup", return_value=self.reputation("threat")):
            code, result, _ = self.check(URL)
        self.assertEqual(code, 200, result)
        with patch.object(self.main.reputation_client, "lookup", side_effect=AssertionError("PDF must not query Google")) as lookup:
            code, pdf, _ = self.api("/report/" + str(result["scan_id"]), token=self.token("a@example.test"))
            self.assertEqual(code, 200)
            self.assertTrue(pdf.startswith(b"%PDF"))
            with self.database.SessionLocal() as db:
                record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
                with patch.object(self.main.SimpleDocTemplate, "build") as build:
                    self.main._build_report(record)
                self.assertEqual(build.call_args.args[0][0].getPlainText(), "Known Dangerous")
                metadata = json.loads(record.score_explanation)
                metadata["live_reputation"] = self.reputation("threat", age=1801, ttl=3600)
                record.score_explanation = json.dumps(metadata)
                with patch.object(self.main.SimpleDocTemplate, "build") as build:
                    self.main._build_report(record)
                self.assertEqual(build.call_args.args[0][0].getPlainText(), "Unable to Verify")
        lookup.assert_not_called()
        self.assert_offline()

    def test_pdf_provider_details_are_xml_escaped_and_actual_pdf_still_builds(self):
        reply = self.reputation("threat")
        reply["reason"] = "<script>alert(1)</script>& synthetic provider detail"
        with patch.object(self.main.reputation_client, "lookup", return_value=reply):
            code, result, _ = self.check(URL)
        self.assertEqual(code, 200, result)
        with self.database.SessionLocal() as db:
            record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
            with patch.object(self.main.SimpleDocTemplate, "build") as build:
                self.main._build_report(record)
            xml = "\n".join(paragraph_xml(build.call_args.args[0]))
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;&amp;", xml)
            self.assertNotIn("<script>alert(1)</script>", xml)
            self.assertIn("Google Safe Browsing", xml)
        with patch.object(self.main.reputation_client, "lookup", side_effect=AssertionError("PDF must not query Google")):
            code, pdf, _ = self.api("/report/" + str(result["scan_id"]), token=self.token("a@example.test"))
        self.assertEqual(code, 200)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assert_offline()

    def test_pdf_attribution_only_applies_to_a_current_google_threat_warning(self):
        fixtures = [
            ("http://paypal-login.example.com/verify", self.reputation("clear"), "Suspicious", False),
            (URL, self.reputation("clear"), "No Known Threats Detected", False),
            (URL, self.reputation("disabled"), "Unable to Verify", False),
            (URL, self.reputation("threat", age=1801, ttl=3600), "Unable to Verify", False),
            (URL, self.reputation("threat"), "Known Dangerous", True),
        ]
        for url, reply, title, attributed in fixtures:
            with self.subTest(title=title, status=reply["status"]):
                with patch.object(self.main.reputation_client, "lookup", return_value=reply):
                    code, result, _ = self.check(url)
                self.assertEqual(code, 200, result)
                with self.database.SessionLocal() as db:
                    record = db.query(self.database.ScanRecord).filter_by(id=result["scan_id"]).one()
                    with patch.object(self.main.SimpleDocTemplate, "build") as build:
                        self.main._build_report(record)
                story = build.call_args.args[0]
                self.assertEqual(story[0].getPlainText(), title)
                xml = "\n".join(paragraph_xml(story))
                self.assertEqual("Advisory provided by Google" in xml, attributed)
        self.assert_offline()


if __name__ == "__main__":
    unittest.main()
