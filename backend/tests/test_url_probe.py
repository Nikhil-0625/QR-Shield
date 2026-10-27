"""Focused, mocked tests for DNS-pinned TLS and redirect evidence probes."""
import http.client
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

import url_probe


def target(url):
    scheme = url.split(":", 1)[0]
    host = url.split("/", 3)[2].split(":", 1)[0]
    port = 443 if scheme == "https" else 80
    return url_probe.Target(url, scheme, host, port, host, "/", ((socket.AF_INET, ("8.8.8.8", port)),))


class ImmediateFuture:
    def __init__(self, value):
        self.value = value

    def result(self, timeout=None):
        return self.value

    def done(self):
        return True


class URLProbeTests(unittest.TestCase):
    def test_dns_answers_are_public_and_all_addresses_are_checked(self):
        answer = lambda ip: (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))
        with patch.object(url_probe, "_dns_future", None), \
             patch.object(url_probe._resolver, "submit", return_value=ImmediateFuture([answer("8.8.8.8")])):
            self.assertEqual(url_probe._public_addresses("public.example.net", 443, url_probe.time.monotonic() + 2),
                             ((socket.AF_INET, ("8.8.8.8", 443)),))
        for ips in (["127.0.0.1"], ["10.0.0.1"], ["169.254.169.254"], ["8.8.8.8", "10.0.0.1"]):
            with self.subTest(ips=ips), patch.object(url_probe, "_dns_future", None), \
                 patch.object(url_probe._resolver, "submit", return_value=ImmediateFuture([answer(ip) for ip in ips])), \
                 self.assertRaises(url_probe.ProbeError) as caught:
                url_probe._public_addresses("public.example.net", 443, url_probe.time.monotonic() + 2)
            self.assertEqual(caught.exception.status, "blocked")

    def test_https_valid_certificate_uses_default_verification_and_host_name(self):
        connection = Mock()
        with patch.object(url_probe, "validate_target", return_value=target("https://public.example.net/")), \
             patch.object(url_probe, "_PinnedHTTPSConnection", return_value=connection) as factory:
            result = url_probe.check_https("https://public.example.net/")
        self.assertEqual(result["status"], "completed")
        self.assertIs(result["valid"], True)
        factory.assert_called_once()
        connection.connect.assert_called_once()
        connection.close.assert_called_once()

    def test_invalid_or_mismatched_certificate_fails_without_bypassing_verification(self):
        connection = url_probe._PinnedHTTPSConnection(
            target("https://public.example.net/"), url_probe.time.monotonic() + 2
        )
        with patch.object(url_probe, "validate_target", return_value=target("https://public.example.net/")), \
             patch.object(connection, "connect", side_effect=ssl.SSLCertVerificationError("synthetic")), \
             patch.object(url_probe, "_PinnedHTTPSConnection", return_value=connection):
            result = url_probe.check_https("https://public.example.net/")
        self.assertEqual(result["status"], "failed")
        self.assertIs(result["valid"], False)
        created = connection._context
        self.assertEqual(created.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(created.check_hostname)

    def test_pinned_tls_connection_uses_numeric_peer_and_original_hostname_for_sni(self):
        connection = url_probe._PinnedHTTPSConnection(
            target("https://public.example.net/"), url_probe.time.monotonic() + 2
        )
        raw = Mock()
        tls = Mock()
        with patch.object(url_probe, "_open_raw_socket", return_value=raw), \
             patch.object(connection._context, "wrap_socket", return_value=tls) as wrap:
            connection.connect()
        self.assertIs(connection.sock, tls)
        wrap.assert_called_once_with(raw, server_hostname="public.example.net")


    def test_http_tls_is_not_applicable_and_does_not_resolve(self):
        with patch.object(url_probe, "validate_target", side_effect=AssertionError("HTTP has no TLS check")):
            result = url_probe.check_https("http://public.example.net/")
        self.assertEqual(result["status"], "not_applicable")
        self.assertIsNone(result["valid"])

    def test_tls_timeout_and_network_failure_are_unavailable_not_valid(self):
        connection = Mock()
        connection.connect.side_effect = TimeoutError("synthetic")
        with patch.object(url_probe, "validate_target", return_value=target("https://public.example.net/")), \
             patch.object(url_probe, "_PinnedHTTPSConnection", return_value=connection):
            result = url_probe.check_https("https://public.example.net/")
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["valid"])

    def _trace(self, responses, *, max_hops=5, blocked=None):
        def validated(url, deadline):
            if blocked and url == blocked:
                raise url_probe.ProbeError("blocked", "The destination resolves to a non-public address.")
            return target(url)
        with patch.object(url_probe, "validate_target", side_effect=validated), \
             patch.object(url_probe, "_request_headers", side_effect=responses) as request:
            result = url_probe.trace_redirects("https://public.example.net/start", max_hops=max_hops)
        return result, request

    def test_zero_one_and_multiple_redirects_report_observed_final_destination(self):
        zero, _ = self._trace([(200, None, "HEAD")])
        self.assertEqual((zero["status"], zero["redirect_count"], zero["final_url"]),
                         ("completed", 0, "https://public.example.net/start"))
        one, _ = self._trace([(302, "/next", "HEAD"), (200, None, "HEAD")])
        self.assertEqual((one["status"], one["redirect_count"], len(one["chain"])), ("completed", 1, 2))
        many, _ = self._trace([(301, "/one", "HEAD"), (307, "/two", "HEAD"), (200, None, "HEAD")])
        self.assertEqual((many["status"], many["redirect_count"], many["final_url"]),
                         ("completed", 2, "https://public.example.net/two"))
        self.assertEqual([hop["status_code"] for hop in many["hops"]], [301, 307])

    def test_redirect_limit_blocks_sixth_destination_without_claiming_zero(self):
        responses = [(302, f"/hop{i}", "HEAD") for i in range(1, 7)]
        result, request = self._trace(responses)
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["redirect_count"])
        self.assertEqual(result["observed_redirects"], 6)
        self.assertEqual(request.call_count, 6)
        self.assertEqual(result["chain"][-1], "https://public.example.net/hop5")

    def test_private_and_non_http_redirects_are_blocked_before_request(self):
        result, request = self._trace([(302, "http://127.0.0.1/admin", "HEAD")],
                                      blocked="http://127.0.0.1/admin")
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["redirect_count"])
        self.assertEqual(request.call_count, 1)
        result, request = self._trace([(302, "javascript:alert(1)", "HEAD")],
                                      blocked="javascript:alert(1)")
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["redirect_count"])
        self.assertEqual(request.call_count, 1)

    def test_timeout_and_failed_redirect_checks_never_report_zero(self):
        result, _ = self._trace([url_probe.ProbeError("unavailable", "synthetic timeout")])
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["redirect_count"])

    def test_head_falls_back_to_range_get_without_reading_response_body(self):
        class FakeResponse:
            def __init__(self, status, headers=()):
                self.status = status
                self.headers = list(headers)

            def getheaders(self):
                return self.headers

            def read(self, *_args, **_kwargs):
                raise AssertionError("Response bodies must not be read")

        class FakeConnection:
            def __init__(self, response):
                self.response = response
                self.requests = []
                self.sock = None

            def request(self, *args, **kwargs):
                self.requests.append((args, kwargs))

            def getresponse(self):
                return self.response

            def close(self):
                pass

        head = FakeConnection(FakeResponse(405))
        get = FakeConnection(FakeResponse(302, [("Location", "/next")]))
        with patch.object(url_probe, "_connection", side_effect=[head, get]):
            code, location, method = url_probe._request_headers(
                target("https://public.example.net/"), url_probe.time.monotonic() + 2
            )
        self.assertEqual((code, location, method), (302, "/next", "GET"))
        self.assertEqual(head.requests[0][0][0], "HEAD")
        self.assertEqual(get.requests[0][0][0], "GET")
        self.assertEqual(get.requests[0][1]["headers"]["Range"], "bytes=0-0")

    def test_offline_gate_does_not_resolve_or_connect(self):
        with patch.object(url_probe, "validate_target", side_effect=AssertionError("offline DNS forbidden")), \
             patch.object(url_probe, "_request_headers", side_effect=AssertionError("offline HTTP forbidden")):
            result = url_probe.trace_redirects("https://public.example.net/", allow_network=False)
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["redirect_count"])


if __name__ == "__main__":
    unittest.main()
