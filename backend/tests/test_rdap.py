"""Registration security tests. Every provider/DNS/socket operation is mocked."""
from datetime import datetime, timedelta, timezone
import io
import json
import os
import socket
import ssl
import time
import unittest
from unittest.mock import Mock, patch

import rdap

DOMAIN = "wikipedia.org"
SERVICE = "https://rdap.registry.org/rdap/"
BOOTSTRAP = {"services": [[["org"], [SERVICE]], [["com"], ["https://rdap.registry.com/"]]]}


def observation(domain=DOMAIN, days=42):
    return {"objectClassName": "domain", "ldhName": domain, "events": [
        {"eventAction": "registration", "eventDate": (datetime.now(timezone.utc)-timedelta(days=days)).isoformat()}]}


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"RDAP_ENABLED": "true", "QR_SHIELD_MODE": "development"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.client = rdap.RdapClient()
        self.fetch = patch.object(rdap, "_fetch_json", side_effect=lambda url, *_: BOOTSTRAP if url == rdap.BOOTSTRAP else observation())
        self.request = self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def test_valid_registration_and_exact_aware_age(self):
        now = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
        data = {"objectClassName":"domain","ldhName":DOMAIN,"events":[
            {"eventAction":"registration","eventDate":"2026-10-01T17:30:00+05:30"},
            {"eventAction":"last changed","eventDate":"2026-10-25T12:00:00Z"}]}
        self.assertEqual(rdap._registration(data, DOMAIN, now), ("2026-10-01T12:00:00+00:00", 25))
        result = self.client.lookup("https://www.wikipedia.org/wiki/private?token=not-sent")
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["domain_age_days"], 42)
        self.assertEqual(self.request.call_args_list[1].args[0], SERVICE+"domain/"+DOMAIN)
        self.assertNotIn("token", str(self.request.call_args_list))

    def test_available_result_exposes_only_rdap_metadata_that_is_present(self):
        data = observation()
        data["events"].append({"eventAction": "expiration", "eventDate": "2030-01-02T03:04:05Z"})
        data["status"] = ["client transfer prohibited"]
        data["entities"] = [{"roles": ["registrar"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "Example Registrar"]
        ]]}]
        self.request.side_effect = [BOOTSTRAP, data]
        result = rdap.RdapClient().lookup(DOMAIN)
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["registered_domain"], DOMAIN)
        self.assertEqual(result["registration_provider"], "rdap.registry.org")
        self.assertEqual(result["registration_date"], data["events"][0]["eventDate"].replace("Z", "+00:00"))
        self.assertEqual(result["expiration_date"], "2030-01-02T03:04:05+00:00")
        self.assertEqual(result["domain_status"], ["client transfer prohibited"])
        self.assertEqual(result["registrar"], "Example Registrar")

    def test_optional_malformed_registration_fields_are_not_invented(self):
        data = observation()
        data["events"].append({"eventAction": "expiration", "eventDate": "not-a-date"})
        data["status"] = "not-an-array"
        data["entities"] = [{"roles": ["registrar"], "vcardArray": ["vcard", []]}]
        self.request.side_effect = [BOOTSTRAP, data]
        result = rdap.RdapClient().lookup(DOMAIN)
        self.assertEqual(result["status"], "available")
        self.assertIsNone(result["expiration_date"])
        self.assertIsNone(result["domain_status"])
        self.assertIsNone(result["registrar"])

    def test_disabled_results_have_explicit_optional_fields(self):
        with patch.dict(os.environ, {"RDAP_ENABLED": "false"}):
            disabled = rdap.RdapClient().lookup(DOMAIN)
        self.assertEqual(disabled["status"], "disabled")
        for field in ("registration_provider", "registration_date", "expiration_date", "domain_status", "registrar"):
            self.assertIsNone(disabled[field])

    def test_missing_registration_never_uses_updated_or_expiry(self):
        for events in [[], [{"eventAction":"last changed","eventDate":"2001-01-01T00:00:00Z"}],
                       [{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]]:
            with self.subTest(events=events):
                self.client = rdap.RdapClient()
                data = observation();data["events"] = events
                self.request.side_effect = [BOOTSTRAP, data]
                result = self.client.lookup(DOMAIN)
                self.assertEqual(result["status"], "unavailable")
                self.assertIsNone(result["domain_age_days"])

    def test_bad_future_naive_conflicting_and_wrong_domain_data(self):
        cases = [
            {"events":[{"eventAction":"registration","eventDate":"2099-01-01T00:00:00Z"}]},
            {"events":[{"eventAction":"registration","eventDate":"2001-01-01"}]},
            {"events":[{"eventAction":"registration","eventDate":"invalid"}]},
            {"events":[{"eventAction":"registration","eventDate":"20010101X000000+0000"}]},
            {"events":[{"eventAction":"registration","eventDate":"2001-01-01T00:00:00Z"},
                       {"eventAction":"registration","eventDate":"2002-01-01T00:00:00Z"}]},
            {"ldhName":"other.org"}, {"objectClassName":"entity"}, {"events":None}]
        for changes in cases:
            with self.subTest(changes=changes):
                self.request.side_effect = [BOOTSTRAP, {**observation(), **changes}]
                self.assertEqual(rdap.RdapClient().lookup(DOMAIN)["status"], "unavailable")

    def test_offline_and_disabled_override_cached_results_without_io(self):
        self.assertEqual(self.client.lookup(DOMAIN)["status"], "available")
        self.request.reset_mock()
        for environment in [{"QR_SHIELD_MODE":"restricted-demo"}, {"RDAP_ENABLED":"false"}]:
            with patch.dict(os.environ, environment), patch.object(rdap.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                result = self.client.lookup(DOMAIN)
                self.assertEqual(result["status"], "disabled")
                self.assertIsNone(result["domain_age_days"])
        self.request.assert_not_called()

    def test_nonpublic_reserved_ip_and_non_url_content_never_requests(self):
        for value in ["http://127.0.0.1/", "http://10.1.2.3/", "https://[::1]/", "https://8.8.8.8/",
                      "localhost", "printer.internal", "https://db.local/", "http://host.home.arpa/",
                      "https://example.test/", "https://example.com/", "not a url",
                      "upi://pay?pa=demo@upi", "https://metadata.google.internal/"]:
            with self.subTest(value=value):
                self.assertEqual(self.client.lookup(value)["status"], "not_applicable")
        self.request.assert_not_called()

    def test_timeout_and_provider_error_are_generic_and_negative_cached(self):
        for error in [socket.timeout("private details"), OSError("private socket"), ValueError("private body")]:
            self.request.side_effect = error
            client = rdap.RdapClient()
            result = client.lookup(DOMAIN)
            self.assertEqual(result["status"], "unavailable")
            self.assertNotIn("private", json.dumps(result))
            self.request.reset_mock()
            self.assertTrue(client.lookup(DOMAIN)["cached"])
            self.request.assert_not_called()

    def test_positive_cache_bootstrap_retention_and_rate_limit_are_bounded(self):
        one = self.client.lookup("https://en.wikipedia.org/wiki/A")
        two = self.client.lookup("https://www.wikipedia.org/wiki/B")
        self.assertFalse(one["cached"]);self.assertTrue(two["cached"])
        self.assertEqual(self.request.call_count, 2)
        self.assertLessEqual(next(iter(self.client.cache.values()))[0]-time.monotonic(), 3600)
        self.assertNotIn(DOMAIN, str(self.client.cache.keys()))
        self.client.events.extend([time.monotonic()]*10)
        self.request.reset_mock()
        self.assertEqual(self.client.lookup("other.org")["status"], "unavailable")
        self.request.assert_not_called()
        self.client.cache={str(i):(time.monotonic()+60, {}) for i in range(rdap.MAX_CACHE)}
        self.client.events.clear()
        self.assertEqual(self.client.lookup("other.org")["status"], "unavailable")
        self.request.assert_not_called()

    def test_quota_backoff_and_busy_fail_without_extra_requests(self):
        self.request.side_effect=rdap.ProviderLimited(120)
        self.assertEqual(self.client.lookup(DOMAIN)["status"], "unavailable")
        self.assertGreater(self.client.retry_at, time.monotonic()+119)
        self.request.reset_mock()
        self.assertEqual(self.client.lookup("other.org")["status"], "unavailable")
        self.request.assert_not_called()
        self.client.lock.acquire()
        try:self.assertEqual(self.client.lookup("third.org")["status"], "unavailable")
        finally:self.client.lock.release()

    def test_bootstrap_is_fixed_and_unsafe_cached_endpoint_is_revalidated(self):
        self.client.bootstrap={"org":["http://127.0.0.1/"]}
        self.client.bootstrap_until=time.monotonic()+60
        self.assertEqual(self.client.lookup(DOMAIN)["status"], "unavailable")
        self.request.assert_not_called()
        self.request.side_effect=[{"services":[[["org"],["http://insecure.org/"]]]}]
        self.assertEqual(rdap.RdapClient().lookup(DOMAIN)["status"], "unavailable")
        self.assertEqual(self.request.call_args.args[0], rdap.BOOTSTRAP)


class TransportTests(unittest.TestCase):
    def test_only_secure_well_formed_endpoints(self):
        for url in ["http://registry.org/", "https://name:secret@registry.org/", "https://registry.org:8443/",
                    "https://127.0.0.1/", "https://[::1]/", "https://localhost/", "https://registry.internal/",
                    "https://registry.org/?next=private", "https://registry.org/#fragment",
                    "https://registry.org/../private", "https://registry.org/%2e%2e/"]:
            with self.subTest(url=url), self.assertRaises((rdap.LookupUnavailable, ValueError)):
                rdap._endpoint(url)

    def test_dns_mixed_private_and_rebinding_addresses_are_rejected(self):
        def answer(ip):return (socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,"",(ip,443))
        for ips in [["127.0.0.1"],["10.0.0.1"],["169.254.169.254"],["8.8.8.8","10.0.0.1"],["224.0.0.1"]]:
            future=Mock();future.result.return_value=[answer(ip) for ip in ips];future.done.return_value=True
            with patch.object(rdap,"_dns_future",None), patch.object(rdap._resolver,"submit",return_value=future), self.assertRaises(rdap.LookupUnavailable):
                rdap._public_addresses("registry.org",time.monotonic()+8)

    def test_connection_pins_numeric_ip_and_keeps_tls_hostname_validation(self):
        raw=Mock();tls=Mock()
        connection=rdap._PinnedHTTPS("rdap.registry.org",time.monotonic()+8)
        self.assertEqual(connection._context.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(connection._context.check_hostname)
        with patch.object(rdap,"_public_addresses",return_value=[(socket.AF_INET,("8.8.8.8",443))]) as resolve, \
             patch.object(rdap.socket,"socket",return_value=raw), \
             patch.object(connection._context,"wrap_socket",return_value=tls) as wrap:
            connection.connect()
        resolve.assert_called_once()
        raw.connect.assert_called_once_with(("8.8.8.8",443))
        wrap.assert_called_once_with(raw,server_hostname="rdap.registry.org")

    def test_dns_timeout_does_not_queue_or_create_more_resolver_jobs(self):
        future=Mock();future.done.return_value=False;future.result.side_effect=rdap.FutureTimeout()
        with patch.object(rdap,"_dns_future",None),patch.object(rdap._resolver,"submit",return_value=future) as submit:
            for _ in range(2):
                with self.assertRaises(rdap.LookupUnavailable):rdap._public_addresses("registry.org",time.monotonic()+8)
            submit.assert_called_once()

    def fetch(self, body=b'{}', headers=None, status=200, limit=1024):
        response=Mock();response.status=status
        values={"Content-Type":"application/rdap+json","Content-Length":str(len(body)),**(headers or {})}
        response.getheader.side_effect=lambda key,default=None:values.get(key,default)
        response.read1.side_effect=[body,b""]
        connection=Mock()
        connection.getresponse.return_value=response
        with patch.object(rdap,"_PinnedHTTPS",return_value=connection):
            result=rdap._fetch_json(SERVICE+"domain/"+DOMAIN,limit,time.monotonic()+8)
        return result,connection,response

    def test_valid_utf8_identity_json_and_no_proxy_or_redirect_client(self):
        result,connection,_=self.fetch(b'{"events":[]}')
        self.assertEqual(result,{"events":[]})
        args=connection.request.call_args
        self.assertEqual(args.args[:2],("GET","/rdap/domain/"+DOMAIN))
        self.assertEqual(args.kwargs["headers"]["Accept-Encoding"],"identity")
        connection.close.assert_called()

    def test_redirects_api_errors_malformed_encoding_json_and_sizes_fail(self):
        cases=[
            {"status":301},{"status":302},{"status":404},{"status":403},{"status":500},
            {"body":b"\xff"},{"body":b"{"},{"body":b"[]"},
            {"body":b'{"events":[],"events":[]}'},{"body":b'{"events":NaN}'},
            {"headers":{"Content-Type":"text/html"}},
            {"headers":{"Content-Encoding":"gzip"}},
            {"headers":{"Content-Length":"999999"}},
            {"headers":{"Content-Length":"12"}}, # Truncated framing cannot be accepted as JSON.
            {"body":b"x"*1025},
        ]
        for values in cases:
            with self.subTest(values={key:(len(value) if key=="body" else value) for key,value in values.items()}), self.assertRaises((rdap.LookupUnavailable,ValueError,UnicodeError)):
                self.fetch(**values)

    def test_quota_errors_preserve_bounded_backoff(self):
        for status in [429,503]:
            with self.subTest(status=status),self.assertRaises(rdap.ProviderLimited) as error:
                self.fetch(status=status,headers={"Retry-After":"120"})
            self.assertEqual(error.exception.delay,120)

    def test_total_deadline_watchdog_closes_a_slow_response_socket(self):
        response=Mock(status=200)
        response.getheader.side_effect=lambda key,default=None:{"Content-Type":"application/json","Content-Length":"2"}.get(key,default)
        response.read1.side_effect=[b"{}",b""]
        connection=Mock();connection.getresponse.return_value=response
        timer=Mock()
        with patch.object(rdap,"_PinnedHTTPS",return_value=connection),patch.object(rdap.threading,"Timer",return_value=timer) as factory:
            rdap._fetch_json(SERVICE+"domain/"+DOMAIN,1024,time.monotonic()+8)
            delay,expire=factory.call_args.args
            self.assertGreater(delay,0);self.assertLessEqual(delay,8)
            timer.start.assert_called_once();timer.cancel.assert_called_once()
            expire()
            connection.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)

    def test_bootstrap_skips_unrelated_insecure_services_without_using_them(self):
        client=rdap.RdapClient()
        data={"services":[[["bad"],["http://insecure.bad/"]],[["org"],[SERVICE]]]}
        with patch.object(rdap,"_fetch_json",side_effect=[data,observation()]) as request,patch.dict(os.environ,{"RDAP_ENABLED":"true","QR_SHIELD_MODE":"development"}):
            self.assertEqual(client.lookup(DOMAIN)["status"],"available")
        self.assertEqual(request.call_args_list[0].args[0],rdap.BOOTSTRAP)
        self.assertEqual(request.call_args_list[1].args[0],SERVICE+"domain/"+DOMAIN)


if __name__=="__main__":unittest.main()
