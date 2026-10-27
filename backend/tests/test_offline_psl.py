"""Synthetic PSL prerequisite checks; never log hostname values."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from offline_psl import OfflineDomainParser
finally:
    sys.path.pop(0)


class OfflinePslTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyaddr", "socket.gethostbyname", "socket.gethostbyname_ex"):
            guard = patch(name, side_effect=AssertionError("Network operation forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.parser = OfflineDomainParser()

    def test_multi_level_suffix(self):
        self.assertTrue(self.parser.group("x.merchant.co.uk") == "domain:merchant.co.uk")

    def test_private_suffix(self):
        self.assertTrue(self.parser.group("x.merchant.blogspot.com") == "domain:merchant.blogspot.com")

    def test_wildcard(self):
        self.assertTrue(self.parser.group("x.y.ck") == "domain:x.y.ck")

    def test_exception(self):
        self.assertTrue(self.parser.group("x.www.ck") == "domain:www.ck")

    def test_ips_bypass_psl_without_dns(self):
        with patch.object(self.parser.psl, "get_sld", side_effect=AssertionError("IP passed to PSL")), patch.object(self.parser.psl, "get_tld", side_effect=AssertionError("IP passed to PSL")):
            self.assertTrue(self.parser.group("192.0.2.1") == "ip:192.0.2.1")
            self.assertTrue(self.parser.group("2001:db8::1") == "ip:2001:db8::1")

    def test_nonregistrable_or_unknown_suffix_rejected(self):
        for host in ("co.uk", "y.ck", "local", "merchant.invalid"):
            with self.assertRaises(ValueError):
                self.parser.group(host)


if __name__ == "__main__":
    unittest.main()
