import unittest
from unittest.mock import patch

import main
from brand_config import LOOKALIKE_SIMILARITY_THRESHOLD, PROTECTED_BRANDS


class BrandDetectionTests(unittest.TestCase):
    def test_official_domains_and_subdomains_are_not_lookalikes(self):
        legitimate_domains = [
            "paypal.com",
            "www.paypal.com",
            "google.com",
            "accounts.google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
        ]
        for domain in legitimate_domains:
            with self.subTest(domain=domain):
                self.assertEqual(main.check_lookalike(domain), (None, 0))

    def test_normalizes_url_hostname_case_www_trailing_dot_and_port(self):
        self.assertEqual(
            main.check_lookalike("HTTPS://WWW.PAYPAL.COM.:443/login?next=account"),
            (None, 0),
        )

    def test_domain_boundary_attack_is_not_allowlisted_or_matched(self):
        for domain in ["paypal.com.attacker.test", "fakepaypal.com"]:
            with self.subTest(domain=domain):
                brand, similarity = main.check_lookalike(domain)
                self.assertIsNone(brand)
                self.assertLess(similarity, LOOKALIKE_SIMILARITY_THRESHOLD)

    def test_typo_domains_match_brand_and_similarity_without_network(self):
        cases = [
            ("paypa1-login.example", "PayPal"),
            ("micros0ft-security.example", "Microsoft"),
            ("amaz0n-account.example", "Amazon"),
        ]
        with patch.object(main.requests, "get", side_effect=AssertionError("network request")):
            with patch.object(main.socket, "getaddrinfo", side_effect=AssertionError("DNS lookup")):
                for hostname, expected_brand in cases:
                    with self.subTest(hostname=hostname):
                        brand, similarity = main.check_lookalike(hostname)
                        self.assertEqual(brand, expected_brand)
                        self.assertGreaterEqual(similarity, LOOKALIKE_SIMILARITY_THRESHOLD)

    def test_lookalike_contribution_uses_existing_penalty_and_explanation(self):
        brand, similarity = main.check_lookalike("paypa1-login.example")
        self.assertEqual(brand, "PayPal")
        self.assertGreaterEqual(similarity, LOOKALIKE_SIMILARITY_THRESHOLD)

        rule_score, breakdown = main.calculate_rule_contributions(
            domain_age=365,
            https_valid=True,
            brand_match=brand,
            chain=["https://paypa1-login.example"],
            final_url="https://paypa1-login.example",
        )

        self.assertEqual(rule_score, 25)
        self.assertEqual(breakdown, [{
            "source": "rule",
            "name": "Possible Brand Impersonation",
            "points": 25,
            "reason": (
                "The domain resembles the protected brand PayPal "
                "but is not an official PayPal domain."
            ),
        }])

    def test_unrelated_hostname_has_no_match(self):
        brand, similarity = main.check_lookalike("unrelated-service.example")
        self.assertIsNone(brand)
        self.assertLess(similarity, LOOKALIKE_SIMILARITY_THRESHOLD)

    def test_all_existing_protected_tokens_remain_configured(self):
        configured_tokens = {brand["token"] for brand in PROTECTED_BRANDS}
        self.assertTrue({
            "paytm", "phonepe", "googlepay", "amazon", "flipkart", "paypal",
            "fedex", "bookmyshow", "google", "gmail", "youtube", "microsoft",
            "apple", "facebook", "instagram", "whatsapp", "twitter", "linkedin",
            "netflix", "myntra", "zomato", "swiggy", "ola", "uber", "sbi",
            "icicibank", "hdfcbank", "axisbank", "kotak", "irctc", "uidai",
            "incometax", "anthropic", "openai", "github", "adobe", "spotify",
            "hotstar", "airtel", "jio", "vodafone", "hsbc", "zerodha", "groww",
            "upstox", "dream11", "indiapost", "epfo", "reddit", "pinterest",
            "snapchat", "telegram", "discord", "wikipedia", "ebay", "makemytrip",
            "goibibo", "yatra", "policybazaar", "lic", "bajajfinserv", "indigo",
        } <= configured_tokens)


if __name__ == "__main__":
    unittest.main()
