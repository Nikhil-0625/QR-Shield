import unittest
from unittest.mock import patch

import main
from brand_config import LOOKALIKE_SIMILARITY_THRESHOLD, PROTECTED_BRANDS
from url_security import official_host


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

    def test_incidental_substring_is_not_a_brand_match(self):
        for domain in ["fakepaypal.com"]:
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
        self.assertEqual(len(breakdown), 1)
        self.assertEqual(breakdown[0]['name'], 'Possible Brand Impersonation')
        self.assertEqual(breakdown[0]['points'], 25)
        self.assertIn('paypa1-login.example', breakdown[0]['reason'])
        self.assertIn('not an official PayPal domain', breakdown[0]['reason'])

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

    # --- Task 1 Regression Tests: International Brand Domains ---

    def test_international_regional_domains_recognized_as_official(self):
        official_regional_domains = [
            "amazon.co.uk",
            "amazon.de",
            "amazon.fr",
            "amazon.ca",
            "amazon.it",
            "amazon.es",
            "google.co.uk",
            "google.de",
            "google.fr",
            "google.co.in",
            "google.ca",
            "google.com.au",
            "paypal.co.uk",
            "paypal.de",
            "paypal.fr",
            "paypal.ca",
            "paypal.com.au",
            "paypal.in",
            "apple.co.uk",
            "apple.in",
            "apple.de",
            "apple.ca",
            "microsoft.co.uk",
            "microsoft.in",
            "microsoft.de",
            "bing.com",
            "office365.com",
            "outlook.com",
            "commons.wikimedia.org",
            "wikidata.org",
            "ebay.co.uk",
            "ebay.de",
        ]
        for domain in official_regional_domains:
            with self.subTest(domain=domain):
                brand, score = main.check_lookalike(domain)
                self.assertIsNone(brand, f"{domain} should be recognized as official, got {brand}")
                self.assertEqual(score, 0)

    def test_regional_domain_impersonation_detected(self):
        regional_phishing_cases = [
            ("amaz0n.co.uk", "Amazon"),
            ("amazon-security-update.co.uk", "Amazon"),
            ("google-login.co.uk", "Google"),
            ("paypa1.co.uk", "PayPal"),
            ("paypal-security.co.uk", "PayPal"),
            ("apple-security.co.uk", "Apple"),
            ("micros0ft.co.uk", "Microsoft"),
        ]
        for hostname, expected_brand in regional_phishing_cases:
            with self.subTest(hostname=hostname):
                brand, score = main.check_lookalike(hostname)
                self.assertEqual(brand, expected_brand, f"Failed to detect lookalike for {hostname}")
                self.assertGreaterEqual(score, LOOKALIKE_SIMILARITY_THRESHOLD)

    def test_domain_boundary_attack_is_not_allowlisted_or_matched(self):
        for evil_host in ["fake-amazon.co.uk", "notgoogle.de", "fake-paypal.ca"]:
            with self.subTest(evil_host=evil_host):
                self.assertFalse(official_host(evil_host))

    # --- Task 2 Regression Tests: Short Brands and Common Words ---

    def test_short_brands_and_common_words_avoid_false_positives(self):
        unrelated_legitimate = [
            "lic.concordia.ca",
            "lic.wisc.edu",
            "lic.asn.au",
            "chapters.indigo.ca",
            "indigo.ca",
            "ola.terra.com.br",
            "radio-ola.es",
            "ups.edu.ec",
        ]
        for host in unrelated_legitimate:
            with self.subTest(host=host):
                brand, score = main.check_lookalike(host)
                self.assertIsNone(brand, f"{host} was falsely flagged as {brand} (score={score})")

    def test_short_brands_and_common_words_impersonations_detected(self):
        genuine_phishing = [
            ("lic-policy.com", "LIC"),
            ("lic-login.com", "LIC"),
            ("licindia-online.com", "LIC"),
            ("licindia.org", "LIC"),
            ("olacabs-support.com", "Ola"),
            ("ola-cabs.xyz", "Ola"),
            ("ola-driver.com", "Ola"),
            ("indigo-airlines.com", "IndiGo"),
            ("goindigo-flights.com", "IndiGo"),
            ("goindigo-booking.com", "IndiGo"),
            ("sbi-yono.com", "State Bank of India"),
            ("onlinesbi-banking.com", "State Bank of India"),
            ("ups-tracking.com", "UPS"),
        ]
        for host, expected_brand in genuine_phishing:
            with self.subTest(host=host):
                brand, score = main.check_lookalike(host)
                self.assertEqual(brand, expected_brand, f"Failed to detect {expected_brand} on {host}")
                self.assertGreaterEqual(score, LOOKALIKE_SIMILARITY_THRESHOLD)

    # --- Task 3 Regression Tests: Separate Transport Security from Phishing ---

    def test_transport_security_separated_from_phishing_verdict(self):
        # 1. Plain HTTP without phishing indicators
        http_clean = main._analyze_url("http://ordinary.example/", include_ml=False)
        self.assertEqual(http_clean["risk_label"], "unverified")
        self.assertIn("HTTP Connection", [f["name"] for f in http_clean["risk_breakdown"]])
        self.assertEqual(len([f for f in http_clean["risk_breakdown"] if f["name"] != "HTTP Connection"]), 0)

        # 2. Plain HTTP alongside brand impersonation
        http_phish = main._analyze_url("http://paypa1-login.example/verify", include_ml=False)
        self.assertEqual(http_phish["risk_label"], "suspicious")
        rule_names = {f["name"] for f in http_phish["risk_breakdown"]}
        self.assertIn("HTTP Connection", rule_names)
        self.assertIn("Possible Brand Impersonation", rule_names)


if __name__ == "__main__":
    unittest.main()
