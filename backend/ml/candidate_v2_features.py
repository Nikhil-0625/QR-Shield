"""Stateless candidate ML features, version candidate_lexical_v2.

Designed for Phase 5 Phishing Detection Research:
- NO `has_https` feature: prevents catastrophic HTTPS-only bias.
- Bounded, deterministic extraction without network calls or external I/O.
- Interpretable lexical and structural signals.
- Robust IP address detection.
"""
import ipaddress
import math
import re
from urllib.parse import urlparse, urlsplit

FEATURE_NAMES = (
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question_marks",
    "num_equal",
    "num_underscore",
    "num_slash",
    "has_ip",
    "num_digits",
    "num_subdomains",
    "char_entropy",
    "tld_in_subdomain_or_path",
    "digit_ratio",
)
SCHEMA_VERSION = "candidate_lexical_v2"

COMMON_TLDS = ("com", "net", "org", "gov", "edu", "info", "biz", "online", "live")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon character entropy of a string."""
    if not text:
        return 0.0
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def has_tld_in_subdomain_or_path(url: str, hostname: str, path: str) -> int:
    """Check if top-level domain tokens appear in subdomains or path segments,
    a common deception pattern (e.g. paypal.com.account-verify.xyz/update.html)."""
    if hostname:
        parts = hostname.lower().split(".")
        if len(parts) > 2:
            # Check internal subdomain components (excluding the actual registered domain)
            for part in parts[:-2]:
                if part in COMMON_TLDS:
                    return 1
    if path:
        lower_path = path.lower()
        for tld in COMMON_TLDS:
            if f".{tld}/" in lower_path or f".{tld}?" in lower_path or lower_path.endswith(f".{tld}"):
                return 1
    return 0


def extract_candidate_features(url: str):
    """Extract candidate lexical features from a raw URL string."""
    if not isinstance(url, str) or len(url) > 8192:
        raise ValueError("Expected a bounded URL string (<= 8192 characters)")

    # Scheme-agnostic hostname and path parsing
    clean_url = url if ("://" in url or url.startswith("//")) else "//" + url
    try:
        parsed = urlsplit(clean_url)
        host = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        host = ""
        path = ""

    # IP detection
    has_ip = 0
    if host:
        try:
            has_ip = int(bool(ipaddress.ip_address(host)))
        except (ValueError, TypeError):
            has_ip = 0

    url_len = len(url)
    digits = sum(c.isdigit() for c in url)
    digit_ratio = round(digits / url_len, 4) if url_len > 0 else 0.0

    # Subdomain count
    num_subdomains = 0
    if host and not has_ip:
        dot_count = host.count(".")
        num_subdomains = max(0, dot_count - 1) if dot_count > 1 else 0

    return [
        url_len,
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("_"),
        url.count("/"),
        has_ip,
        digits,
        num_subdomains,
        calculate_entropy(url),
        has_tld_in_subdomain_or_path(url, host, path),
        digit_ratio,
    ]

