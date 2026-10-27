"""Stateless production-compatible features, version production_lexical_v1.

Matches main.py's current extractor, NOT the notebook's legacy IP regex.
No URL normalization: scheme-less IPv4 has has_ip=0; HTTPS matching remains
case-sensitive, and dot/subdomain counts include the complete input string.
This preserves the current contract without importing the application.
"""
import ipaddress
from urllib.parse import urlparse

FEATURE_NAMES = (
    "url_length", "has_https", "num_dots", "num_hyphens", "num_at",
    "num_question_marks", "num_equal", "num_underscore", "num_slash",
    "has_ip", "num_digits", "num_subdomains",
)
SCHEMA_VERSION = "production_lexical_v1"


def feature_vector(url):
    if not isinstance(url, str) or len(url) > 8192:
        raise ValueError("Expected a bounded URL string")
    try:
        hostname = urlparse(url).hostname
        has_ip = int(bool(hostname) and bool(ipaddress.ip_address(hostname)))
    except (ValueError, TypeError):
        has_ip = 0
    return [len(url), int(url.startswith("https")), url.count("."), url.count("-"),
            url.count("@"), url.count("?"), url.count("="), url.count("_"),
            url.count("/"), has_ip, sum(c.isdigit() for c in url),
            url.count(".")-1 if url.count(".") > 1 else 0]
