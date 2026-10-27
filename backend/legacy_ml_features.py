"""Notebook-compatible lexical features, NOT URL security validation.

Do not use the legacy IP regex to authorize network access or assess host safety.
No parsing, normalization, DNS resolution, or network access is performed.
"""
import re


FEATURE_NAMES = (
    "url_length", "has_https", "num_dots", "num_hyphens", "num_at",
    "num_question_marks", "num_equal", "num_underscore", "num_slash",
    "has_ip", "num_digits", "num_subdomains",
)


def extract_legacy_features(url):
    """Reproduce notebook cell 13 exactly for a string, preserving insertion order."""
    if not isinstance(url, str):
        raise TypeError("url must be a string")
    return {
        "url_length": len(url),
        "has_https": 1 if url.startswith("https") else 0,
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_question_marks": url.count("?"),
        "num_equal": url.count("="),
        "num_underscore": url.count("_"),
        "num_slash": url.count("/"),
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": url.count(".") - 1 if url.count(".") > 1 else 0,
    }


def legacy_feature_vector(url):
    """Return the twelve feature values in their original training order."""
    features = extract_legacy_features(url)
    return [features[name] for name in FEATURE_NAMES]
