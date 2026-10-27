"""Fail-closed live-network policy and bounded URL syntax validation. No I/O."""
import ipaddress
import re
from urllib.parse import urlsplit

MAX_QR_BYTES = 16 * 1024
MAX_URL_LENGTH = 8192
NETWORK_DISABLED = "No destination HTTP or TLS check was performed for this offline request. Normal development checks, when enabled, are limited to DNS-pinned public destinations and bounded response headers; page bodies are not downloaded. Optional live reputation and RDAP are separate gated checks. Unavailable checks have not passed."


def network_notice(restricted=False):
    return ("Restricted demo: all external lookups are disabled. " if restricted else "") + NETWORK_DISABLED


def url_input_error(url):
    if not isinstance(url,str) or len(url)>MAX_URL_LENGTH:
        return "URL exceeds the 8,192-character analysis limit"
    if any(c.isspace() or ord(c)<32 or ord(c)==127 for c in url) or "\\" in url:
        return "URL contains unsupported whitespace, control characters or backslashes"
    if re.search(r"%(?![0-9A-Fa-f]{2})",url):
        return "URL contains malformed percent encoding"
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname:
            return "URL must contain an HTTP or HTTPS hostname"
        host = parsed.hostname
        if "%" in host or host.endswith(".."):
            return "URL hostname has an ambiguous representation"
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        host = host.rstrip(".").encode("idna").decode("ascii")
        if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*",host,re.I):
            return "URL hostname uses an ambiguous numeric address representation"
        labels = host.split(".")
        if len(host)>253 or len(labels)>32:
            return "URL hostname exceeds the supported size or subdomain limit"
        if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",label) for label in labels):
            return "URL hostname is malformed"
        for label in labels:
            if label.lower().startswith("xn--"):
                label.encode("ascii").decode("idna")
    except (ValueError,UnicodeError):
        return "URL cannot be parsed reliably"
    # Credentials and unusual/invalid ports are never fetched and retain existing
    # explainable offline rules. Do not silently change their scoring here.
    return None
