"""Direct-link syntax and destination checks. Deliberately performs no DNS or I/O."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException
from url_policy import MAX_URL_LENGTH, url_input_error

WEBSITE_NETWORK_NOTICE = (
    "Where enabled, TLS and HTTP redirect checks use DNS-pinned public destinations, bounded timeouts, and response headers only. "
    "Page bodies, client-side redirects, scripts, and subresources are not fetched. RDAP and live reputation are separately gated. "
    "ML is excluded from this website verdict because feature compatibility is not verified."
)


def normalize_website_url(value):
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(400, "Enter a website URL")
    # Bound the submitted string too, before stripping or parsing it.
    if len(value) > MAX_URL_LENGTH:
        raise HTTPException(413, "URL exceeds the 8,192-character analysis limit")
    url = value.strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", url):
        url = "https://" + url
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(413, "URL exceeds the 8,192-character analysis limit")
    error = url_input_error(url)
    if error:
        raise HTTPException(400, error)
    try:
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("credentials")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port  # Reject invalid or out-of-range ports.
        address = None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        if address is not None:
            # Explicitly exclude multicast and IPv4-mapped IPv6 too.
            mapped = getattr(address, "ipv4_mapped", None)
            if (not address.is_global or address.is_multicast or address.is_reserved
                    or (mapped is not None and not mapped.is_global)):
                raise ValueError("non-public address")
            host = "[" + address.compressed + "]" if address.version == 6 else address.compressed
        elif ("." not in host or host in {"metadata.google.internal", "instance-data.ec2.internal"}
              or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa"))):
            raise ValueError("local hostname")
        authority = host + (":" + str(port) if port is not None else "")
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path, parsed.query, parsed.fragment))
    except (ValueError, UnicodeError, AttributeError):
        raise HTTPException(400, "Use a public HTTP or HTTPS website URL without embedded credentials") from None
