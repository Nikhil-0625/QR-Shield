"""Bounded HTTP/TLS evidence checks for public URL destinations.

Connections are pinned to validated public DNS answers. No proxy settings,
redirect-following client, cookies, authorization, or response-body reads are used.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

from url_policy import MAX_URL_LENGTH, url_input_error
from url_security import educational_host

MAX_REDIRECTS = 5
TOTAL_TIMEOUT = 10.0
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 2.0
MAX_DNS_ANSWERS = 32

_resolver = ThreadPoolExecutor(max_workers=1, thread_name_prefix="qrshield-url-dns")
_resolver_lock = threading.Lock()
_dns_future = None


class ProbeError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    authority: str
    request_target: str
    addresses: tuple


def _remaining(deadline, limit):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeError("unavailable", "The bounded network-check time limit was reached.")
    return min(remaining, limit)


def _public_addresses(host, port, deadline):
    """Resolve once, reject mixed/private answers, and pin later connections."""
    global _dns_future
    with _resolver_lock:
        if _dns_future is not None and not _dns_future.done():
            raise ProbeError("unavailable", "A previous DNS check is still pending.")
        _dns_future = _resolver.submit(
            socket.getaddrinfo, host, port, socket.AF_UNSPEC,
            socket.SOCK_STREAM, socket.IPPROTO_TCP,
        )
        future = _dns_future
    try:
        answers = future.result(timeout=_remaining(deadline, CONNECT_TIMEOUT))
    except (FutureTimeout, OSError, OverflowError) as error:
        raise ProbeError("unavailable", "The destination could not be resolved within the check limit.") from error
    if not answers or len(answers) > MAX_DNS_ANSWERS:
        raise ProbeError("unavailable", "DNS returned no usable destination addresses.")

    addresses = []
    for family, kind, protocol, _, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            raise ProbeError("blocked", "DNS returned an unsupported destination address.")
        raw = sockaddr[0]
        if "%" in raw:
            raise ProbeError("blocked", "Scoped IP destinations are not checked.")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as error:
            raise ProbeError("blocked", "DNS returned an invalid destination address.") from error
        if (not address.is_global or address.is_multicast or address.is_reserved
                or getattr(address, "ipv4_mapped", None) is not None
                or getattr(address, "sixtofour", None) is not None
                or getattr(address, "teredo", None) is not None):
            raise ProbeError("blocked", "The destination resolves to a non-public address.")
        if family == socket.AF_INET:
            pinned = (address.compressed, port)
        else:
            pinned = (address.compressed, port, 0, 0)
        item = (family, pinned)
        if item not in addresses:
            addresses.append(item)
    return tuple(addresses)


def validate_target(value, deadline=None):
    """Validate an HTTP(S) destination and return the pinned public addresses."""
    if deadline is None:
        deadline = time.monotonic() + TOTAL_TIMEOUT
    if not isinstance(value, str) or len(value) > MAX_URL_LENGTH:
        raise ProbeError("blocked", "The URL is outside the supported size limit.")
    syntax_error = url_input_error(value)
    if syntax_error:
        raise ProbeError("blocked", "The URL is not eligible for a network check.")
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ProbeError("blocked", "Only HTTP and HTTPS destinations are checked.")
        if parsed.username is not None or parsed.password is not None:
            raise ProbeError("blocked", "URLs with embedded credentials are not checked.")
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
    except (ValueError, UnicodeError, AttributeError) as error:
        if isinstance(error, ProbeError):
            raise
        raise ProbeError("blocked", "The URL cannot be parsed reliably.") from error

    if port != (443 if scheme == "https" else 80):
        raise ProbeError("blocked", "Non-standard web ports are not checked.")
    if (not host or "." not in host or educational_host(host)
            or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa", ".arpa"))):
        raise ProbeError("blocked", "Local, reserved, and educational destinations are not checked.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        # Keep direct IP scans offline, including public IP literals.
        raise ProbeError("blocked", "IP-literal destinations are not checked.")

    addresses = _public_addresses(host, port, deadline)
    path = parsed.path or "/"
    request_target = path + (("?" + parsed.query) if parsed.query else "")
    explicit_port = parsed.port
    authority = host + ((":" + str(explicit_port)) if explicit_port is not None else "")
    safe_url = urlunsplit((scheme, authority, path, parsed.query, ""))
    return Target(safe_url, scheme, host, port, authority, request_target, addresses)


def _open_raw_socket(target, deadline):
    last_error = None
    for family, sockaddr in target.addresses[:3]:
        raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            raw.settimeout(_remaining(deadline, CONNECT_TIMEOUT))
            raw.connect(sockaddr)
            raw.settimeout(_remaining(deadline, READ_TIMEOUT))
            return raw
        except (OSError, ProbeError) as error:
            raw.close()
            last_error = error
    raise ProbeError("unavailable", "A bounded connection to the validated destination could not be completed.") from last_error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target, deadline):
        super().__init__(target.host, target.port, timeout=CONNECT_TIMEOUT)
        self._target = target
        self._deadline = deadline

    def connect(self):
        self.sock = _open_raw_socket(self._target, self._deadline)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target, deadline):
        super().__init__(target.host, target.port, timeout=CONNECT_TIMEOUT,
                         context=ssl.create_default_context())
        self._target = target
        self._deadline = deadline

    def connect(self):
        raw = _open_raw_socket(self._target, self._deadline)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self._target.host)
            self.sock.settimeout(_remaining(self._deadline, READ_TIMEOUT))
        except ssl.SSLCertVerificationError:
            raw.close()
            raise
        except (OSError, ssl.SSLError, ProbeError):
            raw.close()
            raise


def _connection(target, deadline):
    if target.scheme == "https":
        return _PinnedHTTPSConnection(target, deadline)
    return _PinnedHTTPConnection(target, deadline)


def _deadline_watchdog(connection, deadline):
    def expire():
        sock = connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()
    timer = threading.Timer(_remaining(deadline, TOTAL_TIMEOUT), expire)
    timer.daemon = True
    timer.start()
    return timer


def _request_once(target, method, headers, deadline):
    connection = _connection(target, deadline)
    timer = _deadline_watchdog(connection, deadline)
    try:
        connection.request(method, target.request_target, headers=headers)
        if connection.sock is not None:
            connection.sock.settimeout(_remaining(deadline, READ_TIMEOUT))
        response = connection.getresponse()
        locations = [value.strip() for name, value in response.getheaders()
                     if name.lower() == "location"]
        if len(locations) > 1:
            raise ProbeError("failed", "The server returned conflicting redirect destinations.")
        return response.status, locations[0] if locations else None
    finally:
        timer.cancel()
        connection.close()


def _request_headers(target, deadline):
    """HEAD first, then a one-byte Range GET only when HEAD is unsupported."""
    headers = {
        "Host": target.authority,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "User-Agent": "QR-Shield-URL-Check/1.0",
    }
    method = "HEAD"
    try:
        status, location = _request_once(target, method, headers, deadline)
        if status in (405, 501):
            method = "GET"
            headers["Range"] = "bytes=0-0"
            status, location = _request_once(target, method, headers, deadline)
        return status, location, method
    except ProbeError:
        raise
    except ssl.SSLCertVerificationError as error:
        raise ProbeError("failed", "The destination TLS certificate could not be validated.") from error
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as error:
        raise ProbeError("unavailable", "A bounded response-header check could not be completed.") from error


def _display_hostname(value):
    try:
        return urlsplit(value).hostname if isinstance(value, str) else None
    except ValueError:
        return None


def check_https(url, allow_network=True):
    """Validate TLS chain and hostname without sending an HTTP request."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() == "http":
            return {"status": "not_applicable", "valid": None,
                    "reason": "TLS certificate validation applies only to HTTPS URLs.", "hostname": parsed.hostname}
        if parsed.scheme.lower() != "https":
            return {"status": "blocked", "valid": None,
                    "reason": "Only HTTPS destinations can receive a TLS certificate check.", "hostname": None}
        if not allow_network:
            return {"status": "blocked", "valid": None,
                    "reason": "Network checks are disabled for this offline or restricted request.",
                    "hostname": parsed.hostname}
        deadline = time.monotonic() + min(TOTAL_TIMEOUT, 4.0)
        target = validate_target(url, deadline)
        connection = _PinnedHTTPSConnection(target, deadline)
        timer = _deadline_watchdog(connection, deadline)
        try:
            connection.connect()
            return {"status": "completed", "valid": True,
                    "reason": "The certificate chain and hostname were validated using the system trust store.",
                    "hostname": target.host}
        finally:
            timer.cancel()
            connection.close()
    except ProbeError as error:
        return {"status": error.status, "valid": None, "reason": error.reason,
                "hostname": _display_hostname(url)}
    except ssl.SSLCertVerificationError:
        return {"status": "failed", "valid": False,
                "reason": "The destination TLS certificate or hostname did not validate.",
                "hostname": _display_hostname(url)}
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, TypeError):
        return {"status": "unavailable", "valid": None,
                "reason": "TLS validation could not be completed within the check limits.",
                "hostname": _display_hostname(url)}


def trace_redirects(url, max_hops=MAX_REDIRECTS, allow_network=True):
    """Record only bounded HTTP redirect headers; never download response bodies."""
    original = url
    max_hops = max(0, min(int(max_hops), MAX_REDIRECTS))
    chain = []
    hops = []
    if not allow_network:
        return {"status": "blocked", "original_url": original, "final_url": original,
                "redirect_count": None, "observed_redirects": 0, "chain": [original],
                "hops": [], "final_response_status": None,
                "reason": "Network checks are disabled for this offline or restricted request."}

    deadline = time.monotonic() + TOTAL_TIMEOUT
    current = original
    visited = set()
    successful_redirects = 0
    for _ in range(max_hops + 1):
        try:
            target = validate_target(current, deadline)
            if target.url in visited:
                raise ProbeError("failed", "A redirect loop was detected.")
            status_code, location, method = _request_headers(target, deadline)
        except ProbeError as error:
            return {"status": error.status, "original_url": original,
                    "final_url": chain[-1] if chain else original,
                    "redirect_count": None, "observed_redirects": len(hops),
                    "chain": chain or [original], "hops": hops,
                    "final_response_status": None, "reason": error.reason}
        except (TypeError, ValueError, OverflowError):
            return {"status": "failed", "original_url": original,
                    "final_url": chain[-1] if chain else original,
                    "redirect_count": None, "observed_redirects": len(hops),
                    "chain": chain or [original], "hops": hops,
                    "final_response_status": None, "reason": "Redirect response data was invalid."}

        visited.add(target.url)
        if not chain or chain[-1] != target.url:
            chain.append(target.url)

        if status_code not in (301, 302, 303, 307, 308):
            return {"status": "completed", "original_url": original,
                    "final_url": target.url, "redirect_count": successful_redirects,
                    "observed_redirects": len(hops), "chain": chain, "hops": hops,
                    "final_response_status": status_code, "method": method,
                    "reason": "Redirect headers were checked without downloading page content."}

        if not location:
            hops.append({"from": target.url, "status_code": status_code, "to": None,
                         "method": method, "state": "failed"})
            return {"status": "failed", "original_url": original, "final_url": target.url,
                    "redirect_count": None, "observed_redirects": len(hops),
                    "chain": chain, "hops": hops, "final_response_status": status_code,
                    "reason": "The server returned a redirect without a usable Location header."}

        next_url = urljoin(target.url, location)
        if successful_redirects >= max_hops:
            hops.append({"from": target.url, "status_code": status_code, "to": next_url,
                         "method": method, "state": "blocked"})
            return {"status": "blocked", "original_url": original, "final_url": target.url,
                    "redirect_count": None, "observed_redirects": len(hops),
                    "chain": chain, "hops": hops, "final_response_status": status_code,
                    "reason": "The redirect limit was reached; the next destination was not followed."}
        try:
            next_target = validate_target(next_url, deadline)
        except ProbeError as error:
            hops.append({"from": target.url, "status_code": status_code, "to": next_url,
                         "method": method, "state": error.status})
            return {"status": "blocked" if error.status == "blocked" else "unavailable",
                    "original_url": original, "final_url": target.url,
                    "redirect_count": None, "observed_redirects": len(hops),
                    "chain": chain, "hops": hops, "final_response_status": status_code,
                    "reason": "The redirect destination was not followed: " + error.reason}
        hops.append({"from": target.url, "status_code": status_code, "to": next_target.url,
                     "method": method, "state": "followed"})
        successful_redirects += 1
        current = next_target.url

    # Defensive bound; normal execution returns inside the loop.
    return {"status": "blocked", "original_url": original,
            "final_url": chain[-1] if chain else original,
            "redirect_count": None, "observed_redirects": len(hops),
            "chain": chain or [original], "hops": hops,
            "final_response_status": None, "reason": "The redirect limit was reached."}
