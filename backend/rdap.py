"""Opt-in registration observations. Never fetches a submitted website.

IANA's TLS-authenticated DNS bootstrap is the only source of registry endpoints.
Every HTTPS connection resolves once, rejects non-public answers, then connects
to a numeric address while retaining the original hostname for TLS validation.
"""
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from demo_runtime import restricted_demo
from url_security import educational_host, hostname, registered_domain

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
MAX_BODY = 256 * 1024
MAX_BOOTSTRAP = 512 * 1024
MAX_CACHE = 512
TOTAL_TIMEOUT = 8.0
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 2.0
_resolver = ThreadPoolExecutor(max_workers=1, thread_name_prefix="qrshield-rdap-dns")
_resolver_lock = threading.Lock()
_dns_future = None


class LookupUnavailable(Exception):
    pass


class ProviderLimited(LookupUnavailable):
    def __init__(self, delay=60):
        self.delay = delay


def _remaining(deadline, limit):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LookupUnavailable()
    return min(remaining, limit)


def _endpoint(value):
    if not isinstance(value, str) or len(value) > 1024 or not value.isascii():
        raise LookupUnavailable()
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.query or parsed.fragment
            or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", host, re.I)
            or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".arpa"))
            or not re.fullmatch(r"/[A-Za-z0-9/_~.-]*", parsed.path or "/")
            or any(part in (".", "..") for part in parsed.path.split("/"))):
        raise LookupUnavailable()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host, parsed.path or "/"
    raise LookupUnavailable()


def _public_addresses(host, deadline):
    """At most one resolver job exists, including after an OS DNS timeout."""
    global _dns_future
    with _resolver_lock:
        if _dns_future is not None and not _dns_future.done():
            raise LookupUnavailable()
        _dns_future = _resolver.submit(socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        future = _dns_future
    try:
        answers = future.result(timeout=_remaining(deadline, CONNECT_TIMEOUT))
    except (FutureTimeout, OSError) as error:
        raise LookupUnavailable() from error
    _remaining(deadline, CONNECT_TIMEOUT)
    if not answers or len(answers) > 32:
        raise LookupUnavailable()
    addresses = []
    for family, kind, protocol, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            raise LookupUnavailable()
        raw = address[0]
        if "%" in raw:
            raise LookupUnavailable()
        ip = ipaddress.ip_address(raw)
        if (not ip.is_global or ip.is_multicast or ip.is_reserved
                or getattr(ip, "ipv4_mapped", None) is not None):
            raise LookupUnavailable()
        item = (family, (ip.compressed, 443) if family == socket.AF_INET else (ip.compressed, 443, 0, 0))
        if item not in addresses:
            addresses.append(item)
    return addresses


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, deadline):
        super().__init__(host, port=443, timeout=CONNECT_TIMEOUT, context=ssl.create_default_context())
        self.deadline = deadline

    def connect(self):
        addresses = _public_addresses(self.host, self.deadline)
        for family, address in addresses[:3]:
            raw = socket.socket(family, socket.SOCK_STREAM)
            try:
                raw.settimeout(_remaining(self.deadline, CONNECT_TIMEOUT))
                raw.connect(address)  # Numeric IP: no second hostname resolution.
                raw.settimeout(_remaining(self.deadline, READ_TIMEOUT))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except OSError:
                raw.close()
        raise LookupUnavailable()


def _fetch_json(url, limit, deadline):
    host, path = _endpoint(url)
    connection = _PinnedHTTPS(host, deadline)
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
    try:
        # No requests session, proxy environment, netrc, credentials or redirects.
        connection.request("GET", path, headers={"Accept": "application/rdap+json, application/json", "Accept-Encoding": "identity", "User-Agent": "QR-Shield-Registration-Check"})
        response = connection.getresponse()
        if response.status in (429, 503):
            retry = response.getheader("Retry-After", "")
            delay = max(60, min(int(retry), 86400)) if re.fullmatch(r"[0-9]{1,8}", retry) else 60
            raise ProviderLimited(delay)
        if response.status != 200:  # Includes every redirect.
            raise LookupUnavailable()
        media = response.getheader("Content-Type", "").strip()
        if not re.fullmatch(r'application/(?:rdap\+json|json)(?:\s*;\s*charset\s*=\s*(?:"utf-8"|utf-8))?', media, re.I):
            raise LookupUnavailable()
        if response.getheader("Content-Encoding", "identity").strip().lower() != "identity":
            raise LookupUnavailable()
        length = response.getheader("Content-Length")
        if length is not None and (not re.fullmatch(r"[0-9]{1,9}", length) or int(length) > limit):
            raise LookupUnavailable()
        body = bytearray()
        while True:
            _remaining(deadline, READ_TIMEOUT)
            if connection.sock is not None:
                connection.sock.settimeout(_remaining(deadline, READ_TIMEOUT))
            chunk = response.read1(min(4096, limit + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > limit:
                raise LookupUnavailable()
        _remaining(deadline, READ_TIMEOUT)
        if length is not None and len(body) != int(length):
            raise LookupUnavailable()
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise LookupUnavailable()
                value[key] = item
            return value
        def invalid_constant(_):
            raise LookupUnavailable()
        data = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=invalid_constant)
        if not isinstance(data, dict):
            raise LookupUnavailable()
        return data
    finally:
        timer.cancel()
        connection.close()


def _result(status, domain, reason, **extra):
    return {"status": status, "provider": "RDAP", "registered_domain": domain,
            "registration_date": None, "expiration_date": None, "domain_status": None,
            "registrar": None, "registration_provider": None,
            "domain_age_days": None, "checked_at": None,
            "cached": False, "reason": reason, **extra}


def _registration(data, domain, now):
    if data.get("objectClassName") != "domain" or not isinstance(data.get("ldhName"), str) or data["ldhName"].lower().rstrip(".") != domain:
        raise LookupUnavailable()
    events = data.get("events", [])
    if not isinstance(events, list) or len(events) > 128:
        raise LookupUnavailable()
    dates = set()
    for event in events:
        if not isinstance(event, dict):
            raise LookupUnavailable()
        if event.get("eventAction") != "registration":
            continue
        raw = event.get("eventDate")
        if (not isinstance(raw, str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
                raw, re.I)):
            raise LookupUnavailable()
        date = datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
        if date.tzinfo is None:
            raise LookupUnavailable()
        date = date.astimezone(timezone.utc)
        if date > now:
            raise LookupUnavailable()
        dates.add(date)
    # Missing or conflicting dates are not inferred from update/expiry events.
    if len(dates) != 1:
        raise LookupUnavailable()
    date = dates.pop()
    return date.isoformat(), (now - date).days


def _optional_registration_metadata(data):
    """Return only optional values present and structurally valid in the RDAP object."""
    result = {"expiration_date": None, "domain_status": None, "registrar": None}
    events = data.get("events")
    if isinstance(events, list) and len(events) <= 128:
        expirations = set()
        for event in events:
            if not isinstance(event, dict) or event.get("eventAction") != "expiration":
                continue
            raw = event.get("eventDate")
            if not isinstance(raw, str) or not re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
                    raw, re.I):
                expirations.clear()
                break
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
            except ValueError:
                expirations.clear()
                break
            if parsed.tzinfo is None:
                expirations.clear()
                break
            expirations.add(parsed.astimezone(timezone.utc).isoformat())
        if len(expirations) == 1:
            result["expiration_date"] = next(iter(expirations))

    statuses = data.get("status")
    if (isinstance(statuses, list) and len(statuses) <= 32
            and all(isinstance(item, str) and 0 < len(item) <= 128 for item in statuses)):
        result["domain_status"] = list(dict.fromkeys(statuses))

    entities = data.get("entities")
    if isinstance(entities, list) and len(entities) <= 256:
        names = set()
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles")
            if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
                continue
            if "registrar" not in {role.lower() for role in roles}:
                continue
            vcard = entity.get("vcardArray")
            if not isinstance(vcard, list) or len(vcard) != 2 or vcard[0] != "vcard" or not isinstance(vcard[1], list):
                continue
            for field in vcard[1][:64]:
                if (isinstance(field, list) and len(field) >= 4 and field[0] == "fn"
                        and isinstance(field[3], str) and 0 < len(field[3]) <= 256):
                    names.add(field[3].strip())
        if len(names) == 1:
            result["registrar"] = next(iter(names))
    return result


class RdapClient:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache = {}
        self.events = deque()
        self.retry_at = 0.0
        self.bootstrap = {}
        self.bootstrap_until = 0.0

    def _service(self, domain, deadline):
        if time.monotonic() >= self.bootstrap_until:
            data = _fetch_json(BOOTSTRAP, MAX_BOOTSTRAP, deadline)
            services = data.get("services")
            if not isinstance(services, list) or len(services) > 2000:
                raise LookupUnavailable()
            mapping = {}
            for service in services:
                if (not isinstance(service, list) or len(service) != 2
                        or not isinstance(service[0], list) or not isinstance(service[1], list)
                        or len(service[0]) > 2000 or len(service[1]) > 8):
                    raise LookupUnavailable()
                endpoints = []
                for endpoint in service[1]:
                    try:
                        _endpoint(endpoint)  # Never upgrade or use an insecure endpoint.
                    except (LookupUnavailable, ValueError):
                        continue
                    endpoints.append(endpoint.rstrip("/") + "/")
                for suffix in service[0]:
                    if not isinstance(suffix, str) or not re.fullmatch(r"[a-z0-9-]{2,63}", suffix):
                        raise LookupUnavailable()
                    if suffix in mapping and mapping[suffix] != endpoints:
                        raise LookupUnavailable()
                    mapping[suffix] = endpoints
                    if len(mapping) > 2500:
                        raise LookupUnavailable()
            self.bootstrap = mapping
            self.bootstrap_until = time.monotonic() + 86400
        endpoints = self.bootstrap.get(domain.rsplit(".", 1)[-1], [])
        if not endpoints:
            raise LookupUnavailable()
        base = endpoints[0]
        _endpoint(base)  # Revalidate even cached endpoint metadata.
        return base + "domain/" + domain

    def lookup(self, value):
        # Mode gates precede validation, DNS, bootstrap fetching and cache reads.
        if restricted_demo():
            return _result("disabled", None, "Restricted offline demo: RDAP is disabled.")
        if os.environ.get("RDAP_ENABLED", "false").strip().lower() != "true":
            return _result("disabled", None, "RDAP is disabled by configuration.")
        domain = None
        try:
            if not isinstance(value, str) or len(value) > 8192:
                raise ValueError()
            parsed = urlsplit(value if "://" in value else "//" + value)
            if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
                raise ValueError()
            host = hostname(value)
            if (not host or len(host) > 253 or "." not in host or educational_host(host)
                    or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa"))):
                raise ValueError()
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError()
            if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", host):
                raise ValueError()
            domain = registered_domain(host)
            if not domain:
                raise ValueError()
        except (ValueError, UnicodeError, TypeError):
            return _result("not_applicable", domain, "No eligible public registered domain; RDAP was not requested.")
        if not self.lock.acquire(blocking=False):
            return _result("unavailable", domain, "A registration lookup is in progress. Try again later.")
        try:
            now = time.monotonic()
            self.cache = {key: entry for key, entry in self.cache.items() if entry[0] > now}
            key = hashlib.sha256(domain.encode("ascii")).hexdigest()
            if key in self.cache:
                return {**self.cache[key][1], "cached": True}
            if len(self.cache) >= MAX_CACHE or now < self.retry_at:
                return _result("unavailable", domain, "Registration lookup capacity is unavailable. Try again later.")
            while self.events and self.events[0] <= now - 60:
                self.events.popleft()
            if len(self.events) >= 10:
                return _result("unavailable", domain, "The local registration lookup limit was reached. Try again later.")
            self.events.append(now)
            try:
                deadline = now + TOTAL_TIMEOUT
                service = self._service(domain, deadline)
                data = _fetch_json(service, MAX_BODY, deadline)
                checked = datetime.now(timezone.utc)
                date, age = _registration(data, domain, checked)
                optional = _optional_registration_metadata(data)
                result = _result("available", domain, "A matching domain registration event was reported by RDAP. Domain age does not prove safety.",
                                 registration_date=date, domain_age_days=age, checked_at=checked.isoformat(),
                                 registration_provider=urlsplit(service).hostname, **optional)
                ttl = 3600
            except ProviderLimited as error:
                self.retry_at = time.monotonic() + error.delay
                result = _result("unavailable", domain, "The registration provider is rate limited or unavailable. Try again later.")
                ttl = 60
            except (LookupUnavailable, OSError, ValueError, TypeError, OverflowError, RecursionError, http.client.HTTPException):
                result = _result("unavailable", domain, "Reliable domain registration data is unavailable. Other checks are unaffected.")
                ttl = 60
            self.cache[key] = (time.monotonic() + ttl, result)
            return dict(result)
        finally:
            self.lock.release()


client = RdapClient()
