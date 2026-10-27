"""Opt-in Safe Browsing v5 reputation lookup. Never connects to the submitted site.

No persisted cache, raw matched URLs, API keys in query strings, retries or redirects.
The limited in-memory cache honors Google's positive AND negative cacheDuration.
"""
from collections import deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
import re
import threading
import time

import requests
from demo_runtime import restricted_demo
from website_input import normalize_website_url

ENDPOINT = "https://safebrowsing.googleapis.com/v5/urls:search"
PROVIDER = "Google Safe Browsing"
ADVISORY_URL = "https://safebrowsing.google.com/"
THREAT_TYPES = frozenset({"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"})
INT_TO_THREAT_TYPE = {
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION",
}
THREAT_TYPE_TO_INT = {name: val for val, name in INT_TO_THREAT_TYPE.items()}
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CACHE_ENTRIES = 256
PRIVACY_NOTICE = ("When enabled, the full website URL is sent to Google Safe Browsing. "
                  "Google may use, retain and share submitted URLs and associated data with third parties. "
                  "Do not submit private or token-bearing links. The submitted website is never visited.")
ACCURACY_NOTICE = ("Google Safe Browsing can miss dangerous sites or flag safe sites by mistake. "
                   "A threat-list match indicates a potential risk; no match does not prove a website is safe.")


def decode_varint(data, p, end):
    res = 0
    shift = 0
    while p < end:
        b = data[p]
        p += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, p
        shift += 7
        if shift > 64:
            raise ValueError("varint overflow")
    raise ValueError("truncated varint")


def encode_varint(value):
    if value < 0:
        raise ValueError("negative varint")
    res = bytearray()
    while value > 0x7F:
        res.append((value & 0x7F) | 0x80)
        value >>= 7
    res.append(value & 0x7F)
    return bytes(res)


def decode_search_urls_response(data: bytes):
    pos = 0
    end = len(data)
    threats = []
    cache_duration_seconds = None
    cache_duration_nanos = 0

    def skip_field(p, wire_type):
        if wire_type == 0:
            _, p = decode_varint(data, p, end)
            return p
        elif wire_type == 1:
            if p + 8 > end:
                raise ValueError("truncated fixed64")
            return p + 8
        elif wire_type == 2:
            length, p = decode_varint(data, p, end)
            if p + length > end:
                raise ValueError("truncated length-delimited")
            return p + length
        elif wire_type == 5:
            if p + 4 > end:
                raise ValueError("truncated fixed32")
            return p + 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")

    while pos < end:
        tag, pos = decode_varint(data, pos, end)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 1 and wire_type == 2:
            sub_len, pos = decode_varint(data, pos, end)
            sub_end = pos + sub_len
            if sub_end > end:
                raise ValueError("truncated threat entry")
            threat_url = ""
            threat_types = []
            tp = pos
            while tp < sub_end:
                t_tag, tp = decode_varint(data, tp, sub_end)
                t_field = t_tag >> 3
                t_wire = t_tag & 0x07
                if t_field == 1 and t_wire == 2:
                    u_len, tp = decode_varint(data, tp, sub_end)
                    if tp + u_len > sub_end:
                        raise ValueError("truncated threat url")
                    threat_url = data[tp:tp + u_len].decode("utf-8")
                    tp += u_len
                elif t_field == 2 and t_wire == 0:
                    val, tp = decode_varint(data, tp, sub_end)
                    threat_types.append(INT_TO_THREAT_TYPE.get(val, f"UNKNOWN_{val}"))
                elif t_field == 2 and t_wire == 2:
                    p_len, tp = decode_varint(data, tp, sub_end)
                    p_end = tp + p_len
                    while tp < p_end:
                        val, tp = decode_varint(data, tp, p_end)
                        threat_types.append(INT_TO_THREAT_TYPE.get(val, f"UNKNOWN_{val}"))
                else:
                    tp = skip_field(tp, t_wire)
            pos = sub_end
            threats.append({"url": threat_url, "threatTypes": threat_types})
        elif field_num == 2 and wire_type == 2:
            sub_len, pos = decode_varint(data, pos, end)
            sub_end = pos + sub_len
            if sub_end > end:
                raise ValueError("truncated duration")
            dp = pos
            while dp < sub_end:
                d_tag, dp = decode_varint(data, dp, sub_end)
                d_field = d_tag >> 3
                d_wire = d_tag & 0x07
                if d_field == 1 and d_wire == 0:
                    cache_duration_seconds, dp = decode_varint(data, dp, sub_end)
                elif d_field == 2 and d_wire == 0:
                    cache_duration_nanos, dp = decode_varint(data, dp, sub_end)
                else:
                    dp = skip_field(dp, d_wire)
            pos = sub_end
        else:
            pos = skip_field(pos, wire_type)

    if cache_duration_seconds is None or cache_duration_seconds < 0 or cache_duration_nanos < 0:
        raise ValueError("missing or invalid cacheDuration in protobuf")

    if cache_duration_nanos > 0:
        duration_str = f"{cache_duration_seconds}.{cache_duration_nanos:09d}".rstrip("0") + "s"
    else:
        duration_str = f"{cache_duration_seconds}s"

    return {"threats": threats, "cacheDuration": duration_str}


def encode_duration(seconds, nanos=0):
    body = bytearray()
    body.extend(encode_varint((1 << 3) | 0))
    body.extend(encode_varint(seconds))
    if nanos > 0:
        body.extend(encode_varint((2 << 3) | 0))
        body.extend(encode_varint(nanos))
    return bytes(body)


def encode_threat_url(url, threat_types):
    url_bytes = (url or "").encode("utf-8") if isinstance(url, str) else b""
    body = bytearray()
    if url_bytes:
        body.extend(encode_varint((1 << 3) | 2))
        body.extend(encode_varint(len(url_bytes)))
        body.extend(url_bytes)
    types_bytes = bytearray()
    if isinstance(threat_types, list):
        for t in threat_types:
            if isinstance(t, str) and t in THREAT_TYPE_TO_INT:
                types_bytes.extend(encode_varint(THREAT_TYPE_TO_INT[t]))
            elif isinstance(t, str):
                types_bytes.extend(encode_varint(99))
            else:
                types_bytes.extend(encode_varint(0))
    elif isinstance(threat_types, str):
        types_bytes.extend(b"\x00")
    if types_bytes:
        body.extend(encode_varint((2 << 3) | 2))
        body.extend(encode_varint(len(types_bytes)))
        body.extend(types_bytes)
    return bytes(body)


def encode_search_urls_response(threats=None, seconds=300, nanos=0, force_threat_entry=False):
    body = bytearray()
    if force_threat_entry:
        body.extend(encode_varint((1 << 3) | 2))
        body.extend(encode_varint(0))
    elif threats is not None:
        if isinstance(threats, list):
            for item in threats:
                if isinstance(item, dict):
                    url = item.get("url", "")
                    ttypes = item.get("threatTypes", [])
                    t_bytes = encode_threat_url(url, ttypes)
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    t_bytes = encode_threat_url(item[0], item[1])
                elif isinstance(item, str):
                    t_bytes = encode_threat_url("", [item])
                else:
                    t_bytes = b""
                body.extend(encode_varint((1 << 3) | 2))
                body.extend(encode_varint(len(t_bytes)))
                body.extend(t_bytes)
        elif isinstance(threats, str):
            t_bytes = encode_threat_url("", [threats])
            body.extend(encode_varint((1 << 3) | 2))
            body.extend(encode_varint(len(t_bytes)))
            body.extend(t_bytes)
        elif isinstance(threats, dict):
            t_bytes = b""
            body.extend(encode_varint((1 << 3) | 2))
            body.extend(encode_varint(len(t_bytes)))
            body.extend(t_bytes)
    if seconds is not None:
        d_bytes = encode_duration(seconds, nanos)
        body.extend(encode_varint((2 << 3) | 2))
        body.extend(encode_varint(len(d_bytes)))
        body.extend(d_bytes)
    return bytes(body)


def _iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _result(status, reason, **fields):
    return {"provider": PROVIDER, "status": status, "reason": reason, "threat_types": [],
            "checked_at": None, "cached": False, "cache_expires_at": None,
            "verdict_expires_at": None, **fields}


def current_reputation(value):
    """Downgrade expired observations without networking (also used for saved PDFs)."""
    if not isinstance(value, dict) or value.get("status") not in {"threat", "clear"}:
        return value if isinstance(value, dict) else _result("disabled", "Live reputation was not checked.")
    try:
        expiry = datetime.fromisoformat(value["verdict_expires_at"].replace("Z", "+00:00")).timestamp()
        checked = datetime.fromisoformat(value["checked_at"].replace("Z", "+00:00")).timestamp()
        now = time.time()
        if expiry <= now or checked > now or (value["status"] == "threat" and now - checked >= 1800):
            raise ValueError("expired")
    except (KeyError, ValueError, TypeError, OverflowError, AttributeError):
        return _result("unavailable", "The stored reputation observation has expired; it is not a current warning. Run a new check.")
    return value


def website_verdict(offline_label, reputation):
    """Presentation policy only. Existing QR scores and offline rules are unchanged."""
    reputation = current_reputation(reputation)
    if reputation.get("status") == "threat":
        return {"code": "known_dangerous", "title": "Known Dangerous", "tone": "danger",
                "explanation": "Google Safe Browsing reports a known threat-list match. This website may be dangerous; the service can make mistakes.",
                "action": "Do not visit, download files, log in, or make payments. Verify the address independently."}
    if offline_label == "suspicious":
        return {"code": "suspicious", "title": "Suspicious", "tone": "warning",
                "explanation": "Offline URL rules found warning signs. These are indicators, not proof of phishing.",
                "action": "Don't enter passwords or payment details. Verify the website independently."}
    if reputation.get("status") == "clear":
        return {"code": "no_known_threats", "title": "No Known Threats Detected", "tone": "safe",
                "explanation": "The live reputation check found no known threat, and the available offline rules found no major warning signs. This does not verify legitimacy or guarantee safety.",
                "action": "Check the address and sender before sharing sensitive information. A new or unlisted threat may be missed."}
    return {"code": "unable_to_verify", "title": "Unable to Verify", "tone": "neutral",
            "explanation": "No major warning signs were found by the available offline rules. Website legitimacy could not be verified; unavailable checks have not passed.",
            "action": "Verify the address and sender before logging in, paying, or sharing information."}


class SafeBrowsingClient:
    def __init__(self):
        self.cache = {}
        self.events = deque()
        self.retry_at = 0.0
        self.lock = threading.Lock()

    def lookup(self, url):
        # Recheck both gates before consulting even a previously populated cache.
        if restricted_demo():
            return _result("disabled", "Restricted offline demo: live reputation is disabled.")
        if os.environ.get("SAFE_BROWSING_ENABLED", "false").strip().lower() != "true":
            return _result("disabled", "Live reputation is disabled by configuration; offline rules remain available.")
        key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        if not key:
            return _result("disabled", "Live reputation is not configured; offline rules remain available.")
        if len(key) > 256 or any(ord(char) < 33 or ord(char) > 126 for char in key):
            return _result("unavailable", "Reputation service configuration is invalid.")
        try:
            url = normalize_website_url(url)
        except Exception:
            return _result("unavailable", "Only validated public website URLs can be checked.")
        if not self.lock.acquire(blocking=False):
            return _result("unavailable", "A reputation request is already in progress. Try again later.")
        try:
            now = time.monotonic()
            self.cache = {digest: entry for digest, entry in self.cache.items() if entry[0] > now}
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
            if digest in self.cache:
                return current_reputation({**self.cache[digest][1], "cached": True})
            if len(self.cache) >= MAX_CACHE_ENTRIES:
                return _result("unavailable", "The reputation cache is at capacity. Try again after entries expire.")
            if now < self.retry_at:
                return _result("unavailable", "The reputation service is in backoff. Try again later.")
            while self.events and self.events[0] <= now - 60:
                self.events.popleft()
            if len(self.events) >= 10:
                return _result("unavailable", "The local reputation request limit was reached. Try again later.")
            self.events.append(now)
            return self._request(url, key, digest)
        finally:
            self.lock.release()

    def _backoff(self, response, default=60):
        delay = default
        value = response.headers.get("Retry-After", "")
        try:
            delay = max(default, int(value)) if value.isascii() and value.isdigit() else max(default, parsedate_to_datetime(value).timestamp() - time.time())
        except (ValueError, TypeError, OverflowError):
            pass
        self.retry_at = time.monotonic() + delay

    def _request(self, url, key, digest):
        started = time.monotonic()
        try:
            with requests.Session() as session:
                session.trust_env = False  # Do not inherit proxy, netrc or credentials.
                # Safe Browsing v5 natively speaks binary Protocol Buffers (application/x-protobuf).
                with session.get(ENDPOINT, params={"urls": url},
                                 headers={"X-Goog-Api-Key": key, "Accept": "application/x-protobuf", "Accept-Encoding": "identity"},
                                 timeout=(3, 5), allow_redirects=False, stream=True, verify=True) as response:
                    if response.status_code in (401, 403):
                        self._backoff(response, 300)
                        return _result("unavailable", "Reputation service credentials were rejected. Offline rules remain available.")
                    if response.status_code in (429, 503):
                        self._backoff(response)
                        return _result("unavailable", "Reputation service quota or capacity is unavailable. Try again later.")
                    if response.status_code != 200:
                        self._backoff(response)
                        return _result("unavailable", "The reputation service could not complete the check.")
                    content_type = response.headers.get("Content-Type", "").strip()
                    if not re.match(r"^application/(?:x-protobuf|octet-stream|vnd\.google\.protobuf)(?:\s*;.*)?$", content_type, re.I):
                        raise ValueError("unexpected response media type")
                    # Reject before iter_content() can automatically decompress.
                    if response.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
                        raise ValueError("unexpected response content encoding")
                    length = response.headers.get("Content-Length")
                    if length is not None and (not length.isascii() or not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
                        raise ValueError("response size")
                    body = bytearray()
                    # Small reads enforce the elapsed-time limit even for a trickling response.
                    for chunk in response.iter_content(chunk_size=1):
                        if time.monotonic() - started > 8:
                            raise requests.Timeout()
                        if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError("response size")
                        body.extend(chunk)
                    data = decode_search_urls_response(bytes(body))
            if not isinstance(data, dict) or not re.fullmatch(r"[0-9]{1,10}(?:\.[0-9]{1,9})?s", str(data.get("cacheDuration", ""))):
                raise ValueError("invalid cache duration")
            duration = float(data["cacheDuration"][:-1])
            # Bounded timestamps avoid overflow; never shorten a provider TTL to requery early.
            if duration > 315576000000:
                raise ValueError("unsupported cache duration")
            threats = data.get("threats", [])
            if not isinstance(threats, list):
                raise ValueError("invalid threats")
            types = set()
            for threat in threats:
                if (not isinstance(threat, dict) or not isinstance(threat.get("url"), str)
                        or not threat.get("url")
                        or not isinstance(threat.get("threatTypes"), list)
                        or not threat["threatTypes"] or not all(isinstance(item, str) for item in threat["threatTypes"])):
                    raise ValueError("invalid threat match")
                supported = set(threat["threatTypes"]) & THREAT_TYPES
                if not supported:
                    raise ValueError("unrecognized threat types")
                types.update(supported)
            checked = time.time()
            result = _result("threat" if types else "clear",
                             "The provider reported a potential threat." if types else "No known threats were found by the provider. This is not proof of safety.",
                             threat_types=sorted(types), checked_at=_iso(checked),
                             cache_expires_at=_iso(checked + duration),
                             verdict_expires_at=_iso(checked + min(duration, 1800) if types else checked + duration))
            # Store hashes and small sanitized results, not submitted/matched URLs.
            self.cache[digest] = (time.monotonic() + duration, result)
            return current_reputation(result)
        except (requests.RequestException, OSError, ValueError, TypeError, OverflowError, RecursionError):
            self.retry_at = time.monotonic() + 60
            return _result("unavailable", "The reputation service is unavailable or returned an invalid response. Offline rules remain available.")


client = SafeBrowsingClient()
