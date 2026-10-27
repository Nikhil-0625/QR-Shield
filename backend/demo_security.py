"""Single-instance restricted-demo boundary. Never trust forwarding headers."""
import asyncio
import base64
from collections import deque
import hashlib
import hmac
from http.cookies import SimpleCookie, CookieError
import json
import os
import time
from urllib.parse import urlsplit

COOKIE = "qr_demo_access"


def settings():
    origin = os.environ.get("PUBLIC_ORIGIN", "")
    parsed = urlsplit(origin)
    local = parsed.hostname in {"localhost", "127.0.0.1"}
    if parsed.scheme not in ({"http", "https"} if local else {"https"}) or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise RuntimeError("PUBLIC_ORIGIN must be an exact HTTPS origin (HTTP only on loopback)")
    password = os.environ.get("DEMO_ACCESS_PASSWORD", "")
    username = os.environ.get("DEMO_ACCESS_USER", "demo")
    if len(password.encode()) < 24 or not username or ":" in username:
        raise RuntimeError("Configure a strong DEMO_ACCESS_PASSWORD and valid DEMO_ACCESS_USER")
    extra = [host.strip().lower() for host in os.environ.get("DEMO_ALLOWED_HOSTS", "").split(",") if host.strip()]
    if any(not host or any(c in host for c in "/*?#@ ") for host in extra):
        raise RuntimeError("DEMO_ALLOWED_HOSTS must contain exact hostnames")
    return origin, parsed.scheme == "https", username, password, {parsed.netloc.lower(), *extra}


class DemoBoundary:
    def __init__(self, app):
        self.app = app
        self.origin, self.secure, self.username, self.password, self.hosts = settings()
        self.key = hashlib.sha256(("QRShield demo cookie:" + self.password).encode()).digest()
        self.events = {}
        self.active = 0
        self.max_active = 4
        self.body_timeout = 10
        self.request_timeout = 45

    def allowed(self, name, count, seconds):
        now = time.monotonic()
        events = self.events.setdefault(name, deque())
        while events and events[0] <= now - seconds:
            events.popleft()
        if len(events) >= count:
            return False
        events.append(now)
        return True

    def cookie_value(self):
        expires = str(int(time.time()) + 8 * 3600)
        signature = hmac.new(self.key, (self.origin + ":" + expires).encode(), hashlib.sha256).hexdigest()
        return expires + "." + signature

    def cookie_valid(self, headers):
        try:
            cookie = SimpleCookie()
            cookie.load(headers.get("cookie", ""))
            value = cookie[COOKIE].value
            expires, signature = value.split(".", 1)
            if not int(time.time()) < int(expires) <= int(time.time()) + 8 * 3600 + 5:
                return False
            expected = hmac.new(self.key, (self.origin + ":" + expires).encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except (KeyError, ValueError, TypeError, CookieError):
            return False

    def basic_valid(self, headers):
        try:
            scheme, value = headers.get("authorization", "").split(" ", 1)
            if scheme.lower() != "basic":
                return False
            username, password = base64.b64decode(value, validate=True).decode("utf-8").split(":", 1)
            return hmac.compare_digest(username.encode(), self.username.encode()) & hmac.compare_digest(password.encode(), self.password.encode())
        except (ValueError, UnicodeError):
            return False

    async def respond(self, send, status, message, challenge=False):
        body = json.dumps({"status": "error", "message": message, "detail": message}).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                   (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]
        if challenge:
            headers.append((b"www-authenticate", b'Basic realm="QR Shield restricted demo", charset="UTF-8"'))
        if status == 429:
            headers.append((b"retry-after", b"60"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("qr_demo_guarded"):
            return await self.app(scope, receive, send)
        for name in (b"host",b"authorization",b"origin",b"content-length",b"content-type",b"transfer-encoding"):
            if sum(k.lower()==name for k,_ in scope.get("headers",[]))>1:
                return await self.respond(send,400,"Ambiguous request headers")
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        if ("transfer-encoding" in headers and ("content-length" in headers or headers["transfer-encoding"].lower()!="chunked")) or len(headers.get("authorization",""))>8192:
            return await self.respond(send,400,"Invalid request headers")
        if headers.get("host", "").lower() not in self.hosts:
            return await self.respond(send, 400, "Unrecognized host")
        path = scope.get("path", "")
        if path == "/healthz":
            await send({"type":"http.response.start", "status":200,"headers":[(b"content-type",b"application/json"),(b"cache-control",b"no-store")]})
            return await send({"type":"http.response.body","body":b'{"status":"ok"}'})
        if headers.get("origin") and headers["origin"] != self.origin:
            return await self.respond(send, 403, "Origin not permitted")
        basic = self.basic_valid(headers)
        if not basic and not self.cookie_valid(headers):
            if not self.allowed("gate", 30, 60):
                return await self.respond(send, 429, "Demo access attempts limited")
            return await self.respond(send, 401, "Restricted demonstration access required", True)
        route = path[4:] if path.startswith("/api/") else path
        if route in {"/docs", "/redoc", "/openapi.json", "/register"}:
            return await self.respond(send, 403 if route == "/register" else 404, "Not available in the restricted demonstration")
        category = "scan" if route in {"/scan", "/website/check"} else "login" if route == "/login" else "report" if route.startswith("/report/") else "other"
        if not self.allowed(category, {"scan":10,"login":20,"report":20,"other":180}[category], 60):
            return await self.respond(send, 429, "Demo request limit reached")
        if self.active >= self.max_active:
            return await self.respond(send, 503, "Demo server is busy")
        lengths = [v for k,v in scope.get("headers",[]) if k.lower() == b"content-length"]
        limit = 6 * 1024 * 1024 if route == "/scan" else 16 * 1024
        if lengths and (len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0])>10):
            return await self.respond(send, 400, "Invalid content length")
        if lengths and int(lengths[0]) > limit:
            return await self.respond(send, 413, "Request body too large")
        self.active += 1
        started = False
        try:
            body = bytearray()
            try:
                async with asyncio.timeout(self.body_timeout):
                    while True:
                        event = await receive()
                        if event["type"] == "http.disconnect":
                            return
                        chunk=event.get("body",b"")
                        if len(body)+len(chunk) > limit:
                            return await self.respond(send, 413, "Request body too large")
                        body.extend(chunk)
                        if not event.get("more_body", False):
                            break
            except TimeoutError:
                return await self.respond(send, 408, "Request body timed out")
            if lengths and int(lengths[0])!=len(body):
                return await self.respond(send,400,"Incomplete request body")
            delivered = False
            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type":"http.request", "body":bytes(body), "more_body":False}
                return await receive()
            async def secured_send(message):
                nonlocal started
                if message["type"] == "http.response.start":
                    started = True
                    message = dict(message)
                    blocked = {b"cache-control",b"x-content-type-options",b"x-frame-options",b"referrer-policy",b"permissions-policy"}
                    response_headers = [(k,v) for k,v in message.get("headers",[]) if k.lower() not in blocked]
                    response_headers += [(b"cache-control",b"no-store"),(b"x-content-type-options",b"nosniff"),
                        (b"x-frame-options",b"DENY"),(b"referrer-policy",b"no-referrer"),
                        (b"permissions-policy",b"camera=(self), microphone=(), geolocation=()"),
                        (b"content-security-policy",b"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")]
                    if self.secure:
                        response_headers.append((b"strict-transport-security",b"max-age=86400"))
                    if basic:
                        cookie = COOKIE + "=" + self.cookie_value() + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800" + ("; Secure" if self.secure else "")
                        response_headers.append((b"set-cookie",cookie.encode()))
                    message["headers"] = response_headers
                await send(message)
            scope = dict(scope, qr_demo_guarded=True)
            try:
                async with asyncio.timeout(self.request_timeout):
                    await self.app(scope, replay, secured_send)
            except TimeoutError:
                if not started:
                    await self.respond(send, 504, "Demo request timed out")
            except Exception:
                if not started:
                    await self.respond(send, 500, "The request could not be completed")
        finally:
            self.active -= 1
