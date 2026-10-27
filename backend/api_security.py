"""Bounded development API boundary; restricted demo retains its stronger access gate."""
import asyncio
from collections import deque
import json
import os
import re
import time
from urllib.parse import urlsplit


class ApiBoundary:
    def __init__(self, app):
        self.app = app
        self.extra_hosts = {h.strip().lower() for h in os.environ.get("QR_SHIELD_ALLOWED_HOSTS", "").split(",") if h.strip()}
        self.origins = {value.strip().encode() for value in os.environ.get("CORS_ALLOWED_ORIGINS","http://localhost:5500,http://127.0.0.1:5500").split(",") if value.strip()}
        if any(not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?", host) for host in self.extra_hosts):
            raise RuntimeError("QR_SHIELD_ALLOWED_HOSTS must contain exact hosts, not wildcards")
        self.events = {}
        self.active = 0
        self.max_active = 4
        self.body_timeout = 10
        self.request_timeout = 45

    def allowed(self, category, count, seconds):
        now = time.monotonic()
        events = self.events.setdefault(category, deque())
        while events and events[0] <= now - seconds:
            events.popleft()
        if len(events) >= count:
            return False
        events.append(now)
        return True

    async def respond(self, send, status, text):
        body = json.dumps({"status":"error", "message":text, "detail":text}).encode()
        headers = [(b"content-type",b"application/json"),(b"content-length",str(len(body)).encode()),
                   (b"cache-control",b"no-store"),(b"x-content-type-options",b"nosniff")]
        if status == 429: headers.append((b"retry-after",b"60"))
        await send({"type":"http.response.start","status":status,"headers":headers})
        await send({"type":"http.response.body","body":body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("qr_demo_guarded"):
            return await self.app(scope, receive, send)
        headers = [(key.lower(),value) for key,value in scope.get("headers",[])]
        for name in (b"host",b"authorization",b"origin",b"content-length",b"content-type",b"transfer-encoding"):
            if sum(key == name for key,_ in headers) > 1:
                return await self.respond(send,400,"Ambiguous request headers")
        values = dict(headers)
        original_send = send
        async def cors_send(message):
            if message["type"]=="http.response.start" and values.get(b"origin") in self.origins:
                message=dict(message)
                response_headers=list(message.get("headers",[]))
                if not any(key.lower()==b"access-control-allow-origin" for key,_ in response_headers):
                    response_headers += [(b"access-control-allow-origin",values[b"origin"]),(b"access-control-allow-credentials",b"true"),(b"vary",b"Origin")]
                message["headers"]=response_headers
            await original_send(message)
        send=cors_send
        if b"transfer-encoding" in values and (b"content-length" in values or values[b"transfer-encoding"].lower()!=b"chunked"):
            return await self.respond(send,400,"Invalid request framing")
        if len(values.get(b"authorization",b""))>8192:
            return await self.respond(send,401,"Invalid authorization header")
        host = values.get(b"host",b"").decode("latin1").lower()
        try:
            parsed = urlsplit("//"+host)
            # A port is optional; accessing it rejects malformed port syntax.
            parsed.port
            valid_host = bool(host and parsed.hostname and not any(c in host for c in "/\\?#@ \t\r\n"))
        except ValueError:
            valid_host = False
        if not valid_host or (parsed.hostname not in {"localhost","127.0.0.1","::1"} and host not in self.extra_hosts):
            return await self.respond(send,400,"Unrecognized host")
        path = scope.get("path","")
        category = "scan" if path in {"/scan", "/website/check"} else "login" if path == "/login" else "register" if path == "/register" else "report" if path.startswith("/report/") else "history" if path in {"/history", "/history/page", "/history/summary"} else "other"
        count, seconds = {"scan":(60,60),"login":(60,60),"register":(20,600),"report":(120,60),"history":(120,60),"other":(300,60)}[category]
        if not self.allowed(category,count,seconds):
            return await self.respond(send,429,"Request limit reached; please wait before trying again")
        if self.active >= self.max_active:
            return await self.respond(send,503,"The server is busy; please retry later")
        limit = 6*1024*1024 if path == "/scan" else 16*1024
        length = values.get(b"content-length")
        if length is not None and (not length.isdigit() or len(length)>10):
            return await self.respond(send,400,"Invalid content length")
        if length is not None and int(length)>limit:
            return await self.respond(send,413,"Request body exceeds the upload limit")
        self.active += 1
        started = False
        try:
            body = bytearray()
            try:
                async with asyncio.timeout(self.body_timeout):
                    while True:
                        event = await receive()
                        if event["type"] == "http.disconnect": return
                        chunk = event.get("body",b"")
                        if len(body)+len(chunk)>limit:
                            return await self.respond(send,413,"Request body exceeds the upload limit")
                        body.extend(chunk)
                        if not event.get("more_body",False): break
            except TimeoutError:
                return await self.respond(send,408,"Request body timed out")
            if length is not None and int(length)!=len(body):
                return await self.respond(send,400,"Incomplete request body")
            delivered = False
            async def replay():
                nonlocal delivered
                if delivered: return await receive()
                delivered = True
                return {"type":"http.request","body":bytes(body),"more_body":False}
            async def secured_send(message):
                nonlocal started
                if message["type"] == "http.response.start":
                    started = True
                    message = dict(message)
                    response_headers = [(k,v) for k,v in message.get("headers",[]) if k.lower() not in {b"cache-control",b"x-content-type-options",b"x-frame-options",b"referrer-policy"}]
                    message["headers"] = response_headers+[(b"cache-control",b"no-store"),(b"x-content-type-options",b"nosniff"),(b"x-frame-options",b"DENY"),(b"referrer-policy",b"no-referrer")]
                await send(message)
            try:
                async with asyncio.timeout(self.request_timeout):
                    await self.app(scope,replay,secured_send)
            except TimeoutError:
                if not started: await self.respond(send,504,"Request processing timed out")
            except Exception:
                if not started: await self.respond(send,500,"The request could not be completed")
                else: raise
        finally:
            self.active -= 1
