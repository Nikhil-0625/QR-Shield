# QR Shield private remote testing gateway

This is a temporary development gateway, not production hosting. It uses Python standard-library HTTP modules; no new packages are required. FastAPI and its existing JWT/CORS/security configuration remain unchanged.

## Start

Keep the existing FastAPI server running on 127.0.0.1:8000. Stop the old Python frontend HTTP server with Ctrl+C in its terminal first: only one process can bind port 5500. From the project root run:

```powershell
.\backend\venv\Scripts\python.exe .\tools\dev_gateway.py
```

Open http://127.0.0.1:5500/login.html (or http://localhost:5500/login.html). The gateway binds only 127.0.0.1. Its / URL opens login.html. For debugging a different local port, use --port 5501; its upstream remains fixed at 127.0.0.1:8000.

Serve/forward only this gateway on port 5500. Keep its VS Code visibility Private. The existing port-8000 forwarding is no longer needed; manually stop forwarding that port in VS Code to achieve a one-forwarded-port setup. No tunnel settings were changed by this implementation.

## Mobile

Copy the exact HTTPS forwarded address for port 5500 from VS Code and open /login.html on the phone. Authenticate to the private tunnel with the account that owns/has permitted access to the tunnel, then sign in separately to QR Shield using a local test account. Browser API requests now target the same forwarded origin under /api. /api/login maps to /login; /api/scan to /scan; /api/history to /history; /api/report/{id} to /report/{id}. No CORS changes or tunnel tokens in frontend code are required.

Private visibility does not automatically invite friends. Under the standard VS Code private-port flow, access is restricted to the tunnel owner. Sending the URL alone does not grant access. Supporting other identities requires supported explicit tunnel access controls and authorization; do not share account credentials or paste tunnel bearer tokens into frontend code. The current tunnel ACL/authentication flow was not exercised. No public port or tunnel was started.

## Local compatibility

Gateway-served login/scanner/dashboard HTML receives a fixed non-secret window.QR_SHIELD_API_BASE='/api' marker. Those three pages use it before their existing localhost fallback. Original files served by a plain Python server still call http://127.0.0.1:8000 on localhost (or file://); non-local hosts default to /api. No URL-supplied overrides or host-derived backend URLs are accepted. Existing API bodies, JWT headers, scoring and response rendering are unchanged. Login/theme preferences are origin-specific: the forwarded URL needs its own QR Shield sign-in.

Experimental ML remains isolated at 127.0.0.1:8766, with its existing local-only CSP, CORS and Host/client/origin guards. It is not proxied. Remote synthetic demonstrations work; live candidate prediction remains local-only.

## Boundaries

Only frontend files with approved web-asset extensions are served. No directory listings. Dot paths, traversal, encoded traversal/backslashes, Windows drive/alternate-stream syntax and symlink/junction paths are rejected. Resolving a file outside frontend is rejected. /api always connects to the fixed loopback backend, never a client-selected host. Tunnel authentication headers/cookies and forwarded headers are not passed to FastAPI; the application Authorization header is preserved. Hop-by-hop headers are removed. Responses use validated Content-Length when available, or explicitly terminated HTTP/1.1 chunked framing for streams; status, content type and PDF disposition are retained. Incomplete upstream bodies close the connection without falsely signaling successful completion.

Gateway limits: 20 MiB request-body cap, 30-second upload read timeout, 120-second upstream socket timeout. Incoming chunked requests are rejected (normal browser FormData uploads use Content-Length). Bodies are buffered before forwarding; responses stream. The gateway has no independent app login, rate limiter or production concurrency hardening: security relies on private tunnel access and FastAPI endpoint authorization. It can reach the existing backend routes under /api, including public backend documentation if enabled. Never serve the project root or expose 8766.

## Tests actually executed

- 7 gateway unittest cases passed. Boundary/protocol tests use a synthetic HTTP upstream on an ephemeral loopback port. They cover methods, binary multipart body bytes, query strings, JWT header preservation, tunnel credential stripping, unavailable upstream, unknown paths, traversal, mocked symlink rejection and upload/framing limits.
- Real local HTTP integration through the gateway to an isolated FastAPI server passed: synthetic account registration/login using real bcrypt/JWT, generated PNG QR decoded by the existing scanner, user history, real PDF rendering/download headers and foreign-account PDF denial. SQLite is in memory; model loading is stubbed; the QR encodes plain text, with no external URL analysis. This is not a test against the user's running FastAPI or existing records.
- Actual gateway-served pages loaded in headless Edge: same-origin API configuration checked on all three API pages; synthetic interactions passed across all five pages, including QR generation/download dispatch. Browser API responses were mocked. No live tunnel/mobile session was tested.
- Existing isolated backend suite: 99 tests run, 0 failures/errors, 1 OS-dependent symlink test skipped. See tests/gateway-backend-regressions.txt.
- Existing frontend checks: 8 scripts compiled, 21 navigation links, 19 checks passed. Experimental UI runner: 45 synthetic and 35 mocked prediction checks passed at each requested width 1280/390/320.
- git diff --check passed for implementation files.

Run gateway tests again:

```powershell
.\backend\venv\Scripts\python.exe -m unittest discover -s tests -p test_dev_gateway.py -v
```

Manual checks remaining: real private-tunnel sign-in and ACL behavior, mobile camera permissions, scans against the running backend, device PDF save/open, friend access and disconnects/timeouts. No database records, backend security logic, ML artifacts, external backup, commit/push/deployment or tunnel visibility settings were changed.

Application files changed: tools/dev_gateway.py (new), frontend/login.html, frontend/scan.html, frontend/dashboard.html. Documentation/tests: tools/DEV_GATEWAY.md, tests/test_dev_gateway.py, tests/gateway-backend-regressions.txt. Browser test artifacts were added under .design-review.


## Response framing repair

The original gateway removed Content-Length and upstream chunk framing and relied on Connection: close to terminate every proxied body. Close delimiting is permitted by HTTP/1.1, but it makes completion depend on EOF being propagated through the tunnel. It also discarded evidence of upstream body truncation: a synthetic upstream claiming 10 bytes but sending 2 was accepted as a complete response by the downstream client. The live Dev Tunnel HTTP/2 error was not reproduced; connection-close handling by the relay is a plausible explanation, not a proven live-tunnel root cause.

The gateway now validates and emits upstream Content-Length for fixed bodies. Python's HTTP client decodes upstream chunk framing; the gateway produces its own chunk framing for responses without known lengths, and sends the final zero chunk only after successful completion. Body chunks and final framing are explicitly flushed. HEAD retains valid length metadata but emits no body; 204/304 and informational responses do not stream bodies. Hop-by-hop headers remain filtered, including Connection-nominated fields. Upstream failures before headers return a length-delimited 502; failures after headers close the connection without a false completion marker. No registration/authentication logic or frontend code changed for this repair.

Final protocol suite: 14 tests passed. Tests cover fixed-length and chunked completion with connection reuse, HEAD/GET/OPTIONS, JSON error statuses 400/401/403/404/422/500, 256 KiB binary body/disposition, invalid upstream length, detectable truncation, gateway boundaries and synthetic FastAPI registration/login/real QR scan/history/real PDF. The backend integration used ephemeral loopback ports, an in-memory database, synthetic accounts and stub model loading, never the running production database. The existing isolated backend regression suite also passed (99 run, 1 OS-dependent skip). Tests are HTTP/1.1 local tests, not an HTTP/2 tunnel test.

Restart the gateway after this change (Ctrl+C in its terminal, then the startup command above). FastAPI needs no code change or restart for this repair. Keep port 5500 Private. Open the forwarded HTTPS /login.html in a fresh/reloaded tab, authenticate to the private tunnel, and register/login using temporary test accounts. In DevTools check /api/register and /api/login finish with parseable JSON rather than staying pending. Also check scan upload, history and PDF. If the HTTP/2 protocol error persists, capture a sanitized HAR/timing report and compare local versus forwarded behavior; redact passwords, JWTs and tunnel cookies. HTTP/2 responses must not carry Transfer-Encoding: chunked?the tunnel relay must translate the gateway's HTTP/1.1 framing to HTTP/2 DATA/END_STREAM. Do not disable HTTP/2/browser security or make the tunnel public as a workaround.

Files changed for this repair: tools/dev_gateway.py, tests/test_dev_gateway.py, tools/DEV_GATEWAY.md, tests/gateway-backend-regressions.txt (refreshed test output). No existing user data, models, backups, backend security or tunnel settings were changed. No commit/push/deployment.
