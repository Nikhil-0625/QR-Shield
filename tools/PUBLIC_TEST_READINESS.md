# QR Shield temporary public-link readiness

## Assessment

Reasonably prepared for a short, supervised session with a few trusted friends **only when the new public-test gateway mode is enabled**, FastAPI is loopback-only, and port 8000 is not forwarded. This is not production hardening or protection against hostile Internet traffic. No tunnel visibility, live database records or running service settings were changed. The actual forwarded session must be verified manually.

## Launch and stop

Restart FastAPI to load the new upload/secret checks. Use the existing backend working directory so its relative scan_history.db path continues pointing to the SAME database; changing the working directory can select/create a different database. For the usual backend directory launch:

```powershell
cd backend
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

If your existing launch uses a different working directory, retain that directory and module command instead. Do not reset, move or delete any database. No database paths or schema were changed by this task.

Stop the old gateway with Ctrl+C. From the project root:

```powershell
.\backend\venv\Scripts\python.exe .\tools\dev_gateway.py --public-test --allowed-host YOUR-EXACT-5500-HOST.devtunnels.ms
```

Replace the placeholder with the hostname of the existing forwarded HTTPS address, without scheme/path/trailing slash. Localhost:5500 and 127.0.0.1:5500 remain allowed automatically. More than one exact hostname can be specified by repeating --allowed-host. The gateway always binds 127.0.0.1; its backend target remains fixed at 127.0.0.1:8000. This flag does not create a tunnel or change visibility. Do not use the old launch command without --public-test for public access.

Before manually choosing public access, verify only port 5500 is forwarded and FastAPI has no non-loopback listener. Listener inspection during this review produced no entries, so the running bind configuration was not independently confirmed. Keep all testing accounts and QR contents synthetic, and do not reuse real passwords.

Quick disable: Ctrl+C in the gateway terminal stops public access through 5500 immediately (the forwarded URL can remain configured but has no gateway to reach). Also manually stop forwarding or return visibility to Private. No app-token revocation is performed; JWTs still expire normally after 60 minutes. No tunnel setting was changed here.

## Findings and fixes

1. No login/registration throttling: public-test mode enforces shared sliding-window budgets of 30 login attempts per 60 seconds, 10 registrations per 10 minutes, and 10 scans per minute. All attempts count, including failures. State is bounded, locked and in memory; it resets on gateway restart. It deliberately does not trust X-Forwarded-For. Shared budgets protect this one process but can be exhausted by one client. Gateway API errors are JSON with status/message/detail, correct HTTP status and Retry-After on 429.
2. Unbounded gateway threads/connections: gateway now caps accepted concurrent connections at 12 with a 15-second initial/idle socket timeout. Excess connections receive 503 when deliverable, or are disconnected. Public requests are bounded before buffering: 6 MiB scan multipart bodies; 16 KiB other allowed API bodies. Existing 30-second upload and 120-second upstream socket timeouts remain. Limits do not provide a hard overall deadline against trickle traffic.
3. Backend image resource exposure: scan reads at most 5 MiB plus one byte, rejects oversized uploads with 413, validates image structure and checks a 16-megapixel dimension cap with Pillow BEFORE OpenCV allocation. Empty/invalid images remain generic 400. Pillow is already installed through qrcode[pil]; no dependency was added. Format handlers initialize before request-worker use. Scoring/decoding logic is untouched. The gateway remains important because FastAPI parses multipart before the endpoint file-read limit.
4. Public documentation/debug exposure: public-test mode proxies only POST /login, /register, /scan and GET/HEAD /history and /report/{numeric_id}. Docs, OpenAPI, redoc, root/debug/experimental/unknown routes and other methods are blocked at the gateway. Default development mode keeps the previous route behavior. Backend docs are not disabled locally.
5. Host and caching: public-test mode accepts only exact configured tunnel hosts and local gateway hosts. It strips client forwarded/tunnel headers before upstream; backend Host is fixed loopback. API responses are no-store and nosniff, preventing intermediary caching of JWT/history/report responses. Existing explicit Content-Length/chunked framing is retained.
6. JWT secret guard: missing/blank secrets already failed startup; keys shorter than 32 UTF-8 bytes now also fail. Actual .env values were neither read nor printed. Length is not proof of entropy: use a cryptographically random secret. No secret was generated, replaced or rotated. If restart rejects the existing key, configure a strong key yourself; rotating invalidates existing JWTs.
7. Bcrypt input limit: registration rejects passwords beyond 72 UTF-8 bytes before hashing; login returns the existing generic invalid-credentials envelope for these inputs. This prevents silent password truncation and bcrypt version-dependent errors. Existing records were not modified; a legacy account created with a longer password may require recovery outside this test session. Existing normal-length login and registration contracts remain unchanged.

## Existing protections reviewed

JWTs are signature-verified with fixed HS256 and required exp/sub claims. Malformed/expired/wrong-key/wrong-algorithm tokens are rejected. History and PDF authorization filter by the token account, not supplied user IDs; foreign reports return 404. Real bcrypt hashing/salts and 60-minute token expiry were tested. Logout is client-only.

CORS still uses exact local origins via CORS_ALLOWED_ORIGINS; it was not widened. Browser remote requests are same-origin through /api and do not require wildcard CORS. FastAPI itself has no TrustedHostMiddleware; it is intended to remain loopback-only behind the host-checking gateway. Frontend APIs retain their original bodies and JWT headers. No frontend source/design/animations were changed.

Static gateway serving remains confined to frontend with extension checks, no directory listing, and traversal/dot/backslash/drive/encoded traversal plus symlink/junction rejection. It never serves project-root files, .env or databases. Path boundary tests passed; the actual filesystem was not comprehensively inspected for custom private files stored inside frontend. Do not place secrets in web assets. Gateway errors are generic and do not log credentials/URLs. FastAPI debug is off; tested errors did not disclose JWT secrets, hashes or stack traces. Registration still identifies duplicate accounts; credential errors retain the existing HTTP-200 envelope.

SQLite persists accounts/history on disk in the current existing working-directory database. SQLAlchemy bound queries and ownership isolation remain intact. No database was opened by security tests: imports/migrations were redirected to memory. There is no retention policy, quota, encryption-at-rest or automatic cleanup. Friend-created records during a real session WILL persist in the running database. Avoid private URLs/payment details. Backup policy and restoration were not changed or tested.

## Verification

- 18 gateway tests passed, including public-mode host, aggregate throttle/spoofed-forwarded-IP, budget expiry, body-size, docs/debug blocking and bounded-connection checks. Existing framing, path traversal, byte/method/JWT preservation and PDF tests also passed.
- Real HTTP integration used the public-test gateway with a real FastAPI ASGI server, synthetic registration/login, PNG QR decoding, history, actual PDF generation and cross-account report denial. Its SQLite database was in memory; model loading was stubbed; QR content was plain text, with no external URL scanning. This was not against the running app or live forwarded URL.
- Isolated backend regression suite includes upload byte/dimension rejection before OpenCV, overlong UTF-8 password rejection, short-secret startup rejection, and existing authentication/ownership/scoring/ML/PDF/UPI tests. Final count: 102 run, 101 passed, one OS-dependent symlink test skipped; no failures/errors. See tests/public-readiness-regressions.txt.
- Frontend checks passed: 8 scripts compiled, 21 links, 19 checks; experimental UI runner passed 45 synthetic and 35 mocked-prediction checks at each requested width 1280/390/320. QR generator remains client-side.
- git diff --check passed for changed code.

## Residual risks and manual checks

Anyone with public access can register an account; the URL is not an invitation-only access control. Limitations include shared in-process quotas, no account lockout/CAPTCHA/revocation, slow-request/resource denial of service, no disk/scan/account quota, and SQLite concurrent-write pressure. The existing URL scanner makes outbound DNS/HTTP/WHOIS requests; DNS rebinding/resolve-to-connect race and broad outbound resource exhaustion are NOT fully eliminated by this review. No outbound network allowlist was added because that would change scanner scope. Use trusted synthetic QR inputs and supervise the session; stop immediately if abuse occurs. Public access remains a risk acceptance, not a security guarantee.

Experimental port 8766 stays local-only and must not be forwarded. Port 8000 must not be publicly or privately forwarded for this session. Live tunnel host rewriting, HTTPS HTTP/2 behavior, camera permissions, mobile PDF save/open, real backend startup with the current secret, and the emergency-stop procedure need manual verification. No public tunnel was started. Dependencies remain unpinned; use backend/venv (the system Python bcrypt/passlib combination was previously incompatible).

Files changed: tools/dev_gateway.py; backend/main.py; tests/test_dev_gateway.py; backend/tests/test_api_security.py; backend/tests/test_upi_substitution.py (valid PNG fixture for image validation); tools/PUBLIC_TEST_READINESS.md (new); tests/public-readiness-regressions.txt (new). No external backup, existing records, models, commit, push or deployment changes.
