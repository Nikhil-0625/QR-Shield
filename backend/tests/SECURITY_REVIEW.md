# Backend authorization/security review

## Scope and isolation
Actual FastAPI ASGI routes/dependencies, real HS256 JWT validation, real bcrypt hashing and SQLAlchemy queries were exercised locally. Tests redirect import-time database initialization/migrations to in-memory SQLite and stub model loading. Only synthetic accounts and scan records are used; no existing database is opened or reset. Scan ownership test uses a local generated image with mocked decoding/tampering output, not external URL analysis. PDF authorization stubs rendering; the existing PDF regression renders synthetic data. No frontend, ML model or risk-scoring changes.

## Findings and smallest fixes in main.py
- JWT decoding previously accepted signed tokens with no exp claim. Expiry and subject are now required; blank subjects are rejected. Algorithm remains restricted to HS256. Signed exp=null/list claims also caused HTTP 500 in python-jose: decode type/value/overflow errors now return the existing generic 401 response. These malformed claims require a valid signature; they are not evidence of signature bypass.
- Empty/corrupt multipart image uploads caused HTTP 500. Empty bytes, OpenCV decode exceptions and failed image decoding now return generic HTTP 400 before scanning/scoring.
- CORS previously allowed arbitrary origins with credentials. Defaults now allow only http://localhost:5500 and http://127.0.0.1:5500, matching the existing local frontend serving instructions. Set CORS_ALLOWED_ORIGINS to comma-separated exact HTTP(S) origins for another port or deployment. Wildcard and null origins are rejected at startup. GET/POST and Authorization/Content-Type are allowed. CORS is a browser policy, not a substitute for authentication; the previous configuration did not by itself bypass JWT checks. Serve the frontend over HTTP rather than file://.

## Passing authorization checks
Protected routes are POST /scan, GET /history and GET /report/{scan_id}. Missing, malformed, expired, wrong-key, wrong-algorithm, missing-expiry, missing/invalid/blank-subject and invalid-expiry tokens are rejected (401; missing bearer may be 403 depending on FastAPI version). Account A/B histories remain isolated. Foreign/unowned/nonexistent reports return the same 404; report rendering is not called for foreign data. There is no standalone individual-scan retrieval route beyond reports/history. Query user_id/email/scan_id, X-User-ID and multipart user_id cannot change ownership. New scan records use the token account. Error responses tested contain no stack traces or signing key; history has an explicit public field set, no password hashes. Login intentionally returns its own bearer token. Password hashing is salted bcrypt and verification succeeds/fails correctly; issued tokens expire in 60 minutes. Missing secrets already prevent startup; actual secret value/entropy was not inspected.

## Existing contracts and remaining limitations
Logout only removes the browser token; no backend logout/revocation route exists. Replayed JWTs remain valid until expiry. This behavior was tested and left unchanged. Invalid credentials, duplicate registration and weak-password responses retain existing HTTP 200 error envelopes to preserve frontend contracts; malformed request schemas return 422. Missing/foreign report IDs return 404. Image validation failures now return 400.

No rate limiting/lockout, token revocation, enforced secret entropy, upload size/decompression limit or password maximum-byte policy was added. Bcrypt has a 72-byte password limit; explicit long-password validation/migration deserves separate work. Duplicate-registration races and broader exception paths are not exhaustively tested. TLS/reverse proxy configuration, production origin configuration, actual secrets and deployment defenses were not verified. The installed global Python has bcrypt 5.0.0, incompatible with this legacy passlib setup and caused registration failure; project backend/venv uses bcrypt 4.0.1 and hashing passed. Dependencies were not changed. Use the project virtual environment; dependency pinning remains recommended work.

## Verification
The initial system-Python pytest run demonstrated CORS, missing-expiry, invalid-image and hashing-environment failures. Expanded malformed-expiry tests then demonstrated 500 responses, now fixed. Final tests use the project virtual environment. pytest is absent there, so pytest-compatible unittest classes were run with unittest without installing packages.

Commands:
- backend/venv/Scripts/python.exe -m unittest discover -s backend/tests -p test_api_security.py -q
- backend/venv/Scripts/python.exe backend/tests/run_isolated_regressions.py
- git diff --check -- backend/main.py backend/tests/test_api_security.py

Final focused suite: 13 tests passed, including inherited ownership regressions and token subcases. Full suite results are in security-regression-results.txt. No commits, push or deployment. This focused review is not proof of complete security.

Files changed this task: backend/main.py; backend/tests/test_api_security.py (new); backend/tests/SECURITY_REVIEW.md (new); backend/tests/security-regression-results.txt (new test output). Existing unrelated working-tree changes were preserved.
