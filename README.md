# QR Shield

QR Shield is a local-first QR and website security review application. It decodes QR images, reports explainable URL and QR-image indicators, supports UPI safety checks, stores account-scoped scan history, and generates PDF reports. Results are advisory and do not guarantee that a destination is safe.

## Application flow

```text
QR image ──> FastAPI /scan ──> pyzbar / OpenCV decode ──> URL, UPI, or text analysis
                                  │
Website URL ──> /website/check ───┘
                                  ├─ offline URL structure and brand rules
                                  ├─ optional bounded TLS / redirect-header checks
                                  ├─ optional Google Safe Browsing reputation lookup
                                  ├─ optional registered-domain RDAP lookup
                                  ├─ QR image integrity indicators (image scans only)
                                  └─ deterministic overall-risk classification
                                          ├─ HTML result and account history
                                          └─ owner-authorized ReportLab PDF
```

## Main components

| Area | Implementation |
| --- | --- |
| Frontend | Vanilla HTML, CSS, and JavaScript in `frontend/`; shared navigation and four selectable themes |
| API and authentication | FastAPI routes, bcrypt password hashing, HS256 JWT bearer tokens in `backend/main.py` |
| Storage | SQLAlchemy models in `backend/database.py`; SQLite by default; history/report reads are scoped to the authenticated user |
| QR processing | pyzbar first, then OpenCV WeChat QR decoding; image integrity checks are in `backend/main.py` |
| URL evidence | Offline rules in `backend/url_security.py`; bounded public-destination probes in `backend/url_probe.py` |
| Reputation and registration | Optional Safe Browsing v5 in `backend/safe_browsing.py`; optional RDAP in `backend/rdap.py` |
| Payments | Offline UPI parsing and advisory checks in `backend/upi_security.py` |
| Reports | XML-escaped ReportLab construction in `backend/main.py`; reports use the evidence stored with the scan and do not re-run lookups |
| Restricted demonstration | `backend/demo_security.py` and `backend/demo_runtime.py` provide the separate gated, offline demonstration mode |
| Development gateway | `tools/dev_gateway.py` serves only `frontend/` and proxies same-origin `/api/` requests to loopback FastAPI |

## Security and analysis behavior

- Authentication is required for scanning, the Website Checker, dashboard/history, and private PDF reports. History and deletion use the authenticated account, not a client-supplied user ID.
- The combined numeric score is unavailable when experimental ML is excluded. The separate deterministic overall-risk classification uses stored security evidence and does not create a replacement score.
- Experimental ML is excluded from the default QR scan path and the Website Checker. Do not describe it as a calibrated phishing probability.
- Safe Browsing and RDAP are opt-in configuration features. Restricted-demo mode overrides these settings and remains offline.
- When enabled in normal development, destination checks are restricted to validated public DNS results pinned to the connection. TLS uses normal certificate and hostname verification. Redirect inspection is limited to five hops, validates each destination, and reads response headers only; page bodies, scripts, and subresources are not downloaded.
- A Safe Browsing lookup sends the full submitted URL to Google. RDAP receives the registered domain. Avoid submitting private or token-bearing links when either service is enabled.
- QR integrity checks are heuristic indicators. A warning concerns the image itself and is distinct from URL reputation. A clean result is not a safety guarantee.
- The local gateway is for controlled development only. Keep FastAPI on loopback, keep the Dev Tunnel private, and do not treat the gateway as production hosting.

## Local development

Create/configure the ignored `backend/.env` with a random `JWT_SECRET_KEY` of at least 32 bytes. Do not place credentials in frontend files or commit them. `.env.example` and `.env.demo.example` contain templates; the demo template is not a production secret source.

Start FastAPI from the project root:

```powershell
.\backend\venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000
```

For same-origin frontend/API access, start the local development gateway in another terminal:

```powershell
.\backend\venv\Scripts\python.exe -B .\tools\dev_gateway.py --port 5500
```

Open `http://127.0.0.1:5500/login.html`. The gateway binds to loopback and proxies `/api/` to the existing local FastAPI service. Do not forward port 8000 for remote access.

Optional live-analysis flags default off:

```text
SAFE_BROWSING_ENABLED=false
RDAP_ENABLED=false
QR_SCANNER_ML_ENABLED=false
```

Safe Browsing additionally requires `GOOGLE_SAFE_BROWSING_API_KEY` in the backend process environment or ignored backend `.env`. Enable live checks only after reviewing their data sharing, quotas, and configuration. `QR_SHIELD_MODE=restricted-demo` must continue to block external analysis.

## Regression checks

Use the project virtual environment so the dependency versions in `backend/requirements-demo.lock` are applied:

```powershell
.\backend\venv\Scripts\python.exe -B .\backend\tests\run_isolated_regressions.py
.\backend\venv\Scripts\python.exe -B .\backend\tests\run_frontend_static_checks.py
.\backend\venv\Scripts\python.exe -B .\backend\tests\run_result_explanation_checks.py
.\backend\venv\Scripts\python.exe -B -m unittest discover -s .\tests -p "test_*.py"
```

The isolated backend runner uses synthetic records, an in-memory SQLite database, a stub model, and blocks external DNS/network access. Browser runners depend on the locally installed Edge executable and may be unavailable in restricted/headless environments. Mocked provider tests do not confirm live API credentials, provider quotas, or live network availability.

## Known limits

- URL rules, reputation results, registration metadata, TLS observations, redirect observations, and QR integrity checks are evidence with different scopes; none proves legitimacy or malicious intent by itself.
- Safe Browsing can miss new threats or return false positives. An unlisted URL is not verified as legitimate.
- The QR image tampering detector is heuristic and can produce false positives or miss changes. Treat its reasons as a request for manual review, not proof of alteration.
- The project has no production deployment hardening claim. Development rate limits are process-local, the SQLite default is for local use, and the development gateway is not a production reverse proxy.
- Physical-device camera behavior, real network/provider responses, tunnel access rules, and PDF handling on target phones still require manual verification for a final demonstration.
