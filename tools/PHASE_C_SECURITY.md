# Phase C security hardening — 21 October 2026

## Scope and decision

Implemented Phase C only on `fix/history-user-isolation`. Pre-existing edits/untracked files were preserved. Relevant diffs and baseline suites were inspected before edits; hashes of 146 existing source/report files were recorded for comparison. No branch change, reset, clean, stash, checkout, commit, push, deployment, Docker installation, schema change or production-model retraining.

**URL network analysis is now disabled in every mode. There is no fetching opt-in.** A securely pinned, bounded HTTP/TLS/DNS implementation was not introduced. Instead, the previous requests/WHOIS implementation was removed from scanner helpers. This is the permitted fail-closed mitigation, not a claim that a live fetcher now handles DNS rebinding safely.

## Vulnerabilities and mitigations

### Outbound network behavior

Previously, hostname validation and requests' connection resolution were separate; redirects, HTTP bodies and WHOIS lacked sufficient total/resource bounds. Now `validate_outbound_url()` always rejects fetching; `trace_redirects()` returns only the submitted URL plus an explicit disabled-policy notice; TLS/domain-age helpers return `None` without DNS, requests or WHOIS activity. Restricted-demo mode retains its access gate and disabled checks.

There are **zero scanned-destination connections, zero downloaded HTTP bytes and zero followed redirects**. HTTP/HTTPS syntax does not authorize a connection. Loopback, private, link-local, multicast, reserved, IPv4/IPv6, alternate numeric hosts, DNS failures, rebinding, private redirect targets, endless redirects, oversized bodies and slow responses cannot cause scanner egress because the network operation is never attempted. Environment proxies, destination cookies and credentials consequently have no scanner fetch path. This protection is not an OS-wide egress firewall or a reusable secure network client.

### Bounded inputs and operations

| Boundary | Current limit / behavior |
|---|---|
| API scan multipart body | 6 MiB before multipart parsing in both modes; gateway also rejects larger declared bodies before reading |
| Other API/gateway bodies | 16 KiB |
| Image file | Existing 5 MiB file limit retained |
| Decoded image | Existing 16-megapixel limit before OpenCV allocation retained |
| Decoded QR content | 16 KiB UTF-8; oversize returns 413 |
| URL input | 8,192 characters; oversize returns 413 |
| Hostname | IDNA validation, DNS label lengths, 253 characters and at most 32 labels |
| Invalid URL syntax | 400 for malformed hosts, whitespace/control characters, backslashes, malformed percent encoding, ambiguous numeric/encoded hosts or invalid punycode |
| Body read | 10 seconds at API boundary |
| Gateway upload read | 30-second total body deadline; does not reset indefinitely for trickled chunks |
| Active API requests | Four per process |
| Native scan / PDF / history work | One slot each; HTTP deadlines 30 / 20 / 10 seconds |
| Whole application call | 45 seconds after body read |
| Gateway upstream socket | 45-second socket timeout; this is not claimed as a separate hard total gateway deadline |
| History | ORM batches of 100; at most 5,000 rows and 8 MiB serialized response; 413 instead of silent truncation |

Timeouts cannot kill native threads. Their slots remain occupied until actual completion, including after cancellation/timeouts; a stuck native operation requires restart. Limits are process-local; run one worker/instance for these aggregate limits. History byte limits bound normal serialization accumulation, but unusually large legacy individual database fields can still require allocation before the response limit is checked.

URL validation never trims or rewrites decoded content or changes model feature calculations. Supported private/IP addresses can still be decoded and analyzed offline; they are never contacted. Embedded credentials and invalid/unusual ports retain existing explanatory rules, while network use remains prohibited. Unicode/IDN support does not establish ownership or provide complete homograph detection. No new heuristic risk points, thresholds or weighting were added.

### Authentication, errors and API exposure

Existing HS256 JWT validation, required subject/expiry, secret requirements, bcrypt password handling and per-user history/PDF filters remain. Invalid stored password hashes now fail authentication normally rather than raising an unhandled error. Existing login/registration endpoints, request fields, token storage, expiry and business-error contracts are unchanged. Registration remains enabled in development and disabled in restricted-demo mode.

Development API limits are global per process: login 60/minute, registration 20/10 minutes, scans 60/minute, reports/history 120/minute each, other requests 300/minute. Restricted-demo's existing stricter limits remain. Forwarded IP headers do not create new limiter buckets. These limits can cause shared denial of service and reset on restart; they are not distributed public-service abuse protection.

Both modes reject duplicate/ambiguous sensitive headers and inconsistent body framing. Development API Host defaults to loopback names; optional `QR_SHIELD_ALLOWED_HOSTS` adds exact configured hosts only. Host validation runs outside CORS so preflight cannot bypass it. Explicit-origin CORS remains; permitted local origins receive CORS headers on boundary errors. No wildcard/credential bypass was added. Validation errors remain redacted; unexpected pre-response exceptions receive generic JSON. API responses are no-store with nosniff, frame-denial and no-referrer headers. Restricted-demo keeps its existing additional headers and gate.

`/docs`, `/redoc` and `/openapi.json` are disabled in every mode. `/`, `/login`, `/register`, `/scan`, `/history` and `/report/{scan_id}` remain. Application logout still removes the client token; copied JWTs remain valid until their existing expiry unless the signing secret is rotated.

### Gateway

The gateway still binds only to `127.0.0.1`, serves frontend files and targets only localhost FastAPI. HTTP framing, methods, Authorization, upload bodies, PDF content/status and hop-by-hop/tunnel-header stripping remain covered by regressions. It rejects missing/malformed/duplicate Host, duplicate Authorization/Origin/Content-Type, invalid/signed Content-Length, transfer encoding and oversized bodies. Raw forwarded-host headers cannot override configured Host checks. Frontend test files are unavailable, including case variants on Windows.

Public-test mode still requires explicit CLI configuration. Exact `--allowed-host` entries now enforce a host list even in private development mode. With no explicit host list, ordinary private development still permits syntactically valid tunnel hosts for compatibility; do not interpret that mode as public-link protection. Loopback hosts remain allowed. The gateway does not bypass the restricted-demo gate or forward its cookie: restricted cloud/demo use should use the existing `demo_app:create_app` same-origin wrapper, not substitute the development gateway for it.

## Observable compatibility impact

- New scans retain existing keys and add `final_url_verified: false` and `redirect_check_status: "not_performed"`. `final_url` contains the original recorded URL, not a claimed verified redirect destination. Domain age/TLS are unavailable; raw HTTP remains an observed transport indicator.
- Technical view labels the destination unverified and redirect hops “Not checked”; the one recorded URL is not presented as an observed redirect journey. Copy QR Content, warning-before-opening, themes, layout and existing controls remain intact.
- PDF structure and recorded evidence remain; wording explains the current disabled policy and that downloading does not reverify historical destinations. Single-entry chains no longer imply a verified zero-hop result. No historical record was rewritten.
- The 70/30 formula and 31/61 classification cutoffs are unchanged. **Scores can differ from old live scans because previously observed domain-age/TLS/redirect contributions are now unavailable.** Do not interpret missing checks as passed or a low score as proof of safety.
- Requests over documented limits return explicit 400/413/429/503/504 responses. Histories over the limit are rejected in full so the dashboard does not display misleading partial totals. Normal bounded histories retain their existing response shape/fields.

## Files changed

- `backend/main.py`: no-network helpers, bounded jobs/inputs/history, safe hash failure, disabled docs and unavailable-check/report metadata.
- `backend/api_security.py` (new): development-mode pre-parser resource/header/Host/rate/error boundary.
- `backend/url_policy.py` (new): shared no-network notice and bounded URL syntax checks.
- `backend/demo_runtime.py`: adds bounded history processing alongside existing jobs.
- `backend/demo_security.py`: strengthens duplicate-header/framing/body-size checks without changing access-gate behavior.
- `tools/dev_gateway.py`: header/Host checks, configured private-host enforcement, consistent body caps, test-file blocking and upstream socket timeout.
- `frontend/scan.html`: only destination/redirect availability wording; no redesign or scanning logic changes.
- `backend/tests/test_phase_c_security.py` (new) and `tests/test_phase_c_gateway.py` (new): focused security tests.
- `backend/tests/test_api_security.py`, `backend/tests/test_history_authorization.py`: synthetic ASGI helpers supply a legitimate Host header; authorization assertions retained.
- `backend/tests/test_url_detection.py`: the former live TLS result test now asserts no call/unavailable even if legacy validation is monkeypatched; existing offline scoring tests retained.
- `frontend/tests/result-explanations.test.js`, `backend/tests/run_phase_b_rendered_checks.py`: unavailable-check UI regressions added while preserving Phase B checks.
- `tools/RESTRICTED_CLOUD_DEMO.md`, `tools/RESTRICTED_DEMO_TEST_RESULTS.md`: current-policy notices above historical information.
- This report.

## Executed validation

All Python commands used `backend/venv/Scripts/python.exe -B`.

| Command | Baseline | After changes |
|---|---|---|
| `backend/tests/run_isolated_regressions.py` | 140 tests; zero failures/errors; one skip | 156 tests; zero failures/errors; one skip |
| `-m unittest discover -s tests -v` | 20 passed | 26 passed |
| `backend/tests/run_frontend_static_checks.py` | Passed in Phase A/B | 20 passed; nine scripts compiled; 21 navigation links checked |
| `backend/tests/run_result_explanation_checks.py` | 61 passed in Phase B | 64 passed |
| `backend/tests/run_warning_ui_checks.py` | Passed in Phase B | 45 synthetic + 35 mocked prediction checks at each of 1280, 390, 320 px |
| `backend/tests/run_phase_b_checks.py` | 176 passed in Phase B | 176 passed |
| `backend/tests/run_phase_b_rendered_checks.py` | 10 cases in Phase B | 10 cases; both themes at 320, 390, 768, 1280, 1440 px, now including Technical-view unavailable-check labels |
| `tools/verify_ml_acceptance.py` | Previously passed | Passed; class -1 selection/reordered columns and artifact schema verified |
| `git diff --check` | Passed | Passed |

The sole backend skip is the pre-existing Windows symlink-permission limitation. No existing failing baseline was hidden. The former live-TLS test was changed because that feature is explicitly disabled, with stronger no-network assertions replacing simulated connection success/failure—not deleted to obtain a pass. Tests use memory/fresh temporary databases, synthetic QR images/tokens, local fixture servers and mocked destination behavior. No suspicious URLs/internal services were probed. Root gateway integration tests exercise registration/login, actual QR upload/decoding, history authorization and PDF responses using an isolated backend.

New tests cover private IPv4/IPv6/link-local/multicast/numeric hosts, rebinding/DNS failures, redirect-to-private/loop/large/slow response stubs that must never be reached, body framing and streamed size rejection, image dimensions/types/file size, malformed/oversized URLs and payloads, IDN inputs, safe API errors, request/time/concurrency/rate limits, Host preflight, disabled docs, history row/byte/time limits, oversized legacy history isolation, raw duplicate gateway headers, forwarded-host spoofing, configured private host lists and private tunnel-host compatibility. Unauthorized/cross-account history/report and JWT checks continue in existing suites.

The trusted artifact hash remains `d5ebec79e73c331594effed3dc36ad8bfb817319aa70d0c2cb64298a7150a2ff`. Class -1 estimates remain approximately Google 99.8933%, original PayPal-themed string 20.2194%, alternate string 54.1969%. This phase does not establish model accuracy/calibration or resolve sklearn compatibility warnings.

## Configuration and manual verification

No new setting is required for normal loopback development or the existing restricted wrapper. No environment flag enables scanned-URL fetching. Keep backend port 8000 unforwarded and bound to loopback for local development.

1. Restart FastAPI using the existing environment and `--host 127.0.0.1 --port 8000`; prefer `--no-access-log` to avoid request-query logging. This work did not restart the running personal-data service.
2. Restart the existing gateway. For explicit private-tunnel Host restriction, use `backend/venv/Scripts/python.exe tools/dev_gateway.py --allowed-host YOUR-EXACT-TUNNEL-HOST` from the project root. Keep port 5500 visibility unchanged. Public-test CLI safeguards remain opt-in and require an exact host; no tunnel was made public here.
3. Log in/register locally where enabled. Check two existing test accounts remain isolated and cross-account report downloads fail. Do not expose token values or private report contents in diagnostics.
4. Scan a trusted locally generated URL QR and a synthetic `http://paypal-login.example.com/verify` QR without opening that destination. Confirm exact decoded content, offline reasons/ML output, unavailable network checks, unverified recorded URL and “Not checked” redirects. Test UPI, camera/retake, QR generator, dashboard, PDF and copy controls on the real HTTPS phone link.
5. Confirm large/invalid uploads fail with clear errors and busy/time-limited requests stop loading. Automated rate tests used synthetic traffic; do not flood the live demo.
6. Verify local `/docs` and `/openapi.json` return 404 after restart. Verify wrong configured gateway Host returns 400 and frontend test-script paths return 404. The API allows only configured CORS origins; no wildcard was added.
7. Read the existing restricted-cloud guide before using that separate profile. Its Linux/container/model/version/persistent-volume/hosted-mobile acceptance blockers remain; no deployment readiness is claimed by these changes.

## Remaining risks

Native jobs are not forcibly killed; process-local limits require one instance/worker and may be exhausted by another user. Legacy individual database fields can be larger than current upload constraints; response checks do not retroactively rewrite records. No distributed limiter, OS egress firewall, pinned live-fetch client, phishing reputation service, model retraining/calibration, full Unicode homograph detector or dataset evaluation was introduced. Private gateway mode without an explicit allowlist is not suitable as public exposure protection. ML reliability/version warnings, client-only logout and physical-phone/tunnel behavior remain limitations. No Phase D/E implementation or changes to UPI logic, dashboard calculations, ML feature extraction/class mapping, database schema, risk weights or classification thresholds were made.
