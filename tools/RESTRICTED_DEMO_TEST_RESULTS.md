# Restricted demo verification — 19 October 2026

> Historical baseline. Phase C (21 October 2026) subsequently disabled live URL network checks in **every** mode and extended backend/gateway resource limits. See [PHASE_C_SECURITY.md](PHASE_C_SECURITY.md) for current behavior and verification; older development-network limitations below describe the pre-Phase-C implementation.

No deployment, paid service, Git staging/commit/push, model retraining or personal database modification was performed. No frontend source/design or development-gateway file was edited for this task.

## Executed checks

| Check | Actual result |
|---|---|
| `backend/venv/Scripts/python.exe -B backend/tests/run_isolated_regressions.py` | 140 tests, zero failures/errors, one skipped; includes existing local registration/login, JWT rejection, ownership, QR decoding, scoring, UPI and PDF regressions plus restricted-demo tests |
| `backend/venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 20 tests, all passed; existing local gateway HTTP/security tests plus fresh temporary SQLite persistence/rejected database configuration |
| `backend/venv/Scripts/python.exe -B backend/tests/run_frontend_static_checks.py` | 9 JavaScript scripts compiled, 21 local links checked, 20 syntax/navigation/QR checks passed in headless Edge |
| `backend/venv/Scripts/python.exe -B backend/tests/run_result_explanation_checks.py` | 43 synthetic DOM result-explanation checks passed in Edge |
| `backend/venv/Scripts/python.exe -B .design-review/link_warning_review.py` | 3,038 assertions across 14 viewport/theme cases, plus 10 Escape/focus and 30 keyboard disclosure/Tab checks; 10 screenshots generated; navigation mocked |
| `backend/venv/Scripts/python.exe -B backend/demo_smoke.py` | Local Windows ZBar QR encode/decode round trip, OpenCV contrib detector construction and synthetic PDF passed |
| Syntax and whitespace | Seven runtime Python files parsed successfully; `git diff --check` passed; shell entrypoint verified LF line endings |

Tests use synthetic URLs, locally generated QR images, mocked network/ML data, memory SQLite or a new temporary SQLite file. No real malicious/internal endpoint was contacted. Restricted-mode helper tests assert DNS, requests and WHOIS functions are never called. Real QR decoding is exercised separately from mocked scoring outputs. Wrapper tests check host/origin rejection, private asset allowlisting, gate plus Bearer JWT preservation, cross-account history/report denial and disabled public registration/docs. Body-size rejection happens before the downstream app is called. Tests cover body and processing deadlines, rate rejection and native-job slot retention after timeout. Persistence is tested across engine disposal/reopening, not a real cloud/container restart.

Browser fixtures test the existing scanner/link-warning experience, with synthetic results, at widths 320, 390, 768, 1280 and 1440 in light/dark mode and extra short-height cases. Actual rendered screenshots inspected by the agent: dark 390px and light 1440px, both warning-dialog state. These are not screenshots of the new cloud gate/offline banner or actual hosted pages. Existing QR generation checks are automated; physical scanning and camera permissions remain manual.

## Actual unchanged model inspection

Loaded the trusted local artifact separately from FastAPI/database. File size: 176,397,049 bytes. SHA-256: `d5ebec79e73c331594effed3dc36ad8bfb817319aa70d0c2cb64298a7150a2ff`. Classes: `[-1, 1]`; 12 feature names match the original schema. Raw Wikipedia prediction remains `[[1.0, 0.0]]`; no score or model manipulation was introduced. Process RSS after loading and predicting was approximately 324.8 MiB, not full application peak usage.

The installed Windows sklearn runtime identifies itself as 1.9.1 although artifact metadata specifies 1.9.0; loading emitted InconsistentVersionWarning. The container requirements pin the original 1.9.0. Linux acceptance must run `python demo_smoke.py --model`, which requires that version, verifies the configured artifact hash before deserialization, checks feature names/classes and rejects version warnings. This acceptance command was NOT passed locally against the mismatched Windows runtime or on Linux.

## Remaining release blockers / manual checks

- Docker is not installed here: base-image availability, all pinned Linux wheels, `pip check`, apt libraries, non-root startup and container model smoke remain unverified. Do not call this a verified reproducible image yet.
- Hosted HTTPS redirect, Basic challenge/cookie behavior on actual phones, camera capture/upload/retake, full dashboard, generator downloads, PDF downloads and logout need acceptance on the final URL. No live cloud/tunnel test was performed.
- The injected offline banner and same-origin production routing need rendered inspection on the actual container in light/dark and mobile/desktop layouts. Source-level routing/asset tests pass.
- A real persistent-volume restart, hosting health checks, resource limits/memory peaks, private registry packaging and laptop-off accessibility require manual validation.
- Live SSRF connection pinning, redirect connection checks and bounded WHOIS/HTTP fetches are NOT implemented. Those features are disabled entirely in restricted-demo mode. Development mode retains that known outbound-fetch limitation and must stay private.
- The unchanged ML estimate remains unreliable/uncalibrated. Preserved 70/30 weighting can still produce misleading aggregate results; use the existing disclaimers and show actual evidence rather than promising a safe verdict.
- Native jobs cannot be killed by thread timeouts; slots stay occupied until completion. A permanently stuck native call requires a process restart. Global in-memory rate limits require exactly one instance/worker and are not a public multi-tenant anti-abuse system.

**Decision: local restricted-demo preparation complete; deployment NO-GO until the documented Linux and hosted acceptance gates pass.** Full setup and shutdown instructions: [RESTRICTED_CLOUD_DEMO.md](RESTRICTED_CLOUD_DEMO.md).
