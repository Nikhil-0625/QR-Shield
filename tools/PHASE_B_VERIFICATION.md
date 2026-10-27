# QR Shield Phase B — 21 October 2026

Scope: authorized focused additions to the existing dirty working tree on `fix/history-user-isolation`. No new branch, reset, clean, stash, checkout, commit, push or deployment. Existing source changes and untracked work were preserved. Target source files and their Git diffs were inspected before editing. No conflicts required overwriting or skipping existing work.

## Changes

1. `frontend/login.html`: login/registration keep their endpoints, JSON fields, token storage and redirects. A 15-second deadline covers fetching and reading the response, invokes AbortController where supported and restores the submit label/disabled/busy state. No automatic retries. Duplicate submissions and switching modes during a pending request are blocked. HTTP failures, unreadable/non-JSON/malformed JSON, missing fields, invalid success responses, network failures and blocked session storage receive safe public messages. Arbitrary server details are not echoed; existing known public validation messages remain available.
2. `frontend/scan.html`: adds Copy QR Content beside existing actions. Clipboard API receives the original decoded string without trimming, URL normalization or interpretation. Secure-context clipboard failure/unavailability reveals a labelled, read-only selectable textarea with manual-copy instructions. Accessible status feedback reports success only after writeText resolves. Reset clears copy state and fallback content; late completions from earlier scans do not update a newer result. Existing link warnings/actions remain unchanged. Buttons wrap on desktop and stack on mobile; layout and themes are preserved.
3. `tools/login-performance-diagnostics.js`: manual DevTools-only snippet, not loaded by any application page. Returns numeric navigation/paint and allowlisted static-resource timings. It does not read credentials/storage, include raw URLs/queries or API resources, log data, make requests or send analytics. No caching or gateway policy changes.
4. `frontend/tests/phase-b.test.js` and `backend/tests/run_phase_b_checks.py`: synthetic production-function regressions using temporary browser profiles and fake DOM/fetch/clipboard/timers.
5. `backend/tests/run_phase_b_rendered_checks.py`: actual DOM/layout checks with temporary loopback-only fixtures, blocked external resources, synthetic content and mocked clipboard. Reuses only the pre-existing CDP transport class; does not execute fixture-generating scripts or overwrite existing user fixtures. Screenshot filenames are unique.
6. This report.

No changes to backend application code, ML labels/model, scoring, thresholds, authentication endpoints, database schema, UPI logic, PDF structure, dashboard calculations or gateway security policies. Phases C/D/E were not started.

## Executed tests

All Python commands used `backend/venv/Scripts/python.exe -B`.

| Script / command | Result |
|---|---|
| `backend/tests/run_isolated_regressions.py` | 140 tests; zero failures/errors; one skipped (Windows symlink permissions) |
| `-m unittest discover -s tests -v` | 20 passed: gateway and temporary-database persistence regressions |
| `backend/tests/run_frontend_static_checks.py` | 20 checks passed; nine scripts compiled; 21 navigation links checked |
| `backend/tests/run_result_explanation_checks.py` | 61 synthetic DOM checks passed |
| `backend/tests/run_warning_ui_checks.py` | 45 synthetic + 35 mocked prediction checks at each of 1280, 390 and 320 px; all passed |
| `backend/tests/run_phase_b_checks.py` | 176 synthetic checks passed |
| `backend/tests/run_phase_b_rendered_checks.py` | 10 rendered cases: light/dark at 320, 390, 768, 1280 and 1440 px; copy controls, no overflow, 44px touch targets, success/denied fallback, link warning and reset checked |
| `git diff --check` | Passed |

The new tests cover original login/registration behavior and payload fields, token/redirect behavior, all selected HTTP error statuses, missing/untrusted messages, invalid success bodies, malformed JSON and HTML responses, fetch/body timeouts with and without AbortController, no duplicates/retries, original button restoration, late responses and storage failures. Copy tests include whitespace/CRLF passed unchanged to writeText, denied/missing clipboard, insecure context, manual selection, reset and stale completions. Diagnostics tests verify timing arithmetic and exclusion of synthetic private URLs/queries/API resources.

Initial new-test runs failed because the synthetic window lacked `window.location`. Corrected the fixture, not application authentication behavior; all 176 checks then passed. Existing regressions had no failures. Local unit/browser tests use synthetic credentials/tokens only; real clipboard contents and existing database records are not accessed.

Actual 390×1000 light and dark screenshots of the copy fallback were inspected. Fallback instructions received a small spacing adjustment after review, followed by repeated rendered checks. Screenshots show synthetic data only and use new ignored `.design-review/phase-b-copy-*.png` filenames. No full real-device/tunnel screenshot verification was performed.

## Mobile performance: measured versus unknown

The development diagnostic was executed on a local headless login fixture with no-store static responses. One sample reported approximately 40 ms load, 28 ms from response completion to DOM interactive, and 5–7 ms theme resource durations. These are laboratory observations, not comparable proof of phone/tunnel performance and not evidence that a mobile bottleneck is fixed. There is no new production instrumentation or overhead from this diagnostic file.

### Manual mobile investigation

1. Open the actual forwarded HTTPS login URL on the phone without submitting credentials. Use browser remote inspection if available.
2. After page load, paste the full contents of `tools/login-performance-diagnostics.js` into that page's DevTools console. The expression returns an object locally; it does not print or transmit anything automatically. Inspect only this sanitized timing object.
3. Compare normal reloads and a browser-cache-disabled reload. Record before-request time, response-wait time, download time, DOM-content-loaded/load time and static-resource transfer sizes. Do not change API cache policies.
4. Large pre-request/redirect or response-wait times warrant investigating browser/tunnel authentication, connection establishment and gateway timing; they do not alone prove the tunnel caused the delay. Large parse/synchronous-work intervals warrant a DevTools Performance recording to distinguish parsing, resource blocking and JavaScript. The snippet deliberately does not claim to separate those costs.
5. Keep test screenshots/traces free of credentials, tokens, payment data and personally identifying URLs. Do not paste raw DevTools network headers into reports.

## Remaining manual checks / limitations

- Live phone/tunnel login performance is **not verified or fixed**. No speculative resource deferral, authenticated-response caching or security bypass was added.
- Test actual HTTPS login and registration, invalid credentials, permission-denied clipboard and OS-level manual copy on the intended phones. Synthetic writeText/fallback tests do not prove the system clipboard operation on every browser. Browsers/operating systems may normalize newline representation during manual copy; the application retains the original decoded string and passes it unchanged to Clipboard API.
- Confirm actual QR camera/upload, PDF downloads and dashboard flow with existing local accounts. These flows were not changed; current regressions are synthetic/isolated rather than live-account tests.
- A client timeout does not guarantee the server stopped processing. A timed-out registration may still complete; no automatic retry is issued. Without AbortController, the UI deadline still applies but the transport cannot be cancelled.
- Existing development-mode SSRF limitations, uncalibrated ML behavior/version warnings and dashboard/UPI improvement proposals remain unchanged and require their separately approved phases.

No Phase B changes were skipped due to conflicts. Mobile-speed optimization was deliberately deferred because no live-device bottleneck was demonstrated. No secrets were printed, no dependencies installed, and no deployment/public-port changes were made.
