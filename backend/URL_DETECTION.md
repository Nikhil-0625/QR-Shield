# Requirement 1: evidence-based suspicious URL detection

Scope: only Requirement 1 of the attached request is implemented. Results-page redesign/explanation overhaul, downloadable demonstration assets, simulation UI and subsequent requirements are deferred. No model retraining, ML mapping changes, score-weight changes, database schema changes, gateway edits or frontend edits were made.

## Production rules

The original rule points remain: young domain 20 (only nonnegative observed age below30), HTTPS validation failure20 (only an actual HTTPS request with an SSL error), brand mismatch25, multiple observed redirects15, IP hostname25. Added lexical/contextual points: HTTP20; embedded URL credentials15; login/verify/password path10 only with brand mismatch or IP host; unusual web port5 only with an already suspicious brand/userinfo structure; invalid port10; malformed URL structure10; observed HTTPS-to-HTTP downgrade20. Duplicate findings from the original/final URL are counted once. These are explainable heuristic points, not empirically calibrated probabilities. The existing0.7 rules/0.3 ML weighting and0-30 safe/31-60 suspicious/61-100 unsafe thresholds are unchanged.

Brand analysis uses exact official-domain boundaries for exclusions, exact token boundaries in subdomains and conservative fuzzy matching in registered-domain labels. It catches paypal-login.example.com and paypal.com.example.com without treating a substring such as ola inside an unrelated word as ownership evidence. Ordinary login paths on official subdomains do not trigger the contextual sensitive-action rule. Reasons identify the actual hostname and registered-domain component and explicitly avoid claiming credential theft.

Registered domains use publicsuffix2 with python-whois's installed local PSL snapshot, including multipart/private/wildcard/exception rules. No PSL is downloaded during scanning. publicsuffix2 was already installed/used in offline tests and is now explicitly declared in requirements.txt. No dependency installation was executed. Missing PSL/dependency does not silently fall back to the last two labels; deployment must include the declared dependencies and whois snapshot. Reserved .example/.test/.invalid suffixes are parsed structurally, not represented as real registrations.

All reserved example.com/example.net/example.org domains/subdomains and .example/.test/.invalid hosts are blocked from DNS/HTTP/WHOIS analysis before network resolution. This is a general educational-destination policy, not a hardcoded risk verdict. SSRF/IP/credential/redirect guards remain. Original and final lexical evidence are retained across redirects. Redirect downgrade points require an observed chain transition.

HTTP URLs are no longer probed by silently converting them to HTTPS. HTTPS SSL errors return false; timeout/connection failures return unknown (None), and unknown age/TLS do not invent findings. DNS/nonpublic errors remain represented by the existing network-analysis field. Full user-facing evidence wording is still Requirement2, not implemented here.

## Observed examples, not forced verdicts

Using generated QR images, real QR decoding and the existing artifact's corrected P(class=-1), with all network evidence unavailable/mock DNS failures and in-memory SQLite:

| Payload | Rule points | Model component percentage | Score | Verdict |
|---|---:|---:|---:|---|
| https://www.wikipedia.org/ |0|100.00|30|safe (existing low-risk label)|
| http://paypal-login.example.com/verify |55|57.54|56|suspicious|
| http://paypal.example/verify |55|41.73|51|suspicious|

The synthetic domains received NO real DNS/HTTP/WHOIS traffic. Each suspicious example triggered brand mismatch25 + HTTP20 + contextual verification path10. Reasons identify example.com / paypal.example, rather than incorrectly identifying paypal.com. No new QR image assets or demonstration page were created in this step; images were generated only in memory for tests.

The Wikipedia model output remains a known false-positive/calibration concern. Its low-risk score follows unchanged weighting, not confidence that the site is guaranteed safe. Live network-dependent results can vary. The numeric examples must not be presented as calibrated phishing probabilities or confirmed malicious behavior.

## Verification

- New test_url_detection.py:8 tests covering subdomains/lookalikes, official-domain exclusions, PSL multipart/private/wildcard/exception/IP cases, HTTP versus unknown TLS, uppercase schemes, SSL failure versus timeout/connection error, no educational DNS, userinfo/IP contexts, observed downgrade versus no redirect, retained initial HTTP before HTTPS upgrade, real QR decoding and text/UPI compatibility.
- Full isolated backend suite:113 tests run,112 passed,1 OS-dependent symlink test skipped; no failures/errors. Includes the existing ML class-order/invalid-label safeguards, authentication, history isolation, scoring, UPI, tampering, PDF and experimental tests.
- Gateway suite:18 tests passed, including real local HTTP registration/login/QR/history/PDF in an isolated memory database.
- Frontend static runner:8 compiled scripts,21 links,19 checks passed. Experimental UI runner:45 synthetic +35 mocked prediction checks at each requested width1280/390/320 passed. A separate headless Edge compatibility check rendered the new indicators in the unchanged scanner UI in Light/Dark at390/1440 (4 combinations), with synthetic API data and no horizontal overflow. No live API/tunnel or physical-phone test was used.
- Actual artifact example outputs above were separately computed and passed through the ordinary scan endpoint function using isolated fixtures. Existing model artifact/version warning remains (scikit-learn training1.9.0 versus environment1.9.1).
- git diff --check passed.

Changed/created: backend/main.py; backend/url_security.py; backend/requirements.txt; backend/tests/test_brand_detection.py (updated the formerly missed misleading-domain expectation/explanation assertion); backend/tests/test_url_detection.py; this document. Test output: .design-review/url-detection-regressions.txt. Browser compatibility runner: .design-review/url_result_compatibility.py.

## Remaining limits / deferred work

No claim of website ownership, credential collection or malicious content is made from lexical similarity alone. Homoglyph/IDN attacks, novel brands, encoded obfuscation, compromised legitimate subdomains and DNS rebinding/resolve-to-connect races are not comprehensively addressed. Official-host exclusions can miss compromised official services. PSL freshness depends on the installed snapshot; no live updates occur. Rule weights/thresholds need independent false-positive/false-negative validation.

The frontend and PDF still have previously identified overly reassuring low-risk summaries and TLS wording; Requirement2 is needed to correct these comprehensively. The new registered_domain field is additive in scan responses; existing stored records/history schema are unchanged. The optional ignored offline evaluation copies production functions statically; it must be updated before using it to benchmark these new rules (it is not part of the113-test discovered suite).

No existing user data, model artifact, port forwarding, backup, commit, push or deployment was changed. Restart FastAPI to load the new backend module. Continue to Requirement2 only when requested.
