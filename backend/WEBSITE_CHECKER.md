# Website Checker and optional live reputation

The authenticated Website Checker and QR scanner share normalized URL rules and the same live-reputation service/verdict policy. The QR scanner retains its separate experimental ML estimate and image-integrity findings; neither overrides a current known-threat match or turns unavailable reputation into a pass. QR strings containing embedded credentials remain eligible for offline host-warning analysis, but fail reputation URL validation and are never sent to Google. UPI and other non-URL QR content never enters URL reputation analysis. Neither feature visits the destination, resolves its DNS, follows redirects, verifies its TLS certificate, or queries WHOIS. These checks remain unavailable in every mode.

The current Random Forest is **excluded from website verdicts**: the verified training targets are `-1 = phishing`, `1 = benign`, but the training and production `has_ip` calculations differ. Its predictions are uncalibrated. QR scanning retains its existing model, class mapping, scores, thresholds, and 70/30 formula. Website checks do not invent a substitute numeric score.

## Live reputation: disabled by default

Only an explicit `SAFE_BROWSING_ENABLED=true` **and** a backend `GOOGLE_SAFE_BROWSING_API_KEY` enable Google's v5 `urls.search` for either feature. Missing configuration preserves offline rules. Restricted-demo mode is always offline. The gateway's `--public-test` mode forces offline reputation too; it strips client-supplied overrides before adding its disable-only header. Normal local development can opt in. No tunnel settings are changed.

Only the fixed endpoint `GET https://safebrowsing.googleapis.com/v5/urls:search` is contacted. One validated HTTP(S) URL is sent as the `urls` query parameter. The API key travels in `X-Goog-Api-Key`, never in browser code or the request URL. Environment proxies and netrc credentials are disabled; TLS verification stays enabled. Redirects and automatic retries are disabled. There is a 3-second connect timeout, 5-second read timeout, an elapsed-time read budget, a 64 KiB decoded-response bound, one concurrent lookup, and an additional 10 outbound lookups/minute/process. Existing authentication, API/gateway limits and restricted-demo storage quota still apply.

Both positive and negative successful responses are cached for the exact provider `cacheDuration`. The bounded memory cache stores hashed URL keys and sanitized observations, not raw URLs or matched URL expressions. Unexpired entries are never evicted to permit an early requery: when full, new lookups report unavailable. A threat observation becomes unusable for current warnings after the earlier of its provider expiry or 30 minutes. If its cache TTL is longer, it remains unavailable until TTL expiry rather than requerying early. Provider errors trigger backoff; `Retry-After` is respected. The cache and limit are per process and reset on restart; use one backend worker for this controlled local setup.

## Results

| Evidence | Display |
|---|---|
| Fresh Google threat-list match | Known Dangerous, qualified as a potential threat |
| Existing offline rule findings, regardless of a negative/unavailable live check | Suspicious |
| Fresh completed no-match response and no offline findings | No Known Threats Detected; no guarantee of legitimacy |
| Live check disabled, unavailable, expired, or incomplete with no offline findings | Unable to Verify |

Offline findings, live reputation, and unavailable checks are presented separately. No confidence percentages are invented. Supported v5 categories are social engineering (including phishing), malware, unwanted software, and potentially harmful applications. Unexpected response shapes/categories cannot produce a reassuring no-match verdict.

History uses the existing user-scoped `ScanRecord` and JSON metadata; there is no migration. Live reputation is stored with the existing scan metadata, while the dashboard's existing classification/count definitions are unchanged. QR risk scores and labels remain the existing offline/experimental outputs, not Safe Browsing results. The current paged history contract lacks source metadata, so that table lists these records as URLs; the existing full-history metadata and PDF identify Website Link versus QR analysis. PDF download reuses `/report/{scan_id}`, performs no new lookup, applies reputation freshness, and XML-escapes user content. The UI downgrades expiring reputation observations without sending another request. Historical observations do not prove current safety.

## Privacy, attribution and permitted use

When enabled, the **full submitted website URL or decoded QR URL is sent to Google**. QR images, UPI payloads, and other non-URL QR text are not sent to reputation lookup. Under Google's terms, submitted URLs and associated data may be used, retained and shared with third parties. Do not submit password-reset, private, session-bearing, or confidential links. The existing account history stores non-private scans and website checks; the local administrator can access that database. A private QR scan is not stored in account history, but its URL may still be sent to Google when live reputation is enabled. No additional raw-URL cache or analytics is added.

Google Safe Browsing can miss dangerous sites or flag safe sites by mistake. Its protection is neither comprehensive nor error-free. A match indicates potential risk and no match does not establish legitimacy. Google-derived warnings include “Advisory provided by Google” linked to Safe Browsing and explanatory threat links; offline-only warnings do not use this attribution. These notices are present before use and in the result/PDF.

The API is intended for **noncommercial use**. Review the current terms before enabling it; commercial use requires a suitable separate arrangement or product such as Web Risk.

## Configuration — manual step; no credentials have been created

1. In Google Cloud Console, create/select a project, enable **Safe Browsing API**, and create a standard API key under APIs & Services → Credentials.
2. Restrict the key to Safe Browsing API; where practical restrict its use to your backend's public egress IP. Review the actual project quotas and usage; do not assume the local limit matches your allocated quota. Keep this key out of frontend code, commits, screenshots and chat.
3. In the existing private `backend/.env` or the backend process environment, set the following yourself. The second value below is a placeholder, not a usable credential:

   ```dotenv
   SAFE_BROWSING_ENABLED=true
   GOOGLE_SAFE_BROWSING_API_KEY=<your restricted API key>
   ```

4. Restart the existing local FastAPI process with its existing JWT/database settings. Keep it bound to `127.0.0.1:8000`. For example, from `backend/`:

   ```powershell
   .\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
   ```

5. Continue using the local gateway. From the project root, if it is not already running:

   ```powershell
   .\backend\venv\Scripts\python.exe -B tools\dev_gateway.py --port 5500
   ```

6. Sign in at `http://127.0.0.1:5500/login.html`, then open Website Checker (`/website-checker.html`). Start with `https://www.wikipedia.org/`. A real response depends on your key, quota, connectivity and provider data; it has **not** been live-tested here. No real phishing site is required or recommended.
7. To disable reputation, set `SAFE_BROWSING_ENABLED=false` and restart FastAPI. Restricted-demo/public-test modes remain offline even when a key is present. Keep port 8000 local-only; do not change tunnel visibility for this feature.

Development stops at this configuration step. No API key was invented, retrieved, printed or used, and no live Google lookup was executed.

## Verification and official references

Mocked tests cover match/no-match, credentials, timeout, quota, network errors, configuration gates, cache TTL/freshness/capacity, redaction, authentication, limits, offline-rule consistency, user isolation, reporting, and XSS/XML escaping. Existing QR and UI suites are run separately; mocked provider success does not validate a real API credential.

- [Official v5 URL lookup and cache rules](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search)
- [Supported v5 threat types](https://developers.google.com/safe-browsing/reference/rest/v5/hashList#ThreatType)
- [Appropriate usage, quotas and warning attribution](https://developers.google.com/safe-browsing/reference/Appropriate.Usage)
- [Current Safe Browsing terms](https://developers.google.com/safe-browsing/terms)
- [Create and restrict a Google API key](https://docs.cloud.google.com/docs/authentication/api-keys)
- [API-key handling guidance](https://docs.cloud.google.com/docs/authentication/api-keys-best-practices)
