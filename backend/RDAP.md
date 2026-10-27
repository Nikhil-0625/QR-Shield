# Domain registration observations and score availability

RDAP is disabled by default. No settings, credentials, production records, schema,
ML artifacts, formula weights, thresholds, JWT logic or gateway policy were changed
to enable it.

## Confirmed causes

- The legacy WHOIS helper in `main.py:get_domain_age_days()` returns `None`.
  `validate_outbound_url()` also unconditionally prohibits destination website
  fetching. This intentionally leaves WHOIS, destination DNS, TLS verification and
  redirects unperformed. These boundaries remain unchanged.
- `_analyze_url()` intentionally leaves `risk_score=None` when experimental ML is
  excluded. Missing domain age does not invalidate a computed score. The existing
  combined formula needs its ML input; replacing that input with zero or rescaling
  offline findings would create different scoring semantics.
- `rule_score` is still the actual sum of the performed rules. It is displayed as
  rule-based points, never a replacement combined score or a probability.

## Enable locally

From the project directory, stop the existing FastAPI instance, then start it in
the same PowerShell session as the configuration:

```powershell
$env:RDAP_ENABLED = "true"
.\backend\venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Keep existing Google Safe Browsing settings unchanged. RDAP needs no API key.
Do not enable experimental ML merely to make a numerical score appear.

To disable RDAP, set `$env:RDAP_ENABLED = "false"` and restart FastAPI. The process
reads its own environment; changing another terminal's variables does not update
an already-running process.

`QR_SHIELD_MODE=restricted-demo` overrides RDAP enablement, including cached
observations. Requests carrying the existing public-test offline marker also
disable RDAP and live reputation. The gateway and tunnel visibility are unchanged.

## Network boundary

- Only `https://data.iana.org/rdap/dns.json` supplies registry service endpoints.
  Submitted URLs cannot supply or override a service endpoint.
- The existing bundled public-suffix parser extracts the domain. IP addresses,
  local/internal names, reserved educational destinations and non-URL content do
  not cause registration requests.
- Registry endpoints must be HTTPS on port 443, with no credentials, query,
  fragment, dot traversal or encoded path components. Unsupported bootstrap
  endpoints are skipped rather than upgraded.
- Every connection validates **all** DNS answers as public, rejects mixed public
  and private answers, and connects to a checked numeric address. Original hostname
  SNI and certificate verification remain enabled; there is no second DNS lookup
  at connection time. Proxy/netrc/cookie/authorization environment handling is not
  used.
- Redirects are rejected. Only identity-encoded UTF-8 JSON with the expected media
  type is accepted; compressed data is rejected before decoding.
- Limits: 2-second DNS wait, connect and socket-read timeouts; an 8-second total
  lookup deadline; 512 KiB bootstrap and 256 KiB domain responses. A deadline
  watchdog shuts down active sockets, including slow headers.
- A single bounded resolver worker cannot accumulate more jobs while an OS DNS
  lookup is still running. Further lookups fail unavailable until it completes.
- Per-process limits: 10 uncached lookups/minute; 512 domain cache entries; positive
  observations retained for one hour, failures for 60 seconds, bootstrap for one
  day. Provider rate/capacity errors cause backoff.

RDAP transmits the registered domain only, never the submitted URL path, query,
fragment, credentials or QR payload. Cache keys are hashes; cached observations
contain the domain and small registration metadata, not complete submitted URLs.
Responses and exception details are not logged.

## Evidence and persistence

Registration data must identify the exact requested domain and contain one
unambiguous, timezone-aware registration event. Update/expiration events are not
used as substitutes. Missing, conflicting, future or malformed dates remain
unavailable. The existing under-30-days rule retains its existing 20 points.

Both QR and Website Checker use the same registration path. Additive response
fields are `domain_registration`, `risk_score_status` and `risk_score_reason`.
Existing fields retain their meaning. Metadata is stored inside the existing
`score_explanation` JSON column, with no schema changes or history rewrites.
Private scans retain the result in the response without creating a history row.

PDFs read stored observations, XML-escape values, and make no new network request.
An age is an observation at lookup time, not a fresh check performed on download.
Existing history endpoints and their schemas are unchanged.

Known reputation matches continue to override the displayed assessment regardless
of domain age or a low stored heuristic score. A no-match does not mean zero risk
or establish legitimacy. Stored history classifications remain the existing
offline/heuristic classifications; they are not a new live-reputation aggregate.

## Verification and limitations

Tests use mocked RDAP/Safe Browsing responses and isolated in-memory accounts.
No live RDAP or Google requests were made for this implementation. Live registry
compatibility still requires an explicitly authorized local test.

Registration dates can be absent/redacted; registry responses can be unavailable,
redirected, oversized, unsupported or blocked by the network. Private-PSL tenants
may have no independent registry registration record. These cases stay unavailable.
An old domain does not prove safety; a new domain is not proof of phishing.
The combined score intentionally remains unavailable while ML is excluded.

See [.design-review/RDAP_IMPLEMENTATION_REVIEW.md](../.design-review/RDAP_IMPLEMENTATION_REVIEW.md)
for actual test results, screenshots and the scoped implementation diff.
