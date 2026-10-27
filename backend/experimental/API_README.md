# Isolated candidate API

This is a local experimental model endpoint, not the production scanner.
It never imports main.py, touches a database or dataset, follows redirects,
fetches submitted URLs, performs DNS lookups, or persists submissions/predictions.
URLs exist transiently in process memory; Python cannot guarantee memory erasure.

From the project root, using the existing environment:

```powershell
.\backend\venv\Scripts\python.exe -B -m uvicorn backend.experimental.candidate_api:create_app --factory --host 127.0.0.1 --port 8766 --no-access-log --no-proxy-headers --no-server-header --log-level error --limit-concurrency 8 --timeout-keep-alive 2
```

The application is the `create_app()` factory; there is no module-level `app`.
Use `--factory` with the exact command above. It binds **127.0.0.1:8766**,
disables access logs and proxy headers, and uses no reload or production connection.
Stop with **Ctrl+C** in the same terminal. Do not expose through a proxy, tunnel,
container port publication, or altered bind/proxy settings. Startup checks the
private candidate manifest and model against pinned session SHA-256 digests,
extractor/trainer hashes, Python/dependency versions, and label/feature contract.
Mismatch or missing files fail startup with a generic message. No fallback
model is loaded. Importing the module alone does not load anything.

The equivalent fixed direct launcher is also supported:

```powershell
.\backend\venv\Scripts\python.exe -B .\backend\experimental\candidate_api.py
```

Its error log level now exposes sanitized startup verification failures and
port-binding errors. Previously its critical-only level could hide why the
process exited. If it exits, inspect the error; do not bypass integrity checks.
Factory import and direct-launch dispatch are tested without binding a server
or loading any candidate. Actual candidate startup remains a manual check.

Verification errors now identify a fixed internal `stage` (for example
`dependency_versions`, `manifest_checksum`, or `artifact_checksum`) without
including exception values, submissions, or file contents. Use the backend
virtual environment shown above; do not relax checks to make another Python
environment pass. In the reviewed environment, all verification checks and the
factory lifespan passed, followed by one harmless synthetic prediction with
external networking/DNS blocked. The previously reported generic failure was
not reproducible; its historical cause has not been established.

### Resolved Windows manifest-access failure

The later `stage=manifest_file_access` failure was confirmed to be a Windows
ACL issue: the private candidate directory was sandbox-owned and did not grant
the normal Windows user access. That user's read was denied, although the
sandbox could read the existing checksum-matching manifest. Account-specific
read/execute permission was added to that directory and inherited files;
no broad public access, artifact contents, hashes, or verification rules changed.
The normal-user factory then started on 127.0.0.1:8766 in a short smoke test,
made no predictions, and shut down cleanly. The port was confirmed closed.

Artifact paths already use `Path(__file__).resolve().parents[1]` as the backend
root, so changing the working directory was not the cause. Regression checks
cover the project-root and unrelated-directory cases with synthetic models.
If moving/copying private artifacts later, retain access for your own Windows
account and rerun integrity checks; do not disable private-path safeguards.

POST `http://127.0.0.1:8766/experimental/predict` with `Content-Type:
application/json` and body `{"url":"https://example.invalid/synthetic"}`.
Only explicit HTTP/HTTPS URLs are accepted, without embedded credentials,
whitespace, controls, malformed percent escapes, or invalid host/port syntax.
Limit: 8,192 URL UTF-8 bytes and 12,288 request-body bytes. No URL normalization
is applied before the shared candidate feature extractor.

Response includes `candidate_phishing_probability`, `experimental_ml_warning`,
`warning_explanation`, and the exact inclusive threshold
**0.40144790130467084**. `risk_score` and `risk_classification` are **null** and
`production_risk_evaluated` is **false**: there is no invented production score.
The existing prototype's shared ML-only function supplies warning logic.

This is advisory: warning does not confirm phishing, and no warning does not
guarantee safety. Validation false-positive rate was 19.40%, recall about 90%.
These validation-selected results are not future performance guarantees.
Dataset version and upstream rights remain unverified.

Request failures return generic errors without submitted values. Access logging
is disabled; responses use `Cache-Control: no-store`. CORS is strictly limited:
only `http://localhost:5500` and `http://127.0.0.1:5500` are allowed origins.
JSON POST preflights are supported; no credentials or arbitrary origins are
allowed. File-based (`Origin: null`) pages, non-loopback clients, and unexpected
Host headers are rejected. No authentication
is provided; other processes running as local users can call this API. Binding
is not an OS sandbox. Trusted model loading assumes a user-controlled local
workspace; file checks do not eliminate every hostile filesystem race.

Synthetic tests only (fake predictions and mocked artifact bytes, no model load):

```powershell
.\backend\venv\Scripts\python.exe -B -m unittest discover -s backend/tests -p test_candidate_api.py -v
.\backend\venv\Scripts\python.exe -B -m unittest discover -s backend/tests -p test_ml_warning.py -v
```

## Manual browser testing (not automatically started)

Use two PowerShell terminals at the project root. Terminal 1:

```powershell
.\backend\venv\Scripts\python.exe -B -m uvicorn backend.experimental.candidate_api:create_app --factory --host 127.0.0.1 --port 8766 --no-access-log --no-proxy-headers --no-server-header --log-level error --limit-concurrency 8 --timeout-keep-alive 2
```

Terminal 2 (serve only the frontend, never the project root/private artifacts):

```powershell
.\backend\venv\Scripts\python.exe -B -m http.server 5500 --bind 127.0.0.1 --directory frontend
```

Open `http://localhost:5500/experimental-warning.html` or
`http://127.0.0.1:5500/experimental-warning.html`. Keep the four synthetic
scenarios separate from the new prediction form. Enter a synthetic URL such as
`https://example.invalid/synthetic`, then choose Analyze. Only URL text is sent
to the fixed local endpoint; the destination is never opened or fetched.
Live results show ML-only scores/advisories, not production risk classifications.
Stop the API and retry to check the unavailable message. Stop each terminal
with Ctrl+C. Do not submit credentials or personal information. The page uses
no browser storage, analytics, navigation, or URL-query submission mechanism.
Browser extensions, developer tools, and browser-managed form behavior are
outside application control; autocomplete is disabled on the form/input.

The synthetic UI harness is `frontend/tests/experimental-warning.test.js`; it
is not loaded by the normal page. It runs only with mocked fetch responses.
Run it using the existing Edge installation with
`.\backend\venv\Scripts\python.exe -B backend/tests/run_warning_ui_checks.py`.
The later startup investigation loaded only the checksum-verified local
candidate and exercised one synthetic in-process prediction. No listening
server was needed. Manual browser-to-server testing remains a final check.

Safe existing regression suites (in-memory databases, fake keys, stub models,
dotenv reads suppressed, external networking blocked):

```powershell
.\backend\venv\Scripts\python.exe -B backend/tests/run_isolated_regressions.py
```
