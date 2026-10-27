# Restricted QR Shield cloud demonstration

> Phase C update (21 October 2026): live URL DNS/HTTP/TLS/redirect/WHOIS checks are now disabled in every mode, with no fetching opt-in. Current limits and compatibility notes are in [PHASE_C_SECURITY.md](PHASE_C_SECURITY.md). The Linux/cloud acceptance requirements below still apply; hardening alone does not establish deployment readiness.

Prepared 19 October 2026. Nothing has been deployed, pushed, purchased or made public.

## Release decision

**NO-GO for deployment until the Linux image build, model acceptance, persistent-volume restart and HTTPS/mobile checklist below pass.** Local isolated regressions pass. Docker is unavailable on this workstation, so Linux wheels, base-image availability, native libraries, container startup and actual cloud behavior have NOT been verified. This is a restricted offline demo, not a production URL scanner.

## Architecture and deliberate restrictions

One HTTPS web service runs `demo_app:create_app`, serving an explicit frontend asset allowlist and mounting FastAPI at `/api`. Do not deploy the development gateway or expose a second backend port. Existing localhost development commands remain unchanged.

The browser first supplies a shared demonstration access username/password through HTTP Basic over HTTPS. The gate issues an eight-hour, host-only, HttpOnly, Secure, SameSite=Strict signed cookie. This cookie permits the normal Bearer JWT header to work unchanged. Each participant still needs a separate pre-created application account. Registration returns 403. Keep the gate password separate from account passwords and JWT_SECRET_KEY. Share credentials privately. Do not enter real financial or personal data.

Restricted mode **never performs live DNS, HTTP fetching, redirect following, TLS probes or WHOIS**. Each of those entry points returns before network access; scan responses, the scan page and newly generated reports identify unavailable live analysis. Decoding, offline URL indicators, UPI comparison, experimental ML output, existing thresholds and the 70/30 calculation remain unchanged. This avoids outbound SSRF exposure in this profile; it does not repair the development profile's DNS-validation/connection rebinding gap. Never expose development mode publicly.

Limits are global per process and cannot be bypassed by forged forwarding headers: gate failures 30/minute, login 20/minute, scans 10/minute, PDF reports 20/minute, other authenticated requests 180/minute. Use exactly ONE worker and ONE instance. Four active application requests maximum; one native scan job and one PDF job maximum. Scan request bodies are capped at 6 MiB before multipart parsing, image files remain capped at 5 MiB/16 megapixels. Other bodies: 16 KiB. Body read timeout: 10 seconds; scan/PDF deadlines: 30/20 seconds; application deadline: 45 seconds. A timed-out native thread is not forcibly terminated: its slot stays occupied until completion. Restart on a stuck decoder. Use hosting CPU/memory limits as a further boundary.

Accounts are provisioned only through an interactive administrator CLI. Each account is limited to 200 saved scans in this demo. Do not scale out: limits and SQLite are intentionally single-instance. Rate counters reset on restart. Shared-gate holders can consume the group's quota, so this is suitable only for trusted invitees.

## Build and local acceptance (manual, no execution performed here)

Install/use Docker on a Linux-capable machine. From the project root:

```powershell
Get-FileHash backend/phishing_model_v2.pkl -Algorithm SHA256
docker build --pull -t qr-shield-demo:local .
```

The `.dockerignore` denies everything except explicit runtime source/assets, the pinned requirements, entrypoint and the existing production model. No `.env`, database, training data, backups, venv, experimental server or test outputs are included. Review the context before building; only build the trusted existing pickle. The model remains Git-ignored and must be physically present when building. A Git-based cloud build of the current repository would miss untracked runtime files and the model. Do not upload the whole working tree or a personal database.

Build runs `pip check` and a synthetic ZBar/OpenCV/PDF smoke check. Dependencies and Python are version-pinned, but this is not a hash-locked, bit-for-bit reproducible supply-chain build. Resolve any missing Linux wheels/version conflicts before release; do not silently replace the model or change its behavior. The artifact was trained with scikit-learn 1.9.0; the existing Windows runtime reports 1.9.1 and emits an incompatibility warning. The container pins 1.9.0, and model acceptance deliberately rejects other versions.

Copy `.env.demo.example` to a secret file OUTSIDE this project/build context. For local container acceptance, use:

| Variable | Required setting |
|---|---|
| `QR_SHIELD_MODE` | `restricted-demo` |
| `PUBLIC_ORIGIN` | `http://localhost:8080` locally; exact `https://...` cloud origin without slash |
| `DEMO_ALLOWED_HOSTS` | Optional additional exact provider health-check Host headers; no wildcard |
| `DEMO_ACCESS_USER` | Shared demo gate username |
| `DEMO_ACCESS_PASSWORD` | Independently generated random secret, at least 24 UTF-8 bytes |
| `JWT_SECRET_KEY` | Independently generated random secret, at least 32 UTF-8 bytes |
| `DATABASE_URL` | `sqlite:////data/demo.db` (fresh dedicated volume) |
| `MODEL_PATH` | `/app/backend/phishing_model_v2.pkl` |
| `MODEL_SHA256` | Lowercase SHA-256 from your trusted unchanged artifact |
| `CORS_ALLOWED_ORIGINS` | Omit; factory sets exact PUBLIC_ORIGIN; any supplied value must match |
| `PORT` | Hosting-provided port, default 8000 |

Generate secrets privately with a password manager or cryptographic generator. Do not paste them into source, command-line arguments, screenshots or chat. Never copy backend/.env or scan_history.db to the service.

```powershell
docker run -d --name qr-shield-demo -p 127.0.0.1:8080:8000 --memory=2g --cpus=1 --pids-limit=128 --env-file ..\qr-shield-demo.env -v qrshield-demo-data:/data qr-shield-demo:local
docker exec qr-shield-demo gosu 10001:10001 python demo_smoke.py --model
docker exec -it qr-shield-demo gosu 10001:10001 python demo_accounts.py --email guide@demo.test
docker exec -it qr-shield-demo gosu 10001:10001 python demo_accounts.py --email friend@demo.test
```

Passwords are prompted without echo, hashed using existing bcrypt behavior, and existing users are never reset. The dedicated database is created on the new volume. The entrypoint provisions its directory and drops application privileges to UID/GID 10001. Do not use your personal DB path or reuse an existing data volume. Normal startup is `python -m uvicorn demo_app:create_app --factory --host 0.0.0.0 --port 8000 --workers 1 --no-proxy-headers --no-access-log --limit-concurrency 8 --timeout-keep-alive 5` through the supplied entrypoint. Binding all interfaces is inside the container only; local published port above is loopback-only.

## Cost-conscious hosting plan (not authorized to execute yet)

Use one Render Docker web service with HTTPS and an attached persistent disk mounted at `/data`. Build the reviewed image locally, then manually publish it to a PRIVATE container registry only after approval and pull that exact image/digest. This includes the Git-ignored model without committing it. Use a private registry and appropriate licensing/provenance review for the model; pickle deserialization is inherently unsafe for untrusted artifacts.

1. First pass all local container tests above. Check `docker stats` during real scans, camera-image uploads and report generation. Start testing with 1 vCPU, 2 GiB RAM and at least 1 GiB persistent storage; adjust from measurements, not the 176 MB artifact size alone. The Windows model-only process measured approximately 325 MiB RSS, excluding full FastAPI/OpenCV working memory and peak image allocations.
2. Review current hosting/registry costs and spending controls. No service, registry upload or purchase has been created by this implementation. Proceed only with your own explicit cost approval.
3. Create ONE Docker-image web service and persistent `/data` disk. Select sufficient memory and a single instance. Do not use automatic multi-worker commands. Set the environment variables above with the actual assigned HTTPS hostname and new random secrets through the provider's secret settings. Leave experimental port 8766 unexposed.
4. Configure `/healthz` as the readiness path. It returns only `{"status":"ok"}` after factory/model/database startup. If the provider uses another Host header for probes, explicitly allow only that documented exact host. Do not use wildcard hosts or trust arbitrary forwarded host/IP headers.
5. Ensure provider HTTPS enforcement is enabled. Test HTTP-to-HTTPS redirection externally; this application sits behind TLS termination and does not infer public scheme from untrusted forwarding headers. Secure-cookie decisions use configured PUBLIC_ORIGIN.
6. Provision separate accounts using `python demo_accounts.py --email ...` in `/app/backend` from the running service's authorized shell, under UID 10001 with the same environment and mounted volume. Do not create the database in a build/pre-deploy phase: runtime persistent disks are unavailable there. Do not use public registration as a shortcut.
7. Complete the acceptance checklist. Restart the service and confirm both accounts/history survive. Share only the HTTPS link plus private gate/account credentials with a small group. Test from a phone with the laptop OFF to prove independence from local tunnels.
8. After the demonstration, suspend the service, stop public access and review billable resources; preserve or export only the dedicated demo data if wanted. Deleting a service/disk is not part of this work.

Render Free services sleep after 15 minutes without traffic and cannot attach persistent disks. Their ephemeral filesystem cannot meet the required SQLite persistence. Free hosting is therefore **not a verified fit for this release**; model/native-image memory is another unverified constraint. Do not quietly accept account/data loss or substitute a different model to fit a free tier.

Official guidance checked 19 October 2026: [Free limitations](https://render.com/docs/free), [persistent disks](https://render.com/docs/disks), [prebuilt private images](https://render.com/docs/deploying-an-image). Prices and available plans should be checked at purchase time.

## Acceptance checklist before GO

- Anonymous page/API access challenges at the gate; wrong credentials, modified/expired cookies, wrong Host and foreign Origin fail. `/healthz` intentionally exposes only liveness, no user data.
- Sign into two pre-created accounts. Confirm history isolation and cross-account report 404. Missing/invalid JWT fails even with a valid gate cookie. Public registration is 403; docs/openapi/experimental routes and source/secret paths are unavailable.
- Upload generated QR codes containing `https://www.wikipedia.org/` and `http://paypal-login.example.com/verify`. Do not visit the synthetic destination. Confirm exact decoded URL and actual reasons; Wikipedia can still receive an extreme experimental ML estimate. Never present it as guaranteed safe or calibrated. Confirm offline notice/unavailable network checks, existing 70/30 score and warning-before-opening-link behavior.
- Confirm private-address and redirect-like URL payloads cause no outbound requests in restricted mode. Live redirect/TLS/WHOIS features are intentionally unavailable, not reported as passed. Do not enable them for the demo.
- Check camera upload/Capture and Scan/Retake on HTTPS mobile; QR generation/download, dashboard/history, PDF content/download and Scan Another QR. The existing external jsQR dependency still requires browser access to jsdelivr; image upload does not depend on it.
- Check lavender/light and dark themes and 320/390/768/1280/1440 widths, keyboard link-warning behavior and reduced motion. No source frontend styling was changed; the demo-only notice still needs rendered cloud inspection.
- Confirm 413 for oversized/chunked uploads before multipart parsing, 429 under controlled synthetic rate tests, bounded concurrent scans, timeout completion and normal login recovery. Avoid abusive traffic or third-party target scans.
- Restart with the SAME persistent volume; verify accounts and scan history survive. Confirm no personal development records are present.
- Verify security headers, Secure/HttpOnly/SameSite cookie, HTTPS redirect, exact-origin CORS and unavailable docs externally. Check logs contain no credentials/payloads. Confirm the container is non-root and normal memory stays comfortably under the plan limit.
- Test quick shutdown: suspend the service. Rotating the gate password invalidates its cookies on restart; rotating JWT secret revokes all application JWTs. Existing application logout is client-side, so copied JWTs otherwise remain valid for their existing 60-minute expiry.

## Verification performed locally

See `tools/RESTRICTED_DEMO_TEST_RESULTS.md` for executed checks and remaining blockers. All application-route tests use in-memory SQLite, synthetic tokens/QRs, mock ML predictions and forbidden external network access. The separate persistence test uses a fresh temporary database. Actual trusted model inspection is separate and never opens the application database. No existing user records, frontend design files, development gateway, risk formula or model artifact were changed.
