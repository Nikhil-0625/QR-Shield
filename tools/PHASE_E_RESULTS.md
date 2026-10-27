# Phase E results

Phase E only. Existing branch `fix/history-user-isolation` and dirty/untracked work were preserved. No commits, staging, resets, cleaning, stashing, deployment, dependency installs, model changes, real-record changes or schema migrations.

ML audit was completed before dashboard/history implementation. See [PHASE_E_ML_AUDIT.md](PHASE_E_ML_AUDIT.md) for source evidence, exact reproduced signals, data limitations and the validation proposal. Production still selects class -1 by classes_; twelve-feature extraction, model artifact, 70/30 weighting and thresholds are unchanged. The has_ip mismatch and sklearn 1.9.0 artifact/1.9.1 runtime warning remain unresolved deliberately. No independent test set was established; no real-world accuracy, AUC, FPR/FNR or calibration claims are made. The standalone audit prints reproducible aggregate source diagnostics and real-artifact acceptance results, without fetching URL strings or logging training URLs.

Timestamp correction:

- `backend/database.py` has always used `datetime.utcnow` for the ORM timestamp default. Existing application-created naive timestamps therefore represent UTC. No alternative application timestamp writer was identified. SQLite values are not rewritten.
- New history endpoints explicitly serialize these application timestamps with Z. Missing timestamps stay null and are excluded from date buckets, with an unknown-time count. Imported/manually edited naive timestamps without application provenance cannot be independently verified; no migration or guessed historical offset is applied. Verify external imports separately before treating their dates as reliable.
- Dashboard grouping and labels now consistently use **UTC**, including today and the preceding six calendar days. Table dates explicitly display UTC. The former local-midnight/UTC-key mixing is removed. The old query did not promise ordering and the frontend reversed its input; new pages guarantee descending timestamp order with descending ID tie breaks and unknown timestamps last.
- An empty average is now Unavailable rather than a fabricated zero risk score. Totals, classifications, average stored URL score, stored findings, indicators and content counts preserve the existing dashboard definitions.

History improvements:

- Existing `/history` remains an authenticated list with all prior fields/raw timestamp strings, the 5000-record and 8 MiB limits, and no silent truncation.
- Additive authenticated GET `/history/summary` streams only the columns needed for analytics in a bounded worker. It returns actual owner-scoped aggregates, seven UTC date buckets and a maximum-ID snapshot. It retains explicit 5000-record/8 MiB input/output limits; exceeding them returns 413, not partial statistics.
- Additive authenticated GET `/history/page?limit=50&snapshot=...&cursor=...&category=...` returns items, snapshot_id, has_more, next_cursor and timezone. Limit 1–100, validated categories and positive owner-scoped cursor IDs. Pages use timestamp/ID keyset bounds; snapshots exclude newer inserts. Null-time rows are reachable at the end. Page payloads are capped at 8 MiB. Cursor deletion/manual record editing requires reload; normal application scans are append-only.
- Dashboard loads the summary and one 50-record page rather than downloading/rendering the entire history. Next/Previous and filters request bounded pages; full-snapshot analytics do not change with table filters. Old rows are replaced rather than accumulated in the DOM. Loading, error and empty states are explicit. Authenticated results retain no-store headers.
- Both new routes share the existing history rate bucket and bounded worker. Gateway adds exactly these two GET/HEAD paths to its existing public-test allowlist. Host checks, loopback binding, token handling, body limits, docs restrictions and other method/path restrictions are retained. No port/tunnel visibility changed.

Synthetic size measurement, not a mobile latency benchmark: for 120 isolated records, legacy history was 50244 bytes versus 628-byte summary + 8319-byte first page, with 50 rendered table rows. Larger histories still incur server-side summary work; pagination does not make database sorting constant-time. No live-phone/tunnel speed improvement is claimed.

Files changed in Phase E:

| File | Scope |
| --- | --- |
| backend/main.py | Add authenticated wrappers for summary/page views; no production ML or legacy history edits |
| backend/history_views.py (new) | Bounded summaries, UTC serialization, classification-compatible pagination |
| backend/api_security.py | Share the history rate bucket with the two new routes |
| frontend/dashboard.html | UTC grouping/display, summary-driven charts, bounded paged table and controls |
| tools/dev_gateway.py | Explicit allowlist entries for the two new GET/HEAD routes |
| tools/verify_ml_acceptance.py | Optional URL-string cases parameter; default acceptance behavior retained |
| tools/phase_e_ml_audit.py (new) | Separate offline artifact/data diagnostic runner |
| backend/tests/test_phase_e_history.py (new) | Thirteen synthetic tests including reproducibility; isolated memory database |
| backend/tests/run_phase_e_dashboard_checks.py (new) | Rendered dashboard against actual isolated ASGI views |
| tests/test_phase_e_gateway.py (new) | New route forwarding and adjacent path/method denial |
| tools/PHASE_E_ML_AUDIT.md (new) | ML evidence, limitations and approval-required proposals |
| tools/PHASE_E_RESULTS.md (new) | This report |

Validation executed:

| Command/check | Actual result |
| --- | --- |
| Baseline `backend/venv/Scripts/python.exe -B backend/tests/run_isolated_regressions.py` | 169 run, zero failures/errors, one OS symlink-permission skip |
| Final same isolated regression command | 182 run, zero failures/errors, same one skip; includes auth/login, URL/UPI, PDF, class mapping and new history tests |
| `backend/venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 27 passed; gateway security/protocol, native local integration and temporary database persistence |
| `tools/phase_e_ml_audit.py` | Real artifact/feature ordering and class selection accepted; expected mismatches/uncalibrated predictions reproduced; warnings retained; dataset diagnostics completed |
| `run_frontend_static_checks.py` | 20 checks passed, nine scripts compiled, 21 local links |
| `run_result_explanation_checks.py` | 84 synthetic assertions passed |
| `run_phase_b_checks.py` | 176 synthetic login/copy/diagnostic checks passed |
| `run_warning_ui_checks.py` | 45 synthetic + 35 mocked-prediction assertions at each of 1280/390/320 px passed |
| `run_phase_b_rendered_checks.py` | 10 existing cases + 30 UPI cases passed in both themes at 320/390/768/1280/1440 px |
| `run_upi_generator_checks.py` | 69 assertions + 10 theme/width cases + actual browser-PNG-to-isolated-scanner round trip passed |
| `run_phase_e_dashboard_checks.py` | 10 theme/width cases passed, Next/Previous/filter/totals, UTC under Asia/Kolkata and America/Los_Angeles, XSS escaping, three error/empty scenarios |
| `git diff --check` | Passed; existing LF/CRLF notice for test_history_authorization.py is not a failure |

New backend tests cover UTC midnight and seven-day boundaries, month/year transitions, duplicate-day counts, empty/unknown time, offset conversion, totals and content categories, averages/findings, invalid legacy score exclusion, cursor ordering/ties, insertion-stable snapshots, null-time pagination, invalid inputs, owner isolation/auth rejection, a 5001-record dataset, legacy API shape, byte caps/no-store and deterministic ML source diagnostics. Real-artifact checks use local trusted model files without running FastAPI against real data. Browser download/clipboard regression checks use mocks; generator PNG decoding and dashboard ASGI calls are real isolated operations. No real user records or suspicious-site requests were used.

Two new test-harness defects were corrected during validation: DOM readiness originally returned a non-serializable element instead of a boolean, and a gateway mock raised during HTTPConnection construction instead of during the request. The final tests pass; neither was a pre-existing application failure.

Actual visual inspection: dashboard overview and history/pagination screenshots at 390x1000 and 1280x1000, both themes, stored as unique ignored `.design-review/phase-e-dashboard*.png` artifacts. All five widths were also checked through rendered DOM assertions. The mobile history table retains its existing internal horizontal scroll; the page itself does not overflow. Existing design, themes/navigation and scanner/generator presentation remain unchanged.

Remaining limits/proposals requiring separate approval:

- Production ML is still uncalibrated/unvalidated and has demonstrated false positives. Fixing feature semantics, dependencies or model quality requires an independently evaluated, explicitly approved ML change. No retraining, replacement or calibration occurred.
- Dashboard summary processing intentionally retains 5000-row/8 MiB limits. Beyond them the UI displays an explicit error and API pagination remains available. A future SQL aggregate/materialized-summary design should be profiled and reviewed before lifting those limits.
- No new index/migration was introduced. Large per-user page sorts may benefit from a composite user_id/scanned_at/id index; that schema change needs approval. Bounded worker deadlines remain the safeguard, not a performance guarantee.
- Legacy timestamps created outside the documented ORM path remain provenance-ambiguous. No real database was inspected, rewritten or repaired to resolve external imports.
- No real mobile/tunnel latency, live user account, camera hardware or physical file-save/clipboard test was performed.

Manual verification after restarting backend/gateway and refreshing dashboard:

1. With an existing test account, compare full totals with its known scans. Confirm the UTC label, newest-first order and same-date tie order. Verify seven-day activity near your local midnight against UTC, not local calendar dates.
2. If the account has more than 50 records, use Next/Previous and every classification filter. Totals/charts should remain full-snapshot values. A new scan appears after dashboard reload.
3. Check a second account sees only its own rows and still cannot download the first account's reports. Recheck URL/UPI scanning, PDF and Website/Text/UPI generation on the actual phone without initiating payments.
4. Use the development performance diagnostic/DevTools to measure real forwarded-link behavior. Do not infer real-device speed from synthetic payload-size reduction.
