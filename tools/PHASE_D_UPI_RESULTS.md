# Phase D UPI analysis implementation and validation

Only Phase D was implemented. Existing dirty/untracked work was inspected and retained; no staging, commits, resets, cleaning, deployment, new dependencies or database migration.

Existing functionality found: offline UPI parsing, first-value fields, local VPA format checks, decimal numeric checks, repeated/conflicting parameters, expected-ID comparison and unverified-identity notices. Existing comparison statuses and their meanings were retained, including `ambiguous` taking precedence for conflicting parameters. UPI content was already separate from URL ML/scoring.

The new `/scan` field `upi_analysis` is additive. Existing `upi_details`, `upi_comparison`, decoded content, scores, model labels, URL thresholds and response fields are preserved. Legacy `amount_valid` still means the old nonnegative-number check; the new `fields.amount.status` additionally flags zero, non-plain-decimal representations and excessive precision. Consumers should use the new validation notes for those distinctions. No changes to authentication endpoints, schema, ownership rules, gateway or network restrictions.

Changes made:

- `backend/upi_security.py` (new): pure offline analysis, Payment Request/send-money education and unverified recipient notes; exact monetary strings validated with Decimal; required recipient, explicit currency, URI shape, encoding, control characters, parameter-count and value bounds; duplicates/conflicts and specific contextual phrase warnings. It does not initiate a payment, call a provider, verify ownership, invent a bank limit or calculate a fraud probability.
- `backend/main.py`: attach the new analysis only for UPI content, including unsupported UPI structures; derive UPI report details from stored decoded content. UPI PDFs label recipient information unverified and include content type, direction, exact amount, currency, payee, note/reference, warnings and recommendations. Long rows are split into bounded continued rows, with escaped untrusted text. URL PDF logic is retained.
- `frontend/scan.html`: display education, payment details, all conflicting encoded values and visible field states in Simple and Technical views. Existing comparison controls remain available. Remove JavaScript Number/Intl rounding of amount strings, including the fallback display for older responses. Preserve decoded-content copying, disabled non-HTTP Open Link behavior, PDF, retake and scanning controls.
- `frontend/theme.css`: small scoped UPI wrapping, field-state and security-note styles using existing light/dark tokens.
- `backend/tests/test_upi_security.py` (new): 13 focused tests, with parameterized cases for format/amount/language/bounds, additive scan integration, PDF escaping/long values, owner-only report downloads and history isolation. Synthetic memory-only data; no production model/database loads.
- `frontend/tests/result-explanations.test.js`: 20 added assertions for UPI education, exact amounts, visible state content, missing fields, text escaping, Simple/Technical persistence and unsupported structures.
- `backend/tests/run_phase_b_rendered_checks.py`: retain existing Phase B checks and add 30 synthetic UPI rendered cases, both views/themes, no horizontal overflow, unverified labels and no payment-link action. Uses pure analyzer fixtures without importing the backend app.
- `tools/PHASE_D_UPI_RESULTS.md` (this report).

Indicators include missing/invalid payee, duplicate/conflicting parameters, invalid/negative/zero/excessive-precision amounts, missing/unexpected currency, malformed URI or encoding, unparseable/oversized parameters, and payment-context refund verification, cashback collection/verification, prize collection, account/service activation payment, KYC fee and pay-to-receive language. Bare benign notes such as "Refund for returned item", "Cashback", "KYC" and "Lunch payment" are covered as negative cases. These are contextual indicators, never a finding that a recipient is a confirmed scammer.

Validation executed:

| Check | Actual result |
| --- | --- |
| Baseline isolated backend suite | 156 run, zero failures/errors, one OS symlink-permission skip |
| Final `backend/venv/Scripts/python.exe -B backend/tests/run_isolated_regressions.py` | 169 run, zero failures/errors, same one skip; includes existing UPI/URL/PDF/security/authorization and all 13 new tests |
| `backend/venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 26 passed: gateway protocol/security and temporary-database persistence/integration |
| `run_frontend_static_checks.py` | 20 checks passed; nine scripts compiled, 21 local links checked |
| `run_result_explanation_checks.py` | 84 synthetic DOM assertions passed |
| `run_phase_b_checks.py` | 176 synthetic checks passed |
| `run_warning_ui_checks.py` | 45 synthetic + 35 mocked-prediction checks at each of 1280, 390 and 320 px passed |
| `run_phase_b_rendered_checks.py` | 10 existing + 30 UPI cases passed, light/dark, widths 320/390/768/1280/1440, 1000px viewport height |
| `git diff --check` | Passed; only a pre-existing LF/CRLF warning for test_history_authorization.py |

The backend tests guard against real database/model access and external networking; scan integration uses synthetic image data and mocked decoding. Existing URL tests also cover real generated synthetic QR decoding. The browser fixtures mock API responses and do not represent live payment or live-device tests. New UPI PDFs were actually generated and owner-scoped downloads exercised through the local ASGI harness; PDF text input and escaping were checked, but final PDF pages were not visually rendered/reviewed.

Actual screenshot review: two iterations, light/dark at 390x1000 and 1280x1000. The first revealed that field-state explanations were only tooltips; the second verified visible state text, all conflicting values, and readable details/security notes. Eight final screenshots were captured and inspected (details and notes for each theme/size), stored under the existing ignored `.design-review/*.png` pattern. Other widths were checked by rendered DOM assertions, not separate screenshot inspection. No horizontal overflow was detected in either view for valid, conflicting/excessive-precision and unsupported/long-value fixtures.

Preservation: production artifact SHA256 remains `d5ebec79e73c331594effed3dc36ad8bfb817319aa70d0c2cb64298a7150a2ff`; no model/class mapping or scoring edits were made. No existing database/user records or external backup were touched. No Phase E work.

Remaining limitations: these English phrase rules can miss disguised wording or warn on legitimate contexts. Missing currency is a review note, not an invented default. The value/count bounds are local analysis limits, not payment-provider limits. Format validity is not bank acceptance or recipient identity verification; URI signatures are not cryptographically verified. Historical PDFs re-derive notes under the current rules rather than persisting a versioned analysis, and expected-VPA comparisons remain transient as before. PDF font coverage for arbitrary Unicode payee names should be checked manually. No live mobile camera, tunnel, physical-device UI, real payment app or payment-network validation was performed.

Manual verification after restarting the backend and refreshing the frontend:

1. Generate/upload a synthetic QR containing `upi://pay?pa=merchant@upi&pn=Example%20Store&am=250.00&cu=INR&tn=Lunch&tr=DEMO`. Confirm Payment Request/send-money explanation, exact `250.00`, six detail fields and unverified recipient notices. Do not approve a payment.
2. Use `upi://pay?pa=merchant@upi&cu=INR&tn=Pay%20to%20receive%20refund`. Confirm contextual warnings and no fraud probability or URL risk score.
3. Use `upi://pay?pa=merchant@upi&pa=other@upi&am=10.001&cu=INR`. Confirm all payee values, ambiguous comparison where requested, exact unrounded amount and visible review states.
4. On the real phone, check both themes, Simple/Technical views, camera/upload/retake, copy content, PDF download and Scan Another QR. Verify the PDF's recipient/warnings and long names visually. Check a second account cannot obtain the first account's report. No payment app should launch from the results.
