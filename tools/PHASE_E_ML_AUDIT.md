# Phase E ML audit — production behavior retained

Baseline: branch fix/history-user-isolation, existing dirty work retained. Isolated backend baseline: 169 run, zero failures/errors, one Windows symlink-permission skip.

Evidence:

- `backend/ml/train_model.ipynb`, code cells 13–14: the URL dataset type is mapped with `1 if x == 'benign' else -1`, then passed directly as y2 to model2.fit. Cell 23 saves **model2**, not the enriched model3, as phishing_model_v2.pkl. Enrichment also uses the same label meanings. No inversion of model2 targets is present.
- `backend/main.py`, extract_ml_features and the /scan feature_order list; notebook cell 12: all twelve names/order match the artifact feature_names_in_. The sole calculation mismatch is has_ip: notebook searches the entire URL for an IPv4-shaped regex; production validates the actual hostname with ipaddress. A numeric path and invalid IPv4-shaped hostname give training=1/production=0; valid IPv6 gives training=0/production=1. The legacy helper is diagnostic only and is not substituted into production.
- `backend/ml_probability.py` and /scan: actual classes_ locate label **-1**. Reordered probability columns pass acceptance. The label mapping is correct regardless of plausibility of individual outputs.
- Trusted artifact SHA256: d5ebec79e73c331594effed3dc36ad8bfb817319aa70d0c2cb64298a7150a2ff. Loading reports sklearn 1.9.0 estimators under installed 1.9.1. The warning is retained. A successful local load does not prove compatibility; installing/changing versions needs a separate controlled environment proposal.

Reproduced lexical-only predictions with the existing production extractor:

| String (never visited) | P(class=-1), percent |
| --- | ---: |
| https://www.google.com | 99.89330948121646 |
| https://www.wikipedia.org/ | 100.0 |
| https://www.paypal.com/ | 100.0 |
| www.wikipedia.org/ | 23.152234307365884 |
| http://paypal-secure-login.verify-account.tk | 20.219436119436118 |
| http://paypal-login.verify-account.tk | 54.196922513331145 |

Features for these six strings match the notebook, so their disagreement with expectation cannot be attributed to has_ip. These are acceptance examples, not a measured false-positive rate or labelled phishing test set. The synthetic names are not confirmed phishing sites. Reproduced Wikipedia/PayPal false positives remain a concern, not evidence for inverting class labels. Scores are uncalibrated RF estimates.

Available data: malicious_phish.csv has 651191 rows: benign 428103, phishing 94111, defacement 96457, malware 32520. The production notebook balances phishing and a sampled subset of benign rows, then performs a random 80/20 URL-row split with seed42. It does not deduplicate or group by domain/campaign/time before splitting. Across the binary source subset there are 522166 unique exact URL strings, 48 duplicate occurrences and six conflicting-label duplicate occurrences. Duplicates/domain overlap across splits are leakage risks; the 48 duplicates alone do not establish the exact overlap in the persisted model's training split. Only 60230 binary rows have an explicit HTTP(S) prefix; production normally receives explicit HTTP(S) URLs. This is a substantial lexical distribution-shift risk, particularly for has_https, URL length and slash count.

phishing.csv contains 11054 precomputed 30-feature rows (4897 label -1, 6157 label1). It belongs to the earlier model, has no raw URLs for current twelve-feature inference and is not a valid independent test set for model2. Candidate preprocessing manifests/splits also exist, but derive from the available source data; disjointness from model2 training is not proven. Original dataset collection dates, licensing/provenance and persistent production train/test identities are not established. Notebook precision/recall defaults score label1 (benign), not phishing; notebook scores must not be reused as current phishing-performance claims.

No trustworthy independent labelled corpus was established. Consequently no real-world confusion matrix, precision, recall, F1, FPR/FNR, ROC-AUC, PR-AUC or calibration results are claimed. Do not evaluate on the entire training source and present it as a test score.

Reproduce without executing notebook network/enrichment cells:

`backend/venv/Scripts/python.exe -B tools/phase_e_ml_audit.py`

It reuses tools/verify_ml_acceptance.py for artifact hash, classes, feature ordering, drift counterexamples and real-artifact predictions, and separately emits aggregate source diagnostics without logging URLs. It does not load FastAPI, databases or secrets, fetch URLs, suppress warnings or write artifacts. Existing synthetic compatibility tests exercise class ordering/invalid labels; Phase E tests cover diagnostic reproducibility.

Proposal requiring separate approval: reproduce the artifact in its original dependency environment; establish independently reviewed benign/phishing labels and source provenance; deduplicate exact/canonical URLs and split by registered domain/campaign and time, excluding production training overlap. Lock the input representation before computing positive-class=-1 confusion metrics, ROC/PR curves, Brier/log loss and reliability bins. Evaluate raw/training and production feature pipelines separately. Only then propose a versioned feature repair, retraining/replacement or calibration. None of those production changes are authorized or implemented in Phase E.
