"""Offline provenance/duplication diagnostics, not independent performance metrics.

Run with backend/venv/Scripts/python.exe -B tools/phase_e_ml_audit.py.
No URLs are requested; model acceptance uses the existing trusted local artifact.
"""
import csv
import hashlib
import json
from pathlib import Path


def dataset_diagnostics(path):
    seen = {}
    counts = {}
    duplicate_rows = conflicts = explicit_scheme = 0
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            label = row["type"]
            counts[label] = counts.get(label, 0) + 1
            if label not in ("benign", "phishing"):
                continue
            url = row["url"]
            key = hashlib.sha256(url.encode("utf-8")).digest()
            if key in seen:
                duplicate_rows += 1
                conflicts += seen[key] != label
            else:
                seen[key] = label
            explicit_scheme += url.startswith(("http://", "https://"))
    return {"label_counts": counts, "binary_unique_urls": len(seen),
            "duplicate_binary_rows": duplicate_rows, "conflicting_duplicate_occurrences": conflicts,
            "explicit_http_scheme_rows": explicit_scheme,
            "independent_test_metrics": None,
            "limitation": "This is a training-source dataset with unverified provenance, not an independent evaluation set."}


if __name__ == "__main__":
    from verify_ml_acceptance import main
    # Deliberately retain compatibility warnings; never retrain or rewrite.
    main(urls=("https://www.google.com", "https://www.wikipedia.org/", "https://www.paypal.com/",
               "www.wikipedia.org/", "http://paypal-secure-login.verify-account.tk", "http://paypal-login.verify-account.tk"))
    print(json.dumps(dataset_diagnostics(Path(__file__).resolve().parents[1] / "backend/ml/malicious_phish.csv"), indent=2))
