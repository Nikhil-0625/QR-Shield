"""Offline Detection Quality Evaluation Framework for QR Shield.

This utility evaluates the deterministic offline heuristic detection rules of QR Shield
against labeled URL datasets without any network requests, third-party lookups,
or database modifications.
"""

import argparse
import collections
import csv
import json
import os
from pathlib import Path
import random
import re
import sys
import time
from urllib.parse import urlsplit

# Ensure backend modules can be imported with isolation guards
BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("JWT_SECRET_KEY", "evaluation-safety-secret-key-32-chars-min!!")

try:
    from offline_psl import OfflineDomainParser
    from main import calculate_rule_contributions, parse_hostname, get_root_domain
    from url_security import brand_match, structural_findings, hostname, registered_domain
    from url_policy import url_input_error
    from website_input import normalize_website_url
except ImportError as e:
    print(f"Error importing QR Shield backend modules: {e}", file=sys.stderr)
    sys.exit(1)


def is_formula_cell(value: str) -> bool:
    """Check if a cell starts with spreadsheet formula injection characters."""
    return isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))


def load_and_audit_dataset(dataset_path: Path, max_rows: int = None):
    """Load, validate, and audit the raw dataset."""
    print(f"[*] Loading dataset from: {dataset_path}")
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    total_rows = 0
    class_distribution = collections.Counter()
    formula_count = 0
    seen_urls = collections.defaultdict(set)
    records = []

    with dataset_path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        if "url" not in reader.fieldnames or "type" not in reader.fieldnames:
            raise ValueError(f"Dataset must contain 'url' and 'type' columns; found {reader.fieldnames}")

        for row in reader:
            total_rows += 1
            url = row.get("url", "")
            raw_type = (row.get("type") or "").strip().lower()
            class_distribution[raw_type] += 1

            if is_formula_cell(url):
                formula_count += 1

            seen_urls[url].add(raw_type)

            # Focus on binary detection: benign vs phishing
            if raw_type in ("benign", "phishing"):
                records.append({"raw_url": url, "label": 1 if raw_type == "phishing" else 0, "type": raw_type})

            if max_rows and total_rows >= max_rows:
                print(f"[*] Reached max row limit: {max_rows}")
                break

    # Analyze conflicts and duplicates
    duplicate_rows = total_rows - len(seen_urls)
    conflicting_urls = {u: types for u, types in seen_urls.items() if len(types) > 1}

    # Filter binary records: exclude conflicting URLs
    clean_records = []
    quarantined_records = []
    seen_binary = set()

    for rec in records:
        u = rec["raw_url"]
        if u in conflicting_urls:
            quarantined_records.append({**rec, "reason": "conflicting_labels", "labels": list(conflicting_urls[u])})
            continue
        if u in seen_binary:
            continue
        seen_binary.add(u)
        clean_records.append(rec)

    audit_summary = {
        "total_rows_inspected": total_rows,
        "class_distribution_raw": dict(class_distribution),
        "formula_cells_detected": formula_count,
        "unique_urls_total": len(seen_urls),
        "duplicate_rows_detected": duplicate_rows,
        "conflicting_url_labels_count": len(conflicting_urls),
        "binary_accepted_unique_rows": len(clean_records),
        "binary_benign_count": sum(1 for r in clean_records if r["label"] == 0),
        "binary_phishing_count": sum(1 for r in clean_records if r["label"] == 1),
    }

    print(f"[*] Dataset audit complete: {len(clean_records):,} clean unique binary samples accepted.")
    return clean_records, audit_summary, conflicting_urls


def split_domain_disjoint(records, seed: int = 42, test_ratio: float = 0.20):
    """Split records by registered domain to prevent domain-level data leakage."""
    print(f"[*] Partitioning records into domain-disjoint splits (seed={seed}, test_ratio={test_ratio})...")
    parser = OfflineDomainParser()

    domain_groups = collections.defaultdict(list)
    for rec in records:
        url = rec["raw_url"]
        clean_url = url if ("://" in url or url.startswith("//")) else "//" + url
        try:
            host = urlsplit(clean_url).hostname
            group = parser.group(host) if host else "unknown_group"
        except Exception:
            group = "unparseable_group"
        rec["domain_group"] = group
        domain_groups[group].append(rec)

    groups = sorted(domain_groups.keys())
    rng = random.Random(seed)
    rng.shuffle(groups)

    n_test_groups = max(1, int(len(groups) * test_ratio))
    test_group_set = set(groups[:n_test_groups])

    test_records = []
    train_records = []
    for g in groups:
        if g in test_group_set:
            test_records.extend(domain_groups[g])
        else:
            train_records.extend(domain_groups[g])

    print(f"[*] Groups: {len(groups):,} total ({len(test_group_set):,} test, {len(groups)-len(test_group_set):,} train).")
    print(f"[*] Records: {len(test_records):,} test ({sum(r['label']==1 for r in test_records):,} phish), {len(train_records):,} train.")

    return train_records, test_records


def run_offline_analysis(url: str, mode: str = "website_checker", ignore_http_rule: bool = False, classify_transport_as_phishing: bool = False):
    """Execute QR Shield's offline deterministic URL analysis on a single URL."""
    # Step 1: Normalization
    if mode == "website_checker":
        # Website Checker normalizes schemeless URLs by prepending https://
        eval_url = url.strip()
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", eval_url):
            eval_url = "https://" + eval_url
    else:
        # QR scanner evaluates decoded string directly
        eval_url = url

    # Step 2: Hostname and Brand Lookalike Matching
    domain = parse_hostname(eval_url)
    matched_brand, brand_score = brand_match(domain)
    if not matched_brand and eval_url != domain:
        initial_brand, initial_score = brand_match(eval_url)
        if initial_brand:
            matched_brand, brand_score = initial_brand, initial_score

    # Step 3: Heuristic Rule Evaluation (Offline: domain_age=None, https_valid=None, chain=[url])
    rule_score, risk_breakdown = calculate_rule_contributions(
        domain_age=None,
        https_valid=None,
        brand_match=matched_brand,
        chain=[eval_url],
        final_url=eval_url,
        original_url=eval_url
    )

    if ignore_http_rule:
        risk_breakdown = [f for f in risk_breakdown if f["name"] != "HTTP Connection"]
        rule_score = sum(f["points"] for f in risk_breakdown)

    # Step 4: Classification Verdict
    if classify_transport_as_phishing:
        is_suspicious = bool(risk_breakdown)
    else:
        # Decouple transport security warnings from phishing evidence (matching main.py)
        phishing_findings = [
            f for f in risk_breakdown
            if f.get("category") != "transport" and f["name"] not in {"HTTP Connection", "HTTPS Downgrade Redirect", "HTTPS Validation Failed"}
        ]
        is_suspicious = bool(phishing_findings)

    verdict_code = "suspicious" if is_suspicious else "unverified"

    return {
        "eval_url": eval_url,
        "domain": domain,
        "matched_brand": matched_brand,
        "rule_score": rule_score,
        "risk_breakdown": risk_breakdown,
        "is_suspicious": is_suspicious,
        "verdict_code": verdict_code
    }


def compute_metrics(y_true, y_pred, y_abstained=None):
    """Compute standard classification and selective/abstention metrics."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    specificity = tn / (fp + tn) if (fp + tn) > 0 else 0.0

    coverage = (tp + fp) / total if total > 0 else 0.0
    abstention_rate = (tn + fn) / total if total > 0 else 0.0

    return {
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
        "false_positive_rate": fpr,
        "specificity": specificity,
        "coverage": coverage,
        "abstention_rate": abstention_rate
    }


def evaluate_records(records, mode: str = "website_checker", ignore_http_rule: bool = False, classify_transport_as_phishing: bool = False):
    """Run evaluation over a list of records."""
    y_true = []
    y_pred = []
    rule_counts = collections.defaultdict(lambda: collections.Counter())
    false_positives = []
    false_negatives = []
    true_positives = []

    start_time = time.time()
    for idx, rec in enumerate(records):
        label = rec["label"]
        res = run_offline_analysis(
            rec["raw_url"],
            mode=mode,
            ignore_http_rule=ignore_http_rule,
            classify_transport_as_phishing=classify_transport_as_phishing
        )
        pred = 1 if res["is_suspicious"] else 0

        y_true.append(label)
        y_pred.append(pred)

        for item in res["risk_breakdown"]:
            name = item["name"]
            rule_counts[label][name] += 1

        if label == 0 and pred == 1 and len(false_positives) < 50:
            false_positives.append({
                "raw_url": rec["raw_url"],
                "eval_url": res["eval_url"],
                "domain": res["domain"],
                "rules": [f["name"] for f in res["risk_breakdown"]],
                "rule_score": res["rule_score"]
            })

        if label == 1 and pred == 0 and len(false_negatives) < 50:
            false_negatives.append({
                "raw_url": rec["raw_url"],
                "eval_url": res["eval_url"],
                "domain": res["domain"]
            })

        if label == 1 and pred == 1 and len(true_positives) < 20:
            true_positives.append({
                "raw_url": rec["raw_url"],
                "domain": res["domain"],
                "rules": [f["name"] for f in res["risk_breakdown"]]
            })

    elapsed = time.time() - start_time
    metrics = compute_metrics(y_true, y_pred)
    metrics["elapsed_seconds"] = round(elapsed, 2)
    metrics["throughput_urls_per_sec"] = round(len(records) / elapsed, 1) if elapsed > 0 else 0

    return {
        "metrics": metrics,
        "rule_triggers": {
            "phishing_actual": dict(rule_counts[1]),
            "benign_actual": dict(rule_counts[0])
        },
        "sample_false_positives": false_positives,
        "sample_false_negatives": false_negatives,
        "sample_true_positives": true_positives
    }


def main():
    parser = argparse.ArgumentParser(description="Offline Detection Quality Evaluation for QR Shield")
    parser.add_argument("--dataset", type=Path, default=BACKEND / "ml/malicious_phish.csv", help="Path to labeled CSV dataset")
    parser.add_argument("--sample-size", type=int, default=None, help="Maximum number of rows to evaluate (default: full dataset)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for domain-disjoint split")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent, help="Output directory for reports")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print("                QR SHIELD OFFLINE DETECTION QUALITY EVALUATION                  ")
    print("================================================================================")

    # Step 1: Load and Audit Dataset
    clean_records, audit_summary, conflicting_urls = load_and_audit_dataset(args.dataset, args.sample_size)

    # Step 2: Create Domain-Disjoint Splits
    train_records, test_records = split_domain_disjoint(clean_records, seed=args.seed, test_ratio=0.20)

    # Step 3: Run Evaluation Modes
    # Phase A: Development Split Evaluation (as required by prompt before held-out test set)
    print(f"\n[+] Running Development Split ({len(train_records):,} records)...")
    res_wc_dev = evaluate_records(train_records, mode="website_checker", classify_transport_as_phishing=False)

    # Phase B: Held-Out Test Set (Domain-Disjoint)
    print(f"\n[+] Running Configuration 1: Production Website Checker (Decoupled Transport) on Test Set ({len(test_records):,} records)...")
    res_wc_test = evaluate_records(test_records, mode="website_checker", classify_transport_as_phishing=False)

    print("\n[+] Running Configuration 2: Legacy Baseline Mode (HTTP Connection flags as suspicious) on Test Set...")
    res_legacy_test = evaluate_records(test_records, mode="website_checker", classify_transport_as_phishing=True)

    print("\n[+] Running Configuration 3: Content & Brand Rules Only (Ablation without HTTP rule) on Test Set...")
    res_nohttp_test = evaluate_records(test_records, mode="website_checker", ignore_http_rule=True)

    print("\n[+] Running Configuration 4: QR Scanner Pipeline (Raw strings, decoupled transport) on Test Set...")
    res_qr_test = evaluate_records(test_records, mode="qr_scanner", classify_transport_as_phishing=False)

    # Phase C: Full Validated Dataset Evaluation (All clean binary records)
    print(f"\n[+] Running Configuration 5: Full Validated Corpus ({len(clean_records):,} records) - Production Decoupled...")
    res_full_corpus = evaluate_records(clean_records, mode="website_checker", classify_transport_as_phishing=False)

    results_bundle = {
        "metadata": {
            "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dataset_path": str(args.dataset),
            "seed": args.seed,
            "sample_size": args.sample_size,
        },
        "dataset_audit": audit_summary,
        "evaluation_development_split": {
            "description": "Evaluated on development partition (80% domain-disjoint split) before held-out verification.",
            "sample_count": len(train_records),
            "website_checker_production": res_wc_dev
        },
        "evaluation_domain_disjoint_test": {
            "description": "Evaluated strictly on unseen held-out domain groups (20% split) to eliminate domain leakage.",
            "sample_count": len(test_records),
            "website_checker_production": res_wc_test,
            "website_checker_legacy_transport_baseline": res_legacy_test,
            "website_checker_ablation_no_http_rule": res_nohttp_test,
            "qr_scanner_raw_mode": res_qr_test
        },
        "evaluation_full_corpus": {
            "description": "Evaluated across all deduplicated binary records in the corpus.",
            "sample_count": len(clean_records),
            "website_checker_production": res_full_corpus
        }
    }

    # Save JSON results
    out_json = args.output_dir / "evaluation_results.json"
    with out_json.open("w", encoding="utf-8") as f:
        json.dump(results_bundle, f, indent=2)
    print(f"\n[OK] Results successfully written to: {out_json}")

    # Display console summary table
    print("\n" + "="*96)
    print("                           SUMMARY EVALUATION METRICS                           ")
    print("="*96)
    print(f"{'Metric':<28} | {'Dev Set (Prod)':<15} | {'Test (Prod)':<15} | {'Test (Legacy)':<15} | {'Test (No HTTP)':<15}")
    print("-"*96)

    m0 = res_wc_dev["metrics"]
    m1 = res_wc_test["metrics"]
    m2 = res_legacy_test["metrics"]
    m3 = res_nohttp_test["metrics"]

    rows = [
        ("Evaluated Samples", f"{m0['total']:,}", f"{m1['total']:,}", f"{m2['total']:,}", f"{m3['total']:,}"),
        ("True Positives (TP)", f"{m0['true_positives']:,}", f"{m1['true_positives']:,}", f"{m2['true_positives']:,}", f"{m3['true_positives']:,}"),
        ("False Positives (FP)", f"{m0['false_positives']:,}", f"{m1['false_positives']:,}", f"{m2['false_positives']:,}", f"{m3['false_positives']:,}"),
        ("True Negatives (TN)", f"{m0['true_negatives']:,}", f"{m1['true_negatives']:,}", f"{m2['true_negatives']:,}", f"{m3['true_negatives']:,}"),
        ("False Negatives (FN)", f"{m0['false_negatives']:,}", f"{m1['false_negatives']:,}", f"{m2['false_negatives']:,}", f"{m3['false_negatives']:,}"),
        ("Precision", f"{m0['precision']*100:.2f}%", f"{m1['precision']*100:.2f}%", f"{m2['precision']*100:.2f}%", f"{m3['precision']*100:.2f}%"),
        ("Recall (Detection Rate)", f"{m0['recall']*100:.2f}%", f"{m1['recall']*100:.2f}%", f"{m2['recall']*100:.2f}%", f"{m3['recall']*100:.2f}%"),
        ("F1-Score", f"{m0['f1_score']*100:.2f}%", f"{m1['f1_score']*100:.2f}%", f"{m2['f1_score']*100:.2f}%", f"{m3['f1_score']*100:.2f}%"),
        ("False Positive Rate (FPR)", f"{m0['false_positive_rate']*100:.2f}%", f"{m1['false_positive_rate']*100:.2f}%", f"{m2['false_positive_rate']*100:.2f}%", f"{m3['false_positive_rate']*100:.2f}%"),
        ("Accuracy", f"{m0['accuracy']*100:.2f}%", f"{m1['accuracy']*100:.2f}%", f"{m2['accuracy']*100:.2f}%", f"{m3['accuracy']*100:.2f}%"),
        ("Coverage (Flagged Rate)", f"{m0['coverage']*100:.2f}%", f"{m1['coverage']*100:.2f}%", f"{m2['coverage']*100:.2f}%", f"{m3['coverage']*100:.2f}%"),
        ("Abstention (Unverified)", f"{m0['abstention_rate']*100:.2f}%", f"{m1['abstention_rate']*100:.2f}%", f"{m2['abstention_rate']*100:.2f}%", f"{m3['abstention_rate']*100:.2f}%"),
    ]

    for label, c0, c1, c2, c3 in rows:
        print(f"{label:<28} | {c0:<15} | {c1:<15} | {c2:<15} | {c3:<15}")
    print("="*96)


if __name__ == "__main__":
    main()
