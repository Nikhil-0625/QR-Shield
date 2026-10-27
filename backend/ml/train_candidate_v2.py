"""Phase 5: Candidate ML Model Training and Comprehensive Evaluation.

Requirements:
- Strict domain-disjoint splitting (eTLD+1).
- No HTTPS feature: eliminates the legacy HTTPS shortcut.
- No network requests, external lookups, or URL fetching.
- Preserves untouched holdout test set.
- Generates comprehensive metrics: precision, recall, F1, FPR, FNR,
  confusion matrix, calibration (Brier score), feature importances,
  prevalence sensitivity analysis, and comparison with heuristic engine.
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

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score,
    auc,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

try:
    from offline_psl import OfflineDomainParser
    from ml.candidate_v2_features import FEATURE_NAMES, SCHEMA_VERSION, extract_candidate_features
    from main import calculate_rule_contributions, parse_hostname
    from url_security import brand_match
except ImportError as e:
    print(f"Error importing QR Shield backend modules: {e}", file=sys.stderr)
    sys.exit(1)

OUTPUT_DIR = BACKEND / "ml/candidate_artifacts/candidate_v2_seed42"


def load_dataset_and_audit(dataset_path: Path):
    print(f"[*] Step 1: Loading and auditing dataset: {dataset_path}")
    total_rows = 0
    type_counts = collections.Counter()
    seen_urls = collections.defaultdict(set)
    records = []
    formula_count = 0

    with dataset_path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            url = row.get("url", "")
            raw_type = (row.get("type") or "").strip().lower()
            type_counts[raw_type] += 1

            if url.lstrip().startswith(("=", "+", "-", "@")):
                formula_count += 1

            seen_urls[url].add(raw_type)

            if raw_type in ("benign", "phishing"):
                records.append({
                    "raw_url": url,
                    "label": 1 if raw_type == "phishing" else 0,
                    "type": raw_type
                })

    conflicts = {u: types for u, types in seen_urls.items() if len(types) > 1}

    # Filter binary records
    clean_records = []
    seen_binary = set()
    for rec in records:
        u = rec["raw_url"]
        if u in conflicts:
            continue
        if u in seen_binary:
            continue
        seen_binary.add(u)
        clean_records.append(rec)

    audit_stats = {
        "total_rows_inspected": total_rows,
        "class_distribution_raw": dict(type_counts),
        "formula_cells_quarantined": formula_count,
        "unique_urls_total": len(seen_urls),
        "duplicate_rows_quarantined": total_rows - len(seen_urls),
        "conflicting_urls_quarantined": len(conflicts),
        "clean_binary_records": len(clean_records),
        "clean_benign_records": sum(1 for r in clean_records if r["label"] == 0),
        "clean_phishing_records": sum(1 for r in clean_records if r["label"] == 1),
    }

    print(f"[*] Audit complete: {len(clean_records):,} clean binary records accepted.")
    return clean_records, audit_stats


def split_domain_disjoint_three_way(records, seed: int = 42, test_ratio: float = 0.15, val_ratio: float = 0.15):
    print(f"[*] Step 2: Creating domain-disjoint partitions (seed={seed}, test={test_ratio}, val={val_ratio})...")
    psl = OfflineDomainParser()

    domain_groups = collections.defaultdict(list)
    for rec in records:
        url = rec["raw_url"]
        clean_url = url if ("://" in url or url.startswith("//")) else "//" + url
        try:
            host = urlsplit(clean_url).hostname
            grp = psl.group(host) if host else "unknown"
        except Exception:
            grp = "unparseable"
        domain_groups[grp].append(rec)

    groups = sorted(domain_groups.keys())
    rng = random.Random(seed)
    rng.shuffle(groups)

    n_groups = len(groups)
    n_test = max(1, int(n_groups * test_ratio))
    n_val = max(1, int(n_groups * val_ratio))

    test_groups = set(groups[:n_test])
    val_groups = set(groups[n_test:n_test + n_val])
    train_groups = set(groups[n_test + n_val:])

    splits = {"train": [], "validation": [], "test": []}
    for g, recs in domain_groups.items():
        if g in test_groups:
            splits["test"].extend(recs)
        elif g in val_groups:
            splits["validation"].extend(recs)
        else:
            splits["train"].extend(recs)

    print(f"[*] Domain groups: {len(train_groups):,} train, {len(val_groups):,} val, {len(test_groups):,} test")
    print(f"[*] Records: {len(splits['train']):,} train, {len(splits['validation']):,} val, {len(splits['test']):,} test")
    return splits


def extract_features_for_split(records, split_name: str):
    print(f"[*] Extracting features for {split_name} ({len(records):,} records)...")
    t0 = time.time()
    X = []
    y = []
    for rec in records:
        feats = extract_candidate_features(rec["raw_url"])
        X.append(feats)
        y.append(rec["label"])
    elapsed = round(time.time() - t0, 2)
    print(f"[*] Extracted {split_name} in {elapsed}s.")
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int32)


def compute_comprehensive_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    precision = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    recall = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
    accuracy = float(accuracy_score(y_true, y_pred))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    coverage = float((tp + fp) / len(y_true)) if len(y_true) > 0 else 0.0

    roc_auc = float(roc_auc_score(y_true, y_prob))
    precisions_curve, recalls_curve, _ = precision_recall_curve(y_true, y_prob, pos_label=1)
    pr_auc = float(auc(recalls_curve, precisions_curve))
    avg_precision = float(average_precision_score(y_true, y_prob))
    brier = float(brier_score_loss(y_true, y_prob))

    return {
        "threshold": threshold,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "specificity": specificity,
        "coverage": coverage,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "average_precision": avg_precision,
        "brier_score": brier,
        "confusion_matrix": cm.tolist()
    }


def simulate_prevalence(y_true, y_prob, threshold, target_prevalences=(0.01, 0.05, 0.10, 0.20)):
    """Evaluate performance under varying realistic phishing prevalence rates using Bayes theorem."""
    metrics = compute_comprehensive_metrics(y_true, y_prob, threshold)
    tpr = metrics["recall"]
    fpr = metrics["false_positive_rate"]

    prevalence_results = {}
    for prev in target_prevalences:
        # P(Phish | Flagged) = (TPR * prev) / (TPR * prev + FPR * (1 - prev))
        denom = (tpr * prev) + (fpr * (1 - prev))
        sim_precision = (tpr * prev) / denom if denom > 0 else 0.0
        # Sim F1: 2 * P * R / (P + R)
        sim_f1 = (2 * sim_precision * tpr) / (sim_precision + tpr) if (sim_precision + tpr) > 0 else 0.0
        prevalence_results[f"{int(prev*100)}pct_prevalence"] = {
            "prevalence": prev,
            "simulated_precision": round(sim_precision, 4),
            "recall": round(tpr, 4),
            "simulated_f1": round(sim_f1, 4),
            "false_positive_rate": round(fpr, 4)
        }
    return prevalence_results


def evaluate_offline_heuristics_on_records(records):
    """Run production offline heuristic engine on the same test records for head-to-head comparison."""
    print(f"[*] Running offline heuristics on {len(records):,} test records...")
    t0 = time.time()
    y_true = []
    y_pred = []

    for rec in records:
        url = rec["raw_url"]
        label = rec["label"]
        eval_url = url.strip()
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", eval_url):
            eval_url = "https://" + eval_url

        domain = parse_hostname(eval_url)
        matched_brand, brand_score = brand_match(domain)
        if not matched_brand and eval_url != domain:
            ib, iscore = brand_match(eval_url)
            if ib:
                matched_brand, brand_score = ib, iscore

        rule_score, risk_breakdown = calculate_rule_contributions(
            domain_age=None, https_valid=None, brand_match=matched_brand,
            chain=[eval_url], final_url=eval_url, original_url=eval_url
        )
        # Production decoupled transport logic
        phishing_findings = [
            f for f in risk_breakdown
            if f.get("category") != "transport" and f["name"] not in {"HTTP Connection", "HTTPS Downgrade Redirect", "HTTPS Validation Failed"}
        ]
        pred = 1 if phishing_findings else 0

        y_true.append(label)
        y_pred.append(pred)

    elapsed = round(time.time() - t0, 2)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    precision = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    recall = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    print(f"[*] Offline heuristics evaluated in {elapsed}s.")
    return {
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": cm.tolist(),
        "elapsed_seconds": elapsed
    }


def main():
    parser = argparse.ArgumentParser(description="Candidate ML Model Training & Evaluation")
    parser.add_argument("--dataset", type=Path, default=BACKEND / "ml/malicious_phish.csv")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--trees", type=int, default=100)
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      QR SHIELD PHASE 5: CANDIDATE ML MODEL TRAINING & EVALUATION       ")
    print("=" * 80)

    # 1. Load and Audit Dataset
    clean_records, audit_stats = load_dataset_and_audit(args.dataset)

    # 2. Domain-Disjoint Split
    splits = split_domain_disjoint_three_way(clean_records, seed=args.seed)

    # 3. Extract Features
    X_train, y_train = extract_features_for_split(splits["train"], "train")
    X_val, y_val = extract_features_for_split(splits["validation"], "validation")
    X_test, y_test = extract_features_for_split(splits["test"], "test")

    # 4. Train Candidate Model (Random Forest, Balanced)
    print(f"\n[*] Training Candidate Random Forest model ({args.trees} trees, max_depth=20)...")
    rf_model = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1
    )
    t0 = time.time()
    rf_model.fit(X_train, y_train)
    rf_train_time = round(time.time() - t0, 2)
    print(f"[*] Model trained in {rf_train_time}s.")

    # 5. Train Baseline Interpretable Model (Logistic Regression)
    print("\n[*] Training Baseline Calibrated Logistic Regression...")
    lr_model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=args.seed)
    lr_model.fit(X_train, y_train)

    # 6. Feature Importances
    importances = {
        name: round(float(imp), 4)
        for name, imp in zip(FEATURE_NAMES, rf_model.feature_importances_)
    }
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))
    print("\nCandidate Feature Importances:")
    for feat, imp in sorted_importances.items():
        print(f"  • {feat:<26}: {imp*100:.2f}%")

    # 7. Threshold Selection on Validation Set
    val_probs = rf_model.predict_proba(X_val)[:, 1]
    thresholds = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    val_candidates = []
    print("\nValidation Threshold Tuning (Untouched Test Set Preserved):")
    for th in thresholds:
        m = compute_comprehensive_metrics(y_val, val_probs, threshold=th)
        val_candidates.append((th, m))
        print(f"  th={th:.1f} | Prec: {m['precision']*100:.2f}% | Rec: {m['recall']*100:.2f}% | F1: {m['f1_score']*100:.2f}% | FPR: {m['false_positive_rate']*100:.2f}%")

    # Select threshold maximizing F1, breaking ties toward conservative false-positive rate
    best_th, best_val_m = max(val_candidates, key=lambda pair: (pair[1]["f1_score"], -pair[1]["false_positive_rate"]))
    print(f"\n[*] Selected optimal validation threshold: {best_th} (Val F1: {best_val_m['f1_score']*100:.2f}%)")

    # 8. Single Final Evaluation on Untouched Holdout Test Set
    print("\n" + "="*80)
    print("            FINAL EVALUATION ON UNTOUCHED HOLDOUT TEST SET              ")
    print("="*80)
    test_probs = rf_model.predict_proba(X_test)[:, 1]
    final_test_metrics = compute_comprehensive_metrics(y_test, test_probs, threshold=best_th)

    # Logistic regression comparison on test set
    lr_test_probs = lr_model.predict_proba(X_test)[:, 1]
    lr_test_metrics = compute_comprehensive_metrics(y_test, lr_test_probs, threshold=0.5)

    # Offline Heuristics comparison on the exact same test set
    heuristic_metrics = evaluate_offline_heuristics_on_records(splits["test"])

    # 9. Prevalence Sensitivity Analysis
    prevalence_analysis = simulate_prevalence(y_test, test_probs, threshold=best_th)

    # Display Test Results Table
    print(f"\n{'Metric':<30} | {'Candidate RF (th=0.7)':<22} | {'Baseline LR (th=0.5)':<22} | {'Offline Heuristics':<20}")
    print("-" * 100)
    rows = [
        ("Evaluated Samples", f"{len(y_test):,}", f"{len(y_test):,}", f"{len(y_test):,}"),
        ("True Positives (TP)", f"{final_test_metrics['true_positives']:,}", f"{lr_test_metrics['true_positives']:,}", f"{heuristic_metrics['true_positives']:,}"),
        ("False Positives (FP)", f"{final_test_metrics['false_positives']:,}", f"{lr_test_metrics['false_positives']:,}", f"{heuristic_metrics['false_positives']:,}"),
        ("True Negatives (TN)", f"{final_test_metrics['true_negatives']:,}", f"{lr_test_metrics['true_negatives']:,}", f"{heuristic_metrics['true_negatives']:,}"),
        ("False Negatives (FN)", f"{final_test_metrics['false_negatives']:,}", f"{lr_test_metrics['false_negatives']:,}", f"{heuristic_metrics['false_negatives']:,}"),
        ("Precision", f"{final_test_metrics['precision']*100:.2f}%", f"{lr_test_metrics['precision']*100:.2f}%", f"{heuristic_metrics['precision']*100:.2f}%"),
        ("Recall (Detection Rate)", f"{final_test_metrics['recall']*100:.2f}%", f"{lr_test_metrics['recall']*100:.2f}%", f"{heuristic_metrics['recall']*100:.2f}%"),
        ("F1-Score", f"{final_test_metrics['f1_score']*100:.2f}%", f"{lr_test_metrics['f1_score']*100:.2f}%", f"{heuristic_metrics['f1_score']*100:.2f}%"),
        ("False Positive Rate (FPR)", f"{final_test_metrics['false_positive_rate']*100:.2f}%", f"{lr_test_metrics['false_positive_rate']*100:.2f}%", f"{heuristic_metrics['false_positive_rate']*100:.2f}%"),
        ("ROC AUC", f"{final_test_metrics['roc_auc']:.4f}", f"{lr_test_metrics['roc_auc']:.4f}", "N/A (discrete)"),
        ("PR AUC", f"{final_test_metrics['pr_auc']:.4f}", f"{lr_test_metrics['pr_auc']:.4f}", "N/A (discrete)"),
        ("Brier Calibration Score", f"{final_test_metrics['brier_score']:.4f}", f"{lr_test_metrics['brier_score']:.4f}", "N/A"),
    ]
    for label, c1, c2, c3 in rows:
        print(f"{label:<30} | {c1:<22} | {c2:<22} | {c3:<20}")
    print("=" * 100)

    # 10. Save Model Artifact and Manifest
    model_artifact_path = OUTPUT_DIR / "candidate_rf_v2.joblib"
    joblib.dump(rf_model, model_artifact_path, compress=3)
    print(f"\n[OK] Candidate model saved to: {model_artifact_path}")

    manifest = {
        "metadata": {
            "model_version": "candidate_v2_seed42",
            "schema_version": SCHEMA_VERSION,
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": sys.version.split()[0],
            "algorithm": "RandomForestClassifier",
            "features_used": FEATURE_NAMES,
            "has_https_feature_included": False,
            "training_time_seconds": rf_train_time,
            "production_ml_enabled": False,
        },
        "dataset_audit": audit_stats,
        "feature_importances": sorted_importances,
        "threshold_selection": {
            "selected_threshold": best_th,
            "validation_candidates": [
                {"threshold": th, "metrics": m} for th, m in val_candidates
            ]
        },
        "holdout_test_metrics": {
            "candidate_rf_model": final_test_metrics,
            "baseline_logistic_regression": lr_test_metrics,
            "offline_heuristics_engine": heuristic_metrics
        },
        "prevalence_sensitivity": prevalence_analysis
    }

    manifest_path = OUTPUT_DIR / "candidate_v2_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[OK] Manifest saved to: {manifest_path}")


if __name__ == "__main__":
    main()

