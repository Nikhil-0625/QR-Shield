"""Offline candidate training. Real-data execution requires separate approval.

Features mirror current production, including its quirks, rather than legacy
notebook preprocessing. Extraction is stateless and has nothing to fit.
One fixed RF configuration; threshold selected on validation F1 only.
Test is evaluated once after selection, never used for fitting or tuning.
"""
import argparse
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
try:
    from candidate_features import FEATURE_NAMES, SCHEMA_VERSION, feature_vector
    from offline_psl import OfflineDomainParser
finally:
    sys.path.pop(0)
from preprocess_dataset import checked_path, read_input, make_private
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (precision_score, recall_score, f1_score, confusion_matrix,
                             roc_auc_score, average_precision_score, auc, precision_recall_curve)

OUTPUT_ROOT = BACKEND / "ml/candidate_artifacts"
THRESHOLDS = (0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
CURRENT_STAGE = "startup"


def stage(name):
    global CURRENT_STAGE
    CURRENT_STAGE = name


def safe_failure(error):
    """Only internal stage and fixed error classification; never exception text."""
    kind = "validation_error" if isinstance(error, ValueError) else "resource_error" if isinstance(error, MemoryError) else "operation_error"
    return "Candidate training failed at stage=" + CURRENT_STAGE + "; code=" + kind


def prepared_group(url, parser):
    """Mirror preprocessing's hostname interpretation, without altering features."""
    from urllib.parse import urlsplit
    explicit = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    has_scheme = bool(explicit and not re.match(r"^[^/:]+:\d+(?:/|$)", url))
    parsed = urlsplit(url if has_scheme or url.startswith("//") else "//" + url)
    if not parsed.hostname:
        raise ValueError("Prepared record lacks hostname")
    return parser.group(parsed.hostname)


def evaluate(labels, probabilities, threshold):
    predictions = (np.asarray(probabilities) >= threshold).astype(int)
    precision, recall, _ = precision_recall_curve(labels, probabilities, pos_label=1)
    return {
        "precision": float(precision_score(labels, predictions, pos_label=1, zero_division=0)),
        "recall": float(recall_score(labels, predictions, pos_label=1, zero_division=0)),
        "f1": float(f1_score(labels, predictions, pos_label=1, zero_division=0)),
        "confusion_matrix_actual_rows_predicted_columns_0_1": confusion_matrix(labels, predictions, labels=[0,1]).tolist(),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc_trapezoidal": float(auc(recall, precision)),
        "average_precision": float(average_precision_score(labels, probabilities, pos_label=1)),
    }


def fit_candidate(splits, seed=42, trees=100):
    arrays = {}
    for name in ("train", "validation", "test"):
        stage("feature_extraction_" + name)
        records = splits[name]
        labels = np.asarray([row["label"] for row in records], dtype=int)
        if set(labels.tolist()) != {0,1}:
            raise ValueError("Every split must contain exactly both binary labels")
        arrays[name] = (np.asarray([feature_vector(row["url"]) for row in records]), labels)
    parameters = dict(n_estimators=trees, random_state=seed, n_jobs=1, class_weight="balanced",
                      max_depth=24, min_samples_leaf=2)
    model = RandomForestClassifier(**parameters)
    stage("model_fitting")
    model.fit(*arrays["train"])
    stage("fitted_contract_validation")
    if model.classes_.tolist() != [0,1] or model.n_features_in_ != 12:
        raise ValueError("Unexpected fitted model contract")
    column = model.classes_.tolist().index(1)
    stage("validation_prediction")
    validation_probabilities = model.predict_proba(arrays["validation"][0])[:,column]
    stage("threshold_selection")
    candidates = [(threshold, evaluate(arrays["validation"][1], validation_probabilities, threshold)) for threshold in THRESHOLDS]
    # Tie-break toward 0.5, then the lower threshold, determined in advance.
    threshold, validation_metrics = max(candidates, key=lambda pair: (pair[1]["f1"], -abs(pair[0]-0.5), -pair[0]))
    stage("test_prediction")
    test_probabilities = model.predict_proba(arrays["test"][0])[:,column]
    train_labels = arrays["train"][1]
    majority = int(np.sum(train_labels == 1) > np.sum(train_labels == 0))
    stage("final_evaluation_and_manifest")
    manifest = {
        "feature_schema": SCHEMA_VERSION, "feature_names": list(FEATURE_NAMES), "feature_type": "integer",
        "extractor_policy": "raw input; production-compatible; no notebook regex or scheme normalization",
        "label_mapping": {"benign":0,"phishing":1}, "classes": model.classes_.tolist(),
        "hyperparameters": model.get_params(), "seed": seed, "threshold": threshold,
        "selection_policy": "fixed RF configuration; validation F1 threshold selection; ties nearest 0.5 then lower",
        "threshold_candidates": list(THRESHOLDS), "validation_metrics": validation_metrics,
        "test_metrics": evaluate(arrays["test"][1], test_probabilities, threshold),
        "class_counts": {name: {str(label): int(np.sum(values[1]==label)) for label in (0,1)} for name,values in arrays.items()},
        "majority_baseline_class_from_train": majority,
        "majority_baseline_metrics": {name: evaluate(values[1], np.full(len(values[1]),majority),0.5) for name,values in arrays.items() if name != "train"},
        "provenance": "Kaggle CC0 user-confirmed; exact dataset version and upstream rights unverified",
        "python_version": platform.python_version(),
        "dependencies": {name: importlib.metadata.version(name) for name in ("scikit-learn","numpy","scipy","joblib","publicsuffix2")},
        "extractor_sha256": hashlib.sha256((BACKEND/"candidate_features.py").read_bytes()).hexdigest(),
        "trainer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    return model, manifest


def load_splits(directory):
    import io
    stage("dataset_manifest_and_path_validation")
    directory = checked_path(directory)
    audit = json.loads(read_input(directory/"audit_manifest.json"))
    parser = OfflineDomainParser()
    splits, hashes, groups, seen = {}, {}, {}, set()
    for name in ("train","validation","test"):
        stage("checksum_verification_" + name)
        filename = name+".csv"
        raw = read_input(directory/filename)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != audit["output_checksums"][filename]:
            raise ValueError("Prepared input checksum mismatch")
        stage("dataset_schema_" + name)
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""))
        if reader.fieldnames != ["url","label"]:
            raise ValueError("Prepared schema mismatch")
        rows = []
        groups[name] = set()
        from urllib.parse import urlsplit
        for row in reader:
            stage("record_validation_" + name)
            if None in row or row["label"] not in ("0","1") or row["url"] in seen:
                raise ValueError("Invalid or duplicate prepared record")
            url = row["url"]
            stage("feature_validation_" + name)
            feature_vector(url)
            stage("domain_group_validation_" + name)
            groups[name].add(prepared_group(url, parser))
            seen.add(url)
            rows.append({"url":url,"label":int(row["label"])})
        splits[name], hashes[filename] = rows, digest
    stage("split_overlap_validation")
    if any(groups[a] & groups[b] for a,b in (("train","validation"),("train","test"),("validation","test"))):
        raise ValueError("Prepared groups overlap")
    hashes["audit_manifest.json"] = hashlib.sha256(read_input(directory/"audit_manifest.json")).hexdigest()
    return splits, hashes


def main():
    stage("argument_validation")
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--data", type=Path, required=True)
    args.add_argument("--run-name", required=True)
    args.add_argument("--seed", type=int, default=42)
    options = args.parse_args()
    import re
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", options.run_name):
        raise ValueError("Invalid run name")
    stage("destination_validation")
    root = checked_path(OUTPUT_ROOT)
    destination = checked_path(root/options.run_name)
    if destination.exists():
        raise ValueError("Candidate destination already exists")
    splits, hashes = load_splits(options.data)
    model, manifest = fit_candidate(splits, options.seed)
    manifest["input_checksums"] = hashes
    stage("artifact_staging")
    root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="_pending_",dir=root))
    try:
        make_private(temporary)
        stage("artifact_serialization")
        artifact = temporary/"phishing_url_candidate_v1.joblib"
        joblib.dump(model, artifact, compress=3)
        manifest["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest["artifact_filename"] = artifact.name
        stage("manifest_publication")
        (temporary/"model_manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True),encoding="utf-8")
        (temporary/"training_versions.txt").write_text("# Python "+manifest["python_version"]+"\n"+"\n".join(name+"=="+version for name,version in manifest["dependencies"].items())+"\n",encoding="utf-8")
        checked_path(root)
        checked_path(destination)
        if destination.exists():
            raise ValueError("Candidate destination appeared during training")
        stage("atomic_publication")
        temporary.rename(destination)
    finally:
        if temporary.exists():
            checked_path(temporary)
            shutil.rmtree(temporary)
    print("Candidate training completed; private artifacts published. Production unchanged.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(safe_failure(error),file=sys.stderr)
        raise SystemExit(1)
