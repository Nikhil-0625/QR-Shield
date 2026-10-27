"""Local artifact acceptance/feature audit. No FastAPI/DB import or URL requests."""
import ast
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


def extract_function(tree, name, namespace):
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<isolated feature function>", "exec"), namespace)
    return namespace[name]


def main(urls=None):
    import joblib
    sys.path.insert(0, str(ROOT / "backend"))
    from ml_probability import phishing_probability

    production = ast.parse((ROOT / "backend/main.py").read_text(encoding="utf-8-sig"))
    namespace = {"urlparse": urlparse, "ipaddress": ipaddress}
    extract_function(production, "hostname_is_ip", namespace)
    inference = extract_function(production, "extract_ml_features", namespace)
    notebook = json.loads((ROOT / "backend/ml/train_model.ipynb").read_text(encoding="utf-8"))
    cell = next("".join(c.get("source", [])) for c in notebook["cells"]
                if "def extract_features(url):" in "".join(c.get("source", [])))
    training = extract_function(ast.parse(cell), "extract_features", {"re": re})
    def calculations(tree, name):
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
        return {ast.literal_eval(n.targets[0].slice): ast.dump(n.value, include_attributes=False)
                for n in node.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Subscript)}
    train_calculations = calculations(ast.parse(cell), "extract_features")
    infer_calculations = calculations(production, "extract_ml_features")
    differences = [key for key in train_calculations if train_calculations[key] != infer_calculations.get(key)]
    order = next(ast.literal_eval(n.value) for n in ast.walk(production)
                 if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "feature_order" for t in n.targets))
    selected = next(ast.literal_eval(k.value) for n in ast.walk(production)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "select_phishing_probability"
                    for k in n.keywords if k.arg == "phishing_label")
    path = ROOT / "backend/phishing_model_v2.pkl"
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    model = joblib.load(path)
    assert list(model.classes_) in ([-1, 1], [1, -1]), "Unexpected production class labels"
    assert list(model.feature_names_in_) == order
    assert list(training("https://www.google.com")) == order
    cases = []
    for url in urls or ("https://www.google.com", "http://paypal-secure-login.verify-account.tk", "http://paypal-login.verify-account.tk"):
        features = inference(url)
        raw = model.predict_proba([[features[name] for name in order]])
        value = phishing_probability(model.classes_, raw, phishing_label=selected)[0]
        expected = float(raw[0][list(model.classes_).index(-1)])
        assert value == expected, "Production does not select P(class=-1)"
        # Verify the same values remain aligned when the probability columns reorder.
        assert phishing_probability(list(model.classes_)[::-1], raw[:, ::-1], phishing_label=selected)[0] == expected
        cases.append({"url_string_only": url, "selected_signal_percent": 100 * value,
                      "features_equal_to_notebook": features == training(url), "raw_probabilities": raw.tolist()})
    mismatches = []
    for url in ("https://example.test/192.0.2.1", "http://[2001:db8::1]", "http://999.999.999.999"):
        train, infer = training(url), inference(url)
        mismatches.append({"url_string_only": url, "different_features": {
            key: {"training": train[key], "inference": infer[key]} for key in order if train[key] != infer[key]}})
    assert selected == -1, "Production must select the verified phishing training label"
    # Label correctness is independent of whether individual predictions look plausible.
    print(json.dumps({"selected_production_class": selected, "classes": model.classes_.tolist(),
                      "artifact_sha256": digest, "feature_order": order, "acceptance": cases,
                      "calculation_differences": differences,
                      "feature_counterexamples": mismatches, "network_requests": 0}, indent=2))


if __name__ == "__main__":
    main()
