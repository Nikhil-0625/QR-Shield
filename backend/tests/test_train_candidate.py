"""Tiny synthetic training only; no application imports or existing models."""
import ast
import csv
import hashlib
import json
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BACKEND/"ml"))
try:
    spec = importlib.util.spec_from_file_location("candidate_training_test",BACKEND/"ml/train_candidate.py")
    trainer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trainer)
finally:
    sys.path.pop(0)


def synthetic_splits():
    return {name: [{"url": "https://merchant%d.com/page" % (offset+i), "label":0} for i in range(12)]
            + [{"url": "http://192.0.2.%d/login?verify=123456" % (offset+i+1), "label":1} for i in range(12)]
            for name,offset in (("train",0),("validation",30),("test",60))}


class CandidateTrainingTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket","socket.create_connection","socket.getaddrinfo","socket.gethostbyname","socket.gethostbyaddr"):
            guard = patch(name,side_effect=AssertionError("Network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_production_feature_parity_without_importing_application(self):
        # Extract only two pure functions by AST; never execute module imports/startup.
        source = ast.parse((BACKEND/"main.py").read_text(encoding="utf-8"))
        functions = [node for node in source.body if isinstance(node,ast.FunctionDef) and node.name in ("hostname_is_ip","extract_ml_features")]
        import ipaddress
        from urllib.parse import urlparse
        namespace = {"ipaddress":ipaddress,"urlparse":urlparse}
        exec(compile(ast.Module(body=functions,type_ignores=[]),"pure_feature_reference","exec"),namespace)
        urls = ["http://192.0.2.1","http://[2001:db8::1]","https://example.com/path/192.0.2.1","192.0.2.1/path","HTTPS://example.com","https://a-b.com/x_y?u=@&n=2"]
        for url in urls:
            expected = namespace["extract_ml_features"](url)
            self.assertEqual(tuple(expected),trainer.FEATURE_NAMES)
            self.assertTrue(trainer.feature_vector(url) == list(expected.values()))

    def test_deterministic_fit_and_training_only(self):
        splits = synthetic_splits()
        first, report = trainer.fit_candidate(splits,trees=5)
        second, repeated = trainer.fit_candidate(splits,trees=5)
        self.assertEqual(report["test_metrics"],repeated["test_metrics"])
        self.assertEqual(report["threshold"],repeated["threshold"])
        self.assertEqual(first.classes_.tolist(),[0,1])
        self.assertEqual(first.n_features_in_,12)
        self.assertEqual(report["label_mapping"],{"benign":0,"phishing":1})

    def test_test_labels_cannot_influence_model_or_threshold(self):
        original = synthetic_splits()
        altered = synthetic_splits()
        for row in altered["test"]:
            row["label"] = 1-row["label"]
        first,a = trainer.fit_candidate(original,trees=5)
        second,b = trainer.fit_candidate(altered,trees=5)
        self.assertEqual(a["threshold"],b["threshold"])
        self.assertEqual(a["validation_metrics"],b["validation_metrics"])
        vectors = [trainer.feature_vector(r["url"]) for r in original["test"]]
        self.assertTrue((first.predict_proba(vectors)==second.predict_proba(vectors)).all())

    def test_metrics_positive_class_and_baseline(self):
        metrics = trainer.evaluate([0,0,1,1],[0.1,0.7,0.8,0.9],0.5)
        self.assertAlmostEqual(metrics["precision"],2/3)
        self.assertEqual(metrics["recall"],1.0)
        self.assertEqual(metrics["confusion_matrix_actual_rows_predicted_columns_0_1"],[[1,1],[0,2]])
        _, report = trainer.fit_candidate(synthetic_splits(),trees=5)
        self.assertEqual(report["majority_baseline_class_from_train"],0)
        self.assertEqual(report["majority_baseline_metrics"]["test"]["recall"],0)

    def test_single_class_split_rejected(self):
        splits = synthetic_splits()
        splits["validation"] = [r for r in splits["validation"] if r["label"]==0]
        with self.assertRaises(ValueError):
            trainer.fit_candidate(splits,trees=5)

    def test_embedded_scheme_in_schemeless_path_matches_preprocessing(self):
        parser = trainer.OfflineDomainParser()
        from preprocess_dataset import validate_url
        for url in ("merchant.com/redirect/https://other.com", "merchant.com/?next=http://other.com", "merchant.com:8080/path", "https://merchant.com/path", "//merchant.com/path"):
            reasons, group = validate_url(url,parser)
            self.assertFalse(reasons)
            self.assertTrue(trainer.prepared_group(url,parser) == group)
        # Original loader's substring check demonstrably loses this hostname.
        from urllib.parse import urlsplit
        self.assertIsNone(urlsplit("merchant.com/path/https://other.com").hostname)

    def test_synthetic_loader_regression_without_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = {}
            for name,domain in (("train","first.com"),("validation","second.com"),("test","third.com")):
                path = root/(name+".csv")
                with path.open("w",newline="",encoding="utf-8") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(["url","label"])
                    writer.writerow([domain+"/redirect/https://elsewhere.com",0])
                    writer.writerow([domain+"/other",1])
                hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root/"audit_manifest.json").write_text(json.dumps({"output_checksums":hashes}))
            with patch.object(trainer.RandomForestClassifier,"fit",side_effect=AssertionError("Fitting forbidden")):
                splits,_ = trainer.load_splits(root)
            self.assertEqual({name:len(rows) for name,rows in splits.items()},{"train":2,"validation":2,"test":2})

    def test_sanitized_stage_reporting_never_echoes_exception(self):
        trainer.stage("domain_group_validation_train")
        message = trainer.safe_failure(ValueError("PRIVATE_SYNTHETIC_VALUE"))
        self.assertIn("domain_group_validation_train",message)
        self.assertNotIn("PRIVATE_SYNTHETIC_VALUE",message)
        self.assertIn("validation_error",message)


if __name__ == "__main__":
    unittest.main()
