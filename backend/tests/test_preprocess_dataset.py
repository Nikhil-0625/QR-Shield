"""Synthetic preprocessing checks; network blocked and no datasets opened."""
import importlib.util
import csv
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "ml/preprocess_dataset.py"
spec = importlib.util.spec_from_file_location("preprocessing_test_module", SOURCE)
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


def fixtures():
    return [{"url": "https://merchant%d.com/%s" % (i, label), "type": label}
            for i in range(20) for label in ("benign", "phishing")]


class PreprocessingTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyaddr", "socket.gethostbyname", "socket.gethostbyname_ex"):
            guard = patch(name, side_effect=AssertionError("Network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.parser = pipeline.OfflineDomainParser()

    def test_label_mapping_and_category_exclusions(self):
        rows = fixtures() + [{"url": "https://excluded.com/", "type": category} for category in ("malware", "defacement", "unknown")]
        splits, quarantine, manifest = pipeline.prepare(rows, self.parser)
        self.assertEqual(manifest["label_mapping"], {"benign": 0, "phishing": 1})
        self.assertEqual(manifest["exclusions_overlapping"]["excluded_category"], 3)
        self.assertEqual(sum(len(r) for r in splits.values()), 40)
        self.assertEqual(quarantine, [])
        for records in splits.values():
            for row in records:
                self.assertTrue(row["label"] == (1 if row["url"].endswith("phishing") else 0))

    def test_literal_dedup_preserves_semantic_differences(self):
        rows = fixtures()
        rows += [dict(rows[0]), {"url": "https://merchant0.com/Benign", "type": "benign"}, {"url": "https://merchant0.com/benign?x=1", "type": "benign"}]
        splits, _, manifest = pipeline.prepare(rows, self.parser)
        self.assertEqual(manifest["exclusions_overlapping"]["duplicate_excess_rows"], 1)
        self.assertEqual(sum(len(r) for r in splits.values()), 42)

    def test_conflicting_exact_labels_all_quarantined(self):
        conflict = [{"url": "https://conflict.com/", "type": label} for label in ("benign", "phishing")]
        splits, quarantine, manifest = pipeline.prepare(fixtures()+conflict, self.parser)
        self.assertEqual(len(quarantine), 2)
        self.assertTrue(all("conflicting_exact_url_labels" in r["reasons"] for r in quarantine))
        self.assertEqual(manifest["accepted_before_balancing"], 40)

    def test_sensitive_indicators_quarantined(self):
        urls = ["https://example.com/?token=synthetic", "https://user:synthetic@example.com/", "https://example.com/?contact=person%40example.com", "https://example.com/?api_key=synthetic"]
        rows = [{"url": value, "type": "benign"} for value in urls]
        _, quarantine, manifest = pipeline.prepare(fixtures()+rows, self.parser)
        self.assertEqual(len(quarantine), len(rows))
        self.assertEqual(manifest["exclusions_overlapping"]["sensitive_indicator"], len(rows))

    def test_malformed_missing_and_unknown_suffix_quarantined(self):
        urls = ["", "http:///path", "https://bad host.com", "https://example.com/%GG", "https://example.com:bad", "http://999.999.999.999/", "javascript:synthetic", "https://merchant.invalid/"]
        _, quarantine, _ = pipeline.prepare(fixtures()+[{"url": u, "type": "phishing"} for u in urls], self.parser)
        self.assertEqual(len(quarantine), len(urls))

    def test_psl_rules_and_ip_separation(self):
        for host, expected in [("x.merchant.co.uk", "domain:merchant.co.uk"), ("x.y.ck", "domain:x.y.ck"), ("x.www.ck", "domain:www.ck"), ("x.merchant.blogspot.com", "domain:merchant.blogspot.com"), ("192.0.2.1", "ip:192.0.2.1")]:
            self.assertTrue(self.parser.group(host) == expected)

    def test_deterministic_domain_disjoint_splits(self):
        rows = fixtures()+[{"url": "https://sub.merchant0.com/other", "type": "benign"}]
        first = pipeline.prepare(rows, self.parser, seed=42)
        second = pipeline.prepare(rows, self.parser, seed=42)
        self.assertTrue(first == second)
        splits, _, manifest = first
        self.assertTrue(all(value == 0 for value in manifest["group_overlap_counts"].values()))
        owners = {}
        for name, records in splits.items():
            for row in records:
                self.assertTrue(row["group"] not in owners or owners[row["group"]] == name)
                owners[row["group"]] = name
        self.assertTrue(all(splits.values()))

    def test_balancing_only_changes_train(self):
        rows = fixtures()+[{"url": "https://merchant%d.com/extra" % i, "type": "benign"} for i in range(20)]
        original, _, _ = pipeline.prepare(rows, self.parser)
        balanced, _, manifest = pipeline.prepare(rows, self.parser, balance_train=True)
        self.assertTrue(original["test"] == balanced["test"])
        self.assertTrue(original["validation"] == balanced["validation"])
        counts = manifest["splits"]["train"]["label_counts"]
        self.assertEqual(counts["0"], counts["1"])

    def test_fail_closed_for_missing_psl_and_insufficient_groups(self):
        with patch.object(pipeline.OfflineDomainParser, "__init__", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                pipeline.OfflineDomainParser()
        with self.assertRaises(ValueError):
            pipeline.prepare(fixtures()[:2], self.parser)

    def test_url_length_checked_before_sensitive_scan(self):
        with patch.object(pipeline, "sensitive", side_effect=AssertionError("Expensive scanner called")):
            reasons, group = pipeline.validate_url("x" * (pipeline.MAX_URL_LENGTH+1), self.parser)
        self.assertIn("url_length_limit", reasons)
        self.assertIsNone(group)

    def test_bounded_sensitive_detection_preserves_indicators(self):
        for value in ("a" * 8000, "a." * 4000):
            self.assertFalse(pipeline.sensitive(value))
        for value in ("https://example.com/?password=x", "person%40example.com", "AKIA"+"A"*16, "eyJ"+"a"*10+"."+"b"*10+"."+"c"*10, "-----BEGIN PRIVATE KEY-----"):
            self.assertTrue(pipeline.sensitive(value))
        with self.assertRaises(ValueError):
            pipeline.sensitive("a" * (pipeline.MAX_URL_LENGTH+1))

    def test_input_size_and_row_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.csv"
            source.write_bytes(b"synthetic")
            with patch.object(pipeline, "MAX_INPUT_BYTES", 3), self.assertRaises(ValueError):
                pipeline.read_input(source)
            self.assertTrue(source.read_bytes() == b"synthetic")
        with patch.object(pipeline, "MAX_ROWS", 2), self.assertRaises(ValueError):
            pipeline.prepare(fixtures(), self.parser)

    def test_windows_aliases_and_traversal_rejected(self):
        for path in ("../escape", "safe/../escape", "C:relative", "\\\\server\\share", "\\\\?\\C:\\device", "safe/file:stream", "safe/NUL.csv", "safe/COM1", "safe/trailing.", "safe/trailing "):
            with self.assertRaises(ValueError):
                pipeline.checked_path(path)

    def test_reparse_point_rejected_without_following(self):
        class FakeStat:
            st_mode = 0
            st_file_attributes = 0x400
        with patch.object(Path, "lstat", return_value=FakeStat()), self.assertRaises(ValueError):
            pipeline.checked_path("synthetic")

    def test_symlink_rejected_where_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("synthetic")
            link = Path(directory) / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("OS does not permit creating synthetic symlinks")
            with self.assertRaises(ValueError):
                pipeline.read_input(link)

    def test_every_split_requires_both_classes(self):
        with self.assertRaisesRegex(ValueError, "both classes"):
            pipeline.prepare([row for row in fixtures() if row["type"] == "benign"], self.parser)

    def test_transactional_export_formula_safety_and_no_overwrite(self):
        splits, quarantine, manifest = pipeline.prepare(fixtures()+[{"url": "=synthetic()", "type": "benign"}], self.parser)
        with tempfile.TemporaryDirectory() as directory, patch.object(pipeline, "OUTPUT_ROOT", Path(directory)/"outputs"):
            pipeline.publish(splits, quarantine, manifest, "synthetic")
            output = pipeline.OUTPUT_ROOT / "synthetic"
            self.assertEqual(len(list(output.iterdir())), 5)
            with (output/"quarantine.csv").open(newline="", encoding="utf-8") as stream:
                exported = list(csv.DictReader(stream))
            self.assertTrue(exported[0]["url"] == "'=synthetic()")
            for name, rows in splits.items():
                with (output/(name+".csv")).open(newline="", encoding="utf-8") as stream:
                    exported = list(csv.DictReader(stream))
                self.assertTrue([r["url"] for r in exported] == [r["url"] for r in rows])
            report = json.loads((output/"audit_manifest.json").read_text())
            self.assertEqual(len(report["output_checksums"]), 4)
            with self.assertRaises(ValueError):
                pipeline.publish(splits, quarantine, manifest, "synthetic")
            self.assertFalse(any(p.name.startswith("_pending_") for p in pipeline.OUTPUT_ROOT.iterdir()))

    def test_failure_cleanup_before_publication(self):
        splits, quarantine, manifest = pipeline.prepare(fixtures(), self.parser)
        for operation in ("validate_exports", "make_private"):
            with tempfile.TemporaryDirectory() as directory, patch.object(pipeline, "OUTPUT_ROOT", Path(directory)/"outputs"), patch.object(pipeline, operation, side_effect=ValueError("Synthetic failure")):
                with self.assertRaises(ValueError):
                    pipeline.publish(splits, quarantine, manifest, "synthetic")
                self.assertEqual(list(pipeline.OUTPUT_ROOT.iterdir()), [])

    def test_unsafe_training_cell_rejected_not_rewritten(self):
        splits, quarantine, manifest = pipeline.prepare(fixtures(), self.parser)
        splits["train"][0]["url"] = "@synthetic"
        with tempfile.TemporaryDirectory() as directory, patch.object(pipeline, "OUTPUT_ROOT", Path(directory)/"outputs"):
            with self.assertRaises(ValueError):
                pipeline.publish(splits, quarantine, manifest, "synthetic")
            self.assertEqual(list(pipeline.OUTPUT_ROOT.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
