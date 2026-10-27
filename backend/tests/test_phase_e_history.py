"""Phase E: isolated UTC analytics, bounded pages, owner-scoped snapshots."""
from datetime import datetime, timezone, timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_history_authorization as harness
import test_api_security as api_harness


class HistoryViewsTests(unittest.TestCase):
    setUpClass = classmethod(harness.HistoryAuthorizationTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.HistoryAuthorizationTests.tearDownClass.__func__)
    token = harness.HistoryAuthorizationTests.token
    api = api_harness.ApiSecurityTests.api

    def setUp(self):
        harness.HistoryAuthorizationTests.setUp(self)
        with self.database.SessionLocal() as db:
            db.query(self.database.ScanRecord).filter_by(user_id=1).delete()
            db.commit()

    def add(self, entries):
        with self.database.SessionLocal() as db:
            db.add_all([self.database.ScanRecord(user_id=1, **entry) for entry in entries])
            db.commit()

    def summary(self, now):
        with self.database.SessionLocal() as db:
            return self.main.history_views.summary(db, self.database.ScanRecord, 1, now)

    def get(self, path, query="", owner="a@example.test"):
        status, body, _ = self.api(path, token=self.token(owner), query=query)
        return status, json.loads(body)

    def test_totals_content_findings_and_average(self):
        self.add([dict(decoded_content="https://example.test", risk_label="safe", risk_score=30, risk_breakdown='[{"name":"A"},{"name":"A"}]'),
                  dict(decoded_content=" http://example.test ", risk_label="unsafe", risk_score=90),
                  dict(decoded_content="https://example.test", risk_label="suspicious", risk_score=50),
                  dict(decoded_content="upi://pay?pa=synthetic@upi"), dict(decoded_content="Text", risk_label="safe"),
                  dict(decoded_content="", risk_label="safe"), dict(decoded_content="https://example.test", risk_label="unknown")])
        status, result = self.get("/history/summary")
        self.assertEqual(status, 200)
        self.assertEqual(result["total"], 7)
        self.assertEqual(result["counts"], dict(safe=1, suspicious=1, unsafe=1, non_url=2, unclassified=2))
        self.assertAlmostEqual(result["average_url_risk"], 170/3)
        self.assertEqual(result["stored_findings"], 2)
        self.assertEqual(result["indicators"], {"A":2})
        self.assertEqual(result["content_counts"], {"URL":4,"UPI":1,"Text / Other":1,"Unclassifiable":1})

    def test_utc_midnight_seven_days_month_and_year_boundaries(self):
        for today in [datetime(2026,1,2,0,15,tzinfo=timezone.utc), datetime(2026,3,1,23,59,tzinfo=timezone.utc)]:
            with self.subTest(today=today):
                with self.database.SessionLocal() as db:
                    db.query(self.database.ScanRecord).filter_by(user_id=1).delete(); db.commit()
                start = today.replace(hour=0,minute=0) - timedelta(days=6)
                stamps = [start-timedelta(microseconds=1), start, start+timedelta(seconds=1),
                          today.replace(hour=0,minute=0)-timedelta(microseconds=1),
                          today.replace(hour=0,minute=0), today.replace(hour=0,minute=0)+timedelta(days=1)]
                self.add([dict(decoded_content="Text",scanned_at=stamp.replace(tzinfo=None)) for stamp in stamps])
                result = self.summary(today)
                self.assertEqual(len(result["activity"]), 7)
                self.assertEqual(result["activity"][0]["key"], start.date().isoformat())
                self.assertEqual(result["activity"][0]["count"], 2)
                self.assertEqual(result["activity"][-1]["key"], today.date().isoformat())
                self.assertEqual(result["activity"][-1]["count"], 1)
                self.assertEqual(sum(d["count"] for d in result["activity"]), 4)

    def test_empty_and_unknown_time_are_not_fabricated(self):
        result = self.summary(datetime(2026,1,1,tzinfo=timezone.utc))
        self.assertEqual(result["total"], 0)
        self.assertIsNone(result["average_url_risk"])
        self.assertTrue(all(day["count"] == 0 for day in result["activity"]))
        self.add([dict(decoded_content="Text")])
        with self.database.SessionLocal() as db:
            db.query(self.database.ScanRecord).filter_by(user_id=1).update({"scanned_at":None}); db.commit()
        result = self.summary(datetime(2026,1,1,tzinfo=timezone.utc))
        self.assertEqual(result["unknown_timestamps"], 1)
        self.assertEqual(sum(day["count"] for day in result["activity"]), 0)
        self.assertIsNone(self.get("/history/page")[1]["items"][0]["scanned_at"])

    def test_timestamp_offset_conversion(self):
        view = self.main.history_views
        self.assertEqual(view.utc_timestamp(datetime(2026,1,1,0,15,tzinfo=timezone(timedelta(hours=5,minutes=30)))), "2025-12-31T18:45:00Z")
        self.assertEqual(view.utc_timestamp(datetime(2026,1,1,0,15)), "2026-01-01T00:15:00Z")

    def test_page_order_ties_snapshot_and_boundaries(self):
        self.add([dict(id=40+i, decoded_content="Text", scanned_at=datetime(2026,1,1,0,i//2)) for i in range(6)])
        status, first = self.get("/history/page", "limit=2")
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in first["items"]], [45,44])
        self.add([dict(id=46, decoded_content="New", scanned_at=datetime(2026,1,2))])
        _, second = self.get("/history/page", f"limit=2&cursor={first['next_cursor']}&snapshot={first['snapshot_id']}")
        _, last = self.get("/history/page", f"limit=2&cursor={second['next_cursor']}&snapshot={first['snapshot_id']}")
        self.assertEqual([r["id"] for r in second["items"]+last["items"]], [43,42,41,40])
        self.assertFalse(last["has_more"])
        self.assertIsNone(last["next_cursor"])
        self.assertTrue(first["items"][0]["scanned_at"].endswith("Z"))
        self.assertEqual(self.get("/history/page", "snapshot=0")[1]["items"], [])

    def test_null_times_follow_known_dates_without_dropping_rows(self):
        self.add([dict(id=40,decoded_content="Text",scanned_at=datetime(2026,1,1)),dict(id=41,decoded_content="Text"),dict(id=42,decoded_content="Text")])
        with self.database.SessionLocal() as db:
            db.query(self.database.ScanRecord).filter(self.database.ScanRecord.id.in_([41,42])).update({"scanned_at":None}); db.commit()
        _, first = self.get("/history/page", "limit=1")
        _, second = self.get("/history/page", "limit=1&cursor=40")
        _, third = self.get("/history/page", "limit=1&cursor=42")
        self.assertEqual([p["items"][0]["id"] for p in [first,second,third]], [40,42,41])

    def test_protected_routes_and_owner_isolation(self):
        for path in ["/history/page", "/history/summary"]:
            for token in [None,"bad",self.token("a@example.test",True)]:
                self.assertIn(self.api(path,token=token)[0], (401,403))
        self.add([dict(id=40,decoded_content="Private A")])
        self.assertEqual(self.get("/history/summary",owner="b@example.test")[1]["total"], 1)
        self.assertEqual([r["id"] for r in self.get("/history/page", "user_id=1",owner="b@example.test")[1]["items"]], [22])
        self.assertEqual(self.get("/history/page", "cursor=22")[0], 400)
        self.assertEqual(self.get("/history/page", "cursor=99999")[0], 400)

    def test_invalid_inputs_and_category_filter(self):
        for query in ["limit=0","limit=101","limit=bad","cursor=0","snapshot=-1","cursor=9223372036854775808","category=invalid"]:
            self.assertEqual(self.get("/history/page", query)[0], 422, query)
        self.add([dict(decoded_content="https://example.test",risk_label="safe"), dict(decoded_content="upi://pay?pa=synthetic@upi"), dict(decoded_content="",risk_label="safe")])
        for category, count in [("safe",1),("non_url",1),("unclassified",1),("unsafe",0)]:
            status, result = self.get("/history/page", "category="+category)
            self.assertEqual(status, 200)
            self.assertEqual(len(result["items"]), count)

    def test_large_history_is_paged_without_changing_legacy_limits(self):
        with self.database.SessionLocal() as db:
            db.bulk_insert_mappings(self.database.ScanRecord,[dict(user_id=1,decoded_content="Text",scanned_at=datetime(2026,1,1)) for _ in range(5001)])
            db.commit()
        status, result = self.get("/history/page", "limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(len(result["items"]), 100)
        self.assertTrue(result["has_more"])
        self.assertEqual(self.get("/history")[0], 413)
        self.assertEqual(self.get("/history/summary")[0], 413)

    def test_legacy_list_fields_and_raw_timestamps_unchanged(self):
        self.add([dict(decoded_content="Text",scanned_at=datetime(2026,1,1,1,2,3))])
        status, result = self.get("/history")
        self.assertEqual(status, 200)
        self.assertIsInstance(result, list)
        self.assertEqual(result[0]["scanned_at"], "2026-01-01 01:02:03")
        self.assertIn("score_explanation", result[0])

    def test_new_views_keep_byte_limits_and_no_store(self):
        self.add([dict(decoded_content="Synthetic",risk_breakdown="not-json")])
        for path in ["/history/page", "/history/summary"]:
            status, _, headers = self.api(path,token=self.token("a@example.test"))
            self.assertEqual(status,200)
            self.assertEqual(headers[b"cache-control"], b"no-store")
            with patch.object(self.main.history_views,"MAX_BYTES",10):
                self.assertEqual(self.get(path)[0],413)
        self.assertEqual(self.get("/history/summary")[1]["stored_findings"],0)

    def test_non_numeric_legacy_scores_do_not_break_averages(self):
        self.add([dict(decoded_content="https://example.test",risk_score="not-a-number",risk_label="safe"),
                  dict(decoded_content="https://example.test",risk_score=20,risk_label="safe")])
        status, result = self.get("/history/summary")
        self.assertEqual(status,200)
        self.assertEqual(result["total"],2)
        self.assertEqual(result["average_url_risk"],20)


class MlAuditReproducibilityTests(unittest.TestCase):
    def test_diagnostics_are_deterministic_and_do_not_claim_test_metrics(self):
        path = Path(__file__).resolve().parents[2]/"tools/phase_e_ml_audit.py"
        spec = importlib.util.spec_from_file_location("phase_e_audit",path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)/"synthetic.csv"
            data.write_text("url,type\nhttps://example.test,benign\nhttps://example.test,phishing\nexample.test,benign\nother.test,malware\n",encoding="utf-8")
            first = module.dataset_diagnostics(data)
            self.assertEqual(first, module.dataset_diagnostics(data))
            self.assertEqual(first["duplicate_binary_rows"],1)
            self.assertEqual(first["conflicting_duplicate_occurrences"],1)
            self.assertIsNone(first["independent_test_metrics"])
