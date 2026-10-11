"""Authorization regression tests; no application database or model file is opened."""
import asyncio
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import sqlalchemy
from sqlalchemy.pool import StaticPool
from jose import jwt


BACKEND = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, BACKEND / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HistoryAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = sqlalchemy.create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        # Redirect database.py's import-time create_all and migrations before import.
        with patch.object(sqlalchemy, "create_engine", return_value=cls.engine):
            cls.database = load_module("history_test_database", "database.py")
        cls.signing_key = secrets.token_urlsafe(48)
        import joblib
        with patch.dict(sys.modules, {"database": cls.database}), \
                patch.dict(os.environ, {"JWT_SECRET_KEY": cls.signing_key}), \
                patch.object(joblib, "load", return_value=object()):
            sys.path.insert(0, str(BACKEND))
            try:
                cls.main = load_module("history_test_main", "main.py")
            finally:
                sys.path.pop(0)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def setUp(self):
        db = self.database.SessionLocal()
        try:
            db.query(self.database.ScanRecord).delete()
            db.query(self.database.User).delete()
            db.add_all([
                self.database.User(id=1, email="a@example.test"),
                self.database.User(id=2, email="b@example.test"),
                self.database.User(id=3, email="empty@example.test"),
            ])
            db.add_all([
                self.database.ScanRecord(
                    id=11, user_id=1, decoded_content="synthetic A", risk_score=20,
                    risk_label="safe", risk_breakdown='[{"name":"synthetic"}]',
                    score_explanation='{"final_score":20}',
                    tampering_reasons="[]", redirect_chain="[]",
                ),
                self.database.ScanRecord(id=22, user_id=2, decoded_content="synthetic B"),
                self.database.ScanRecord(id=33, user_id=None, decoded_content="unowned"),
            ])
            db.commit()
        finally:
            db.close()

    def token(self, email, expired=False):
        return jwt.encode(
            {"sub": email, "exp": datetime.now(timezone.utc) + timedelta(minutes=-1 if expired else 5)},
            self.signing_key, algorithm="HS256",
        )

    def request(self, path, token=None):
        # Exercise the actual ASGI routing/dependency stack without httpx/TestClient.
        async def run():
            messages = []
            delivered = False

            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                await asyncio.Event().wait()

            async def send(message):
                messages.append(message)

            headers = [] if token is None else [(b"authorization", ("Bearer " + token).encode())]
            await self.main.app({
                "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1", "method": "GET", "scheme": "http",
                "path": path, "raw_path": path.encode(), "query_string": b"",
                "root_path": "", "headers": headers,
                "client": ("127.0.0.1", 1234), "server": ("test", 80),
            }, receive, send)
            status = next(m["status"] for m in messages if m["type"] == "http.response.start")
            body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
            return status, body
        return asyncio.run(run())

    def snapshot(self):
        db = self.database.SessionLocal()
        try:
            return [tuple(getattr(row, c.name) for c in self.database.ScanRecord.__table__.columns)
                    for row in db.query(self.database.ScanRecord).order_by(self.database.ScanRecord.id)]
        finally:
            db.close()

    def test_each_user_sees_only_owned_records_and_response_is_preserved(self):
        before = self.snapshot()
        for email, expected in [("a@example.test", 11), ("b@example.test", 22)]:
            status, body = self.request("/history", self.token(email))
            self.assertEqual(status, 200)
            rows = json.loads(body)
            self.assertEqual([r["id"] for r in rows], [expected])
            self.assertEqual(set(rows[0]), {
                "id", "decoded_content", "final_url", "domain", "risk_score", "risk_label",
                "risk_breakdown", "score_explanation", "tampering_score", "tampering_reasons",
                "redirect_chain", "domain_age_days", "https_valid", "lookalike_brand",
                "lookalike_score", "ml_phishing_probability", "rule_score", "scanned_at",
            })
            if expected == 11:
                self.assertEqual(rows[0]["risk_breakdown"], [{"name": "synthetic"}])
                self.assertEqual(rows[0]["score_explanation"], {"final_score": 20})
        self.assertEqual(self.snapshot(), before)

    def test_user_without_scans_gets_empty_list(self):
        status, body = self.request("/history", self.token("empty@example.test"))
        self.assertEqual((status, json.loads(body)), (200, []))

    def test_nonexistent_account_is_rejected(self):
        status, body = self.request("/history", self.token("missing@example.test"))
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"detail": "User not found"})

    def test_missing_invalid_and_expired_tokens_are_rejected(self):
        before = self.snapshot()
        for token in [None, "invalid", self.token("a@example.test", expired=True)]:
            with self.subTest(kind="missing" if token is None else "provided"):
                status, _ = self.request("/history", token)
                self.assertIn(status, (401, 403))  # HTTPBearer status varies by FastAPI version.
        self.assertEqual(self.snapshot(), before)

    def test_pdf_owner_allowed_other_user_rejected_without_mutation(self):
        before = self.snapshot()
        # Rendering is outside this authorization suite; retain real route/DB/JWT checks.
        with patch.object(self.main, "_build_report", return_value=io.BytesIO(b"%PDF-test")) as render:
            status, body = self.request("/report/11", self.token("a@example.test"))
            self.assertEqual(status, 200)
            self.assertTrue(body.startswith(b"%PDF"))
            self.assertEqual(render.call_args[0][0].user_id, 1)
            render.reset_mock()
            status, _ = self.request("/report/11", self.token("b@example.test"))
            self.assertEqual(status, 404)
            render.assert_not_called()
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
