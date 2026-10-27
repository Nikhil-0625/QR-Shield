"""Fresh temporary SQLite only: never imports the application's personal database."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BACKEND=Path(__file__).resolve().parents[1]/"backend"
sys.path.insert(0,str(BACKEND))


def load_database():
    spec=importlib.util.spec_from_file_location("isolated_demo_database",BACKEND/"database.py")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DemoPersistenceTests(unittest.TestCase):
    def test_fresh_absolute_database_survives_engine_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            url="sqlite:///"+(Path(folder)/"demo.db").as_posix()
            with patch.dict(os.environ,{"QR_SHIELD_MODE":"restricted-demo","DATABASE_URL":url}):
                first=load_database()
                with first.SessionLocal() as db:
                    db.add(first.User(email="synthetic@example.test",hashed_password="synthetic-test-only"))
                    db.commit()
                first.engine.dispose()
                second=load_database()
                try:
                    with second.SessionLocal() as db:
                        self.assertEqual(db.query(second.User).one().email,"synthetic@example.test")
                finally: second.engine.dispose()

    def test_demo_rejects_relative_or_development_database(self):
        for url in ("sqlite:///relative-demo.db", "sqlite:////data/scan_history.db"):
            with self.subTest(url=url), patch.dict(os.environ,{"QR_SHIELD_MODE":"restricted-demo","DATABASE_URL":url}):
                with self.assertRaises(RuntimeError): load_database()


if __name__=="__main__": unittest.main()
