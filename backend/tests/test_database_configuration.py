"""Database URL, dialect, and additive-schema checks using local/fake engines only."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable


BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_database(name, mode="development", database_url="sqlite://"):
    spec = importlib.util.spec_from_file_location(name, BACKEND / "database.py")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {"QR_SHIELD_MODE": mode, "DATABASE_URL": database_url}):
        spec.loader.exec_module(module)
    return module


class DatabaseConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = load_database("database_configuration_under_test")

    @classmethod
    def tearDownClass(cls):
        cls.database.engine.dispose()

    def test_sqlite_engine_initializes_and_retains_local_connection_options(self):
        parsed, options = self.database.database_engine_configuration("sqlite://")
        self.assertEqual(parsed.drivername, "sqlite")
        self.assertEqual(
            options,
            {"connect_args": {"check_same_thread": False, "timeout": 10}},
        )
        engine = self.database.create_database_engine("sqlite://")
        try:
            with engine.connect() as connection:
                self.assertEqual(connection.exec_driver_sql("SELECT 1").scalar_one(), 1)
        finally:
            engine.dispose()

    def test_postgresql_fake_engine_uses_psycopg3_and_non_sqlite_arguments(self):
        with patch.object(self.database, "create_engine", return_value=object()) as factory:
            self.database.create_database_engine("postgresql://db.invalid/qrshield")

        url, options = factory.call_args.args[0], factory.call_args.kwargs
        self.assertEqual(url.drivername, "postgresql+psycopg")
        self.assertEqual(url.query["sslmode"], "require")
        self.assertEqual(options["connect_args"], {"connect_timeout": 10})
        self.assertTrue(options["pool_pre_ping"])
        self.assertNotIn("check_same_thread", options["connect_args"])
        self.assertNotIn("timeout", options["connect_args"])

    def test_aiven_style_url_is_normalized_and_existing_strong_ssl_is_preserved(self):
        url, _ = self.database.database_engine_configuration(
            "postgres://db.invalid/qrshield?sslmode=verify-full&connect_timeout=7"
        )
        self.assertEqual(url.drivername, "postgresql+psycopg")
        self.assertEqual(url.query["sslmode"], "verify-full")
        self.assertEqual(url.query["connect_timeout"], "7")

    def test_runtime_mode_accepts_production_without_changing_restricted_gate(self):
        runtime = sys.modules["demo_runtime"]
        with patch.dict(os.environ, {"QR_SHIELD_MODE": "production"}):
            self.assertEqual(runtime.runtime_mode(), "production")
            self.assertFalse(runtime.restricted_demo())
        with patch.dict(os.environ, {"QR_SHIELD_MODE": "restricted-demo"}):
            self.assertEqual(runtime.runtime_mode(), "restricted-demo")
            self.assertTrue(runtime.restricted_demo())

    def test_runtime_mode_rejects_invalid_mode_with_allowed_values(self):
        runtime = sys.modules["demo_runtime"]
        with patch.dict(os.environ, {"QR_SHIELD_MODE": "staging"}):
            with self.assertRaisesRegex(
                RuntimeError,
                "expected development, production, or restricted-demo",
            ):
                runtime.runtime_mode()

    def test_postgresql_engine_failure_is_propagated_without_sqlite_fallback(self):
        with patch.object(self.database, "create_engine", side_effect=RuntimeError("connection failed")) as factory:
            with self.assertRaisesRegex(RuntimeError, "connection failed"):
                self.database.create_database_engine("postgresql://db.invalid/qrshield")
        self.assertEqual(factory.call_count, 1)

    def test_column_migration_sql_is_idempotent_for_postgresql(self):
        postgres_sql = self.database.additive_column_sql("postgresql", "domain_age_days", "INTEGER")
        sqlite_sql = self.database.additive_column_sql("sqlite", "domain_age_days", "INTEGER")
        self.assertEqual(
            postgres_sql,
            "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS domain_age_days INTEGER",
        )
        self.assertEqual(
            sqlite_sql,
            "ALTER TABLE scan_history ADD COLUMN domain_age_days INTEGER",
        )

    def test_postgresql_without_required_tls_is_rejected(self):
        for mode in ("disable", "allow", "prefer"):
            with self.subTest(sslmode=mode), self.assertRaises(RuntimeError):
                self.database.database_engine_configuration(
                    "postgresql://db.invalid/qrshield?sslmode=" + mode
                )

    def test_production_requires_database_url_and_never_selects_sqlite_fallback(self):
        with self.assertRaisesRegex(RuntimeError, "Production mode requires DATABASE_URL"):
            self.database.resolve_database_url(None, "production")
        with self.assertRaisesRegex(RuntimeError, "requires a PostgreSQL DATABASE_URL"):
            self.database.resolve_database_url("sqlite:////data/demo.db", "production")
        self.assertEqual(
            self.database.resolve_database_url("postgresql://db.invalid/qrshield", "production"),
            "postgresql://db.invalid/qrshield",
        )
        self.assertEqual(
            self.database.resolve_database_url(None, "development"),
            "sqlite:///./scan_history.db",
        )

        spec = importlib.util.spec_from_file_location(
            "production_without_database_url", BACKEND / "database.py"
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"QR_SHIELD_MODE": "production"}):
            os.environ.pop("DATABASE_URL", None)
            with self.assertRaisesRegex(RuntimeError, "Production mode requires DATABASE_URL"):
                spec.loader.exec_module(module)

    def test_restricted_demo_rejects_postgresql_and_requires_fresh_absolute_sqlite(self):
        with self.assertRaisesRegex(RuntimeError, "absolute SQLite"):
            self.database.resolve_database_url("postgresql://db.invalid/qrshield", "restricted-demo")
        for url in (None, "sqlite:///relative-demo.db", "sqlite:////data/scan_history.db"):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                self.database.resolve_database_url(url, "restricted-demo")

        with tempfile.TemporaryDirectory() as folder:
            demo_file = Path(folder) / "qrshield-demo.db"
            demo_url = "sqlite:///" + demo_file.as_posix()
            self.assertEqual(
                self.database.resolve_database_url(demo_url, "restricted-demo"),
                demo_url,
            )

        spec = importlib.util.spec_from_file_location(
            "restricted_demo_postgresql_rejected", BACKEND / "database.py"
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "QR_SHIELD_MODE": "restricted-demo",
            "DATABASE_URL": "postgresql://db.invalid/qrshield",
        }):
            with self.assertRaisesRegex(RuntimeError, "absolute SQLite"):
                spec.loader.exec_module(module)

    def test_models_compile_for_postgresql_and_match_initialized_sqlite_schema(self):
        for table in self.database.Base.metadata.sorted_tables:
            statement = str(CreateTable(table).compile(dialect=postgresql.dialect()))
            self.assertIn(table.name, statement)

        inspector = inspect(self.database.engine)
        self.assertEqual(set(inspector.get_table_names()), {"users", "scan_history"})
        for table in self.database.Base.metadata.sorted_tables:
            actual = {column["name"] for column in inspector.get_columns(table.name)}
            self.assertEqual(actual, {column.name for column in table.columns})

    def test_initialization_adds_legacy_columns_idempotently_without_losing_rows(self):
        engine = create_engine("sqlite://")
        try:
            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE scan_history ("
                    "id INTEGER PRIMARY KEY, decoded_content VARCHAR, final_url VARCHAR, "
                    "domain VARCHAR, risk_score INTEGER, risk_label VARCHAR, "
                    "tampering_score INTEGER, scanned_at DATETIME)"
                ))
                connection.execute(text(
                    "INSERT INTO scan_history "
                    "(id, decoded_content, final_url, domain, risk_score, risk_label, "
                    "tampering_score) VALUES (1, 'preserve-me', NULL, NULL, 0, 'safe', 0)"
                ))

            self.database.initialize_schema(engine)
            self.database.initialize_schema(engine)

            inspector = inspect(engine)
            columns = {column["name"] for column in inspector.get_columns("scan_history")}
            self.assertTrue({column.name for column in self.database.ScanRecord.__table__.columns} <= columns)
            with engine.connect() as connection:
                row = connection.execute(text(
                    "SELECT id, decoded_content FROM scan_history WHERE id = 1"
                )).one()
            self.assertEqual(tuple(row), (1, "preserve-me"))
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
