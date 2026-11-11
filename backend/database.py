from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from pathlib import Path
from sqlalchemy.engine import make_url

from demo_runtime import runtime_mode


DEFAULT_DATABASE_URL = "sqlite:///./scan_history.db"


def resolve_database_url(configured_url, mode):
    """Select the configured database without permitting production fallback."""
    if configured_url is None:
        if mode == "production":
            raise RuntimeError("Production mode requires DATABASE_URL")
        if mode == "restricted-demo":
            raise RuntimeError("Restricted demo requires an explicit absolute SQLite DATABASE_URL")
        return DEFAULT_DATABASE_URL
    if not configured_url.strip():
        raise RuntimeError("DATABASE_URL cannot be empty")

    parsed = make_url(configured_url)
    if mode == "production" and parsed.get_backend_name() not in {"postgres", "postgresql"}:
        raise RuntimeError("Production mode requires a PostgreSQL DATABASE_URL")
    if mode == "restricted-demo":
        if parsed.drivername != "sqlite" or not Path(parsed.database or "").is_absolute():
            raise RuntimeError("Restricted demo requires an explicit absolute SQLite DATABASE_URL")
        if Path(parsed.database).name.lower() == "scan_history.db":
            raise RuntimeError("Use a fresh demonstration database, not scan_history.db")
    return configured_url


def database_engine_configuration(database_url):
    """Return a normalized URL and dialect-specific SQLAlchemy options."""
    parsed = make_url(database_url)
    backend = parsed.get_backend_name()

    if backend in {"postgres", "postgresql"}:
        # Provider URLs commonly use postgresql:// (or legacy postgres://).
        # The application uses the synchronous Psycopg 3 SQLAlchemy dialect.
        parsed = parsed.set(drivername="postgresql+psycopg")
        query = dict(parsed.query)
        sslmode = query.get("sslmode")
        if sslmode is None:
            query["sslmode"] = "require"
        elif not isinstance(sslmode, str) or sslmode.lower() not in {"require", "verify-ca", "verify-full"}:
            raise RuntimeError("PostgreSQL DATABASE_URL must require TLS")
        parsed = parsed.set(query=query)

        connect_args = {}
        if "connect_timeout" not in parsed.query:
            connect_args["connect_timeout"] = 10
        return parsed, {"connect_args": connect_args, "pool_pre_ping": True}

    if backend == "sqlite":
        return parsed, {"connect_args": {"check_same_thread": False, "timeout": 10}}

    return parsed, {}


def create_database_engine(database_url):
    normalized_url, options = database_engine_configuration(database_url)
    return create_engine(normalized_url, **options)


def additive_column_sql(dialect_name, column_name, column_type):
    idempotence_clause = " IF NOT EXISTS" if dialect_name == "postgresql" else ""
    return f"ALTER TABLE scan_history ADD COLUMN{idempotence_clause} {column_name} {column_type}"


DATABASE_URL = resolve_database_url(
    os.environ.get("DATABASE_URL"),
    runtime_mode(),
)
engine = create_database_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    decoded_content = Column(String)
    final_url = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_label = Column(String, nullable=True)
    tampering_score = Column(Integer, nullable=True)
    tampering_reasons = Column(Text, nullable=True)
    redirect_chain = Column(Text, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    https_valid = Column(Integer, nullable=True)
    lookalike_brand = Column(String, nullable=True)
    lookalike_score = Column(String, nullable=True)
    ml_phishing_probability = Column(String, nullable=True)
    rule_score = Column(Integer, nullable=True)
    risk_breakdown = Column(Text, nullable=True)
    score_explanation = Column(Text, nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# Add report and explainability fields without replacing existing scan history.
_report_columns = {
    "user_id": "INTEGER",
    "tampering_reasons": "TEXT",
    "redirect_chain": "TEXT",
    "domain_age_days": "INTEGER",
    "https_valid": "INTEGER",
    "lookalike_brand": "VARCHAR",
    "lookalike_score": "VARCHAR",
    "ml_phishing_probability": "VARCHAR",
    "rule_score": "INTEGER",
    "risk_breakdown": "TEXT",
    "score_explanation": "TEXT",
}


def initialize_schema(target_engine):
    """Create missing tables and apply only additive, idempotent columns."""
    Base.metadata.create_all(bind=target_engine)
    with target_engine.begin() as connection:
        existing_columns = {
            column["name"] for column in inspect(connection).get_columns("scan_history")
        }
        postgres = connection.dialect.name == "postgresql"
        for column_name, column_type in _report_columns.items():
            if column_name in existing_columns:
                continue
            connection.execute(text(additive_column_sql(
                "postgresql" if postgres else connection.dialect.name,
                column_name,
                column_type,
            )))
            existing_columns.add(column_name)


initialize_schema(engine)
