from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from demo_runtime import restricted_demo
from pathlib import Path
from sqlalchemy.engine import make_url

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./scan_history.db")
if restricted_demo():
    configured = make_url(DATABASE_URL)
    if not os.environ.get("DATABASE_URL") or configured.drivername != "sqlite" or not Path(configured.database or "").is_absolute():
        raise RuntimeError("Restricted demo requires an explicit absolute SQLite DATABASE_URL")
    if DATABASE_URL.endswith("/scan_history.db"):
        raise RuntimeError("Use a fresh demonstration database, not scan_history.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 10})
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

Base.metadata.create_all(bind=engine)

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
with engine.begin() as connection:
    existing_columns = {
        column["name"] for column in inspect(engine).get_columns("scan_history")
    }
    for column_name, column_type in _report_columns.items():
        if column_name not in existing_columns:
            connection.execute(text(
                f"ALTER TABLE scan_history ADD COLUMN {column_name} {column_type}"
            ))