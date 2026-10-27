"""Bounded additive dashboard views. ORM-default timestamps are naive UTC.

No migration or historical rewrite. Missing timestamps stay unknown. Summaries
retain the Phase C 5000-row/8MiB processing limits; pages have independent bounds.
"""
from datetime import datetime, timedelta, timezone
import json
import math
from fastapi import HTTPException
from sqlalchemy import case, func, or_, and_

MAX_BYTES = 8 * 1024 * 1024
# ECMAScript trim whitespace, matching the existing dashboard classification.
WHITESPACE = " \t\r\n\v\f\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"


def content_type(value):
    text = (value or "").strip(WHITESPACE).lower()
    return "Unclassifiable" if not text else "URL" if text.startswith(("http://", "https://")) else "UPI" if text.startswith("upi://") else "Text / Other"


def classification(content, label):
    kind = content_type(content)
    if kind == "Unclassifiable":
        return "unclassified"
    if kind != "URL":
        return "non_url"
    label = (label or "").lower()
    return label if label in ("safe", "suspicious", "unsafe") else "unclassified"


def utc_timestamp(value):
    if value is None:
        return None
    # datetime.utcnow has always supplied the ORM default. Imported/manual
    # timestamps without that provenance cannot be independently verified.
    value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def classification_expression(record):
    text = func.lower(func.trim(func.coalesce(record.decoded_content, ""), WHITESPACE))
    is_url = or_(text.startswith("http://"), text.startswith("https://"))
    label = func.lower(func.coalesce(record.risk_label, ""))
    return case((text == "", "unclassified"), (~is_url, "non_url"),
                (label.in_(["safe", "suspicious", "unsafe"]), label), else_="unclassified")


def summary(db, record, user_id, now=None):
    now = now or datetime.now(timezone.utc)
    today = now.astimezone(timezone.utc).date()
    days = [{"key": (today - timedelta(days=offset)).isoformat(), "count": 0} for offset in range(6, -1, -1)]
    by_day = {day["key"]: day for day in days}
    result = {"timezone": "UTC", "timestamp_convention": "ORM timestamps are UTC; missing timestamps are unknown",
              "snapshot_id": db.query(func.max(record.id)).filter(record.user_id == user_id).scalar() or 0,
              "total": 0, "counts": dict.fromkeys(["safe", "suspicious", "unsafe", "non_url", "unclassified"], 0),
              "content_counts": dict.fromkeys(["URL", "UPI", "Text / Other", "Unclassifiable"], 0),
              "average_url_risk": None, "stored_findings": 0, "indicators": {}, "activity": days,
              "unknown_timestamps": 0}
    query = db.query(record.decoded_content, record.risk_label, record.risk_score, record.risk_breakdown, record.scanned_at).filter(
        record.user_id == user_id, record.id <= result["snapshot_id"]).limit(5001).yield_per(100)
    size = 0
    score_sum = score_count = 0
    for row in query:
        if result["total"] >= 5000:
            raise HTTPException(413, "Dashboard summary exceeds the 5,000-record processing limit; paged history remains available")
        size += len(json.dumps(list(row), default=str, ensure_ascii=False).encode("utf-8"))
        if size > MAX_BYTES:
            raise HTTPException(413, "Dashboard summary exceeds the 8 MiB processing limit")
        content, label, score, breakdown, scanned_at = row
        kind = content_type(content)
        result["total"] += 1
        result["counts"][classification(content, label)] += 1
        result["content_counts"][kind] += 1
        try:
            numeric_score = float(score) if score is not None and score != "" else None
        except (TypeError, ValueError, OverflowError):
            numeric_score = None
        if kind == "URL" and numeric_score is not None and math.isfinite(numeric_score):
            score_sum += numeric_score
            score_count += 1
        try:
            findings = json.loads(breakdown) if breakdown else []
        except (ValueError, TypeError):
            findings = []
        if isinstance(findings, list):
            result["stored_findings"] += len(findings)
            for item in findings:
                if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
                    name = item["name"]
                    result["indicators"][name] = result["indicators"].get(name, 0) + 1
        stamp = utc_timestamp(scanned_at)
        if stamp is None:
            result["unknown_timestamps"] += 1
        elif stamp[:10] in by_day:
            by_day[stamp[:10]]["count"] += 1
    result["average_url_risk"] = score_sum / score_count if score_count else None
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_BYTES:
        raise HTTPException(413, "Dashboard summary exceeds the 8 MiB response limit")
    return result


def page(db, record, user_id, limit, cursor_id=None, snapshot_id=None, category="all"):
    if snapshot_id is None:
        snapshot_id = db.query(func.max(record.id)).filter(record.user_id == user_id).scalar() or 0
    query = db.query(record).filter(record.user_id == user_id, record.id <= snapshot_id)
    if category != "all":
        query = query.filter(classification_expression(record) == category)
    if cursor_id is not None:
        cursor = db.query(record.id, record.scanned_at).filter(record.user_id == user_id, record.id == cursor_id, record.id <= snapshot_id).first()
        if cursor is None:
            raise HTTPException(400, "Invalid history cursor")
        if cursor.scanned_at is None:
            query = query.filter(record.scanned_at.is_(None), record.id < cursor.id)
        else:
            query = query.filter(or_(record.scanned_at < cursor.scanned_at, record.scanned_at.is_(None),
                                     and_(record.scanned_at == cursor.scanned_at, record.id < cursor.id)))
    rows = query.order_by(record.scanned_at.desc().nullslast(), record.id.desc()).limit(limit + 1).all()
    more = len(rows) > limit
    items = [{"id": row.id, "decoded_content": row.decoded_content, "final_url": row.final_url,
              "domain": row.domain, "risk_score": row.risk_score, "risk_label": row.risk_label,
              "scanned_at": utc_timestamp(row.scanned_at)} for row in rows[:limit]]
    result = {"items": items, "has_more": more, "next_cursor": items[-1]["id"] if more else None,
              "snapshot_id": snapshot_id, "timezone": "UTC"}
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_BYTES:
        raise HTTPException(413, "History page exceeds the 8 MiB response limit; use a smaller page size")
    return result
