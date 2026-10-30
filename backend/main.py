from fastapi import FastAPI, File, Form, UploadFile, Depends, HTTPException, Query, Request, status
from typing import Annotated
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import requests
import whois
import ssl
import socket
from urllib.parse import parse_qsl, urljoin, urlparse
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
from dateutil import parser as date_parser
from rapidfuzz import fuzz
import joblib
import ipaddress
import io
import json
import logging
import os
import re
from html import escape
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv
from pydantic import BaseModel, StrictStr
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from demo_runtime import restricted_demo, load_production_model, scan_jobs, report_jobs, history_jobs
from api_security import ApiBoundary
from url_policy import MAX_QR_BYTES, MAX_URL_LENGTH, network_notice, url_input_error
from website_input import normalize_website_url, WEBSITE_NETWORK_NOTICE
from safe_browsing import client as reputation_client, current_reputation, website_verdict, deterministic_overall_risk, PRIVACY_NOTICE, ACCURACY_NOTICE, ADVISORY_URL
from rdap import client as registration_client
from upi_security import analyze_upi, upi_intent_banner
import history_views
from ml_probability import phishing_probability as select_phishing_probability
from url_security import hostname as parse_hostname, registered_domain, educational_host, brand_match as detect_brand_match, structural_findings
from url_probe import ProbeError, validate_target as validate_public_target, check_https as probe_https, trace_redirects as probe_redirects
from PIL import Image, UnidentifiedImageError

# Initialize image format handlers before request-worker threads use them.
Image.init()
from database import SessionLocal, ScanRecord, User
from brand_config import (
    LOOKALIKE_SIMILARITY_THRESHOLD,
    MULTI_LABEL_PUBLIC_SUFFIXES,
    PROTECTED_BRANDS,
)
from reportlab.lib import colors
from reportlab.lib.fonts import addMapping, ps2tt
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

for _candidate in [
    os.path.join(os.path.dirname(__file__), "fonts", "Carlito-Bold.ttf"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "fonts", "Carlito-Bold.ttf"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "Carlito-Bold.ttf"),
    os.path.join("backend", "fonts", "Carlito-Bold.ttf"),
]:
    if os.path.exists(_candidate):
        if "QRShieldUpiHeader" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("QRShieldUpiHeader", _candidate))
        pdfmetrics.registerFontFamily("QRShieldUpiHeader", normal="QRShieldUpiHeader", bold="QRShieldUpiHeader", italic="QRShieldUpiHeader", boldItalic="QRShieldUpiHeader")
        for _b in (0, 1):
            for _i in (0, 1):
                addMapping("QRShieldUpiHeader", _b, _i, "QRShieldUpiHeader")
        break

MAX_HISTORY_BYTES = 8 * 1024 * 1024

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(RequestValidationError)
async def redacted_validation_error(request, exc):
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": list(error["loc"]), "type": error["type"], "msg": "Invalid or missing field"}
        for error in exc.errors()
    ]})
logger = logging.getLogger(__name__)

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=False)
cors_origins = [origin.strip() for origin in os.environ.get(
    "CORS_ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500"
).split(",") if origin.strip()]
if any(origin == "*" or origin == "null" or urlparse(origin).scheme not in ("http", "https")
       or not urlparse(origin).netloc for origin in cors_origins):
    raise RuntimeError("CORS_ALLOWED_ORIGINS must contain explicit HTTP(S) origins.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
if restricted_demo():
    from demo_security import DemoBoundary
    app.add_middleware(DemoBoundary)
else:
    # Validate hosts and resource limits even for CORS preflight requests.
    app.add_middleware(ApiBoundary)

def is_ml_enabled() -> bool:
    """Return True if experimental ML scoring is explicitly enabled via environment."""
    return os.environ.get("QR_SCANNER_ML_ENABLED", "false").strip().lower() in ("true", "1")


# The experimental ML model is loaded ONLY when QR_SCANNER_ML_ENABLED is true.
# When disabled (the production default), startup does not touch the model file.
ml_model = None


def get_ml_model(loader=None):
    """Lazily load and return the experimental ML model only when QR_SCANNER_ML_ENABLED is true.

    When QR_SCANNER_ML_ENABLED is false (the default), returns None without touching the model file
    or invoking joblib.load.
    """
    global ml_model
    if not is_ml_enabled():
        return None
    if ml_model is None:
        if loader is None:
            loader = joblib.load
        ml_model = load_production_model(loader)
    return ml_model


if is_ml_enabled():
    try:
        ml_model = load_production_model(joblib.load)
    except Exception as exc:
        logger.warning("Experimental ML model enabled but could not be loaded at startup: %s", exc)
        ml_model = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=False)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY or not SECRET_KEY.strip():
    raise RuntimeError("JWT_SECRET_KEY environment variable is required and must not be blank.")
if len(SECRET_KEY.encode('utf-8')) < 32:
    raise RuntimeError("JWT_SECRET_KEY must be at least 32 bytes; use a cryptographically random secret.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()
report_security = HTTPBearer(auto_error=False)


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        return False


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verifies the JWT sent in the Authorization: Bearer <token> header.
    Raises 401 if missing, invalid, or expired. Use as a route dependency
    to protect any endpoint that requires a logged-in user."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM],
                             options={"require_exp": True, "require_sub": True})
        email = payload.get("sub")
        if not isinstance(email, str) or not email.strip():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return email
    except (JWTError, TypeError, ValueError, OverflowError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def get_report_user(
    credentials: HTTPAuthorizationCredentials = Depends(report_security)
):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization required"
        )
    return get_current_user(credentials)


def check_password_strength(password):
    if len(password) < 6:
        return "weak", "Password must be at least 6 characters"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    strength_score = sum([has_upper, has_lower, has_digit, has_special])

    if len(password) >= 10 and strength_score >= 3:
        return "strong", "Strong password"
    elif len(password) >= 8 and strength_score >= 2:
        return "medium", "Medium strength password"
    else:
        return "weak", "Weak password - try adding uppercase, numbers, and symbols"


@app.get("/")
def home():
    return {"message": "QR Scanner Backend is running"}


def validate_outbound_url(url):
    """Allow only bounded probes to public DNS destinations pinned by url_probe."""
    if restricted_demo():
        return False, network_notice(True)
    try:
        validate_public_target(url)
        return True, None
    except ProbeError as error:
        return False, error.reason


def trace_redirects(url, max_hops=5, allow_network=True):
    """Inspect only bounded redirect response headers; page bodies are not read."""
    is_restricted = restricted_demo()
    if is_restricted:
        allow_network = False
    details = probe_redirects(url, max_hops=max_hops, allow_network=allow_network)
    if is_restricted:
        details["reason"] = "Restricted demo: all external destination checks are disabled."
    return details["chain"], details

def get_root_domain(domain):
    return registered_domain(domain)


def get_domain_age_days(domain):
    return None  # WHOIS is intentionally disabled in every mode.


def check_https_valid(url, allow_network=True, include_details=False):
    """Validate TLS chain and hostname; optionally return structured evidence."""
    is_restricted = restricted_demo()
    details = probe_https(url, allow_network=allow_network and not is_restricted)
    if is_restricted and details["status"] == "blocked":
        details["reason"] = "Restricted demo: all external destination checks are disabled."
    return details if include_details else details["valid"]

def check_lookalike(domain):
    return detect_brand_match(domain)


def _normalize_hostname(domain):
    return parse_hostname(domain)


def hostname_is_ip(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        ipaddress.ip_address(hostname)
        return True
    except (TypeError, ValueError):
        return False


def calculate_rule_contributions(domain_age, https_valid, brand_match, chain, final_url, original_url=None):
    risk_breakdown = []

    if domain_age is not None and 0 <= domain_age < 30:
        risk_breakdown.append({
            "source": "rule",
            "category": "phishing",
            "name": "Newly Registered Domain",
            "points": 20,
            "reason": "The domain was registered less than 30 days ago."
        })
    if https_valid is False and urlparse(final_url).scheme.lower() == "https":
        risk_breakdown.append({
            "source": "rule",
            "category": "transport",
            "name": "HTTPS Validation Failed",
            "points": 20,
            "reason": "The HTTPS check for this destination failed."
        })
    if brand_match is not None:
        risk_breakdown.append({
            "source": "rule",
            "category": "phishing",
            "name": "Possible Brand Impersonation",
            "points": 25,
            "reason": (
                f"The domain resembles the protected brand {brand_match} "
                f"but is not an official {brand_match} domain."
            )
        })
    if len(chain) > 2:
        risk_breakdown.append({
            "source": "rule",
            "category": "phishing",
            "name": "Multiple Redirects",
            "points": 15,
            "reason": "The URL passed through more than one redirect before reaching its destination."
        })
    if hostname_is_ip(final_url):
        risk_breakdown.append({
            "source": "rule",
            "category": "phishing",
            "name": "IP Address URL",
            "points": 25,
            "reason": "The URL uses an IP address instead of a normal domain name."
        })

    for url in dict.fromkeys([original_url or final_url, final_url]):
        for finding in structural_findings(url, brand_match):
            if url != final_url and finding['name'] == 'HTTP Connection':
                finding['reason'] = 'The original QR destination uses unencrypted HTTP before redirects; information on that connection may not be protected in transit. Insecure transport is a transport security risk, not proof of phishing.'
            if not any(item['name'] == finding['name'] for item in risk_breakdown):
                risk_breakdown.append(finding)
    if brand_match:
        offending = next((u for u in (original_url or final_url, final_url)
                          if detect_brand_match(u)[0] == brand_match), final_url)
        domain = registered_domain(offending)
        official_domains = next((brand["domains"] for brand in PROTECTED_BRANDS if brand["name"] == brand_match), [])
        official_description = ", ".join(official_domains) or "the configured official domains"
        for item in risk_breakdown:
            if item['name'] == 'Possible Brand Impersonation':
                item['reason'] = (f'The hostname {parse_hostname(offending)} resembles {brand_match}, '
                                  f'but its registered-domain component is {domain or "unavailable"}, '
                                  f'not an official {brand_match} domain (configured domains: {official_description}). Familiar wording can imitate a service; verify the destination independently. This is an indicator, not proof of malicious behavior.')
                if educational_host(parse_hostname(offending)):
                    item['reason'] += ' This is a reserved educational destination, not a confirmed phishing site.'
    if any(urlparse(a).scheme.lower() == 'https' and urlparse(b).scheme.lower() == 'http'
           for a,b in zip(chain,chain[1:])):
        risk_breakdown.append({'source':'rule','category':'transport','name':'HTTPS Downgrade Redirect','points':20,
                               'reason':'An observed redirect changed HTTPS to HTTP, reducing transport protection.'})
    return sum(item["points"] for item in risk_breakdown), risk_breakdown


def calculate_hybrid_score(rule_score, phishing_probability):
    rule_weight = 0.7
    ml_weight = 0.3
    rule_contribution = rule_score * rule_weight
    ml_contribution = phishing_probability * 100 * ml_weight
    calculated_score = (rule_score * rule_weight) + (phishing_probability * 100 * ml_weight)
    final_score = min(round(calculated_score), 100)

    return final_score, {
        "rule_score": rule_score,
        "rule_weight": rule_weight,
        "rule_contribution": rule_contribution,
        "ml_probability": phishing_probability,
        "ml_weight": ml_weight,
        "ml_contribution": ml_contribution,
        "calculated_score": calculated_score,
        "final_score": final_score
    }


def check_tampering_edges(img):
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        img_h, img_w = img.shape[:2]
        img_area = img_h * img_w
        edge_margin = 0.05 * min(img_w, img_h)
        suspicious = False
        for contour in contours:
            area = cv2.contourArea(contour)
            x, y, w, h = cv2.boundingRect(contour)
            if h == 0:
                continue
            aspect_ratio = w / float(h)
            if 0.85 < aspect_ratio < 1.15 and (img_area * 0.3) < area < (img_area * 0.85):
                left_margin = x
                top_margin = y
                right_margin = img_w - (x + w)
                bottom_margin = img_h - (y + h)
                spans_full_width = left_margin <= edge_margin and right_margin <= edge_margin
                spans_full_height = top_margin <= edge_margin and bottom_margin <= edge_margin

                area_ratio = area / img_area
                width_ratio = w / float(img_w)
                height_ratio = h / float(img_h)
                centered = (
                    abs(left_margin - right_margin) <= img_w * 0.05
                    and abs(top_margin - bottom_margin) <= img_h * 0.05
                )
                dominant_boundary = (
                    area_ratio >= 0.5
                    and width_ratio >= 0.7
                    and height_ratio >= 0.7
                    and centered
                )
                is_outer_frame = (spans_full_width and spans_full_height) or dominant_boundary
                logger.debug(
                    "tampering contour image=%sx%s box=(%s,%s,%s,%s) "
                    "area=%.3f aspect=%.3f margins=(%s,%s,%s,%s) outer=%s",
                    img_w, img_h, x, y, w, h, area_ratio, aspect_ratio,
                    left_margin, top_margin, right_margin, bottom_margin,
                    is_outer_frame,
                )
                if not is_outer_frame:
                    suspicious = True
        return suspicious
    except Exception:
        return False


def check_internal_overlay(img):
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)

        img_h, img_w = img.shape[:2]
        img_area = img_h * img_w
        for contour in contours:
            area = cv2.contourArea(contour)
            x, y, w, h = cv2.boundingRect(contour)
            if h == 0:
                continue

            area_ratio = area / img_area
            width_ratio = w / float(img_w)
            height_ratio = h / float(img_h)
            aspect_ratio = w / float(h)
            center_x = (x + w / 2) / img_w
            center_y = (y + h / 2) / img_h
            if not (
                0.005 <= area_ratio <= 0.15
                and 0.08 <= width_ratio <= 0.45
                and 0.08 <= height_ratio <= 0.45
                and 0.8 <= aspect_ratio <= 1.25
                and 0.3 <= center_x <= 0.7
                and 0.3 <= center_y <= 0.7
            ):
                continue

            perimeter = cv2.arcLength(contour, True)
            if perimeter == 0:
                continue
            polygon = cv2.approxPolyDP(contour, 0.02 * perimeter, True)
            rectangularity = area / float(w * h)
            if (
                len(polygon) == 4
                and cv2.isContourConvex(polygon)
                and rectangularity >= 0.85
            ):
                logger.debug(
                    "internal overlay candidate image=%sx%s box=(%s,%s,%s,%s) "
                    "area=%.3f aspect=%.3f rectangularity=%.3f",
                    img_w, img_h, x, y, w, h, area_ratio, aspect_ratio,
                    rectangularity,
                )
                return True

        return False
    except Exception:
        return False


def check_finder_pattern_consistency(img):
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (5, 5), 0)

        thresh = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY_INV, 11, 2
        )

        contours, hierarchy = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

        if hierarchy is None or len(hierarchy) == 0:
            return False

        img_h, img_w = img.shape[:2]
        zone_margin = 0.38  # Finder patterns sit in outer corners of the QR region

        hierarchy = hierarchy[0]
        corners = {}

        for i, contour in enumerate(contours):
            child = hierarchy[i][2]
            if child == -1:
                continue
            grandchild = hierarchy[child][2]
            if grandchild == -1:
                continue

            area = cv2.contourArea(contour)
            x, y, w, h = cv2.boundingRect(contour)
            if h == 0 or area < 200:
                continue

            aspect_ratio = w / float(h)
            if not (0.75 < aspect_ratio < 1.33):
                continue

            # Finder pattern cannot be larger than the corner zone dimension
            if w > img_w * zone_margin or h > img_h * zone_margin:
                continue

            cx = x + w / 2.0
            cy = y + h / 2.0

            # Determine which corner the candidate center sits in, ensuring bounding box does not span across the image
            in_tl = (cx < img_w * zone_margin) and (cy < img_h * zone_margin) and (x + w <= img_w * (1 - zone_margin)) and (y + h <= img_h * (1 - zone_margin))
            in_tr = (cx > img_w * (1 - zone_margin)) and (cy < img_h * zone_margin) and (x >= img_w * zone_margin) and (y + h <= img_h * (1 - zone_margin))
            in_bl = (cx < img_w * zone_margin) and (cy > img_h * (1 - zone_margin)) and (x + w <= img_w * (1 - zone_margin)) and (y >= img_h * zone_margin)

            corner = None
            if in_tl:
                corner = "TL"
            elif in_tr:
                corner = "TR"
            elif in_bl:
                corner = "BL"
            else:
                continue

            # Concentricity check with grandchild (the inner nested pattern)
            gc_x, gc_y, gc_w, gc_h = cv2.boundingRect(contours[grandchild])
            gc_cx = gc_x + gc_w / 2.0
            gc_cy = gc_y + gc_h / 2.0
            if abs(cx - gc_cx) > w * 0.25 or abs(cy - gc_cy) > h * 0.25:
                continue

            # Nested ratio check: inner core width should be between 15% and 85% of outer box width
            ratio = gc_w / float(w)
            if not (0.15 < ratio < 0.85):
                continue

            # In each corner, retain the outermost candidate (largest width)
            if corner not in corners or w > corners[corner]["w"]:
                corners[corner] = {"w": w, "h": h, "x": x, "y": y, "area": area}

        if len(corners) >= 3:
            sizes = [corners[c]["w"] for c in ["TL", "TR", "BL"]]
            mean_size = sum(sizes) / 3.0
            size_variance = np.std(sizes)
            variance_ratio = size_variance / mean_size if mean_size > 0 else 0
            if mean_size > 0 and variance_ratio > 0.3:
                return True
        return False
    except Exception:
        return False


def check_image_sharpness(img):
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        if laplacian_var < 100:
            return True
        return False
    except Exception:
        return False


def analyze_tampering(img):
    score = 0
    reasons = []

    edge_tampering = check_tampering_edges(img)
    internal_overlay = check_internal_overlay(img)
    if edge_tampering:
        score += 30
        reasons.append("Unexpected sticker-like border detected around QR")
    elif internal_overlay:
        score += 30
        reasons.append("Possible internal overlay detected; manual review recommended")

    if check_finder_pattern_consistency(img):
        score += 35
        reasons.append("QR finder pattern proportions look inconsistent")

    if check_image_sharpness(img):
        score += 20
        reasons.append("Image quality suggests a reprinted/low-quality QR")

    return {"tampering_score": score, "tampering_reasons": reasons}


def extract_ml_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_https'] = 1 if url.startswith('https') else 0
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at'] = url.count('@')
    features['num_question_marks'] = url.count('?')
    features['num_equal'] = url.count('=')
    features['num_underscore'] = url.count('_')
    features['num_slash'] = url.count('/')
    features['has_ip'] = 1 if hostname_is_ip(url) else 0
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_subdomains'] = url.count('.') - 1 if url.count('.') > 1 else 0
    return features


def decode_qr(img):
    """Try pyzbar first (fast, reliable on clean QR codes). If it finds
    nothing -- common with logo-embedded payment QRs (GPay/PhonePe/Paytm)
    -- fall back to OpenCV's WeChat QR detector, which uses a small
    pretrained neural model instead of classical geometry and handles
    logo obstruction and noisy real-world photos far better."""
    decoded_objects = decode(img)
    if decoded_objects:
        return decoded_objects[0].data.decode("utf-8")

    wechat_detector = cv2.wechat_qrcode_WeChatQRCode()
    results, points = wechat_detector.detectAndDecode(img)
    if results and len(results) > 0 and results[0]:
        return results[0]

    return None


def parse_upi_payment_uri(content):
    """Parse payment fields embedded in a UPI URI without contacting a provider."""
    try:
        parsed = urlparse(content)
    except ValueError:
        return None
    if parsed.scheme.lower() != "upi" or parsed.netloc.lower() != "pay":
        return None

    parameters = {}
    occurrences = {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = key.lower()
        occurrences.setdefault(normalized_key, []).append(value.strip() or None)
        if normalized_key not in parameters:
            parameters[normalized_key] = value.strip() or None

    payee_vpa = parameters.get("pa")
    vpa_format_valid = bool(
        payee_vpa
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",
            payee_vpa,
        )
    )
    amount = parameters.get("am")
    amount_valid = None
    if amount is not None:
        try:
            parsed_amount = Decimal(amount)
            amount_valid = parsed_amount.is_finite() and parsed_amount >= 0
        except InvalidOperation:
            amount_valid = False

    return {
        "payee_vpa": payee_vpa,
        "payee_vpa_present": payee_vpa is not None,
        "payee_name": parameters.get("pn"),
        "mode": parameters.get("mode"),
        "amount": amount,
        "currency": parameters.get("cu"),
        "transaction_note": parameters.get("tn"),
        "transaction_reference": parameters.get("tr"),
        "merchant_code": parameters.get("mc"),
        "vpa_format_valid": vpa_format_valid,
        "amount_valid": amount_valid,
        "identity_verified": False,
        "duplicate_parameters": [key for key, values in occurrences.items() if len(values) > 1],
        "conflicting_parameters": {
            key: list(dict.fromkeys(values)) for key, values in occurrences.items()
            if len(set(values)) > 1
        },
    }


def compare_upi_payment(details, expected_vpa=None):
    expected = expected_vpa.strip() if expected_vpa else None
    scanned = details["payee_vpa"]
    if details["conflicting_parameters"]:
        comparison_status = "ambiguous"
        message = "Conflicting payment parameters: unable to compare. Review before paying."
    elif not expected:
        comparison_status = "not_requested"
        message = "Comparison not requested. Enter an expected merchant UPI ID before scanning."
    elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", expected):
        comparison_status = "invalid_expected"
        message = "The expected merchant UPI ID has an invalid format."
    elif not details["vpa_format_valid"]:
        comparison_status = "invalid_scanned"
        message = "The scanned UPI ID is missing or malformed."
    elif expected.lower() == scanned.lower():
        comparison_status = "match"
        message = "Scanned UPI ID matches the expected UPI ID."
    else:
        comparison_status = "mismatch"
        message = "Possible payment redirection or QR substitution: the UPI IDs differ."
    return {
        "expected_vpa": expected, "scanned_vpa": scanned,
        "status": comparison_status, "message": message, "identity_verified": False,
    }


def _offline_url_findings(risk_breakdown):
    return [
        item for item in risk_breakdown
        if item.get("category") != "transport" and item["name"] not in {"HTTP Connection", "HTTPS Downgrade Redirect", "HTTPS Validation Failed"}
    ]


def _offline_url_label(risk_breakdown):
    return "suspicious" if _offline_url_findings(risk_breakdown) else "unverified"


def _disabled_reputation(reason):
    return {
        "provider": "Google Safe Browsing", "status": "disabled", "reason": reason,
        "threat_types": [], "checked_at": None, "cached": False,
        "cache_expires_at": None, "verdict_expires_at": None,
    }


def _normalize_qr_url_for_analysis(value):
    try:
        return normalize_website_url(value)
    except HTTPException:
        parsed = urlparse(value)
        if parsed.username is not None or parsed.password is not None:
            return value
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
            if not address.is_global or address.is_multicast or address.is_reserved:
                return value
        except ValueError:
            pass
        raise


def _analyze_url(qr_content, include_ml=None, allow_registration=True, allow_network=False):
    """Shared offline rules plus explicitly gated, pinned public-destination checks."""
    if include_ml is None:
        include_ml = is_ml_enabled()
    result = {}
    chain, redirect_details = trace_redirects(qr_content, allow_network=allow_network)
    final_url = redirect_details["final_url"]
    domain = parse_hostname(final_url)

    root_domain = get_root_domain(domain)
    https_details = check_https_valid(final_url, allow_network=allow_network, include_details=True)
    https_valid = https_details["valid"]
    network_analysis = (
        "Bounded HTTP response headers were checked against public, DNS-pinned destinations. "
        "Page bodies, client-side redirects, and website content were not fetched."
        if redirect_details["status"] == "completed" else redirect_details["reason"]
    )
    # This opt-in registration service never connects to the scanned website.
    # Public-test requests can disable it, but cannot enable it through a header.
    registration = registration_client.lookup(final_url) if allow_registration else {
        "status": "disabled", "provider": "RDAP", "registered_domain": root_domain,
        "registration_date": None, "expiration_date": None, "domain_status": None,
        "registrar": None, "registration_provider": None, "domain_age_days": None,
        "checked_at": None, "cached": False,
        "reason": "Public-test offline request: RDAP is disabled.",
    }
    domain_age = registration.get("domain_age_days") if registration.get("status") == "available" else None
    brand_match, similarity_score = check_lookalike(domain)
    if not brand_match:
        initial_brand, initial_similarity = check_lookalike(qr_content)
        if initial_brand:
            brand_match, similarity_score = initial_brand, initial_similarity

    if include_ml:
        ml_features = extract_ml_features(final_url)
        feature_order = ['url_length', 'has_https', 'num_dots', 'num_hyphens', 'num_at',
                          'num_question_marks', 'num_equal', 'num_underscore', 'num_slash',
                          'has_ip', 'num_digits', 'num_subdomains']
        feature_vector = [[ml_features[f] for f in feature_order]]
        try:
            active_model = ml_model if ml_model is not None else get_ml_model()
            if active_model is None:
                raise ValueError("Experimental ML model is not available")
            classes = list(active_model.classes_)
            if (len(classes) != 2 or any(isinstance(label, (bool, np.bool_)) for label in classes)
                    or set(classes) != {-1, 1}):
                raise ValueError("Unexpected production model labels")
            probabilities = select_phishing_probability(
                # Verified training targets: -1 = phishing, 1 = benign.
                classes, active_model.predict_proba(feature_vector), phishing_label=-1
            )
            if len(probabilities) != 1:
                raise ValueError("Unexpected production prediction row count")
            phishing_probability = probabilities[0]
        except (ValueError, TypeError, AttributeError):
            logger.error("Production ML probability validation failed")
            raise HTTPException(status_code=503, detail="ML analysis unavailable; scan classification was not completed")
    else:
        phishing_probability = None

    rule_score, risk_breakdown = calculate_rule_contributions(
        domain_age, https_valid, brand_match, chain, final_url, original_url=qr_content
    )
    risk_reasons = []
    if any(item["name"] == "IP Address URL" for item in risk_breakdown):
        risk_reasons.append("URL uses an IP address instead of a domain name.")

    if include_ml:
        final_risk_score, score_explanation = calculate_hybrid_score(
            rule_score, phishing_probability
        )

        if final_risk_score >= 61:
            label = "unsafe"
        elif final_risk_score >= 31:
            label = "suspicious"
        else:
            label = "safe"
    else:
        # No substitute weights or thresholds: no hybrid verdict without verified ML.
        final_risk_score, score_explanation = None, {}
        # Transport-only warnings (like unencrypted HTTP) are preserved in risk_breakdown
        # and security checks, but do not produce misleading phishing verdicts.
        label = _offline_url_label(risk_breakdown)

    result["redirect_chain"] = chain
    result["final_url"] = final_url
    result["final_url_verified"] = False
    result["redirect_check_status"] = redirect_details["status"]
    result["redirect_check_details"] = redirect_details
    result["redirect_count"] = redirect_details["redirect_count"]
    result["domain"] = domain
    result["registered_domain"] = root_domain
    result["domain_age_days"] = domain_age
    result["https_valid"] = https_valid
    result["https_check_status"] = https_details["status"]
    result["https_check_details"] = https_details
    result["lookalike_brand"] = brand_match
    result["lookalike_score"] = similarity_score
    result["ml_phishing_probability"] = round(phishing_probability * 100, 2) if phishing_probability is not None else None
    result["rule_score"] = rule_score
    result["risk_breakdown"] = risk_breakdown
    result["score_explanation"] = score_explanation
    result["risk_reasons"] = risk_reasons
    result["risk_score"] = final_risk_score
    result["risk_label"] = label
    result["domain_registration"] = registration
    result["domain_registration_status"] = registration.get("status", "unavailable")
    result["risk_score_status"] = "available" if final_risk_score is not None else "unavailable"
    result["risk_score_reason"] = (
        "The existing 70/30 rule/ML heuristic score uses the available evidence. It is not a phishing probability; unavailable checks have not passed. Live reputation is separate and takes priority over this number."
        if final_risk_score is not None else
        "The combined 70/30 score is unavailable because experimental ML is excluded. Rule-based points describe the performed checks only; they are not a replacement overall score or a probability."
    )
    result["score_explanation"].update({
        "domain_registration": registration, "rule_score": rule_score,
        "risk_score_status": result["risk_score_status"],
        "risk_score_reason": result["risk_score_reason"],
    })
    result["network_analysis"] = network_analysis
    return result


def _url_unavailable_checks(result, include_ml, reputation):
    unavailable = []
    if result.get("https_check_status") in {"blocked", "unavailable"}:
        unavailable.append("TLS certificate verification")
    if result.get("redirect_check_status") in {"blocked", "unavailable", "failed"}:
        unavailable.append("Redirect destination")
    if result.get("domain_registration_status") not in {"available", "not_applicable"}:
        unavailable.append("Domain registration / RDAP")
    if not include_ml:
        unavailable.append("ML verdict")
    if reputation.get("status") not in {"threat", "clear"}:
        unavailable.append("Live reputation")
    return unavailable


@app.post("/scan")
async def scan_qr(file: UploadFile = File(...), current_user: str = Depends(get_current_user),
                  expected_vpa: str = Form(default=None, max_length=256),
                  private_scan: Annotated[bool, Form()] = False, request: Request = None):
    contents = await file.read(5 * 1024 * 1024 + 1)
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image exceeds the 5 MiB upload limit")
    allow_live = request is None or not request.headers.get("X-QR-Shield-Offline")
    return await scan_jobs.run(_analyze_scan, contents, current_user, expected_vpa, private_scan, allow_live)


def _analyze_scan(contents, current_user, expected_vpa, private_scan=False, allow_live=True):
    if restricted_demo():
        with SessionLocal() as quota_db:
            owner = quota_db.query(User).filter(User.email == current_user).first()
            if not owner:
                raise HTTPException(401, "User not found")
            if quota_db.query(ScanRecord).filter(ScanRecord.user_id == owner.id).count() >= 200:
                raise HTTPException(429, "This demo account has reached its 200-scan storage limit")
    if not contents:
        raise HTTPException(status_code=400, detail="Upload must contain a valid image")
    # Inspect dimensions before allocating an OpenCV decompressed image.
    try:
        with Image.open(io.BytesIO(contents)) as header:
            if header.width * header.height > 16_000_000:
                raise HTTPException(status_code=413, detail="Image exceeds the 16 megapixel limit")
            header.verify()
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError):
        raise HTTPException(status_code=400, detail="Upload must contain a valid image")
    nparr = np.frombuffer(contents, np.uint8)
    try:
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    except cv2.error:
        raise HTTPException(status_code=400, detail="Upload must contain a valid image")
    if img is None:
        raise HTTPException(status_code=400, detail="Upload must contain a valid image")

    try:
        qr_content = decode_qr(img)
    except (UnicodeError, cv2.error, ValueError):
        raise HTTPException(400,"QR content could not be decoded; upload a clear supported QR image")

    if not qr_content:
        return {"status": "error", "message": "No QR code found in the image"}
    if not isinstance(qr_content, str) or len(qr_content.encode("utf-8")) > MAX_QR_BYTES:
        raise HTTPException(413, "Decoded QR content exceeds the 16 KiB analysis limit")
    if qr_content.lower().startswith(("http://", "https://")):
        if len(qr_content)>MAX_URL_LENGTH:
            raise HTTPException(413, "URL exceeds the 8,192-character analysis limit")
        invalid_url = url_input_error(qr_content)
        if invalid_url:
            raise HTTPException(400, invalid_url)
    tampering_result = analyze_tampering(img)

    result = {"status": "success", "decoded_content": qr_content}

    if qr_content.lower().startswith(("http://", "https://")):
        analysis_url = _normalize_qr_url_for_analysis(qr_content)
        include_ml = is_ml_enabled()
        result.update(_analyze_url(analysis_url, include_ml=include_ml,
                                   allow_registration=allow_live, allow_network=allow_live))
        offline_label = _offline_url_label(result["risk_breakdown"])
        reputation = reputation_client.lookup(analysis_url) if allow_live else _disabled_reputation(
            "Public-test gateway: live reputation is disabled."
        )
        url_verdict = website_verdict(offline_label, reputation)
        unavailable = _url_unavailable_checks(result, include_ml, reputation)
        integrity_warning = (
            tampering_result.get("tampering_score", 0) > 0
            or bool(tampering_result.get("tampering_reasons"))
        )
        overall_risk = deterministic_overall_risk(
            offline_label, reputation, unavailable, result.get("risk_breakdown"), integrity_warning
        )
        result.update({
            "analysis_source": "qr",
            "live_reputation": reputation,
            "website_verdict": url_verdict,
            "overall_risk": overall_risk,
            "offline_verdict": website_verdict(offline_label, None),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "unavailable_checks": unavailable,
            "reputation_privacy_notice": PRIVACY_NOTICE,
            "reputation_accuracy_notice": ACCURACY_NOTICE,
        })
        if not include_ml:
            result["ml_status"] = "excluded"
            result["ml_note"] = (
                "ML is excluded from QR risk scoring: the production model is experimental, "
                "uncalibrated, and exhibits false-positive bias on HTTPS URLs. No artificial score is added."
            )
        score_explanation = result.get("score_explanation")
        result["score_explanation"] = {
            **(score_explanation if isinstance(score_explanation, dict) else {}),
            "analysis_source": "qr",
            "offline_risk_label": offline_label,
            "live_reputation": reputation,
            "overall_risk": overall_risk,
            "ml_status": result.get("ml_status", "used"),
            "ml_note": result.get("ml_note"),
        }
    else:
        upi_details = parse_upi_payment_uri(qr_content)
        if upi_details is not None:
            result["upi_details"] = upi_details
            result["upi_comparison"] = compare_upi_payment(upi_details, expected_vpa)
        upi_analysis = analyze_upi(qr_content)
        if upi_analysis is not None:
            result["upi_analysis"] = upi_analysis

    result["tampering_score"] = tampering_result["tampering_score"]
    result["tampering_reasons"] = tampering_result["tampering_reasons"]

    return _save_analysis(result, current_user, private_scan)


class WebsiteCheck(BaseModel):
    url: StrictStr


@app.post("/website/check")
async def check_website(payload: WebsiteCheck, request: Request, current_user: str = Depends(get_current_user)):
    # A public-test gateway can only disable live reputation, never enable it.
    allow_live = not request.headers.get("X-QR-Shield-Offline")
    return await scan_jobs.run(_analyze_website, payload.url, current_user, allow_live)


def _analyze_website(raw_url, current_user, allow_live=True):
    url = normalize_website_url(raw_url)
    if restricted_demo():
        with SessionLocal() as db:
            owner = db.query(User).filter(User.email == current_user).first()
            if not owner:
                raise HTTPException(401, "User not found")
            if db.query(ScanRecord).filter(ScanRecord.user_id == owner.id).count() >= 200:
                raise HTTPException(429, "This demo account has reached its 200-scan storage limit")
    result = _analyze_url(url, include_ml=False, allow_registration=allow_live,
                          allow_network=allow_live)
    ml_note = ("ML is excluded from this website verdict: training and production differ in "
               "how the IP-address feature is calculated. The existing model is experimental "
               "and uncalibrated. No replacement score has been invented.")
    offline_label = _offline_url_label(result["risk_breakdown"])
    phishing_findings = _offline_url_findings(result["risk_breakdown"])
    transport_findings = [
        item for item in result["risk_breakdown"]
        if item.get("category") == "transport" or item["name"] in {"HTTP Connection", "HTTPS Downgrade Redirect", "HTTPS Validation Failed"}
    ]
    if phishing_findings:
        explanation = "Offline URL rules found warning signs. These are indicators, not proof of phishing."
        action = "Don't enter passwords or payment details. Verify the website independently."
    elif transport_findings:
        explanation = ("This website uses unencrypted HTTP rather than HTTPS. Information sent over this connection is not protected in transit. "
                       "Insecure transport is a transport risk, not proof of phishing.")
        action = "Avoid entering passwords or payment details over an unencrypted connection. Verify the website independently."
    else:
        explanation = (
            "No major warning signs were found by the available offline rules. "
            "Website legitimacy could not be verified; unavailable checks have not passed."
        )
        action = "Verify the address and sender before logging in, paying, or sharing information."
    reputation = reputation_client.lookup(url) if allow_live else _disabled_reputation(
        "Public-test gateway: live reputation is disabled."
    )
    verdict = website_verdict(offline_label, reputation)
    unavailable = _url_unavailable_checks(result, False, reputation)
    overall_risk = deterministic_overall_risk(
        offline_label, reputation, unavailable, result.get("risk_breakdown"), False
    )
    checks = [
        {"name": "URL structure", "status": "checked", "detail": "Offline syntax and URL-structure rules were applied."},
        {"name": "Hostname and registered domain", "status": "checked", "detail": "Parsed using the bundled public-suffix data; this does not establish site ownership."},
        {"name": "Brand impersonation", "status": "checked", "detail": "Compared with the existing protected-brand rules; this does not verify ownership."},
        {"name": "URL scheme", "status": "checked", "detail": "The URL scheme was parsed; HTTP is unencrypted and HTTPS syntax alone does not establish legitimacy."},
        {"name": "HTTPS certificate", "status": result["https_check_status"],
         "detail": result["https_check_details"]["reason"]},
        {"name": "Redirect analysis", "status": result["redirect_check_status"],
         "detail": result["redirect_check_details"]["reason"]},
        {"name": "Domain registration / RDAP", "status": result["domain_registration_status"],
         "detail": result["domain_registration"]["reason"] + " Domain age does not verify website safety."},
    ] + [{"name": "ML verdict", "status": "not_checked", "detail": ml_note}]
    result.update({
        "status": "success", "submitted_url": raw_url, "normalized_url": url,
        "decoded_content": url, "analysis_source": "website",
        "network_analysis": result["network_analysis"],
        "ml_status": "excluded", "ml_note": ml_note,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "security_checks": checks, "unavailable_checks": unavailable,
        "live_reputation": reputation, "website_verdict": verdict,
        "overall_risk": overall_risk,
        "offline_verdict": website_verdict(offline_label, None),
        "explanation": verdict["explanation"], "recommended_action": verdict["action"],
        "score_explanation": {**result["score_explanation"], "analysis_source": "website", "ml_status": "excluded", "ml_note": ml_note,
                              "submitted_url": raw_url, "explanation": explanation,
                              "recommended_action": action, "security_checks": checks,
                              "live_reputation": reputation, "offline_risk_label": offline_label,
                              "overall_risk": overall_risk},
    })
    return _save_analysis(result, current_user)


def _save_analysis(result, current_user, private_scan=False):
    # Save this scan to the database
    db = SessionLocal()
    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        db.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if private_scan:
        db.close()
        result["scan_id"] = None
        return result
    record = ScanRecord(
        user_id=user.id,
        decoded_content=result.get("decoded_content"),
        final_url=result.get("final_url"),
        domain=result.get("domain"),
        risk_score=result.get("risk_score"),
        risk_label=result.get("risk_label"),
        tampering_score=result.get("tampering_score"),
        tampering_reasons=None if "tampering_reasons" not in result else json.dumps(result["tampering_reasons"]),
        redirect_chain=json.dumps(result.get("redirect_chain", [])),
        domain_age_days=result.get("domain_age_days"),
        https_valid=None if result.get("https_valid") is None else int(result.get("https_valid")),
        lookalike_brand=result.get("lookalike_brand"),
        lookalike_score=None if result.get("lookalike_score") is None else str(result.get("lookalike_score")),
        ml_phishing_probability=None if result.get("ml_phishing_probability") is None else str(result.get("ml_phishing_probability")),
        rule_score=result.get("rule_score"),
        risk_breakdown=None if "risk_breakdown" not in result else json.dumps(result["risk_breakdown"]),
        score_explanation=None if "score_explanation" not in result else json.dumps(result["score_explanation"])
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    db.close()

    result["scan_id"] = record.id
    return result


def _report_text(value, fallback="Unavailable"):
    if value is None or value == "":
        return fallback
    return str(value)


def _report_paragraph(value, style):
    return Paragraph(escape(_report_text(value)).replace("\n", "<br/>"), style)


def _report_table(title, rows, styles, split_in_row=False):
    data = [[Paragraph("<b>" + escape(title) + "</b>", styles["table_heading"]), ""]]
    data.extend([
        [_report_paragraph(label, styles["label"]), _report_paragraph(value, styles["body"])]
        for label, value in rows
    ])
    table = Table(data, colWidths=[55 * mm, 115 * mm], repeatRows=1, splitInRow=int(split_in_row))
    table.setStyle(TableStyle([
        ("SPAN", (0, 0), (1, 0)),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeaf6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#4f3575")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd6ea")),
        ("INNERGRID", (0, 1), (-1, -1), 0.25, colors.HexColor("#eeeaf2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _load_stored_json(value, expected_type):
    if not value:
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, expected_type) else None


def _report_overall_risk(metadata):
    """Validate persisted deterministic verdict metadata for PDF presentation."""
    if not isinstance(metadata, dict):
        return None
    stored = metadata.get("overall_risk")
    if not isinstance(stored, dict):
        return None
    presentation = {
        "known_dangerous": ("HIGH", "DANGEROUS", "danger", "#B4233E"),
        "suspicious": ("MEDIUM", "SUSPICIOUS", "warning", "#92400e"),
        "integrity_review": ("REVIEW REQUIRED", "SUSPICIOUS", "warning", "#92400e"),
        "inconclusive": ("INCONCLUSIVE", "EVIDENCE UNAVAILABLE", "neutral", "#475569"),
        "transport_warning": ("CAUTION", "CONNECTION WARNING", "warning", "#92400e"),
        "low": ("LOW", "NO KNOWN THREATS", "safe", "#166534"),
    }
    code = stored.get("code")
    if code not in presentation:
        return None
    reputation = current_reputation(metadata.get("live_reputation"))
    if code == "known_dangerous" and reputation.get("status") != "threat":
        code = "inconclusive"
    elif code in {"low", "transport_warning"} and reputation.get("status") != "clear":
        code = "inconclusive"
    if code != stored.get("code"):
        explanation = "Important live reputation evidence is no longer current. Unavailable checks have not passed."
        action = "Verify the address and sender independently before logging in, paying, or sharing information."
    else:
        explanation, action = stored.get("explanation"), stored.get("action")
    if not isinstance(explanation, str) or not isinstance(action, str):
        return None
    if len(explanation) > 4000 or len(action) > 2000:
        return None
    level, label, tone, color = presentation[code]
    return {
        "code": code, "level": level, "label": label, "tone": tone,
        "color": color, "explanation": explanation, "action": action,
    }


def _report_summary(record, redirect_chain, tampering_reasons):
    metadata = _load_stored_json(getattr(record, "score_explanation", None), dict) or {}
    if metadata.get("analysis_source") in {"website", "qr"}:
        overall_risk = _report_overall_risk(metadata)
        if overall_risk:
            summary = overall_risk["level"] + ": " + overall_risk["explanation"]
            summary += " Recommended action: " + overall_risk["action"]
            if metadata.get("analysis_source") == "qr" and tampering_reasons:
                integrity_label = "QR integrity warning: " if overall_risk["code"] == "integrity_review" else "The QR image also has a separate integrity warning: "
                summary += " " + integrity_label + "; ".join(tampering_reasons) + "."
            return summary
        summary = website_verdict(
            metadata.get("offline_risk_label", record.risk_label),
            metadata.get("live_reputation"),
        )["explanation"]
        if metadata.get("analysis_source") == "qr" and tampering_reasons:
            summary += " QR integrity indicators also require review."
        return summary
    findings = []
    if hostname_is_ip(record.final_url):
        findings.append("the URL uses an IP address instead of a domain name")
    if record.https_valid == 0:
        findings.append("the URL is not using HTTPS")
    if record.domain_age_days is not None and record.domain_age_days < 30:
        findings.append("the domain is newly registered")
    if record.lookalike_brand:
        findings.append("a possible lookalike brand was detected")
    if record.ml_phishing_probability is not None:
        try:
            if float(record.ml_phishing_probability) >= 50:
                findings.append("the experimental, uncalibrated ML estimate is elevated (not proof of phishing)")
        except (TypeError, ValueError):
            pass
    if tampering_reasons:
        findings.append("QR integrity indicators require review")
    if str(record.risk_label or "").lower() == "safe":
        hops = max(len(redirect_chain) - 1, 0)
        redirect_text = ""
        if hops == 1:
            redirect_text = "1 redirect hop was observed. "
        elif hops > 1:
            redirect_text = f"{hops} redirect hops were observed. "
        if hostname_is_ip(record.final_url):
            return redirect_text + "Finding: the URL uses an IP address instead of a domain name."
        return redirect_text + ("Findings: " + "; ".join(findings) + ". " if findings else "No additional findings were reported by the available checks. ") + "Unavailable checks have not passed. A low calculated score does not guarantee safety."
    if findings:
        return "Findings: " + "; ".join(findings) + "."
    if record.risk_label:
        return "Analysis completed without additional findings from the available checks."
    return "The QR content was decoded successfully; URL security checks do not apply to this content."


def _build_report(record):
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    metadata = _load_stored_json(record.score_explanation, dict) or {}
    analysis_source = metadata.get("analysis_source")
    website = analysis_source == "website"
    qr_url = analysis_source == "qr"
    has_reputation_assessment = website or qr_url
    deterministic_risk = _report_overall_risk(metadata)
    # Presentation only: match the UI's existing human verdict and conflict rules.
    def numeric(value):
        if value is None or isinstance(value, bool) or not str(value).strip():
            return None
        try:
            number = float(value)
            return number if float("-inf") < number < float("inf") else None
        except (TypeError, ValueError, OverflowError):
            return None

    ml = numeric(record.ml_phishing_probability)
    rule = numeric(record.rule_score)
    score = numeric(record.risk_score)
    conflict = ml is not None and rule is not None and (
        (rule == 0 and ml >= 80) or (rule >= 60 and ml <= 20))
    if not record.final_url or ml is None or not 0 <= ml <= 100 or conflict:
        human_verdict = "Can't tell"
        action = "Don't pay or log in. Verify the sender first."
        verdict_color = "#475569"
    elif score is not None and 0 <= score < 31:
        human_verdict = "Likely safe"
        action = "You can open this."
        verdict_color = "#166534"
    else:
        human_verdict = "Be careful"
        action = "Don't enter passwords or payment details. Open only if you trust the sender."
        verdict_color = "#92400e"
    if has_reputation_assessment:
        reputation = current_reputation(metadata.get("live_reputation"))
        if deterministic_risk:
            human_verdicts = {
                "known_dangerous": "Known Dangerous",
                "suspicious": "Be careful",
                "integrity_review": "Be careful",
                "transport_warning": "Be careful",
                "inconclusive": "Can't tell",
                "low": "Likely safe",
            }
            human_verdict = human_verdicts[deterministic_risk["code"]]
            action = deterministic_risk["action"]
            verdict_color = deterministic_risk["color"]
        else:
            website_display = website_verdict(metadata.get("offline_risk_label", record.risk_label), reputation)
            human_verdict, action = website_display["title"], website_display["action"]
            verdict_color = {"danger": "#B4233E", "warning": "#92400e", "safe": "#166534", "neutral": "#475569"}[website_display["tone"]]
    upi_analysis = analyze_upi(record.decoded_content) if not record.final_url else None
    upi_banner = upi_intent_banner(parse_upi_payment_uri(record.decoded_content), upi_analysis) if upi_analysis is not None else None
    if upi_banner:
        human_verdict, action = upi_banner["title"], upi_banner["body"]
        verdict_color = "#B4233E" if upi_banner["state"] in ("collect", "conflict") else "#92400e" if upi_banner["state"] == "pay" else "#475569"
        # The built-in Helvetica fonts lack the Indian rupee character.
        try:
            ps2tt("QRShieldUpiHeader")
        except ValueError:
            font_candidates = [
                os.path.join(os.path.dirname(__file__), "fonts", "Carlito-Bold.ttf"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "fonts", "Carlito-Bold.ttf"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "Carlito-Bold.ttf"),
                os.path.join("backend", "fonts", "Carlito-Bold.ttf"),
            ]
            font_path = next((p for p in font_candidates if os.path.exists(p)), None)
            if font_path:
                if "QRShieldUpiHeader" not in pdfmetrics.getRegisteredFontNames():
                    pdfmetrics.registerFont(TTFont("QRShieldUpiHeader", font_path))
                pdfmetrics.registerFontFamily("QRShieldUpiHeader", normal="QRShieldUpiHeader", bold="QRShieldUpiHeader", italic="QRShieldUpiHeader", boldItalic="QRShieldUpiHeader")
                for b in (0, 1):
                    for i in (0, 1):
                        addMapping("QRShieldUpiHeader", b, i, "QRShieldUpiHeader")
    scanned_at = record.scanned_at
    if scanned_at:
        utc_time = scanned_at.replace(tzinfo=timezone.utc) if scanned_at.tzinfo is None else scanned_at.astimezone(timezone.utc)
        timestamp = utc_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        timestamp = "Timestamp unavailable"
    qr_type = "Website Link" if website else "URL" if record.final_url else "UPI" if upi_analysis is not None else "Text / other"
    ml_status = metadata.get("ml_status")
    valid_ml_value = ml is not None and 0 <= ml <= 100
    if ml_status == "excluded":
        ml_status_text = "Not used — experimental ML was excluded."
    elif valid_ml_value:
        ml_status_text = "Estimate recorded — experimental and uncalibrated."
    elif not record.final_url:
        ml_status_text = "Not applicable to non-URL content."
    else:
        ml_status_text = "Unavailable — no ML estimate was stored."
    ml_limitation = "ML check is experimental. "
    if ml_status == "excluded":
        ml_limitation += "It was not used for this assessment. "
    ml_limitation += "Heuristic result — not a guarantee."
    has_upi_font = "QRShieldUpiHeader" in pdfmetrics.getRegisteredFontNames()
    styles.add(ParagraphStyle(
        name="human_verdict", parent=styles["Heading1"],
        fontName="QRShieldUpiHeader" if (upi_banner and has_upi_font) else "Helvetica-Bold",
        fontSize=30 if upi_banner and upi_banner["state"] in ("collect", "conflict") else 24,
        leading=35 if upi_banner and upi_banner["state"] in ("collect", "conflict") else 28,
        textColor=colors.HexColor(verdict_color), spaceAfter=6, keepWithNext=True
    ))
    styles.add(ParagraphStyle(
        name="human_action", parent=styles["BodyText"], fontSize=10, leading=14,
        spaceAfter=6, keepWithNext=True
    ))
    styles.add(ParagraphStyle(
        name="report_title", parent=styles["Title"], fontSize=19,
        leading=23, textColor=colors.HexColor("#3d285d"), alignment=TA_CENTER,
        spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        name="report_subtitle", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#766d82"), alignment=TA_CENTER, spaceAfter=16
    ))
    styles.add(ParagraphStyle(
        name="section", parent=styles["Heading2"], fontSize=12,
        leading=15, textColor=colors.HexColor("#4f3575"), spaceBefore=14,
        spaceAfter=7
    ))
    styles.add(ParagraphStyle(
        name="body", parent=styles["BodyText"], fontSize=8.5, leading=11,
        textColor=colors.HexColor("#2d2d3a")
    ))
    styles.add(ParagraphStyle(
        name="label", parent=styles["BodyText"], fontSize=8.5, leading=11,
        textColor=colors.HexColor("#756d80")
    ))
    styles.add(ParagraphStyle(
        name="table_heading", parent=styles["BodyText"], fontSize=10,
        leading=12, textColor=colors.HexColor("#4f3575")
    ))
    styles.add(ParagraphStyle(
        name="notice", parent=styles["BodyText"], fontSize=7.5, leading=10,
        textColor=colors.HexColor("#5d5668")
    ))

    document = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm
    )
    story = [
        _report_paragraph(human_verdict, styles["human_verdict"]),
        _report_paragraph(action, styles["human_action"]),
        _report_paragraph(timestamp + " · " + qr_type, styles["body"]),
        Spacer(1, 6),
        Paragraph("<b>Limitations</b><br/>" + escape(
            ("The page was not opened in a browser and its body was not downloaded. When enabled, bounded DNS, TLS, and HTTP response-header checks may run; Google Safe Browsing receives the full URL and RDAP receives only the registered domain. " if website else
             "The QR destination page was not opened in a browser and its body was not downloaded. When enabled, bounded DNS, TLS, and HTTP response-header checks may run; Google Safe Browsing receives the URL and RDAP receives only the registered domain. Non-URL QR content is not sent to these website checks. " if qr_url else
             "Offline analysis only. No links were opened or fetched. ") +
            ("Optional RDAP registration status is reported separately; only the registered domain is shared. " if isinstance(metadata.get("domain_registration"), dict) else "") +
            ml_limitation
        ), styles["body"]),
        Spacer(1, 16),
        Paragraph("QR Shield", styles["report_title"]),
        Paragraph("Website Safety Checker" if website else "QR Code Phishing Detection &amp; Safety Scanner", styles["report_subtitle"]),
        Paragraph("Security Analysis Report", styles["section"]),
    ]
    risk_label = str(record.risk_label or "").lower()
    verdict = {
        "safe": "Low Calculated Risk",
        "suspicious": "Suspicious QR Code",
        "unsafe": "High-Risk QR Code",
    }.get(risk_label, "Analysis Incomplete")
    if upi_analysis is not None:
        verdict = "UPI content - recipient unverified (no URL risk score)"
    if has_reputation_assessment:
        verdict = human_verdict
    story.append(Paragraph(escape("Current scan policy: " + (WEBSITE_NETWORK_NOTICE if website else network_notice(restricted_demo())) + " Historical reports retain their recorded observations; downloading a report does not reverify its destination."), styles["body"]))
    story.append(_report_table("Report Overview", [
        ("Report ID / Scan ID", record.id),
        ("Scan date and time", record.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC") if record.scanned_at else "Unavailable"),
        ("Overall verdict", verdict),
        ("Overall risk score", "Not calculated (ML excluded)" if ml_status == "excluded" else f"{record.risk_score}/100" if record.risk_score is not None else "Unavailable"),
    ], styles))

    stored_chain = _load_stored_json(record.redirect_chain, list) or []
    redirect_chain = [
        item for index, item in enumerate(stored_chain)
        if item and item not in stored_chain[:index]
    ]
    tampering_reasons = _load_stored_json(record.tampering_reasons, list) or []

    if record.final_url:
        stored_lookalike = "None detected"
        if record.lookalike_brand:
            stored_lookalike = f"Possible {record.lookalike_brand} lookalike"
            if record.lookalike_score is not None:
                stored_lookalike += f" (similarity: {record.lookalike_score}%)"
        story.append(Paragraph("URL Analysis", styles["section"]))
        story.append(_report_table("URL Analysis", [
            ("Submitted URL" if website else "Decoded Content", metadata.get("submitted_url", record.decoded_content) if website else record.decoded_content),
            ("Recorded destination (not reverified)", record.final_url),
            ("Original URL", record.decoded_content),
            ("Hostname", record.domain),
            ("Registered domain", registered_domain(record.final_url) or "Unavailable"),
            ("URL scheme", urlparse(record.final_url).scheme.upper() or "Unavailable"),
            ("Redirect Hops", len(redirect_chain)-1 if len(redirect_chain)>1 else "Unavailable (no verified redirect data)"),
        ], styles, split_in_row=website or qr_url))
        registration = metadata.get("domain_registration")
        if isinstance(registration, dict):
            story.append(_report_table("Domain Information", [
                ("Registered domain", registration.get("registered_domain")),
                ("Registration date (UTC)", registration.get("registration_date")),
                ("Domain age at scan", f"{record.domain_age_days} days" if record.domain_age_days is not None else "Unavailable"),
                ("RDAP lookup status", registration.get("status")),
                ("RDAP details", registration.get("reason")),
                ("Observation time", registration.get("checked_at")),
                ("Privacy and limitations", "Only the registered domain is sent to the registration service, never the URL path or query. Domain age is not proof of safety. This report does not recheck registration data."),
            ], styles))
        if "risk_score_status" in metadata:
            story.append(_report_table("Heuristic Risk Assessment", [
                ("Combined score", f"{record.risk_score}/100" if record.risk_score is not None else "Unavailable"),
                ("Scoring status", metadata.get("risk_score_status")),
                ("Why", metadata.get("risk_score_reason")),
                ("Rule-based points (performed checks only)", metadata.get("rule_score")),
                ("Meaning", "Heuristic indicators, not a calibrated phishing probability. Missing checks have not passed; a no-match reputation result is not zero risk."),
            ], styles))
        story.append(Paragraph("Security Checks", styles["section"]))
        story.append(_report_table("Security Checks", [
            ("Transport protection", "HTTP detected - This URL does not use HTTPS." if urlparse(record.final_url).scheme.lower() == "http" else "HTTPS verified" if record.https_valid == 1 else "TLS verification failed" if record.https_valid == 0 else "Verification unavailable (historical check details not stored)"),
            ("Domain Age", f"{record.domain_age_days} days" if record.domain_age_days is not None else "Unavailable"),
            ("Lookalike Brand", stored_lookalike),
            ("Experimental ML status", ml_status_text),
            ("Experimental ML Risk Estimate (Uncalibrated)", f"{ml:g}%" if valid_ml_value else "Unavailable"),
        ], styles))
        if has_reputation_assessment:
            story.append(_report_table("Live reputation", [
                ("Provider", reputation.get("provider", "Google Safe Browsing")),
                ("Status", {"threat": "Known threat-list match (potential risk)", "clear": "No known threats detected (not proof of safety)", "disabled": "Offline only - not checked", "unavailable": "Unable to verify"}.get(reputation.get("status"), "Not checked")),
                ("Details", reputation.get("reason")),
                ("Threat categories", ", ".join(reputation.get("threat_types", [])) or "None reported / not checked"),
                ("Provider check time", reputation.get("checked_at")),
                ("Observation valid until", reputation.get("verdict_expires_at")),
                ("Cached observation", "Yes" if reputation.get("cached") else "No"),
            ], styles))
            story.append(_report_paragraph(ACCURACY_NOTICE, styles["body"]))
            if reputation.get("status") == "threat":
                story.append(Paragraph('<link href="' + ADVISORY_URL + '">Advisory provided by Google</link>', styles["body"]))
                story.append(Paragraph('Learn about <link href="https://developers.google.com/search/docs/monitor-debug/security/social-engineering">social engineering</link>, <link href="https://developers.google.com/search/docs/monitor-debug/security/malware">malware and unwanted software</link>, and <link href="https://developers.google.com/android/play-protect/potentially-harmful-applications">harmful applications</link>.', styles["body"]))
            story.append(_report_table("Offline website checks" if website else "Offline URL checks", [
                (str(item.get("name", "Check")), str(item.get("status", "not_checked")).replace("_", " ") + ": " + str(item.get("detail", "Not checked")))
                for item in metadata.get("security_checks", []) if isinstance(item, dict)
            ], styles))
            if website:
                story.append(_report_paragraph(metadata.get("ml_note"), styles["body"]))
        story.append(Paragraph(
            "The experimental ML estimate is uncalibrated and may produce false positives and false negatives. "
            "It is not proof of phishing or safety. Unavailable checks have not passed. HTTPS protects transport, not website legitimacy.", styles["body"]
        ))
        story.append(Paragraph("Risk Breakdown", styles["section"]))
        stored_breakdown = _load_stored_json(record.risk_breakdown, list)
        if stored_breakdown is None:
            story.append(Paragraph(
                "A detailed risk breakdown was not stored for this scan.",
                styles["body"]
            ))
        elif not stored_breakdown:
            story.append(Paragraph(
                "No rule-based risk indicators were triggered.",
                styles["body"]
            ))
        else:
            breakdown_rows = []
            for item in stored_breakdown:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                reason = item.get("reason")
                points = item.get("points")
                if name is None or reason is None or not isinstance(points, (int, float)):
                    continue
                breakdown_rows.append((f"{name} (+{points:g} rule points)", reason))
            if breakdown_rows:
                story.append(_report_table("Rule Contributions", breakdown_rows, styles))
            else:
                story.append(Paragraph(
                    "A detailed risk breakdown was not available for this scan.",
                    styles["body"]
                ))

        stored_score_explanation = _load_stored_json(record.score_explanation, dict)
        if stored_score_explanation is not None:
            rule_score = stored_score_explanation.get("rule_score")
            rule_weight = stored_score_explanation.get("rule_weight")
            rule_contribution = stored_score_explanation.get("rule_contribution")
            ml_probability = stored_score_explanation.get("ml_probability")
            ml_weight = stored_score_explanation.get("ml_weight")
            ml_contribution = stored_score_explanation.get("ml_contribution")
            calculated_score = stored_score_explanation.get("calculated_score")
            final_score = stored_score_explanation.get("final_score")
            if all(isinstance(value, (int, float)) for value in (
                rule_score, rule_weight, rule_contribution, ml_probability,
                ml_weight, ml_contribution, calculated_score, final_score
            )):
                story.append(_report_table("Hybrid Risk Calculation", [
                    ("Rule-based analysis", f"{rule_score:g} x {rule_weight * 100:g}% = {rule_contribution:g}"),
                    ("Machine-learning analysis", f"{ml_probability * 100:g}% x {ml_weight * 100:g}% = {ml_contribution:g}"),
                    ("Calculated score before rounding and cap", f"{calculated_score:g}/100"),
                    ("Final displayed score (rounded, capped at 100)", f"{final_score:g}/100"),
                ], styles))
        if redirect_chain:
            story.append(Paragraph("Redirect Journey", styles["section"]))
            story.append(_report_table("Redirect Journey", [
                ("Original URL" if index == 0 else "Final Destination" if index == len(redirect_chain) - 1 else "Redirect", item)
                for index, item in enumerate(redirect_chain)
            ], styles, split_in_row=website))
    else:
        story.append(Paragraph("QR Content", styles["section"]))
        if upi_analysis is None:
            story.append(_report_table("QR Content", [("Decoded Content", record.decoded_content)], styles))
        else:
            # Re-analyze recorded content, not payment identity; no schema or network changes.
            # Short rows allow even historical oversized values to paginate safely.
            rows = [("QR content type", upi_analysis["content_type"]),
                    ("Payment direction", "Send money (on approval in a payment app)" if upi_analysis["payment_direction"] == "send_money" else "Unverified"),
                    ("Decoded content", record.decoded_content)]
            for key, label in [("payee_vpa", "Payee UPI ID"), ("payee_name", "QR-declared payee name"),
                               ("amount", "Amount (exact encoded text)"), ("currency", "Currency"),
                               ("transaction_note", "Transaction note"), ("transaction_reference", "Transaction reference")]:
                field = upi_analysis["fields"][key]
                value = " | ".join(item if item else "(blank)" for item in field["encoded_values"]) if "encoded_values" in field else field["value"]
                rows.append((label, (value if value is not None else "Unavailable" if field["status"] == "unavailable" else "Not provided") +
                             " [" + field["status"].replace("_", " ") + "]"))
            bounded_rows = []
            for label, value in rows:
                lines = []
                for line in str(value).split("\n"):
                    # Control characters are displayed as escaped text, not PDF markup.
                    line = "".join(char if ord(char) >= 32 else repr(char)[1:-1] for char in line)
                    lines.extend(line[index:index + 80] for index in range(0, max(len(line), 1), 80))
                for index in range(0, len(lines), 8):
                    bounded_rows.append((label if index == 0 else label + " (continued)", "\n".join(lines[index:index + 8])))
            story.append(_report_table("UPI QR Analysis - unverified recipient", bounded_rows, styles))
            story.append(Paragraph(escape(upi_analysis["payment_explanation"]), styles["body"]))
            story.append(Paragraph("UPI Security Notes", styles["section"]))
            for item in upi_analysis["warnings"]:
                story.append(Paragraph(escape(item["message"]), styles["body"]))
            story.append(Paragraph(escape(upi_analysis["warning_context"]), styles["body"]))
            for note in upi_analysis["safety_notes"]:
                story.append(Paragraph(escape(note), styles["body"]))

    story.append(Paragraph("QR Integrity", styles["section"]))
    if website:
        story.append(Paragraph("Not applicable: a website link was submitted; no QR image was analyzed.", styles["body"]))
        story.append(Paragraph("Recommendations", styles["section"]))
        story.append(_report_paragraph(action, styles["body"]))
    else:
        story.append(_report_table("QR Integrity", [
            ("Tampering Score", f"{record.tampering_score}/85" if record.tampering_score is not None else "Unavailable"),
            ("Tampering Status", "Review needed" if tampering_reasons else "No tampering detected" if record.tampering_reasons else "Unavailable"),
            ("Tampering Reasons", "; ".join(tampering_reasons) if tampering_reasons else "None detected" if record.tampering_reasons else "Unavailable"),
        ], styles))
    story.append(Paragraph("Analysis Summary", styles["section"]))
    story.append(Paragraph(escape(_report_summary(record, redirect_chain, tampering_reasons)), styles["body"]))
    story.append(Spacer(1, 12))
    notice = Table([[
        Paragraph("<b>Security Notice</b><br/>QR Shield applies offline URL rules and QR-image integrity checks; optional reputation, TLS, and bounded redirect-header checks run only when enabled and permitted. Experimental ML is not used unless explicitly enabled. Results are indicators, not guarantees. Verify unexpected or sensitive requests before proceeding.", styles["notice"])
    ]], colWidths=[170 * mm])
    notice.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f0fa")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d9cdea")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(notice)

    def add_page_number(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#8b8195"))
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return buffer


@app.get("/report/{scan_id}")
async def download_report(scan_id: int, current_user: str = Depends(get_report_user)):
    return await report_jobs.run(_download_report, scan_id, current_user)


def _download_report(scan_id, current_user):
    db = SessionLocal()
    user = db.query(User).filter(User.email == current_user).first()
    record = None
    if user:
        record = db.query(ScanRecord).filter(
            ScanRecord.id == scan_id,
            ScanRecord.user_id == user.id
        ).first()
    db.close()
    if not user or not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    pdf = _build_report(record)
    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=qr-shield-report-{record.id}.pdf"}
    )


@app.delete("/history")
async def clear_history(current_user: str = Depends(get_current_user)):
    return await history_jobs.run(_clear_history, current_user)


def _clear_history(current_user):
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == current_user).first()
        if not user:
            raise HTTPException(401, "User not found")
        deleted = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).delete(synchronize_session=False)
        db.commit()
        return {"deleted_count": deleted}


@app.get("/history")
async def get_history(current_user: str = Depends(get_current_user)):
    return await history_jobs.run(_get_history, current_user)


@app.get("/history/summary")
async def get_history_summary(current_user: str = Depends(get_current_user)):
    return await history_jobs.run(_history_view, current_user, None)


@app.get("/history/page")
async def get_history_page(limit: int = Query(50, ge=1, le=100),
                           cursor: int = Query(None, ge=1, le=9223372036854775807),
                           snapshot: int = Query(None, ge=0, le=9223372036854775807),
                           category: str = Query("all", pattern="^(all|safe|suspicious|unsafe|non_url|unclassified)$"),
                           current_user: str = Depends(get_current_user)):
    return await history_jobs.run(_history_view, current_user, (limit, cursor, snapshot, category))


def _history_view(current_user, pagination):
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == current_user).first()
        if not user:
            raise HTTPException(401, "User not found")
        if pagination is None:
            return history_views.summary(db, ScanRecord, user.id)
        return history_views.page(db, ScanRecord, user.id, *pagination)


def _get_history(current_user):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == current_user).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        records = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).limit(5001).yield_per(100)
        history = []
        response_bytes = 2
        for r in records:
            if len(history)>=5000:
                raise HTTPException(413, "History exceeds the 5,000-record response limit; contact the local administrator")
            entry = {
                "id": r.id,
                "decoded_content": r.decoded_content,
                "final_url": r.final_url,
                "domain": r.domain,
                "risk_score": r.risk_score,
                "risk_label": r.risk_label,
                "risk_breakdown": _load_stored_json(r.risk_breakdown, list),
                "score_explanation": _load_stored_json(r.score_explanation, dict),
                "tampering_score": r.tampering_score,
                "tampering_reasons": _load_stored_json(r.tampering_reasons, list),
                "redirect_chain": _load_stored_json(r.redirect_chain, list),
                "domain_age_days": r.domain_age_days,
                "https_valid": r.https_valid,
                "lookalike_brand": r.lookalike_brand,
                "lookalike_score": r.lookalike_score,
                "ml_phishing_probability": r.ml_phishing_probability,
                "rule_score": r.rule_score,
                "scanned_at": str(r.scanned_at)
            }
            response_bytes += len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
            if response_bytes>MAX_HISTORY_BYTES:
                raise HTTPException(413, "History exceeds the 8 MiB response limit; contact the local administrator")
            history.append(entry)
        return history
    finally:
        db.close()


class UserCreate(BaseModel):
    email: str
    password: str


@app.post("/register")
def register(user: UserCreate):
    if restricted_demo():
        raise HTTPException(403, "Public registration is disabled for the restricted demonstration")
    if len(user.password.encode('utf-8')) > 72:
        return {"status": "error", "message": "Password must be at most 72 UTF-8 bytes"}
    db = SessionLocal()
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        db.close()
        return {"status": "error", "message": "Email already registered"}

    strength_level, strength_message = check_password_strength(user.password)

    if strength_level == "weak":
        db.close()
        return {"status": "error", "message": strength_message, "password_strength": strength_level}

    hashed_pw = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.close()
    return {
        "status": "success",
        "message": "User registered successfully",
        "password_strength": strength_level
    }


@app.post("/login")
def login(user: UserCreate):
    if len(user.password.encode('utf-8')) > 72:
        return {"status": "error", "message": "Invalid email or password"}
    db = SessionLocal()
    db_user = db.query(User).filter(User.email == user.email).first()
    db.close()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        return {"status": "error", "message": "Invalid email or password"}

    access_token = create_access_token(data={"sub": db_user.email})
    return {"status": "success", "access_token": access_token, "token_type": "bearer"}
