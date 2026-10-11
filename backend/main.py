from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status
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
from pydantic import BaseModel
from database import SessionLocal, ScanRecord, User
from brand_config import (
    LOOKALIKE_SIMILARITY_THRESHOLD,
    MULTI_LABEL_PUBLIC_SUFFIXES,
    PROTECTED_BRANDS,
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

app = FastAPI()
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained ML model once when the server starts
ml_model = joblib.load("phishing_model_v2.pkl")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY or not SECRET_KEY.strip():
    raise RuntimeError("JWT_SECRET_KEY environment variable is required and must not be blank.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()
report_security = HTTPBearer(auto_error=False)


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return email
    except JWTError:
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
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False, "unsupported URL scheme"
        if parsed.username is not None or parsed.password is not None:
            return False, "embedded URL credentials are not allowed"
        if not parsed.hostname:
            return False, "URL has no hostname"
        try:
            port = parsed.port
        except ValueError:
            return False, "URL has an invalid port"

        try:
            direct_ip = ipaddress.ip_address(parsed.hostname)
            addresses = [direct_ip]
        except ValueError:
            try:
                resolved = socket.getaddrinfo(
                    parsed.hostname,
                    port or (443 if parsed.scheme.lower() == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            except (socket.gaierror, socket.herror, OSError):
                return False, "hostname could not be resolved"
            addresses = []
            for result in resolved:
                address = result[4][0]
                try:
                    parsed_address = ipaddress.ip_address(address)
                except ValueError:
                    return False, "hostname resolved to an invalid address"
                if parsed_address not in addresses:
                    addresses.append(parsed_address)

        if not addresses:
            return False, "hostname resolved to no addresses"
        if any(not address.is_global for address in addresses):
            return False, "destination resolves to non-public IP"
        return True, None
    except (TypeError, ValueError):
        return False, "malformed URL"


def trace_redirects(url, max_hops=10):
    chain = [url]
    for _ in range(max_hops):
        allowed, reason = validate_outbound_url(url)
        if not allowed:
            logger.warning("Blocked outbound URL: %s", reason)
            return chain, "Network analysis blocked for non-public destination."
        try:
            response = requests.get(url, allow_redirects=False, timeout=5)
        except requests.exceptions.RequestException:
            break
        if response.status_code in (301, 302, 303, 307, 308):
            next_url = response.headers.get("Location")
            if not next_url:
                break
            next_url = urljoin(url, next_url)
            allowed, reason = validate_outbound_url(next_url)
            if not allowed:
                logger.warning("Blocked outbound URL: %s", reason)
                return chain, "Network analysis blocked for non-public destination."
            chain.append(next_url)
            url = next_url
        else:
            break
    return chain, None


def get_root_domain(domain):
    parts = domain.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain


def get_domain_age_days(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None
        if isinstance(creation_date, str):
            creation_date = date_parser.parse(creation_date)
        if creation_date.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()
        return (now - creation_date).days
    except Exception:
        return None


def check_https_valid(url):
    try:
        parsed = urlparse(url)
        https_url = parsed._replace(scheme="https").geturl()
        allowed, reason = validate_outbound_url(https_url)
        if not allowed:
            logger.warning("Blocked outbound URL: %s", reason)
            return None
        requests.get(https_url, allow_redirects=False, timeout=5)
        return True
    except requests.exceptions.RequestException:
        return False


def check_lookalike(domain):
    hostname = _normalize_hostname(domain)
    if not hostname:
        return None, 0

    for brand in PROTECTED_BRANDS:
        for official_domain in brand["domains"]:
            official = _normalize_hostname(official_domain)
            if hostname == official or hostname.endswith("." + official):
                return None, 0

    labels = hostname.split(".")
    suffix = ".".join(labels[-2:])
    label_index = -3 if suffix in MULTI_LABEL_PUBLIC_SUFFIXES else -2
    registrable_label = labels[label_index] if len(labels) >= abs(label_index) else labels[0]
    candidates = [registrable_label]
    candidates.extend(part for part in re.split(r"[-_]", registrable_label) if part)

    best_match = None
    best_score = 0
    for brand in PROTECTED_BRANDS:
        token = brand["token"]
        for candidate in candidates:
            if token in candidate and candidate != token:
                continue
            score = fuzz.ratio(token, candidate)
            if score > best_score:
                best_score = score
                best_match = brand["name"]
    if best_score < LOOKALIKE_SIMILARITY_THRESHOLD:
        return None, best_score
    return best_match, best_score


def _normalize_hostname(domain):
    if not domain:
        return ""
    parsed = urlparse(domain if "://" in domain else f"//{domain}")
    try:
        hostname = parsed.hostname
    except ValueError:
        return ""
    if not hostname:
        return ""
    hostname = hostname.rstrip(".").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def hostname_is_ip(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        ipaddress.ip_address(hostname)
        return True
    except (TypeError, ValueError):
        return False


def calculate_rule_contributions(domain_age, https_valid, brand_match, chain, final_url):
    risk_breakdown = []

    if domain_age is not None and domain_age < 30:
        risk_breakdown.append({
            "source": "rule",
            "name": "Newly Registered Domain",
            "points": 20,
            "reason": "The domain was registered less than 30 days ago."
        })
    if https_valid is False:
        risk_breakdown.append({
            "source": "rule",
            "name": "HTTPS Validation Failed",
            "points": 20,
            "reason": "The HTTPS check for this destination failed."
        })
    if brand_match is not None:
        risk_breakdown.append({
            "source": "rule",
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
            "name": "Multiple Redirects",
            "points": 15,
            "reason": "The URL passed through more than one redirect before reaching its destination."
        })
    if hostname_is_ip(final_url):
        risk_breakdown.append({
            "source": "rule",
            "name": "IP Address URL",
            "points": 25,
            "reason": "The URL uses an IP address instead of a normal domain name."
        })

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

        if hierarchy is None:
            return False

        img_h, img_w = img.shape[:2]
        zone_margin = 0.35  # real finder patterns only ever sit in the outer 35% of
                             # each dimension, in one of three corners (top-left,
                             # top-right, bottom-left -- never bottom-right, never
                             # the middle). Dense QR data in the center can otherwise
                             # be mistaken for a 4th "finder pattern" candidate purely
                             # by shape, which throws off the size-consistency check.

        def in_finder_corner_zone(x, y, w, h):
            near_left = x < img_w * zone_margin
            near_right = x > img_w * (1 - zone_margin)
            near_top = y < img_h * zone_margin
            near_bottom = y > img_h * (1 - zone_margin)
            return (near_left and near_top) or (near_right and near_top) or (near_left and near_bottom)

        hierarchy = hierarchy[0]
        finder_candidates = []

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
            if 0.7 < aspect_ratio < 1.3 and in_finder_corner_zone(x, y, w, h):
                finder_candidates.append(w)

        if len(finder_candidates) >= 3:
            sizes = sorted(finder_candidates, reverse=True)[:3]
            mean_size = sum(sizes) / 3
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
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = key.lower()
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
        "amount": amount,
        "currency": parameters.get("cu"),
        "transaction_note": parameters.get("tn"),
        "transaction_reference": parameters.get("tr"),
        "merchant_code": parameters.get("mc"),
        "vpa_format_valid": vpa_format_valid,
        "amount_valid": amount_valid,
        "identity_verified": False,
    }


@app.post("/scan")
async def scan_qr(file: UploadFile = File(...), current_user: str = Depends(get_current_user)):
    contents = await file.read()
    nparr = np.frombuffer(contents, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    qr_content = decode_qr(img)
    tampering_result = analyze_tampering(img)

    if not qr_content:
        return {"status": "error", "message": "No QR code found in the image"}

    result = {"status": "success", "decoded_content": qr_content}

    if qr_content.startswith("http://") or qr_content.startswith("https://"):
        initial_allowed, initial_reason = validate_outbound_url(qr_content)
        if not initial_allowed:
            logger.warning("Blocked outbound URL: %s", initial_reason)
            chain = [qr_content]
            network_analysis = "Network analysis blocked for non-public destination."
        else:
            chain, network_analysis = trace_redirects(qr_content)
        final_url = chain[-1]
        domain = urlparse(final_url).netloc

        root_domain = get_root_domain(domain)
        final_allowed, final_reason = validate_outbound_url(final_url)
        if final_allowed and network_analysis is None:
            domain_age = get_domain_age_days(root_domain)
            https_valid = check_https_valid(final_url)
        else:
            if final_reason:
                logger.warning("Blocked outbound URL: %s", final_reason)
            domain_age = None
            https_valid = None
        brand_match, similarity_score = check_lookalike(domain)

        ml_features = extract_ml_features(final_url)
        feature_order = ['url_length', 'has_https', 'num_dots', 'num_hyphens', 'num_at',
                          'num_question_marks', 'num_equal', 'num_underscore', 'num_slash',
                          'has_ip', 'num_digits', 'num_subdomains']
        feature_vector = [[ml_features[f] for f in feature_order]]
        ml_prediction = ml_model.predict(feature_vector)[0]
        ml_probability = ml_model.predict_proba(feature_vector)[0]
        phishing_probability = ml_probability[list(ml_model.classes_).index(1)]

        rule_score, risk_breakdown = calculate_rule_contributions(
            domain_age, https_valid, brand_match, chain, final_url
        )
        risk_reasons = []
        if any(item["name"] == "IP Address URL" for item in risk_breakdown):
            risk_reasons.append("URL uses an IP address instead of a domain name.")

        final_risk_score, score_explanation = calculate_hybrid_score(
            rule_score, phishing_probability
        )

        if final_risk_score >= 61:
            label = "unsafe"
        elif final_risk_score >= 31:
            label = "suspicious"
        else:
            label = "safe"

        result["redirect_chain"] = chain
        result["final_url"] = final_url
        result["domain"] = domain
        result["domain_age_days"] = domain_age
        result["https_valid"] = https_valid
        result["lookalike_brand"] = brand_match
        result["lookalike_score"] = similarity_score
        result["ml_phishing_probability"] = round(phishing_probability * 100, 2)
        result["rule_score"] = rule_score
        result["risk_breakdown"] = risk_breakdown
        result["score_explanation"] = score_explanation
        result["risk_reasons"] = risk_reasons
        result["risk_score"] = final_risk_score
        result["risk_label"] = label
        result["network_analysis"] = network_analysis
    else:
        upi_details = parse_upi_payment_uri(qr_content)
        if upi_details is not None:
            result["upi_details"] = upi_details

    result["tampering_score"] = tampering_result["tampering_score"]
    result["tampering_reasons"] = tampering_result["tampering_reasons"]

    # Save this scan to the database
    db = SessionLocal()
    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        db.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    record = ScanRecord(
        user_id=user.id,
        decoded_content=result.get("decoded_content"),
        final_url=result.get("final_url"),
        domain=result.get("domain"),
        risk_score=result.get("risk_score"),
        risk_label=result.get("risk_label"),
        tampering_score=result.get("tampering_score"),
        tampering_reasons=json.dumps(result.get("tampering_reasons", [])),
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


def _report_table(title, rows, styles):
    data = [[Paragraph("<b>" + escape(title) + "</b>", styles["table_heading"]), ""]]
    data.extend([
        [_report_paragraph(label, styles["label"]), _report_paragraph(value, styles["body"])]
        for label, value in rows
    ])
    table = Table(data, colWidths=[55 * mm, 115 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("SPAN", (0, 0), (1, 0)),
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


def _report_summary(record, redirect_chain, tampering_reasons):
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
                findings.append("the ML model found elevated phishing probability")
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
        return redirect_text + "No suspicious indicators were detected by the current security checks."
    if findings:
        return "Findings: " + "; ".join(findings) + "."
    if record.risk_label:
        return "Analysis completed without additional findings from the available checks."
    return "The QR content was decoded successfully; URL security checks do not apply to this content."


def _build_report(record):
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
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
        Paragraph("QR Shield", styles["report_title"]),
        Paragraph("QR Code Phishing Detection &amp; Safety Scanner", styles["report_subtitle"]),
        Paragraph("Security Analysis Report", styles["section"]),
    ]
    risk_label = str(record.risk_label or "").lower()
    verdict = {
        "safe": "No Threats Detected",
        "suspicious": "Suspicious QR Code",
        "unsafe": "High-Risk QR Code",
    }.get(risk_label, "Analysis Incomplete")
    story.append(_report_table("Report Overview", [
        ("Report ID / Scan ID", record.id),
        ("Scan date and time", record.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC") if record.scanned_at else "Unavailable"),
        ("Overall verdict", verdict),
        ("Overall risk score", f"{record.risk_score}/100" if record.risk_score is not None else "Unavailable"),
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
            ("Decoded Content", record.decoded_content),
            ("Final Destination", record.final_url),
            ("Domain", record.domain),
            ("Redirect Hops", max(len(redirect_chain) - 1, 0) if redirect_chain else "Unavailable"),
        ], styles))
        story.append(Paragraph("Security Checks", styles["section"]))
        story.append(_report_table("Security Checks", [
            ("HTTPS Status", "Valid" if record.https_valid == 1 else "Not valid" if record.https_valid == 0 else "Unavailable"),
            ("Domain Age", f"{record.domain_age_days} days" if record.domain_age_days is not None else "Unavailable"),
            ("Lookalike Brand", stored_lookalike),
            ("ML Phishing Probability", f"{record.ml_phishing_probability}%" if record.ml_phishing_probability is not None else "Unavailable"),
        ], styles))
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
            ], styles))
    else:
        story.append(Paragraph("QR Content", styles["section"]))
        story.append(_report_table("QR Content", [
            ("Decoded Content", record.decoded_content),
        ], styles))

    story.append(Paragraph("QR Integrity", styles["section"]))
    story.append(_report_table("QR Integrity", [
        ("Tampering Score", f"{record.tampering_score}/85" if record.tampering_score is not None else "Unavailable"),
        ("Tampering Status", "Review needed" if tampering_reasons else "No tampering detected" if record.tampering_reasons else "Unavailable"),
        ("Tampering Reasons", "; ".join(tampering_reasons) if tampering_reasons else "None detected" if record.tampering_reasons else "Unavailable"),
    ], styles))
    story.append(Paragraph("Analysis Summary", styles["section"]))
    story.append(Paragraph(escape(_report_summary(record, redirect_chain, tampering_reasons)), styles["body"]))
    story.append(Spacer(1, 12))
    notice = Table([[
        Paragraph("<b>Security Notice</b><br/>QR Shield performs automated URL, domain, machine-learning, and QR-integrity analysis. The results indicate detected risk signals and do not guarantee that a QR code or destination is completely safe. Users should verify unexpected or sensitive requests before proceeding.", styles["notice"])
    ]], colWidths=[170 * mm])
    notice.setStyle(TableStyle([
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
def download_report(scan_id: int, current_user: str = Depends(get_report_user)):
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


@app.get("/history")
def get_history(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == current_user).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        records = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).all()
    finally:
        db.close()

    history = []
    for r in records:
        history.append({
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
        })
    return history


class UserCreate(BaseModel):
    email: str
    password: str


@app.post("/register")
def register(user: UserCreate):
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
    db = SessionLocal()
    db_user = db.query(User).filter(User.email == user.email).first()
    db.close()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        return {"status": "error", "message": "Invalid email or password"}

    access_token = create_access_token(data={"sub": db_user.email})
    return {"status": "success", "access_token": access_token, "token_type": "bearer"}
