"""Offline, bounded UPI education; never verifies recipients or initiates payments.

This additive analysis does not replace legacy parser/comparison fields or URL scores.
"""
from decimal import Decimal, InvalidOperation
import re
from urllib.parse import parse_qsl, urlparse

PAYMENT_EXPLANATION = (
    "This QR code contains a UPI payment instruction. Approving it in a payment app "
    "may send money from your account to the displayed recipient. Scanning alone does not send money."
)
SAFETY_NOTES = [
    "Receiving an ordinary UPI transfer does not require scanning a payment QR code and authorizing a payment.",
    "Payment recipient details are not independently verified. A QR-declared name does not prove account ownership.",
    "Review the recipient and exact amount in your payment app using an independently trusted source.",
    "Never authorize a payment to receive a promised refund. QR Shield does not launch payment apps or initiate payments.",
]
FIELD_KEYS = {
    "payee_vpa": "pa", "payee_name": "pn", "amount": "am", "currency": "cu",
    "transaction_note": "tn", "transaction_reference": "tr",
}
VPA = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
MAX_VALUE = 1024  # Analysis/display bound, not a bank payment limit.


def upi_intent_banner(details, analysis):
    """Presentation policy only; no identity verification or scoring changes."""
    details = details or {}
    analysis = analysis or {}
    has_amount = details.get("amount") not in (None, "")
    conflicts = bool(details.get("conflicting_parameters")) or any(
        field.get("status") == "conflicting" for field in analysis.get("fields", {}).values()
    ) or any(warning.get("code") == "conflicting_parameters" for warning in analysis.get("warnings", []))
    malformed = (details.get("vpa_format_valid") is not True
                 or details.get("currency") not in (None, "", "INR")
                 or analysis.get("parameters_reliable") is False
                 or analysis.get("content_type") == "malformed_upi"
                 or (has_amount and (details.get("amount_valid") is not True
                     or analysis.get("fields", {}).get("amount", {}).get("status") in ("malformed", "conflicting", "unavailable"))))
    recipient = details.get("payee_name") or details.get("payee_vpa")
    if conflicts:
        return {"state": "conflict", "title": "PAYMENT DETAILS CONFLICT",
                "body": "Do not approve this payment. Verify the recipient and amount first."}
    if malformed or not isinstance(recipient, str) or not recipient:
        return {"state": "unknown", "title": "CAN'T TELL IF THIS IS A PAYMENT OR A MONEY REQUEST",
                "body": "Do not proceed. Verify with the person or merchant first."}
    if details.get("mode") == "collect":
        return {"state": "collect", "title": "THIS WILL REQUEST MONEY FROM YOU",
                "body": recipient + " is asking you to approve a payment."}
    if not has_amount:
        return {"state": "pay", "title": "YOU ARE PAYING " + recipient,
                "body": "Amount is not fixed. Check before you approve."}
    amount = ("₹" if details.get("currency") == "INR" else "") + str(details["amount"])
    return {"state": "pay", "title": "YOU ARE PAYING " + amount + " TO " + recipient,
            "body": "Check the recipient and amount before you approve."}


def analyze_upi(content):
    """Return None for non-UPI content; malformed UPI remains visibly unverified."""
    if not isinstance(content, str) or not content.lstrip().lower().startswith("upi:"):
        return None
    warnings = []

    def warn(code, message):
        if not any(item["code"] == code for item in warnings):
            warnings.append({"code": code, "message": message})

    malformed = set()
    values = {}
    supported = False
    if len(content.encode("utf-8")) > 16 * 1024:
        warn("oversized_payload", "UPI content exceeds the 16 KiB analysis limit; payment details were not parsed.")
    else:
        try:
            parsed = urlparse(content)
            supported = (parsed.scheme.lower() == "upi" and parsed.netloc.lower() == "pay"
                         and parsed.path in ("", "/") and not parsed.fragment
                         and not any(char.isspace() or ord(char) < 32 for char in content))
            if not supported:
                warn("invalid_structure", "Unexpected UPI URI structure. Payment direction and details cannot be relied on.")
            if re.search(r"%(?![0-9a-fA-F]{2})", parsed.query):
                warn("invalid_encoding", "Malformed percent encoding in payment parameters; decoded details may be misleading.")
            if any("=" not in part for part in parsed.query.split("&") if part):
                warn("invalid_parameters", "A payment parameter lacks an equals sign; its meaning is ambiguous.")
            # Strict UTF-8 avoids replacement characters hiding invalid encoded bytes.
            try:
                pairs = parse_qsl(parsed.query, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=128)
            except (ValueError, UnicodeError):
                pairs = []
                warn("invalid_parameters", "Invalid UTF-8 encoding or too many payment parameters; details were not parsed.")
            for key, value in pairs:
                normalized = key.lower()
                values.setdefault(normalized, []).append(value)
                if (len(key) > 64 or len(value) > MAX_VALUE or
                        re.search(r"[\x00-\x1f\x7f]", key + value)):
                    malformed.add(normalized)
                    warn("malformed_value", "An oversized or malformed payment parameter needs review. No bank limit is inferred.")
        except ValueError:
            warn("invalid_structure", "Malformed UPI URI; payment details could not be parsed.")
    duplicates = [key for key, entries in values.items() if len(entries) > 1]
    conflicts = [key for key, entries in values.items() if len(set(entries)) > 1]
    if duplicates:
        warn("duplicate_parameters", "Repeated payment parameters may be interpreted differently by payment apps. Review all values.")
    if conflicts:
        warn("conflicting_parameters", "Conflicting payment parameters make the intended payment ambiguous. Do not rely on the first value.")
    fields = {}
    for name, key in FIELD_KEYS.items():
        raw = values.get(key, [None])[0]
        status = "missing" if raw is None or raw == "" else "present_unverified"
        if key in malformed or key in conflicts:
            status = "malformed" if key not in conflicts else "conflicting"
        fields[name] = {"value": raw, "status": status}
        if len(values.get(key, [])) > 1:
            fields[name]["encoded_values"] = list(values[key])
    vpa = fields["payee_vpa"]
    if vpa["status"] == "missing":
        warn("missing_payee", "The payee UPI ID is missing. Do not approve a payment without verifying the recipient.")
    elif not VPA.fullmatch(vpa["value"] or ""):
        vpa["status"] = "malformed"
        warn("invalid_payee", "The payee UPI ID has an invalid local format; account ownership has not been checked.")
    elif vpa["status"] == "present_unverified":
        vpa["status"] = "valid_format_unverified"
    amount = fields["amount"]
    raw_amount = amount["value"]
    if amount["status"] != "missing":
        valid = False
        if raw_amount is not None and len(raw_amount) <= MAX_VALUE and re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", raw_amount):
            try:
                number = Decimal(raw_amount)
                valid = number.is_finite() and number > 0 and number.as_tuple().exponent >= -2
            except InvalidOperation:
                pass
        if not valid:
            amount["status"] = "malformed"
            warn("invalid_amount", "Amount must be a positive plain decimal with at most two fractional digits. Zero, negative, non-numeric and excessive-precision amounts require review; the encoded amount has not been changed.")
        elif amount["status"] == "present_unverified":
            amount["status"] = "valid_format_unverified"
    currency = fields["currency"]
    if currency["status"] == "missing":
        warn("missing_currency", "No currency is encoded. QR Shield has not assumed INR or another currency.")
    elif currency["value"] != "INR":
        currency["status"] = "malformed"
        warn("unexpected_currency", "The encoded currency is not the supported INR value; confirm it independently before paying.")
    elif currency["status"] == "present_unverified":
        currency["status"] = "valid_format_unverified"

    # Only payment-request notes/names trigger these contextual indicators, not bare keywords.
    if supported:
        text = " ".join(value for key in ("tn", "pn") for value in values.get(key, []) if len(value) <= MAX_VALUE).lower()
        rules = [
            ("refund_language", r"\brefund\b", r"\b(?:pay|payment|fee|charge|verification|verify)\b", "Refund-related payment or verification language: authorizing a payment is not required to receive an ordinary refund."),
            ("cashback_language", r"\bcashback\b", r"\b(?:collect|collection|claim|verification|verify|fee|charge|pay|payment)\b", "Cashback collection or verification language in a payment instruction needs independent confirmation; it is not proof of fraud."),
            ("prize_language", r"\bprize\b", r"\b(?:collect|collection|claim|fee|charge|pay|payment)\b", "Prize collection or payment language can mislead recipients into sending money. Verify the request independently."),
            ("activation_language", r"\bactivation\b|\bactivate\b", r"\b(?:account|service)\b.*\b(?:pay|payment|fee|charge)\b|\b(?:pay|payment|fee|charge)\b.*\b(?:account|service)\b", "Account or service activation payment language needs review; QR parameters do not establish that a fee is legitimate."),
            ("kyc_language", r"\bkyc\b", r"\b(?:fee|charge|pay|payment)\b", "KYC-related payment or fee language needs independent verification with the provider."),
            ("pay_to_receive", r"\b(?:pay|payment|fee|charge)\b", r"\b(?:receive|receiving)\b.*\b(?:money|refund|cashback|prize|funds)\b", "Payment requested to receive money: ordinary incoming transfers do not require authorizing an outgoing payment."),
        ]
        for code, first, second, message in rules:
            if re.search(first, text) and re.search(second, text):
                warn(code, message)
    invalid = any(item["code"] in {"invalid_structure", "oversized_payload", "invalid_encoding", "invalid_parameters"} for item in warnings)
    unavailable = any(item["code"] in {"oversized_payload", "invalid_parameters"} for item in warnings) and not values
    if invalid:
        for field in fields.values():
            if unavailable:
                field["status"] = "unavailable"
            elif field["status"] != "missing":
                field["status"] = "malformed"
    return {
        "content_type": "upi_payment" if supported else "malformed_upi",
        "payment_direction": "send_money" if supported else "unverified",
        "payment_explanation": PAYMENT_EXPLANATION if supported else "This looks like UPI content, but its payment structure is unsupported or malformed. Do not authorize it without independent verification.",
        "validation_status": "review_required" if warnings else "format_checked_unverified",
        "parameters_reliable": supported and not invalid and not conflicts and not malformed and
                               all(field["status"] not in ("malformed", "conflicting") for field in fields.values()) and
                               vpa["status"] == "valid_format_unverified",
        "fields": fields, "warnings": warnings, "safety_notes": list(SAFETY_NOTES),
        "identity_verified": False,
        "warning_context": "These are format and contextual indicators, not proof of fraud or a fraud probability.",
    }
