"""Pure experimental warning presentation; not imported by production.

Accepts the existing integer risk score, not raw rule points. This function
does not calculate or change hybrid scores and never loads a model.
"""

import math

# Exact value recorded in the private offline evaluation's comparison.json.
WARNING_THRESHOLD = 0.40144790130467084
VALIDATION_FALSE_POSITIVE_RATE = 0.19403605641298563


def experimental_warning(phishing_probability):
    """ML-only fields when no production risk assessment has been performed."""
    if type(phishing_probability) not in (int, float):
        raise ValueError("Phishing probability must be a finite number from 0 to 1")
    if not 0 <= phishing_probability <= 1 or not math.isfinite(phishing_probability):
        raise ValueError("Phishing probability must be a finite number from 0 to 1")
    warning = phishing_probability >= WARNING_THRESHOLD
    return {
        "experimental_ml_warning": warning,
        "warning_explanation": (
            "Experimental ML phishing warning: the candidate score meets the "
            "warning threshold. This does not confirm a malicious URL."
            if warning else
            "No experimental ML phishing warning: the candidate score is below "
            "the warning threshold. This does not prove the URL is safe."
        ),
        "warning_threshold": WARNING_THRESHOLD,
    }


def separate_ml_warning(risk_score, phishing_probability):
    """Return independent risk and ML signals for JSON-compatible inputs.

    Risk scores must be integers in [0, 100]. Probabilities must be finite
    int/float values in [0, 1]. Booleans and implicit conversions are rejected.
    Invalid inputs raise ValueError without including their values.
    """
    if type(risk_score) is not int or not 0 <= risk_score <= 100:
        raise ValueError("Risk score must be an integer from 0 to 100")
    signal = experimental_warning(phishing_probability)

    classification = (
        "UNSAFE" if risk_score >= 61 else
        "SUSPICIOUS" if risk_score >= 31 else "SAFE"
    )
    return {
        "risk_score": risk_score,
        "risk_classification": classification,
        **signal,
    }
