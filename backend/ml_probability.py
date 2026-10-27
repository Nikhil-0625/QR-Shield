"""Model-independent probability interpretation; never loads model artifacts."""
import math
from numbers import Real


def phishing_probability(classes, probabilities, *, phishing_label):
    """Return one phishing probability per row of a 2-D predict_proba output.

    Labels must be unique and include the explicitly supplied phishing label.
    Rows must be nonempty probability distributions aligned with those labels.
    """
    try:
        labels = list(classes)
    except TypeError as exc:
        raise ValueError("classes must be a one-dimensional label sequence") from exc
    if isinstance(classes, (str, bytes)) or not labels:
        raise ValueError("classes must be a nonempty label sequence")
    for index, label in enumerate(labels):
        if label is None or isinstance(label, (list, tuple, dict, set)):
            raise ValueError("class labels must be nonmissing scalar values")
        if isinstance(label, Real) and not math.isfinite(label):
            raise ValueError("class labels must be finite")
        try:
            hash(label)
            if any(label == previous for previous in labels[:index]):
                raise ValueError("duplicate class labels")
        except TypeError as exc:
            raise ValueError("class labels must be scalar and hashable") from exc
    if phishing_label not in labels:
        raise ValueError("explicit phishing label is missing from classes")
    column = labels.index(phishing_label)
    try:
        rows = list(probabilities)
    except TypeError as exc:
        raise ValueError("probabilities must be a two-dimensional sequence") from exc
    if isinstance(probabilities, (str, bytes)) or not rows:
        raise ValueError("probabilities must contain at least one row")
    selected = []
    for row in rows:
        try:
            values = list(row)
        except TypeError as exc:
            raise ValueError("probabilities must be two-dimensional") from exc
        if isinstance(row, (str, bytes)) or len(values) != len(labels):
            raise ValueError("probability column count must match classes")
        if any(isinstance(value, bool) or not isinstance(value, Real)
               or not math.isfinite(value) or not 0 <= value <= 1 for value in values):
            raise ValueError("probabilities must be finite real numbers in [0, 1]")
        if not math.isclose(sum(values), 1.0, rel_tol=1e-7, abs_tol=1e-7):
            raise ValueError("each probability row must sum to one")
        selected.append(float(values[column]))
    return selected
