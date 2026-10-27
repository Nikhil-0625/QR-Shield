"""Isolated experimental API. Importing this module never loads a model.

Launch only with the fixed loopback launcher below, never via a public proxy.
No application, database, production model, or dataset imports.
"""
from contextlib import asynccontextmanager
import hashlib
import importlib.metadata
import io
import ipaddress
import json
import math
from pathlib import Path
import platform
import re
import stat
import sys
import threading
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from candidate_features import FEATURE_NAMES, SCHEMA_VERSION, feature_vector
from experimental.ml_warning import experimental_warning, WARNING_THRESHOLD

HOST, PORT = "127.0.0.1", 8766
FRONTEND_ORIGINS = ("http://localhost:5500", "http://127.0.0.1:5500")
MAX_BODY_BYTES, MAX_URL_BYTES = 12288, 8192
CANDIDATE = BACKEND / "ml/candidate_artifacts/candidate_v1_seed42"
MODEL_SHA256 = "64579dd30181b43dd8faec199ac70f3c94d1099764194149d460c48bd18f2e88"
MANIFEST_SHA256 = "6e25bdf431127b983b8aa2172cf7c0cced639c20039f909f45c5903000969bd5"


def private_read(path):
    """Bounded reads, rejecting symlink/reparse ancestors and hard links."""
    path = Path(path)
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Untrusted artifact path")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256 * 1024 * 1024:
        raise ValueError("Invalid artifact file")
    with path.open("rb") as stream:
        import os
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Artifact changed")
        data = stream.read(256 * 1024 * 1024 + 1)
    if len(data) > 256 * 1024 * 1024:
        raise ValueError("Artifact too large")
    return data


class CandidateVerificationError(ValueError):
    """Contains only an internal stage label, never underlying exception text."""
    def __init__(self, stage):
        self.stage = stage
        super().__init__("Candidate verification failed at stage=" + stage)


def load_verified_candidate():
    current_stage = ["verification_initialization"]
    def checkpoint(stage):
        current_stage[0] = stage
    try:
        return _load_verified_candidate(checkpoint)
    except Exception:
        raise CandidateVerificationError(current_stage[0]) from None


def _load_verified_candidate(checkpoint):
    """Only the locally trained artifact pinned in the reviewed session."""
    checkpoint("environment_imports")
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    checkpoint("manifest_file_access")
    raw = private_read(CANDIDATE / "model_manifest.json")
    checkpoint("manifest_checksum")
    if sha(raw) != MANIFEST_SHA256:
        raise ValueError("Manifest integrity mismatch")
    checkpoint("manifest_contract")
    manifest = json.loads(raw)
    if (manifest["artifact_filename"] != "phishing_url_candidate_v1.joblib"
            or manifest["artifact_sha256"] != MODEL_SHA256
            or manifest["label_mapping"] != {"benign": 0, "phishing": 1}
            or manifest["classes"] != [0, 1]
            or manifest["feature_names"] != list(FEATURE_NAMES)
            or manifest["feature_schema"] != SCHEMA_VERSION
            or WARNING_THRESHOLD != 0.40144790130467084
            or manifest["python_version"] != platform.python_version()):
        raise ValueError("Candidate contract mismatch")
    checkpoint("dependency_versions")
    for package, version in manifest["dependencies"].items():
        if importlib.metadata.version(package) != version:
            raise ValueError("Environment mismatch")
    checkpoint("extractor_checksum")
    if sha(private_read(BACKEND / "candidate_features.py")) != manifest["extractor_sha256"]:
        raise ValueError("Feature extractor mismatch")
    checkpoint("trainer_checksum")
    if sha(private_read(BACKEND / "ml/train_candidate.py")) != manifest["trainer_sha256"]:
        raise ValueError("Training source mismatch")
    checkpoint("artifact_file_access")
    artifact = private_read(CANDIDATE / "phishing_url_candidate_v1.joblib")
    checkpoint("artifact_checksum")
    if sha(artifact) != MODEL_SHA256:
        raise ValueError("Candidate integrity mismatch")
    # Deserialize exactly the verified bytes, not a second filesystem read.
    checkpoint("candidate_deserialization")
    model = joblib.load(io.BytesIO(artifact))
    checkpoint("loaded_model_contract")
    if (type(model) is not RandomForestClassifier or model.classes_.tolist() != [0, 1]
            or model.n_features_in_ != len(FEATURE_NAMES)
            or model.get_params() != manifest["hyperparameters"]):
        raise ValueError("Loaded candidate contract mismatch")
    return model


def validate_url(value):
    if type(value) is not str or not value or len(value) > MAX_URL_BYTES:
        raise ValueError("Invalid URL")
    if len(value.encode("utf-8")) > MAX_URL_BYTES:
        raise ValueError("Invalid URL")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Invalid URL")
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Invalid URL")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise ValueError("Invalid URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Invalid URL")
    port = parsed.port
    if port is not None and port == 0 or parsed.netloc.endswith(":"):
        raise ValueError("Invalid URL")
    hostname = parsed.hostname
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        hostname = hostname.encode("idna").decode("ascii")
        if len(hostname) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        ):
            raise ValueError("Invalid URL")
    return value  # Never normalize the feature input or resolve its hostname.


def positive_probability(model, vector):
    classes = list(model.classes_)
    if len(classes) != 2 or classes.count(0) != 1 or classes.count(1) != 1:
        raise ValueError("Invalid class contract")
    values = model.predict_proba([vector])
    if getattr(values, "shape", None) != (1, 2):
        raise ValueError("Invalid prediction shape")
    row = [float(v) for v in values[0]]
    if any(not math.isfinite(v) or not 0 <= v <= 1 for v in row) or not math.isclose(sum(row), 1, abs_tol=1e-8):
        raise ValueError("Invalid prediction")
    return row[classes.index(1)]


def create_app(model_loader=None):
    loader = model_loader or load_verified_candidate
    lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        try:
            app.state.model = loader()
        except CandidateVerificationError as error:
            raise RuntimeError("Experimental candidate unavailable: startup verification failed; stage=" + error.stage) from None
        except Exception:
            raise RuntimeError("Experimental candidate unavailable: startup verification failed; stage=model_initialization") from None
        yield
        app.state.model = None

    app = FastAPI(title="QR Shield experimental localhost API", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(CORSMiddleware, allow_origins=list(FRONTEND_ORIGINS),
                       allow_methods=["POST"], allow_headers=["Content-Type"],
                       allow_credentials=False, max_age=600)

    @app.middleware("http")
    async def local_only(request, call_next):
        if (not request.client or request.client.host != HOST
                or request.headers.get("host") != f"{HOST}:{PORT}"
                or ("origin" in request.headers
                    and request.headers["origin"] not in FRONTEND_ORIGINS)):
            response = JSONResponse({"detail": "Local experimental requests only"}, status_code=403)
        else:
            try:
                response = await call_next(request)
            except Exception:
                response = JSONResponse({"detail": "Experimental request failed"}, status_code=500)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.post("/experimental/predict")
    async def predict(request: Request):
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return JSONResponse({"detail": "JSON required"}, status_code=415)
        body = bytearray()
        try:
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_BODY_BYTES:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
                body.extend(chunk)
            def unique_keys(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate key")
                    result[key] = value
                return result
            payload = json.loads(body, object_pairs_hook=unique_keys)
            if type(payload) is not dict or set(payload) != {"url"}:
                raise ValueError("Invalid payload")
            url = validate_url(payload["url"])
        except Exception:
            return JSONResponse({"detail": "Invalid URL request"}, status_code=422)
        try:
            vector = feature_vector(url)
            # Inference is synchronous and serialized; no request history kept.
            with lock:
                probability = positive_probability(app.state.model, vector)
            return {
                "experimental": True,
                "candidate_phishing_probability": probability,
                **experimental_warning(probability),
                "production_risk_evaluated": False,
                "risk_score": None,
                "risk_classification": None,
            }
        except Exception:
            return JSONResponse({"detail": "Experimental prediction unavailable"}, status_code=503)

    return app


if __name__ == "__main__":
    import uvicorn
    # No host/port overrides, proxy trust, access logs, or reload subprocesses.
    uvicorn.run(create_app(), host=HOST, port=PORT, proxy_headers=False,
                access_log=False, log_level="error", server_header=False,
                limit_concurrency=8, timeout_keep_alive=2)
