"""In-process synthetic API checks; no model or dataset files are accessed."""
import hashlib
import json
import math
import socket
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experimental import candidate_api as api


class FakeModel:
    classes_ = np.array([0, 1])

    def __init__(self, probability=0.5):
        self.probability = probability

    def predict_proba(self, vectors):
        return np.array([[1-self.probability, self.probability]])


class CandidateApiTests(unittest.TestCase):
    def setUp(self):
        self.network = patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden"))
        original_connect = socket.socket.connect
        def loopback_only(sock, address):
            if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1"):
                raise AssertionError("External network forbidden")
            return original_connect(sock, address)
        self.connect = patch("socket.socket.connect", new=loopback_only)
        self.network.start(); self.connect.start()
        self.addCleanup(self.network.stop); self.addCleanup(self.connect.stop)
        self.model = FakeModel()
        self.client = TestClient(api.create_app(lambda: self.model),
                                 base_url=f"http://{api.HOST}:{api.PORT}",
                                 client=(api.HOST, 50000))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def send(self, url="https://example.invalid/synthetic"):
        return self.client.post("/experimental/predict", json={"url": url})

    def test_warning_boundaries_and_no_invented_risk(self):
        for probability, warning in ((math.nextafter(api.WARNING_THRESHOLD, 0), False),
                                     (api.WARNING_THRESHOLD, True),
                                     (math.nextafter(api.WARNING_THRESHOLD, 1), True),
                                     (0, False), (1, True)):
            self.model.probability = probability
            response = self.send()
            self.assertEqual(response.status_code, 200)
            result = response.json()
            self.assertIs(result["experimental_ml_warning"], warning)
            self.assertIsNone(result["risk_score"])
            self.assertIsNone(result["risk_classification"])
            self.assertFalse(result["production_risk_evaluated"])
            self.assertEqual(result["warning_threshold"], 0.40144790130467084)
            self.assertNotIn("example.invalid", response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")

    def test_valid_url_forms_and_feature_order(self):
        for url in ("http://192.0.2.1/a", "https://[2001:db8::1]/", "https://example.invalid:443/a?b=2"):
            with patch.object(self.model, "predict_proba", wraps=self.model.predict_proba) as prediction:
                self.assertEqual(self.send(url).status_code, 200)
                self.assertEqual(prediction.call_args.args[0], [api.feature_vector(url)])

    def test_invalid_urls(self):
        for url in (None, True, 3, [], "", "example.invalid", "file:///private", "ftp://example.invalid",
                    "http:///path", "https://user:password@example.invalid", "http://bad_host.invalid",
                    "http://[broken", "http://example.invalid:99999", "http://example.invalid:0",
                    "http://example.invalid:", "http://example.invalid/with space", "http://example.invalid/\n",
                    "http://example.invalid/\\", "http://example.invalid/%zz", "https://example.invalid/"+"a"*8192):
            with self.subTest(input_type=type(url).__name__):
                self.assertEqual(self.send(url).status_code, 422)

    def test_body_and_schema_limits(self):
        for body in ('{"url":"https://example.invalid","extra":1}', '[]', '{}', '{broken',
                     '{"url":"https://a.invalid","url":"https://b.invalid"}'):
            self.assertEqual(self.client.post("/experimental/predict", content=body,
                                             headers={"content-type":"application/json"}).status_code, 422)
        response = self.client.post("/experimental/predict", content=b"x"*(api.MAX_BODY_BYTES+1),
                                    headers={"content-type":"application/json"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.client.post("/experimental/predict", content="url=x").status_code, 415)

    def test_host_origin_and_remote_client_rejected(self):
        self.assertEqual(self.client.post("/experimental/predict", headers={"host":"attacker.invalid"}).status_code,403)
        self.assertEqual(self.client.post("/experimental/predict", headers={"origin":"null"}).status_code,403)
        with TestClient(api.create_app(lambda:self.model), base_url=f"http://{api.HOST}:{api.PORT}",
                        client=("192.0.2.1",50000)) as remote:
            self.assertEqual(remote.post("/experimental/predict",json={"url":"https://example.invalid"}).status_code,403)

    def test_allowed_cors_preflights_and_predictions(self):
        for origin in api.FRONTEND_ORIGINS:
            preflight = self.client.options("/experimental/predict", headers={
                "origin": origin, "access-control-request-method": "POST",
                "access-control-request-headers": "content-type"})
            self.assertEqual(preflight.status_code, 200)
            self.assertEqual(preflight.headers["access-control-allow-origin"], origin)
            self.assertNotIn("access-control-allow-credentials", preflight.headers)
            response = self.client.post("/experimental/predict", json={"url":"https://example.invalid"},
                                        headers={"origin":origin})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["access-control-allow-origin"], origin)
            response = self.client.post("/experimental/predict", json={"url":"invalid"},
                                        headers={"origin":origin})
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.headers["access-control-allow-origin"], origin)

    def test_cors_rejects_other_origins_methods_and_headers(self):
        for origin in ("null", "https://localhost:5500", "http://localhost:5501",
                       "http://localhost:5500.attacker.invalid", "http://attacker.invalid"):
            response=self.client.options("/experimental/predict",headers={
                "origin":origin,"access-control-request-method":"POST"})
            self.assertEqual(response.status_code,403)
            self.assertNotIn("access-control-allow-origin",response.headers)
        for headers in ({"access-control-request-method":"PUT"},
                        {"access-control-request-method":"POST","access-control-request-headers":"authorization"}):
            response=self.client.options("/experimental/predict",headers={
                "origin":api.FRONTEND_ORIGINS[0], **headers})
            self.assertEqual(response.status_code,400)

    def test_prediction_failures_sanitized(self):
        for prediction in (np.array([[math.nan,.5]]), np.array([.5,.5]),
                           np.array([[.8,.8]]), np.array([[-.1,1.1]])):
            with patch.object(self.model,"predict_proba",return_value=prediction):
                self.assertEqual(self.send().status_code,503)
        with patch.object(self.model,"predict_proba",side_effect=ValueError("synthetic-private-marker")):
            response=self.send()
            self.assertEqual(response.status_code,503)
            self.assertNotIn("synthetic-private-marker",response.text)

    def test_class_order(self):
        self.model.classes_=np.array([1,0]); self.model.probability=.2
        self.assertAlmostEqual(self.send().json()["candidate_phishing_probability"],.8)
        self.model.classes_=np.array([-1,1])
        self.assertEqual(self.send().status_code,503)

    def test_startup_failure_is_generic(self):
        def fail(): raise ValueError("synthetic-private-marker")
        with self.assertRaisesRegex(RuntimeError,"startup verification failed") as caught:
            with TestClient(api.create_app(fail)): pass
        self.assertNotIn("synthetic-private-marker",str(caught.exception))

    def test_verification_before_deserialization_with_synthetic_bytes(self):
        artifact=b"synthetic-not-a-pickle"; extractor=b"synthetic extractor"; trainer=b"synthetic trainer"
        sha=lambda b:hashlib.sha256(b).hexdigest()
        model=RandomForestClassifier()
        model.classes_=np.array([0,1]); model.n_features_in_=12
        manifest=dict(artifact_filename="phishing_url_candidate_v1.joblib",artifact_sha256=sha(artifact),
            label_mapping={"benign":0,"phishing":1},classes=[0,1],feature_names=list(api.FEATURE_NAMES),
            feature_schema=api.SCHEMA_VERSION,python_version=api.platform.python_version(),
            dependencies={"synthetic-package":"1.0"},extractor_sha256=sha(extractor),
            trainer_sha256=sha(trainer),hyperparameters=model.get_params())
        raw=json.dumps(manifest).encode()
        files={"model_manifest.json":raw,"phishing_url_candidate_v1.joblib":artifact,
               "candidate_features.py":extractor,"train_candidate.py":trainer}
        with patch.object(api,"MODEL_SHA256",sha(artifact)), patch.object(api,"MANIFEST_SHA256",sha(raw)), \
             patch.object(api,"private_read",side_effect=lambda p:files[p.name]), \
             patch.object(api.importlib.metadata,"version",return_value="1.0"), \
             patch("joblib.load",return_value=model) as load:
            self.assertIs(api.load_verified_candidate(),model)
            self.assertEqual(load.call_args.args[0].getvalue(),artifact)
            for filename in files:
                original=files[filename]; files[filename]=b"tampered"
                load.reset_mock()
                with self.assertRaises(ValueError): api.load_verified_candidate()
                load.assert_not_called(); files[filename]=original
            with patch.object(api.importlib.metadata,"version",return_value="wrong"):
                load.reset_mock()
                with self.assertRaises(ValueError): api.load_verified_candidate()
                load.assert_not_called()


class StartupImportTests(unittest.TestCase):
    def test_project_root_and_other_cwd_use_same_absolute_artifact_path(self):
        import contextlib
        import runpy
        import tempfile
        source = Path(api.__file__).resolve()
        root = source.parents[2]
        expected = root / "backend/ml/candidate_artifacts/candidate_v1_seed42"
        with tempfile.TemporaryDirectory(prefix="candidate-path-regression-") as other:
            for cwd in (root, Path(other)):
                with contextlib.chdir(cwd), \
                        patch("joblib.load", side_effect=AssertionError("Real model load forbidden")) as load:
                    namespace = runpy.run_path(str(source), run_name="isolated_path_test")
                    self.assertTrue(namespace["CANDIDATE"].is_absolute())
                    self.assertEqual(namespace["CANDIDATE"], expected)
                    with TestClient(namespace["create_app"](lambda: FakeModel()),
                                    base_url="http://127.0.0.1:8766",
                                    client=("127.0.0.1", 50000)) as client:
                        response = client.post("/experimental/predict", json={"url":"https://example.invalid/synthetic"})
                        self.assertEqual(response.status_code, 200)
                    load.assert_not_called()

    def test_verification_stage_is_reported_without_sensitive_exception(self):
        def fail(checkpoint):
            checkpoint("dependency_versions")
            raise ValueError("synthetic-private-marker")
        with patch.object(api, "_load_verified_candidate", side_effect=fail), \
                self.assertRaises(api.CandidateVerificationError) as caught:
            api.load_verified_candidate()
        self.assertEqual(str(caught.exception), "Candidate verification failed at stage=dependency_versions")
        with patch.object(api, "_load_verified_candidate", side_effect=fail), \
                self.assertRaises(RuntimeError) as startup:
            with TestClient(api.create_app()):
                pass
        self.assertIn("stage=dependency_versions", str(startup.exception))
        self.assertNotIn("synthetic-private-marker", str(startup.exception))

    def test_manifest_file_failure_never_deserializes(self):
        with patch.object(api, "private_read", side_effect=OSError("synthetic-private-marker")), \
                patch("joblib.load") as load, self.assertRaises(api.CandidateVerificationError) as caught:
            api.load_verified_candidate()
        self.assertEqual(caught.exception.stage, "manifest_file_access")
        load.assert_not_called()

    def test_uvicorn_factory_import_without_model_loading(self):
        import uvicorn
        from fastapi import FastAPI
        # Config.load resolves and invokes the factory, but does not run lifespan.
        with patch("joblib.load", side_effect=AssertionError("Model load forbidden")) as load:
            config = uvicorn.Config(
                "backend.experimental.candidate_api:create_app", factory=True,
                host="127.0.0.1", port=8766, proxy_headers=False,
                access_log=False, server_header=False, log_level="error",
                limit_concurrency=8, timeout_keep_alive=2, ws="none")
            config.load()
            self.assertTrue(config.loaded)
            # Uvicorn wraps the app in middleware; the factory import is resolved.
            from uvicorn.importer import import_from_string
            factory = import_from_string("backend.experimental.candidate_api:create_app")
            self.assertIsInstance(factory(), FastAPI)
            load.assert_not_called()

    def test_direct_launcher_dispatch_without_starting_server(self):
        import runpy
        with patch("uvicorn.run") as run, \
                patch("joblib.load", side_effect=AssertionError("Model load forbidden")) as load:
            runpy.run_path(str(Path(api.__file__)), run_name="__main__")
            run.assert_called_once()
            options = run.call_args.kwargs
            self.assertEqual(options["host"], "127.0.0.1")
            self.assertEqual(options["port"], 8766)
            self.assertEqual(options["log_level"], "error")
            self.assertFalse(options["access_log"])
            self.assertFalse(options["proxy_headers"])
            self.assertFalse(options["server_header"])
            load.assert_not_called()


if __name__ == "__main__": unittest.main()
