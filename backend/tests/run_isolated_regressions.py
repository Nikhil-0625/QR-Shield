"""Run existing suites without production artifacts, credentials, or SQLite files."""
from contextlib import ExitStack
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


def main():
    tests = Path(__file__).resolve().parent
    sys.path.insert(0, str(tests.parent.parent))
    sys.path.insert(0, str(tests))
    sys.path.insert(0, str(tests.parent))
    import sqlalchemy
    import dotenv
    import joblib
    # Import libraries before socket guards; never import production main directly.
    import sklearn.ensemble
    import test_history_authorization as harness
    original_engine = sqlalchemy.create_engine
    original_connect = socket.socket.connect

    def memory_only(url, *args, **kwargs):
        if str(url) != "sqlite://":
            raise AssertionError("Only isolated in-memory SQLite is allowed")
        return original_engine(url, *args, **kwargs)

    def loopback_only(sock, address):
        if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1"):
            raise AssertionError("External network forbidden")
        return original_connect(sock, address)

    with ExitStack() as guards:
        guards.enter_context(patch.object(sqlalchemy, "create_engine", new=memory_only))
        guards.enter_context(patch.object(dotenv, "load_dotenv", return_value=False))
        guards.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")))
        guards.enter_context(patch("socket.socket.connect", new=loopback_only))
        guards.enter_context(patch.object(joblib, "load", side_effect=AssertionError("Model loading forbidden")))
        # This existing harness supplies a synthetic JWT key, in-memory database,
        # and a stub model. Legacy brand/image tests import its isolated module.
        harness.HistoryAuthorizationTests.setUpClass()
        guards.enter_context(patch.dict(sys.modules, {"main": harness.HistoryAuthorizationTests.main}))
        suite = unittest.defaultTestLoader.discover(str(tests), pattern="test_*.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        print("ISOLATED SUMMARY: run=%d failures=%d errors=%d skipped=%d" % (
            result.testsRun, len(result.failures), len(result.errors), len(result.skipped)))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
