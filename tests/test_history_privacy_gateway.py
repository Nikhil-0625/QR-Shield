"""Public-test gateway exposes only the intended history deletion route."""
import unittest
from unittest.mock import patch
from test_dev_gateway import gateway, start, request


class HistoryPrivacyGatewayTests(unittest.TestCase):
    def test_delete_allowlist_is_narrow(self):
        server = gateway.make_server(0, backend_port=65500, public_test=True,
                                     allowed_hosts=("privacy.example",))
        start(server)
        try:
            with patch.object(gateway, "HTTPConnection") as upstream:
                upstream.return_value.request.side_effect = OSError("Synthetic unavailable backend")
                headers = {"Host": "privacy.example", "Authorization": "Bearer synthetic"}
                self.assertEqual(request(server, "/api/history", "DELETE", headers=headers)[0], 502)
                upstream.return_value.request.assert_called_once()
                args, kwargs = upstream.return_value.request.call_args
                self.assertEqual(args[:2], ("DELETE", "/history"))
                self.assertEqual(kwargs["headers"]["Authorization"], "Bearer synthetic")
                for path in ("/api/history/page", "/api/history/summary", "/api/history/22", "/api/scan"):
                    self.assertEqual(request(server, path, "DELETE", headers=headers)[0], 404)
                self.assertEqual(upstream.return_value.request.call_count, 1)
        finally:
            server.shutdown()
            server.server_close()
