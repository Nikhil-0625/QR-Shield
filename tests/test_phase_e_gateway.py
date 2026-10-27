"""New explicit history routes retain the gateway's existing public allowlist."""
import unittest
from unittest.mock import patch
from test_dev_gateway import gateway, start, request


class PhaseEGatewayTests(unittest.TestCase):
    def test_only_explicit_get_history_views_are_forwarded(self):
        server = gateway.make_server(0, backend_port=65500, public_test=True, allowed_hosts=("phase-e.example",))
        start(server)
        try:
            headers = {"Host":"phase-e.example"}
            with patch.object(gateway, "HTTPConnection") as upstream:
                upstream.return_value.request.side_effect = OSError("Synthetic unavailable backend")
                for path in ["/api/history/page?limit=50&snapshot=2", "/api/history/summary"]:
                    self.assertEqual(request(server,path,headers=headers)[0],502)
                self.assertEqual(upstream.call_count,2)
                for path in ["/api/history/private", "/api/history/summary/extra", "/api/docs"]:
                    self.assertEqual(request(server,path,headers=headers)[0],404)
                self.assertEqual(request(server,"/api/history/page","POST",headers=headers)[0],404)
                self.assertEqual(upstream.call_count,2)
        finally:
            server.shutdown();server.server_close()
