"""Raw HTTP ambiguity checks on ephemeral loopback-only gateways."""
import socket
import unittest
from unittest.mock import patch
from test_dev_gateway import gateway, start, request


class PhaseCGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=gateway.make_server(0,backend_port=65500,public_test=True,allowed_hosts=("guide-demo.example",))
        start(cls.server)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close()

    def raw_status(self,extra):
        with socket.create_connection(("127.0.0.1",self.server.server_port),timeout=5) as connection:
            connection.sendall(b"POST /api/login HTTP/1.1\r\n"+extra+b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            response=connection.recv(4096)
            return int(response.split(b" ")[1])

    def test_duplicate_host_authorization_origin_never_reach_backend(self):
        with patch.object(gateway,"HTTPConnection") as upstream:
            for extra in (b"Host: guide-demo.example\r\nHost: evil.example\r\n",b"Host: guide-demo.example\r\nAuthorization: Bearer one\r\nAuthorization: Bearer two\r\n",b"Host: guide-demo.example\r\nOrigin: https://one.example\r\nOrigin: https://two.example\r\n",b"Host: guide-demo.example\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n",b"Host: guide-demo.example@evil.example\r\n"):
                self.assertEqual(self.raw_status(extra),400)
            upstream.assert_not_called()

    def test_forwarded_host_cannot_override_actual_host(self):
        self.assertEqual(request(self.server,"/login.html",headers={"Host":"evil.example","X-Forwarded-Host":"guide-demo.example"})[0],400)
        self.assertEqual(request(self.server,"/login.html",headers={"Host":"guide-demo.example","X-Forwarded-Host":"evil.example"})[0],200)

    def test_tests_docs_and_signed_lengths_are_not_exposed(self):
        headers={"Host":"guide-demo.example"}
        for path in ("/tests/phase-b.test.js","/TESTS/phase-b.test.js","/tests/result-explanations.test.js","/api/docs","/api/openapi.json"):
            self.assertEqual(request(self.server,path,headers=headers)[0],404)
        with patch.object(gateway,"HTTPConnection") as upstream:
            self.assertEqual(request(self.server,"/api/login","POST",headers={**headers,"Content-Length":"+1"})[0],400)
            upstream.assert_not_called()

    def test_private_tunnel_frontend_host_compatibility(self):
        server=gateway.make_server(0)
        start(server)
        try:
            self.assertEqual(server.server_address[0],"127.0.0.1")
            self.assertEqual(request(server,"/login.html",headers={"Host":"synthetic-5500.devtunnels.ms"})[0],200)
        finally:
            server.shutdown();server.server_close()

    def test_explicit_private_host_configuration_is_enforced(self):
        server=gateway.make_server(0,allowed_hosts=("synthetic-5500.devtunnels.ms",))
        start(server)
        try:
            self.assertEqual(request(server,"/login.html",headers={"Host":"synthetic-5500.devtunnels.ms"})[0],200)
            self.assertEqual(request(server,"/login.html",headers={"Host":"wrong.example"})[0],400)
        finally:
            server.shutdown();server.server_close()

    def test_partial_upload_times_out_before_backend_submission(self):
        with patch.object(gateway,"BODY_READ_SECONDS",.02),patch.object(gateway,"HTTPConnection") as upstream:
            with socket.create_connection(("127.0.0.1",self.server.server_port),timeout=5) as connection:
                connection.sendall(b"POST /api/login HTTP/1.1\r\nHost: guide-demo.example\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx")
                self.assertEqual(int(connection.recv(4096).split(b" ")[1]),408)
            upstream.assert_not_called()
