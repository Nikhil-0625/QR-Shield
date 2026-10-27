"""Gateway tests use ephemeral loopback ports and isolated synthetic backend data."""
import http.client
import importlib.util
import io
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch
import json

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gateway',ROOT/'tools/dev_gateway.py')
gateway=importlib.util.module_from_spec(spec);spec.loader.exec_module(gateway)


def start(server):
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return thread


def request(server,path,method='GET',body=None,headers=None):
    connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=20)
    try:
        connection.request(method,path,body=body,headers=headers or {})
        response=connection.getresponse();return response.status,response.read(),dict(response.getheaders())
    finally: connection.close()


class GatewayBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self):
                body=self.rfile.read(int(self.headers.get('Content-Length',0)))
                payload=json.dumps({'method':self.command,'path':self.path,'body':body.hex(),'authorization':self.headers.get('Authorization'),'tunnel':self.headers.get('X-Tunnel-Authorization'),'cookie':self.headers.get('Cookie'),'content_type':self.headers.get('Content-Type')}).encode()
                self.send_response(201);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            do_GET=do_POST=do_PUT=do_PATCH=do_DELETE=do_OPTIONS=reply
        cls.upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream);start(cls.upstream)
        cls.server=gateway.make_server(0,cls.upstream.server_port);start(cls.server)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.upstream.shutdown();cls.upstream.server_close()
    def test_loopback_binding(self):self.assertEqual(self.server.server_address[0],'127.0.0.1')
    def test_only_frontend_files_and_gateway_configuration(self):
        for path in ['/','/login.html','/scan.html','/dashboard.html']:
            code,body,_=request(self.server,path);self.assertEqual(code,200);self.assertIn(b'window.QR_SHIELD_API_BASE="/api"',body)
        self.assertEqual(request(self.server,'/theme.css')[1],(ROOT/'frontend/theme.css').read_bytes())
        for path in ['/main.py','/backend/main.py','/.env','/scan_history.db','/tools/dev_gateway.py','/.git/config','/missing.html','/tests/','/api']:
            self.assertIn(request(self.server,path)[0],(400,404))
    def test_traversal_and_symlinks(self):
        for path in ['/../backend/main.py','/%2e%2e/backend/main.py','/%252e%252e/backend/main.py','/..%5cbackend%5cmain.py','/C:/Windows/win.ini','/api/../.env']:
            self.assertEqual(request(self.server,path)[0],400,path)
        with patch.object(Path,'is_symlink',return_value=True):self.assertEqual(request(self.server,'/login.html')[0],404)
    def test_proxy_methods_headers_and_binary_body(self):
        body=b'--boundary\r\nraw\x00\xffupload\r\n--boundary--'
        for method in ['GET','POST','PUT','PATCH','DELETE','OPTIONS']:
            code,raw,_=request(self.server,'/api/scan?test=1',method,body,{'Authorization':'Bearer synthetic','Content-Type':'multipart/form-data; boundary=boundary','X-Tunnel-Authorization':'do-not-relay','Cookie':'tunnel-cookie'})
            self.assertEqual(code,201);data=json.loads(raw)
            self.assertEqual((data['method'],data['path'],data['body'],data['authorization']),(method,'/scan?test=1',body.hex(),'Bearer synthetic'))
            self.assertEqual(data['content_type'],'multipart/form-data; boundary=boundary')
            self.assertIsNone(data['tunnel']);self.assertIsNone(data['cookie'])
    def test_bad_framing_and_upload_limit(self):
        self.assertEqual(request(self.server,'/api/scan','POST',headers={'Transfer-Encoding':'chunked'})[0],400)
        self.assertEqual(request(self.server,'/api/scan','POST',headers={'Content-Length':str(gateway.MAX_BODY+1)})[0],413)
    def test_upstream_unavailable(self):
        with patch.object(gateway,'HTTPConnection') as upstream:
            upstream.return_value.request.side_effect=ConnectionRefusedError
            self.assertEqual(request(self.server,'/api/history')[0],502)


class GatewayFramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Upstream(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def do_GET(self):
                if self.path=='/chunked':
                    self.send_response(200);self.send_header('Transfer-Encoding','chunked');self.end_headers()
                    self.wfile.write(b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n');self.wfile.flush()
                elif self.path=='/invalid-length':
                    self.send_response(200);self.send_header('Content-Length','invalid');self.end_headers();self.close_connection=True
                elif self.path.startswith('/status/'):
                    code=int(self.path.rsplit('/',1)[1]);payload=b'{"detail":"synthetic error"}'
                    self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
                elif self.path=='/binary':
                    payload=bytes(range(256))*1024
                    self.send_response(200);self.send_header('Content-Type','application/pdf');self.send_header('Content-Length',str(len(payload)));self.send_header('Content-Disposition','attachment; filename=synthetic.pdf');self.end_headers();self.wfile.write(payload)
                elif self.path=='/truncated':
                    self.send_response(200);self.send_header('Content-Length','10');self.end_headers();self.wfile.write(b'ab');self.close_connection=True
                elif self.path=='/empty':
                    self.send_response(204);self.end_headers()
                else:
                    self.send_response(200);self.send_header('Content-Length','5');self.send_header('Content-Type','application/json');self.send_header('Connection','keep-alive, X-Hop');self.send_header('X-Hop','remove');self.end_headers();self.wfile.write(b'12345')
            def do_HEAD(self):
                self.send_response(200);self.send_header('Content-Length','5');self.end_headers()
            def do_OPTIONS(self):
                self.send_response(204);self.end_headers()
        cls.upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream);start(cls.upstream)
        cls.server=gateway.make_server(0,cls.upstream.server_port);start(cls.server)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.upstream.shutdown();cls.upstream.server_close()
    def test_fixed_length_response_is_self_delimited_and_reusable(self):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=2)
        try:
            for _ in range(2):
                conn.request('GET','/api/fixed');response=conn.getresponse()
                self.assertEqual(response.getheader('Content-Length'),'5')
                self.assertFalse(response.will_close)
                self.assertIsNone(response.getheader('X-Hop'))
                self.assertEqual(response.read(),b'12345')
        finally:conn.close()
    def test_chunked_response_is_explicitly_terminated(self):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=2)
        try:
            conn.request('GET','/api/chunked');r=conn.getresponse()
            self.assertEqual(r.getheader('Transfer-Encoding'),'chunked')
            self.assertIsNone(r.getheader('Content-Length'))
            self.assertEqual(r.read(),b'abcde')
            conn.request('GET','/api/fixed');self.assertEqual(conn.getresponse().read(),b'12345')
        finally:conn.close()
    def test_head_and_options_complete_without_a_body(self):
        code,body,headers=request(self.server,'/api/fixed','HEAD');self.assertEqual((code,body),(200,b''));self.assertEqual(headers.get('Content-Length'),'5')
        for method,path in [('OPTIONS','/api/empty'),('GET','/api/empty')]:
            code,body,headers=request(self.server,path,method);self.assertEqual((code,body),(204,b''));self.assertNotIn('Transfer-Encoding',headers)
    def test_error_statuses_and_binary_payload_preserved(self):
        for code in [400,401,403,404,422,500]:
            status,body,headers=request(self.server,'/api/status/'+str(code))
            self.assertEqual(status,code);self.assertEqual(body,b'{"detail":"synthetic error"}');self.assertEqual(headers['Content-Type'],'application/json');self.assertEqual(int(headers['Content-Length']),len(body))
        code,body,headers=request(self.server,'/api/binary')
        self.assertEqual(body,bytes(range(256))*1024);self.assertEqual(headers['Content-Length'],str(len(body)));self.assertIn('attachment',headers['Content-Disposition'])
    def test_invalid_upstream_length_returns_completed_502(self):
        code,body,headers=request(self.server,'/api/invalid-length');self.assertEqual(code,502);self.assertEqual(int(headers['Content-Length']),len(body))
    def test_static_head_length_matches_get(self):
        code,body,headers=request(self.server,'/login.html')
        status,empty,head=request(self.server,'/login.html','HEAD')
        self.assertEqual((code,status,empty),(200,200,b''));self.assertEqual(head['Content-Length'],str(len(body)))
    def test_upstream_truncation_is_not_reported_as_complete(self):
        with self.assertRaises(http.client.IncompleteRead):request(self.server,'/api/truncated')


class PublicTestingGatewayTests(unittest.TestCase):
    def setUp(self):
        self.server=gateway.make_server(0,public_test=True,allowed_hosts=['friends.example']);start(self.server)
    def tearDown(self):self.server.shutdown();self.server.server_close()
    def test_docs_debug_and_unknown_api_routes_are_not_exposed(self):
        for path in ['/api/docs','/api/redoc','/api/openapi.json','/api/debug','/api/experimental/predict','/api/not-found']:
            self.assertEqual(request(self.server,path)[0],404)
    def test_host_allowlist_and_limits(self):
        self.assertEqual(request(self.server,'/login.html',headers={'Host':'evil.example'})[0],400)
        self.assertEqual(request(self.server,'/login.html',headers={'Host':'friends.example'})[0],200)
        self.assertEqual(request(self.server,'/api/login','POST',headers={'Content-Length':'17000'})[0],413)
    def test_global_rate_limit_cannot_be_bypassed_by_forwarded_ip(self):
        from collections import deque
        self.server.rate_events['/register']=deque([time.monotonic()]*10)
        code,body,_=request(self.server,'/api/register','POST',headers={'X-Forwarded-For':'203.0.113.9'})
        self.assertEqual(code,429)
        self.assertNotIn(b'Traceback',body)
        self.server.rate_events['/register']=deque([time.monotonic()-601]*10)
        with patch.object(gateway,'HTTPConnection') as upstream:
            upstream.return_value.request.side_effect=ConnectionRefusedError
            self.assertEqual(request(self.server,'/api/register','POST')[0],502)
    def test_connection_cap_rejects_excess_without_upstream(self):
        for _ in range(12):self.server.connections.acquire()
        try:
            try:self.assertEqual(request(self.server,'/login.html')[0],503)
            except (ConnectionAbortedError,ConnectionResetError):pass  # Overload may close before Windows delivers the 503.
        finally:
            for _ in range(12):self.server.connections.release()


class IsolatedFastApiGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0,str(ROOT/'backend/tests'))
        import test_history_authorization as harness
        import uvicorn
        cls.harness=harness.HistoryAuthorizationTests
        with patch('dotenv.load_dotenv',return_value=False):cls.harness.setUpClass()
        fixture=cls.harness();fixture.setUp()
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen()
        cls.uvicorn=uvicorn.Server(uvicorn.Config(cls.harness.main.app,log_level='critical',access_log=False))
        cls.thread=threading.Thread(target=lambda:cls.uvicorn.run(sockets=[sock]),daemon=True);cls.thread.start()
        for _ in range(100):
            if cls.uvicorn.started:break
            time.sleep(.05)
        assert cls.uvicorn.started
        cls.server=gateway.make_server(0,sock.getsockname()[1],public_test=True);start(cls.server)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.uvicorn.should_exit=True;cls.thread.join(10);cls.harness.tearDownClass();sys.path.pop(0)
    def test_actual_routes_with_synthetic_accounts_and_real_qr_pdf(self):
        credentials={'email':'gateway@example.test','password':'Local!Gateway123'}
        for route in ['register','login']:
            code,body,_=request(self.server,'/api/'+route,'POST',json.dumps(credentials),{'Content-Type':'application/json'})
            self.assertEqual(code,200);self.assertEqual(json.loads(body)['status'],'success')
        auth={'Authorization':'Bearer '+json.loads(body)['access_token']}
        self.assertEqual(request(self.server,'/api/history')[0],401)
        import qrcode
        image=io.BytesIO();qrcode.make('Synthetic gateway QR text').save(image,format='PNG')
        body=b'--local\r\nContent-Disposition: form-data; name="file"; filename="local.png"\r\nContent-Type: image/png\r\n\r\n'+image.getvalue()+b'\r\n--local--\r\n'
        code,raw,_=request(self.server,'/api/scan','POST',body,{**auth,'Content-Type':'multipart/form-data; boundary=local'})
        self.assertEqual(code,200);result=json.loads(raw);self.assertEqual(result['decoded_content'],'Synthetic gateway QR text')
        record=result['scan_id']
        code,raw,_=request(self.server,'/api/history',headers=auth);self.assertEqual(code,200);self.assertEqual([r['id'] for r in json.loads(raw)],[record])
        code,pdf,headers=request(self.server,'/api/report/'+str(record),headers=auth)
        self.assertEqual(code,200);self.assertTrue(pdf.startswith(b'%PDF'));self.assertIn('application/pdf',headers['content-type']);self.assertIn('attachment',headers['content-disposition'])
        other={'Authorization':'Bearer '+self.harness().token('b@example.test')}
        self.assertEqual(request(self.server,'/api/report/'+str(record),headers=other)[0],404)
        self.assertEqual(request(self.server,'/api/not-found',headers=auth)[0],404)


if __name__=='__main__':unittest.main()
