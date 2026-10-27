"""Loopback-only QR Shield development gateway. Not a production server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection, HTTPException, IncompleteRead
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse
import mimetypes
import json
import re
import threading
import time
from collections import deque

FRONTEND = Path(__file__).resolve().parents[1] / 'frontend'
MAX_BODY = 6 * 1024 * 1024
BODY_READ_SECONDS = 30
HOP_HEADERS = {'connection','keep-alive','proxy-authenticate','proxy-authorization',
               'te','trailer','transfer-encoding','upgrade'}
STATIC_TYPES = {'.html','.css','.js','.png','.jpg','.jpeg','.svg','.ico','.webp','.woff','.woff2'}


class Gateway(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass  # Do not log URLs, credentials, uploaded content or private responses.

    def fail(self, status, message, retry_after=None):
        api_error = self.path.startswith('/api/')
        body = json.dumps({'status': 'error', 'message': message, 'detail': message}).encode() if api_error else (message + '\n').encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json' if api_error else 'text/plain; charset=utf-8')
        if retry_after is not None:
            self.send_header('Retry-After', str(retry_after))
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        if self.command != 'HEAD':
            self.wfile.write(body)

    def dispatch(self):
        hosts = self.headers.get_all('Host', [])
        if len(hosts)!=1 or not re.fullmatch(r'(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?',hosts[0]):
            return self.fail(400,'Invalid host header')
        try:
            urlsplit('//'+hosts[0]).port
        except ValueError:
            return self.fail(400,'Invalid host port')
        if any(len(self.headers.get_all(name,[]))>1 for name in ('Authorization','Origin','Content-Type')) or len(self.headers.get('Authorization',''))>8192:
            return self.fail(400,'Ambiguous request headers')
        if self.server.public_test or self.server.restrict_hosts:
            host = self.headers.get('Host', '').lower()
            if host not in self.server.allowed_hosts:
                return self.fail(400, 'Unrecognized host')
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            return self.fail(400, 'Invalid path')
        path = unquote(parsed.path)
        if parsed.scheme or parsed.netloc or not path.startswith('/') or any(
            c in path for c in ('\\', ':', '\x00', '%')
        ) or any(part.startswith('.') for part in path.split('/') if part):
            return self.fail(400, 'Invalid path')
        if path.startswith('/api/'):
            return self.proxy(path[4:] + ('?' + parsed.query if parsed.query else ''))
        if self.command not in ('GET', 'HEAD'):
            return self.fail(405, 'Method not allowed')
        relative = 'login.html' if path == '/' else path.lstrip('/')
        if relative.lower().startswith('tests/'):
            return self.fail(404,'Not found')
        candidate = FRONTEND / relative
        # Reject symlinks/junctions even if they currently resolve inside the root.
        if any(p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction())
               for p in [candidate, *candidate.parents] if p != FRONTEND.parent):
            return self.fail(404, 'Not found')
        resolved = candidate.resolve()
        if not resolved.is_relative_to(FRONTEND.resolve()) or resolved.suffix.lower() not in STATIC_TYPES or not resolved.is_file():
            return self.fail(404, 'Not found')
        body = resolved.read_bytes()
        if resolved.name in {'login.html','scan.html','dashboard.html','website-checker.html'}:
            body = body.replace(b'<head>', b'<head><script>window.QR_SHIELD_API_BASE="/api";</script>', 1)
        self.send_response(200)
        self.send_header('Content-Type', mimetypes.guess_type(resolved.name)[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def proxy(self, target):
        path = target.split('?', 1)[0]
        if self.server.public_test:
            allowed = (self.command == 'DELETE' and path == '/history') or (self.command == 'POST' and path in ('/login', '/register', '/scan', '/website/check')) or (
                self.command in ('GET', 'HEAD') and (path in {'/history', '/history/page', '/history/summary'} or re.fullmatch(r'/report/[0-9]+', path)))
            if not allowed:
                return self.fail(404, 'Not found')
            limits = {'/login': (30, 60), '/register': (10, 600), '/scan': (10, 60)}
            bucket = '/scan' if path == '/website/check' else path
            if bucket in limits:
                count, seconds = limits[bucket]
                now = time.monotonic()
                with self.server.rate_lock:
                    events = self.server.rate_events.setdefault(bucket, deque())
                    while events and events[0] <= now - seconds:
                        events.popleft()
                    if len(events) >= count:
                        return self.fail(429, 'Testing request limit reached; try again later', retry_after=seconds)
                    events.append(now)
        if self.headers.get('Transfer-Encoding'):
            return self.fail(400, 'Transfer encoding not supported')
        lengths = self.headers.get_all('Content-Length', [])
        try:
            if lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0])>10): raise ValueError
            size = int(lengths[0]) if lengths else 0
            if len(lengths) > 1 or size < 0: raise ValueError
        except ValueError:
            return self.fail(400, 'Invalid content length')
        limit = MAX_BODY if path == '/scan' else 16 * 1024
        if size > limit:
            return self.fail(413, 'Development upload limit exceeded')
        try:
            deadline = time.monotonic()+BODY_READ_SECONDS
            body = bytearray()
            while len(body)<size:
                remaining = deadline-time.monotonic()
                if remaining<=0: return self.fail(408,'Request timeout')
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(64*1024,size-len(body)))
                if not chunk: return self.fail(400,'Incomplete request')
                body.extend(chunk)
            if time.monotonic()>deadline: return self.fail(408,'Request timeout')
            self.connection.settimeout(30)
        except (TimeoutError, OSError):
            return self.fail(408, 'Request timeout')
        excluded = HOP_HEADERS | {'host','content-length','cookie','expect'}
        if self.server.public_test:
            excluded.add('x-qr-shield-offline')
        excluded |= {h.strip().lower() for h in self.headers.get('Connection','').split(',')}
        headers = {k:v for k,v in self.headers.items() if k.lower() not in excluded
                   and not k.lower().startswith(('x-tunnel-', 'x-forwarded-'))}
        if self.server.public_test:
            headers['X-QR-Shield-Offline'] = '1'
        upstream = HTTPConnection('127.0.0.1', self.server.backend_port, timeout=45)
        started = False
        try:
            upstream.request(self.command, target, body=body, headers=headers)
            response = upstream.getresponse()
            no_body = self.command == 'HEAD' or response.status in (204, 304) or 100 <= response.status < 200
            lengths = response.headers.get_all('Content-Length', [])
            length = None
            if lengths and not response.chunked:
                if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                    raise HTTPException('Invalid upstream response length')
                length = int(lengths[0])
            chunked = not no_body and length is None
            self.send_response(response.status)
            excluded_response = HOP_HEADERS | {'content-length','server','date','cache-control'}
            excluded_response |= {h.strip().lower() for h in (response.getheader('Connection') or '').split(',')}
            for k,v in response.getheaders():
                if k.lower() not in excluded_response:
                    self.send_header(k,v)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            # Explicit framing lets HTTP/1.1 relays finish without waiting for EOF.
            if length is not None and response.status != 204 and not 100 <= response.status < 200:
                self.send_header('Content-Length', str(length))
            elif chunked:
                self.send_header('Transfer-Encoding', 'chunked')
            if self.close_connection:
                self.send_header('Connection', 'close')
            self.end_headers()
            started = True
            if not no_body:
                remaining = length
                while remaining is None or remaining > 0:
                    chunk = response.read1(min(64 * 1024, remaining) if remaining is not None else 64 * 1024)
                    if not chunk:
                        if remaining:
                            raise IncompleteRead(b'', remaining)
                        break
                    if chunked:
                        self.wfile.write(f'{len(chunk):X}\r\n'.encode('ascii'))
                    self.wfile.write(chunk)
                    if chunked:
                        self.wfile.write(b'\r\n')
                    if remaining is not None:
                        remaining -= len(chunk)
                    self.wfile.flush()
                if chunked:
                    self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except (OSError, TimeoutError, HTTPException):
            if not started: self.fail(502, 'Local API unavailable')
            else: self.close_connection = True
        finally:
            upstream.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = dispatch


class GatewayServer(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        self.connections = threading.BoundedSemaphore(12)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        request.settimeout(15)
        if not self.connections.acquire(blocking=False):
            try:
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


def make_server(port=5500, backend_port=8000, public_test=False, allowed_hosts=()):
    server = GatewayServer(('127.0.0.1', port), Gateway)
    server.backend_port = backend_port
    server.public_test = public_test
    server.restrict_hosts = bool(allowed_hosts)
    server.allowed_hosts = {f'127.0.0.1:{server.server_port}', f'localhost:{server.server_port}'} | {h.lower() for h in allowed_hosts}
    server.rate_lock = threading.Lock()
    server.rate_events = {}
    return server


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=5500)
    parser.add_argument('--public-test', action='store_true', help='Enable bounded public-link testing safeguards; does not create or publish a tunnel')
    parser.add_argument('--allowed-host', action='append', default=[], help='Exact forwarded HTTPS hostname, without scheme or path')
    args = parser.parse_args()
    if any(not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?', h) for h in args.allowed_host):
        parser.error('--allowed-host must be an exact hostname, optionally with port')
    if args.public_test and not args.allowed_host:
        parser.error('--public-test requires --allowed-host for the forwarded hostname')
    server = make_server(args.port, public_test=args.public_test, allowed_hosts=args.allowed_host)
    print(f'QR Shield gateway: http://127.0.0.1:{server.server_port}/login.html -> localhost:8000')
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
