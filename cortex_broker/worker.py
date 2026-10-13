"""Separate worker HTTP surface; the setup UI's security policy is untouched.

The shipped runtime has no worker-admission integration. A listening socket and
successful admin probes are explicitly NOT proof of worker readiness.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import socket
import threading
import uuid

from .admin import strict_json
from .protocol import Refusal

MAX_BODY = 8_000_000


class Readiness:
    def __init__(self, capture):
        self.capture = capture

    def snapshot(self):
        broker = self.capture is not None and self.capture.healthy()
        blockers = ['proxy_capture_not_integrated', 'orchestrator_events_not_integrated',
                    'live_fc2_fc5_not_verified', 'worker_transport_not_integrated']
        if not broker:
            blockers.insert(0, 'broker_capture_unavailable')
        return {'worker_inference': False, 'broker_capture': broker,
                'capture_scope': 'broker_admin_acceptance', 'blockers': blockers}

    def worker_ready(self):
        # These are missing engineering integrations/acceptance, not a new
        # operator approval gate. No file, flag, fake heartbeat or admin success
        # can turn an unimplemented producer into a live capture source.
        return self.snapshot()['worker_inference']


class WorkerServer(HTTPServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, address, readiness, transport=None):
        self.readiness, self.transport = readiness, transport
        self.thread = None
        super().__init__(address, WorkerHandler)
        self.authority = f'{self.server_address[0]}:{self.server_address[1]}'

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        return connection, address

    def handle_error(self, request, client_address):
        # Never print headers, keys, inputs or exception details.
        pass

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, name='broker-worker', daemon=True)
        self.thread.start()
        return self

    def close(self):
        if self.thread:
            self.shutdown()
            self.thread.join(timeout=300)
            if self.thread.is_alive():
                raise Refusal('worker_shutdown_incomplete')
            self.thread = None
        self.server_close()


class WorkerHandler(BaseHTTPRequestHandler):
    server: WorkerServer

    def setup(self):
        super().setup()
        # A serial listener has at most one ingress timer. Slow header/body
        # trickles cannot occupy it indefinitely or block service shutdown.
        self.ingress_timer = threading.Timer(3, self.expire_ingress)
        self.ingress_timer.daemon = True
        self.ingress_timer.start()

    def expire_ingress(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self.ingress_timer.cancel()
        super().finish()

    # HTTP/1.0 + Connection:close disallows pipelining and ambiguous leftovers.
    def log_message(self, *args):
        pass

    def reply(self, status, body, mime='application/json'):
        if not isinstance(body, bytes):
            body = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def error(self, status, code):
        return self.reply(status, {'error': {'type': 'broker_refusal', 'code': code}})

    def boundary(self):
        if self.headers.get_all('Host') != [self.server.authority] or self.headers.get_all('Origin'):
            self.error(403, 'invalid_origin_or_host')
            return False
        return True

    def admitted(self):
        if self.server.transport is None or self.server.readiness.worker_ready() is not True:
            self.error(503, 'worker_admission_disabled')
            return False
        return True

    def do_GET(self):
        self.ingress_timer.cancel()
        if not self.boundary():
            return
        if self.path == '/healthz':
            state = self.server.readiness.snapshot()
            return self.reply(200 if state['worker_inference'] else 503, state)
        if self.path == '/v1/models':
            if not self.admitted():
                return
            # Capabilities already bind the only supported worker model; do not
            # turn this endpoint into unauthenticated provider catalog access.
            key = self.key()
            if key is None:
                return
            if not self.server.transport.keys.worker_key_active(key):
                return self.refuse_key(key)
            try:
                self.server.transport.capture.append(self.server.transport.keys.run_for_key(key),
                                                     'worker.models', {'model': 'gpt-6.1-sol'})
            except Exception:
                return self.error(503, 'capture_unavailable')
            return self.reply(200, {'object': 'list', 'data': [
                {'id': 'gpt-6.1-sol', 'object': 'model', 'owned_by': 'openai'}]})
        return self.error(404, 'not_found')

    def refuse_key(self, key=None):
        try:
            transport = self.server.transport
            run = transport.keys.run_for_key(key) if key else None
            transport.capture.append(run or ('denied-' + uuid.uuid4().hex),
                                     'request.refused', {'error': 'invalid_run_key'})
        except Exception:
            return self.error(503, 'capture_unavailable')
        return self.error(401, 'invalid_run_key')

    def key(self):
        values = self.headers.get_all('Authorization', [])
        if len(values) != 1 or not re.fullmatch(r'Bearer [A-Za-z0-9_-]{32,128}', values[0]):
            self.refuse_key()
            return None
        return values[0][7:]

    def do_POST(self):
        if not self.boundary():
            return
        if self.path != '/v1/responses':
            return self.error(404, 'not_found')
        if not self.admitted():
            return
        key = self.key()
        if key is None:
            return
        # Internal acceptance keys never authorize worker traffic.
        if not self.server.transport.keys.worker_key_active(key):
            return self.refuse_key(key)
        lengths = self.headers.get_all('Content-Length', [])
        if (self.headers.get_all('Transfer-Encoding') or len(lengths) != 1
                or not re.fullmatch(r'[0-9]{1,8}', lengths[0])):
            return self.error(400, 'invalid_framing')
        size = int(lengths[0])
        if not 0 < size <= MAX_BODY:
            return self.error(413, 'request_too_large')
        if self.headers.get_all('Content-Type') != ['application/json']:
            return self.error(415, 'json_required')
        try:
            body = self.rfile.read(size)
            self.ingress_timer.cancel()
            if len(body) != size:
                return self.error(400, 'invalid_framing')
            payload = strict_json(body.decode('utf-8'))
            if not isinstance(payload, dict):
                return self.error(400, 'invalid_request')
            # Recheck after ingress, not merely before a possibly slow read.
            if not self.admitted():
                return
            self.server.transport.capture.remember_secrets({key})
            self.server.transport.responses(key, payload,
                                            lambda status, mime, body: self.reply(status, body, mime))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            self.error(400, 'invalid_request')
        except (TimeoutError, socket.timeout):
            self.error(408, 'request_timeout')
        except Refusal:
            self.error(503, 'request_refused')
        except Exception:
            self.error(503, 'operation_failed')
