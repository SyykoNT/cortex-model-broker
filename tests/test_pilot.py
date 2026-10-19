import json
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cortex_broker.pilot import PilotReadiness, PilotTransport, UnixWorkerServer
from cortex_broker.protocol import Refusal
from cortex_broker.setup import make_server


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR') or os.getcwd())
        self.root = Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def test_real_capture_rpc_and_nonce_binding(self):
        path = self.root/'capture.sock'
        reply_ok = [True]
        seen = []
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                req = json.loads(self.rfile.readline())
                seen.append(req)
                self.wfile.write(json.dumps({'ok': reply_ok[0], 'nonce': req['nonce'],
                    'run_id': req['run_id'], 'network': 'none', 'stdout': 'fsynced',
                    'events': 'fsynced', 'diff': 'fsynced'}).encode())
        with socketserver.UnixStreamServer(str(path), Handler) as server:
            os.chmod(path, 0o660)
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                readiness=PilotReadiness(SimpleNamespace(healthy=lambda:True),path,os.getuid())
                self.assertTrue(readiness.check('run-one'))
                self.assertEqual('run-one',seen[-1]['run_id'])
                reply_ok[0]=False
                self.assertFalse(readiness.check('run-one'))
                os.chmod(path,0o666)
                self.assertFalse(readiness.check())
            finally:server.shutdown();thread.join()
    def test_missing_capture_server_denies(self):
        r=PilotReadiness(SimpleNamespace(healthy=lambda:True),self.root/'missing',os.getuid())
        self.assertFalse(r.worker_ready())
    def test_wrong_capture_peer_denies(self):
        r=PilotReadiness(SimpleNamespace(healthy=lambda:True),self.root/'missing',os.getuid()+1)
        self.assertFalse(r.check('run'))
    def test_transport_capture_loss_before_dispatch_and_delivery(self):
        checks=[]; sent=[]; emitted=[]
        keys=SimpleNamespace(run_for_key=lambda k:'run',worker_key_active=lambda k:True)
        def response(key,payload,emit):
            sent.append(payload);emit(200,'text/event-stream',b'ok')
        transport=SimpleNamespace(keys=keys,capture=object(),responses=response)
        readiness=SimpleNamespace(check=lambda run:checks.pop(0))
        p=PilotTransport(transport,readiness)
        checks[:]=[False]
        with self.assertRaises(Refusal):p.responses('key',{},lambda *x:emitted.append(x))
        self.assertEqual([],sent)
        checks[:]=[True,False]
        with self.assertRaises(Refusal):p.responses('key',{},lambda *x:emitted.append(x))
        self.assertEqual([],emitted)
        checks[:]=[True,True]
        p.responses('key',{},lambda *x:emitted.append(x))
        self.assertEqual([(200,'text/event-stream',b'ok')],emitted)
    def test_unix_worker_http_boundary_no_other_network_endpoint(self):
        path=self.root/'worker.sock'
        ready=SimpleNamespace(snapshot=lambda:{'worker_inference':True})
        with UnixWorkerServer(path,os.getgid(),ready,None) as server:
            server.start()
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                    s.connect(str(path));s.sendall(b'GET /healthz HTTP/1.0\r\nHost: 127.0.0.1:18743\r\n\r\n')
                    body=b''
                    while True:
                        chunk=s.recv(4096)
                        if not chunk:break
                        body+=chunk
                self.assertIn(b'200 OK',body)
                self.assertIn(b'"worker_inference":true',body)
                self.assertEqual(0o660,path.stat().st_mode&0o777)
            finally:server.close()
        self.assertFalse(path.exists())
    def test_existing_worker_socket_is_not_replaced(self):
        path=self.root/'worker.sock';path.write_text('owned evidence')
        with self.assertRaises(Refusal):UnixWorkerServer(path,os.getgid(),None,None)
        self.assertEqual('owned evidence',path.read_text())
    def test_partial_pilot_options_refused_before_server(self):
        with self.assertRaisesRegex(ValueError,'incomplete_pilot'):
            make_server(str(self.root),0,pilot_worker_socket=str(self.root/'worker.sock'))
