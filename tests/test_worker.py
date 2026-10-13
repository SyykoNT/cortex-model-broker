"""Worker HTTP adapter with explicitly synthetic all-three/acceptance readiness.

These positive fixtures do NOT unlock the deployed CLI or establish FC2/FC5.
"""
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from cortex_broker.protocol import RunKeys
from cortex_broker.traffic import Capture, Transport
from cortex_broker.worker import WorkerServer
from test_admin import FixtureProvider
from test_traffic import AuthFixture


class FixtureReadiness:
    def __init__(self, health):
        self.health = health
        self.acceptance = True  # synthetic test prerequisite only

    def worker_ready(self):
        return self.acceptance and all(self.health.values())

    def snapshot(self):
        return {'worker_inference': self.worker_ready()}


class WorkerTests(unittest.TestCase):
    def setUp(self):
        scanner = os.environ.get('TEST_GITLEAKS')
        self.assertTrue(scanner, 'real gitleaks required')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.health = {'broker': True, 'proxy': True, 'orchestrator': True}
        self.capture = Capture(self.tmp.name, scanner, lambda: all(self.health.values()))
        self.keys = RunKeys()
        self.key = self.keys.mint('fixture-worker', 'builder', 'gpt-6.1-sol', 'medium', time.time() + 60, 3)
        self.provider = FixtureProvider()
        self.limits = []
        self.transport = Transport(AuthFixture(), self.keys, self.capture,
                                   lambda *a: self.limits.append(a), self.provider)
        self.readiness = FixtureReadiness(self.health)
        self.server = WorkerServer(('127.0.0.1', 0), self.readiness, self.transport).start()
        self.addCleanup(self.server.close)
        self.payload = {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'},
                        'input': [{'role': 'user', 'content': 'synthetic prompt'},
                                  {'type': 'function_call_output', 'call_id': 'fixture-tool',
                                   'output': 'synthetic tool result'}]}
        live = patch('cortex_broker.auth.HTTP.open', side_effect=AssertionError('provider forbidden'))
        live.start()
        self.addCleanup(live.stop)

    def call(self, method='POST', path='/v1/responses', payload=None, headers=None):
        c = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            body = json.dumps(self.payload if payload is None else payload)
            h = {'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json'}
            h.update(headers or {})
            c.request(method, path, body, h)
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def rows(self):
        return [json.loads(line) for p in Path(self.tmp.name).glob('*.jsonl')
                for line in p.read_text().splitlines()]

    def test_real_http_capture_and_unmodified_buffered_sse(self):
        status, headers, body = self.call()
        self.assertEqual(200, status)
        self.assertEqual('text/event-stream', headers['Content-Type'])
        self.assertEqual('no-store', headers['Cache-Control'])
        rows = self.rows()
        self.assertEqual(['request.received', 'request.upstream', 'response'], [r['kind'] for r in rows])
        self.assertEqual(body.decode(), rows[-1]['data']['body'])
        self.assertEqual(self.payload, rows[0]['data']['request'])
        upstream = json.loads(self.provider.requests[0].data)
        self.assertFalse(upstream['store'])
        self.assertTrue(upstream['stream'])
        self.assertEqual('gpt-6.1-sol', upstream['model'])
        self.assertNotIn(self.key, json.dumps(rows))

    def test_each_source_and_acceptance_blocks_before_provider(self):
        for source in self.health:
            self.health[source] = False
            self.assertEqual(503, self.call()[0])
            self.assertEqual(503, self.call('GET', '/healthz')[0])
            self.health[source] = True
        self.readiness.acceptance = False
        self.assertEqual(503, self.call()[0])
        self.assertEqual([], self.provider.requests)

    def test_gate_rechecked_after_ingress(self):
        with patch.object(self.readiness, 'worker_ready', side_effect=[True, False]):
            self.assertEqual(503, self.call()[0])
        self.assertEqual([], self.provider.requests)

    def test_downstream_capture_failure_emits_no_upstream_body(self):
        original = self.capture.append
        def fail_response(run, kind, value):
            if kind == 'response':
                raise OSError('synthetic disk failure')
            return original(run, kind, value)
        with patch.object(self.capture, 'append', side_effect=fail_response):
            status, _, body = self.call()
        self.assertEqual(503, status)
        self.assertNotIn(b'response.completed', body)
        self.assertEqual(1, len(self.provider.requests))

    def test_key_bounds_and_denials_captured_without_key(self):
        wrong = {**self.payload, 'reasoning': {'effort': 'high'}}
        self.assertEqual(503, self.call(payload=wrong)[0])
        self.keys.revoke_run('fixture-worker')
        self.assertEqual(401, self.call()[0])
        self.assertEqual(['request.refused', 'request.refused'], [r['kind'] for r in self.rows()])
        self.assertNotIn(self.key, json.dumps(self.rows()))
        self.assertEqual([], self.provider.requests)

    def test_internal_acceptance_key_not_a_worker_key(self):
        self.key = self.keys.mint('fixture-admin', 'acceptance', 'gpt-6.1-sol', 'medium', time.time() + 60, 1)
        self.assertEqual(401, self.call()[0])
        self.assertEqual(401, self.call('GET', '/v1/models')[0])
        self.assertEqual([], self.provider.requests)

    def test_catalog_only_with_active_bound_key_and_captured(self):
        status, _, body = self.call('GET', '/v1/models')
        self.assertEqual(200, status)
        self.assertEqual('gpt-6.1-sol', json.loads(body)['data'][0]['id'])
        self.assertEqual('worker.models', self.rows()[0]['kind'])
        self.assertEqual([], self.provider.requests)

    def test_origin_host_paths_and_untrusted_body_never_dispatch(self):
        for headers, expected in [({'Origin': 'null'}, 403), ({'Host': 'other.example'}, 403),
                                  ({'Content-Type': 'text/plain'}, 415),
                                  ({'Transfer-Encoding': 'chunked'}, 400),
                                  ({'Content-Length': '8000001'}, 413),
                                  ({'Authorization': 'Bearer invalid'}, 401)]:
            self.assertEqual(expected, self.call(headers=headers)[0])
        self.assertEqual(400, self.call(payload=[])[0])
        for path in ('/auth/start', '/auth/callback', '/admin', '/v1/responses?extra=1'):
            self.assertEqual(404, self.call(path=path)[0])
        self.assertEqual([], self.provider.requests)

    def test_duplicate_headers_and_json_fields_refused(self):
        for extra, body in [('Content-Length: 2\r\n', b'{}'),
                            ('Authorization: Bearer invalid\r\n', b'{}'),
                            ('', b'{"model":"one","model":"two"}')]:
            with socket.create_connection(self.server.server_address, timeout=5) as connection:
                raw = (f'POST /v1/responses HTTP/1.1\r\nHost: {self.server.authority}\r\n'
                       f'Authorization: Bearer {self.key}\r\nContent-Type: application/json\r\n'
                       f'Content-Length: {len(body)}\r\n{extra}\r\n').encode() + body
                connection.sendall(raw)
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertIn(response.status, (400, 401))
                response.read()
        self.assertEqual([], self.provider.requests)

    def test_absolute_ingress_deadline_releases_serial_listener(self):
        with socket.create_connection(self.server.server_address, timeout=5) as connection:
            start = time.monotonic()
            connection.sendall(b'POST /v1/responses HTTP/1.1\r\nHost: ')
            for _ in range(5):
                time.sleep(0.4)
                connection.sendall(b'x')
            # Socket inactivity alone would grant another three seconds here.
            connection.recv(4096)
            self.assertLess(time.monotonic() - start, 4.2)
        self.assertEqual(200, self.call('GET', '/healthz')[0])
        self.assertEqual([], self.provider.requests)

    def test_usage_limit_preserved_and_callback_exercised(self):
        self.provider.events = [{'type': 'response.failed', 'response': {
            'error': {'code': 'subscription_sharing_usage_limit_exceeded'}}}]
        status, _, body = self.call()
        self.assertEqual(200, status)
        self.assertIn(b'subscription_sharing_usage_limit_exceeded', body)
        self.assertEqual(1, len(self.limits))
