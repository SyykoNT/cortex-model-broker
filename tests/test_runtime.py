"""Offline deployment composition; synthetic provider, real disk/scanner/HTTP/UDS."""
import http.client
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cortex_broker.admin import request
from cortex_broker.auth import DIRECT
from cortex_broker.capture_health import BrokerCapture
from cortex_broker.setup import make_server
from test_admin import FixtureProvider, packet

SCANNER = os.environ.get('TEST_GITLEAKS')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCANNER, 'real gitleaks required')
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', Path.cwd()))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.logs = self.root / 'capture'
        self.logs.mkdir(mode=0o750)
        self.node = self.root / 'admin.sock'
        self.provider = FixtureProvider()
        self.network = patch('cortex_broker.auth.HTTP.open', side_effect=self.provider.open)
        self.network.start()
        self.addCleanup(self.network.stop)

    def server(self):
        server = make_server(self.root / 'state', 0, admin_path=self.node,
                             admin_uid=os.getuid(), admin_gid=os.getgid(),
                             capture_directory=self.logs, scanner=SCANNER, worker_port=0)
        self.addCleanup(server.server_close)
        return server

    def login_fixture(self, server):
        with server.auth.store.lock():
            server.auth.store.write('active.json', {'account': 'fixture'})
            server.auth.store.write('accounts.json', {'fixture': {
                'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh',
                'client_id': 'synthetic-client', 'scopes': [DIRECT],
                'expires_at': time.time() + 3600, 'refresh_count': 0}})

    def call(self, command, **fields):
        return request(self.node, os.getuid(), packet(command, **fields))

    def http(self, server, method, path, body=None, headers=None):
        c = http.client.HTTPConnection(*server.worker.server_address, timeout=5)
        try:
            c.request(method, path, body, headers or {})
            r = c.getresponse()
            return r.status, json.loads(r.read())
        finally:
            c.close()

    def test_real_composition_admin_acceptance_does_not_unlock_workers(self):
        server = self.server()
        self.login_fixture(server)
        self.assertIs(server.admin.controller.transport.auth, server.auth)
        self.assertEqual(['gpt-6.1-sol'], self.call('models')['result']['models'])
        for effort in ('medium', 'high'):
            result = self.call('infer', model='gpt-6.1-sol', reasoning=effort)
            self.assertTrue(result['ok'], result)
            self.assertEqual(1, result['result']['reconstruction']['verified_calls'])
        self.assertEqual(3, len(self.provider.requests))
        status, health = self.http(server, 'GET', '/healthz')
        self.assertEqual(503, status)
        self.assertTrue(health['broker_capture'])
        self.assertFalse(health['worker_inference'])
        self.assertIn('proxy_capture_not_integrated', health['blockers'])
        self.assertIn('orchestrator_events_not_integrated', health['blockers'])
        self.assertIn('live_fc2_fc5_not_verified', health['blockers'])
        self.assertEqual('worker_admission_disabled', self.call('mint', run_id='fixture',
                         role='builder', model='gpt-6.1-sol', reasoning='medium',
                         expires_at=time.time() + 60, cap=1)['error'])
        for method, path in [('POST', '/v1/responses'), ('GET', '/v1/models')]:
            self.assertEqual(503, self.http(server, method, path, '{}')[0])
        self.assertEqual(3, len(self.provider.requests))
        for path in ('/', '/auth/start', '/auth/callback', '/admin'):
            self.assertEqual(404, self.http(server, 'GET', path)[0])

    def test_capture_outage_refuses_before_provider_and_recovers(self):
        server = self.server()
        self.login_fixture(server)
        self.logs.chmod(0o777)
        self.assertEqual('capture_unavailable', self.call('models')['error'])
        self.assertFalse(self.http(server, 'GET', '/healthz')[1]['broker_capture'])
        self.assertTrue(self.call('status')['ok'])
        self.assertTrue(self.call('revoke', run_id='fixture')['ok'])
        self.assertEqual([], self.provider.requests)
        self.logs.chmod(0o750)
        self.assertTrue(self.call('models')['ok'])
        self.assertFalse(self.http(server, 'GET', '/healthz')[1]['worker_inference'])

    def test_scanner_failure_and_fsync_failure_are_real_health_failures(self):
        server = self.server()
        self.login_fixture(server)
        capture = server.admin.controller.transport.capture
        capture.scanner = '/usr/bin/true'
        self.assertFalse(capture.healthy())  # clean-only fake scanner is not healthy
        self.assertEqual('capture_unavailable', self.call('models')['error'])
        capture.scanner = SCANNER
        with patch('os.fsync', side_effect=OSError('fixture storage failure')):
            self.assertFalse(capture.healthy())
            self.assertEqual('capture_unavailable', self.call('models')['error'])
        self.assertEqual([], self.provider.requests)
        self.assertTrue(capture.healthy())

    def test_unsafe_capture_paths_and_nodes_refused(self):
        for node in ('linked', 'fifo', 'hardlink', 'permissive'):
            with self.subTest(node=node):
                capture = BrokerCapture(self.logs, SCANNER)
                target = self.logs / 'fixture.jsonl'
                outside = self.root / ('outside-' + node)
                outside.write_text('preserve')
                outside.chmod(0o640)
                if node == 'linked':
                    target.symlink_to(outside)
                elif node == 'fifo':
                    os.mkfifo(target, 0o640)
                elif node == 'hardlink':
                    os.link(outside, target)
                else:
                    target.write_text('preserve')
                    target.chmod(0o666)
                try:
                    with self.assertRaises(Exception):
                        capture.append('fixture', 'test', {})
                    self.assertEqual('preserve', outside.read_text())
                finally:
                    target.unlink()
        link = self.root / 'link'
        link.symlink_to(self.logs, target_is_directory=True)
        with self.assertRaises(Exception):
            BrokerCapture(link, SCANNER)

    def test_health_probe_readback_and_root_replacement_fail_closed(self):
        capture = BrokerCapture(self.logs, SCANNER)
        self.assertTrue(capture.healthy())
        with patch('cortex_broker.capture_health.os.pread', return_value=b'wrong'):
            self.assertFalse(capture.healthy())
        self.logs.rename(self.root / 'old-capture')
        self.logs.mkdir(mode=0o750)
        self.assertFalse(capture.healthy())

    def test_health_requires_new_file_creation_and_removes_probes(self):
        capture = BrokerCapture(self.logs, SCANNER)
        self.assertTrue(capture.healthy())
        self.assertEqual([], list(self.logs.iterdir()))
        self.logs.chmod(0o550)
        try:
            self.assertFalse(capture.healthy())
        finally:
            self.logs.chmod(0o750)
        self.assertTrue(capture.healthy())
        with patch('cortex_broker.capture_health.os.pwrite', return_value=0):
            self.assertFalse(capture.healthy())
        self.assertEqual([], list(self.logs.iterdir()))

    def test_root_swapped_after_health_check_is_not_written(self):
        capture = BrokerCapture(self.logs, SCANNER)
        original = capture.safe
        def swap(value):
            result = original(value)
            self.logs.rename(self.root / 'old-capture')
            self.logs.mkdir(mode=0o750)
            return result
        with patch.object(capture, 'safe', side_effect=swap):
            with self.assertRaises(Exception):
                capture.append('fixture', 'test', {})
        self.assertEqual([], list(self.logs.iterdir()))

    def test_failed_start_cleans_bound_listeners_and_admin_socket(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            with self.assertRaises(OSError):
                make_server(self.root / 'state', 0, admin_path=self.node,
                            admin_uid=os.getuid(), admin_gid=os.getgid(),
                            capture_directory=self.logs, scanner=SCANNER,
                            worker_port=occupied.getsockname()[1])
        self.assertFalse(self.node.exists())

    def test_cli_composition_no_session_captures_attempt_and_sigterm_cleans(self):
        command = [sys.executable, '-m', 'cortex_broker.setup', '--state', str(self.root / 'state'),
                   '--port', '0', '--admin-socket', str(self.node), '--admin-uid', str(os.getuid()),
                   '--admin-gid', str(os.getgid()), '--capture-directory', str(self.logs),
                   '--gitleaks', SCANNER, '--worker-port', '0']
        env = {k: v for k, v in os.environ.items() if k not in
               {'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'XAI_API_KEY'}}
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), 'CLI readiness timeout')
                line = proc.stdout.readline()
                self.assertIn(b'worker inference disabled', line)
            authority = line.decode().strip().split('; worker listener at http://')[1]
            connection = http.client.HTTPConnection(authority, timeout=5)
            try:
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                self.assertEqual(503, response.status)
                health = json.loads(response.read())
                self.assertTrue(health['broker_capture'])
                self.assertFalse(health['worker_inference'])
            finally:
                connection.close()
            self.assertFalse(self.call('status')['result']['session']['signed_in'])
            result = self.call('models')
            self.assertEqual('operation_failed', result['error'])  # auth absent, capture operational
            rows = [json.loads(row) for p in self.logs.glob('admin-*.jsonl')
                    for row in p.read_text().splitlines()]
            self.assertEqual(['admin.models', 'models.request'], [r['kind'] for r in rows])
            proc.terminate()
            proc.wait(timeout=10)
            self.assertEqual(0, proc.returncode)
            self.assertFalse(self.node.exists())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()

    def test_cli_invalid_option_combinations_fail_without_state_creation(self):
        for extra in (['--capture-directory', str(self.logs)], ['--worker-port', '0'],
                      ['--gitleaks', SCANNER], ['--worker-host', '0.0.0.0']):
            done = subprocess.run([sys.executable, '-m', 'cortex_broker.setup', '--state',
                                   str(self.root / 'absent'), *extra], capture_output=True, timeout=5)
            self.assertNotEqual(0, done.returncode)
            self.assertFalse((self.root / 'absent').exists())
