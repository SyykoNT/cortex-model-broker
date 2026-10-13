"""Offline same-UID fixtures, not deployed identity isolation or live acceptance."""
import concurrent.futures
import io
import json
import os
from pathlib import Path
import socket
import selectors
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cortex_broker.admin import AdminServer, Controller, MAX_REQUEST, PROMPT, request
from cortex_broker.auth import Auth, AuthError, DIRECT, Store
from cortex_broker.codex_limits import CodexLimits, project_limits
from cortex_broker.protocol import Refusal, RunKeys
from cortex_broker.setup import make_server
from cortex_broker.traffic import Capture, Transport

SCANNER = os.environ.get('TEST_GITLEAKS')


def packet(command, **fields):
    return {'version': 1, 'command': command, **fields}


class Response(io.BytesIO):
    status = 200
    headers = {'Content-Type': 'text/event-stream'}


class FixtureProvider:
    def __init__(self):
        self.requests = []
        self.events = [{'type': 'response.completed', 'response': {
            'model': 'gpt-6.1-sol', 'output': [], 'usage': {'input_tokens': 8, 'output_tokens': 3}}}]
        self.models = {'models': [{'slug': 'gpt-6.1-sol', 'visibility': 'list'}]}
        self.failure = None

    def open(self, req, timeout):
        self.requests.append(req)
        if self.failure:
            raise self.failure
        if req.full_url.endswith('/models'):
            return Response(json.dumps(self.models).encode())
        return Response(''.join('data: ' + json.dumps(e) + '\n\n' for e in self.events).encode())


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', Path.cwd()))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state')
        self.refresh_calls = []
        def refresh(url, form=None):
            self.refresh_calls.append((url, form))
            return {'access_token': 'synthetic-next-access', 'refresh_token': 'synthetic-next-refresh',
                    'expires_in': 3600, 'token_type': 'Bearer', 'scope': DIRECT}
        self.auth = Auth(self.store, 'http://127.0.0.1:18741/auth/callback', refresh)
        with self.store.lock():
            self.store.write('active.json', {'account': 'synthetic-account'})
            self.store.write('accounts.json', {'synthetic-account': {
                'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh',
                'id_token': 'synthetic-identity', 'client_id': 'synthetic-client', 'email': '',
                'scopes': [DIRECT], 'expires_at': time.time() + 3600, 'refresh_count': 0}})
        self.keys = RunKeys()
        self.controller = Controller(self.auth, self.keys)
        self.path = self.root / 'admin.sock'
        self.server = AdminServer(self.path, os.getuid(), os.getgid(), self.controller).start()
        self.addCleanup(self.server.close)
        # Real provider access is an error in every fixture.
        self.no_network = patch('cortex_broker.auth.HTTP.open', side_effect=AssertionError('live network forbidden'))
        self.no_network.start()
        self.addCleanup(self.no_network.stop)

    def call(self, command, **fields):
        return request(self.path, os.getuid(), packet(command, **fields))

    def wire(self, raw):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(self.path))
            s.sendall(raw)
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                try:
                    chunk = s.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return json.loads(b''.join(chunks))

    def transport(self):
        self.assertTrue(SCANNER, 'TEST_GITLEAKS required; do not silently skip')
        self.health = {'broker': True, 'proxy': True, 'orchestrator': True}
        self.capture = Capture(self.root / 'capture', SCANNER, lambda: all(self.health.values()))
        self.provider = FixtureProvider()
        self.controller.transport = Transport(self.auth, self.keys, self.capture, lambda *a: None, self.provider)

    def test_status_projection_and_no_implicit_refresh(self):
        result = self.call('status')
        self.assertTrue(result['ok'])
        session = result['result']['session']
        self.assertEqual([DIRECT], session['scopes'])
        self.assertEqual('synthetic-client', session['client_id'])
        self.assertEqual(self.auth.host_id, session['ext_agent_host_id'])
        self.assertIsNone(session['last_refresh_at'])
        self.assertEqual([], self.refresh_calls)
        for secret in self.auth.token_values():
            self.assertNotIn(secret, json.dumps(result))

    def test_socket_acl_and_mutual_peer_check(self):
        s = self.path.lstat()
        self.assertTrue(stat.S_ISSOCK(s.st_mode))
        self.assertEqual(0o660, stat.S_IMODE(s.st_mode))
        self.assertEqual((os.getuid(), os.getgid()), (s.st_uid, s.st_gid))
        with self.assertRaises(Refusal):
            request(self.path, os.getuid() + 1, packet('status'))
        self.server.allowed_uid = os.getuid() + 1
        result = self.call('status')
        self.assertEqual('peer_not_allowed', result['error'])

    def test_client_refuses_permissive_socket(self):
        self.path.chmod(0o666)
        with self.assertRaises(Refusal):
            self.call('status')

    def test_no_clobber_existing_socket_file_or_symlink(self):
        for name, kind in [('existing-file', 'file'), ('existing-link', 'link'), ('admin.sock', 'socket')]:
            node = self.root / name
            if kind == 'file':
                node.write_text('preserve')
            if kind == 'link':
                node.symlink_to(self.root / 'existing-file')
            before = node.lstat()
            with self.assertRaises(OSError):
                AdminServer(node, os.getuid(), os.getgid(), self.controller)
            self.assertEqual(before.st_ino, node.lstat().st_ino)

    def test_refuse_writable_directory_and_symlink_ancestor(self):
        unsafe = self.root / 'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        with self.assertRaises(Refusal):
            AdminServer(unsafe / 's', os.getuid(), os.getgid(), self.controller)
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Refusal):
            AdminServer(link / 's', os.getuid(), os.getgid(), self.controller)

    def test_cleanup_does_not_remove_replacement(self):
        self.path.unlink()
        self.path.write_text('replacement')
        self.server.close()
        self.assertEqual('replacement', self.path.read_text())

    def test_malformed_duplicate_nonfinite_and_extra_fields(self):
        samples = [b'{}\n', b'[]\n', b'\xff\n', b'{\n', b'{}\n{}\n',
                   b'{"version":1,"version":1,"command":"status"}\n',
                   b'{"version":NaN,"command":"status"}\n',
                   b'{"version":true,"command":"status"}\n',
                   json.dumps(packet('status', path='/arbitrary')).encode() + b'\n',
                   json.dumps(packet('infer', model='gpt-6.1-sol', reasoning='medium', prompt='run tools')).encode() + b'\n']
        for raw in samples:
            with self.subTest(raw=raw):
                self.assertFalse(self.wire(raw)['ok'])
        self.assertEqual('request_too_large', self.wire(b' ' * (MAX_REQUEST + 1))['error'])
        self.assertTrue(self.call('status')['ok'])

    def test_absolute_request_timeout(self):
        with patch('cortex_broker.admin.IO_TIMEOUT', 0.05):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(str(self.path))
                s.sendall(b'{')
                result = json.loads(s.recv(4096))
                self.assertFalse(result['ok'])
        self.assertTrue(self.call('status')['ok'])

    def test_capture_unconfigured_and_worker_gate(self):
        for command, fields in [('models', {}), ('refresh', {}), ('rate_limits', {}),
                                ('infer', {'model': 'gpt-6.1-sol', 'reasoning': 'medium'})]:
            self.assertEqual('capture_unavailable', self.call(command, **fields)['error'])
        self.assertEqual([], self.refresh_calls)
        result = self.call('mint', run_id='fixture', role='builder', model='gpt-6.1-sol',
                           reasoning='medium', expires_at=time.time() + 60, cap=1)
        self.assertEqual('worker_admission_disabled', result['error'])

    def test_mint_bounds_and_revoke_works_during_capture_outage(self):
        self.transport()
        self.controller.worker_ready = lambda: True  # synthetic prerequisite, not deployment readiness
        fields = dict(run_id='fixture', role='builder', model='gpt-6.1-sol', reasoning='medium', expires_at=time.time() + 60, cap=1)
        for field, value in [('role', 'p'), ('model', 'other'), ('reasoning', 'low'), ('cap', True), ('run_id', '../escape')]:
            self.assertFalse(self.call('mint', **{**fields, field: value})['ok'])
        result = self.call('mint', **fields)
        self.assertTrue(result['ok'], result)
        key = result['result']['run_key']
        with self.assertRaises(Refusal):
            self.keys.admit(key, {'model': fields['model'], 'reasoning': {'effort': 'high'}})
        self.health['proxy'] = False
        self.assertTrue(self.call('revoke', run_id='fixture')['ok'])
        with self.assertRaises(Refusal):
            self.keys.admit(key, {'model': fields['model'], 'reasoning': {'effort': 'medium'}})
        for f in self.capture.root.iterdir():
            self.assertNotIn(key, f.read_text())

    def test_each_capture_source_and_scanner_failure_prevents_provider(self):
        self.transport()
        for source in self.health:
            self.health[source] = False
            self.assertEqual('capture_unavailable', self.call('models')['error'])
            self.health[source] = True
        self.capture.scanner = '/nonexistent/scanner'
        self.assertFalse(self.call('models')['ok'])
        self.assertEqual([], self.provider.requests)

    def test_models_and_secret_echo_redaction(self):
        self.transport()
        self.assertEqual(['gpt-6.1-sol'], self.call('models')['result']['models'])
        self.provider.models['models'].append({'slug': 'synthetic-access', 'visibility': 'list'})
        result = self.call('models')
        self.assertFalse(result['ok'])
        for f in self.capture.root.iterdir():
            self.assertNotIn('synthetic-access', f.read_text())

    def test_refresh_uses_auth_lock_and_returns_no_credentials(self):
        self.transport()
        result = self.call('refresh')
        self.assertTrue(result['ok'], result)
        self.assertEqual(1, result['result']['session']['refresh_count'])
        self.assertIsNotNone(result['result']['session']['last_refresh_at'])
        self.assertEqual(1, len(self.refresh_calls))
        self.assertEqual('refresh_token', self.refresh_calls[0][1]['grant_type'])
        text = json.dumps(result) + ''.join(f.read_text() for f in self.capture.root.iterdir())
        for value in ['synthetic-access', 'synthetic-refresh', *self.auth.token_values()]:
            self.assertNotIn(value, text)

    def test_auth_lock_timeout(self):
        with self.store.lock():
            with self.assertRaisesRegex(AuthError, 'auth_lock_timeout'):
                with self.store.lock(timeout=0.02):
                    self.fail('nested independent flock must not enter')

    def test_single_exact_inference_and_reconstruction_both_efforts(self):
        self.transport()
        for effort in ('medium', 'high'):
            result = self.call('infer', model='gpt-6.1-sol', reasoning=effort)
            self.assertTrue(result['ok'], result)
            value = result['result']
            self.assertEqual('response.completed', value['terminal'])
            self.assertEqual({'input_tokens': 8, 'output_tokens': 3}, value['usage'])
            self.assertEqual(1, value['reconstruction']['verified_calls'])
            payload = json.loads(self.provider.requests[-1].data)
            self.assertEqual('gpt-6.1-sol', payload['model'])
            self.assertEqual({'effort': effort}, payload['reasoning'])
            self.assertEqual([{'role': 'user', 'content': PROMPT}], payload['input'])
            self.assertFalse(payload['store'])
            self.assertTrue(payload['stream'])
            self.assertNotIn('tools', payload)
            self.assertTrue(self.call('reconstruct', run_id=value['run_id'])['ok'])
        self.assertEqual(2, len(self.provider.requests))
        self.assertTrue(all(k['expires_at'] == 0 for k in self.keys.keys.values()))

    def test_no_fallback_and_terminal_usage_model_failures(self):
        self.transport()
        for model, effort in [('other', 'medium'), ('gpt-6.1-sol', 'low')]:
            self.assertFalse(self.call('infer', model=model, reasoning=effort)['ok'])
        self.assertEqual([], self.provider.requests)
        good = self.provider.events
        for events in [[], [{'type': 'response.failed'}], good + good,
                       [{'type': 'response.completed', 'response': {'model': 'other', 'usage': {'input_tokens': 8, 'output_tokens': 3}}}],
                       [{'type': 'response.completed', 'response': {'model': 'gpt-6.1-sol'}}]]:
            self.provider.events = events
            self.assertFalse(self.call('infer', model='gpt-6.1-sol', reasoning='medium')['ok'])
        self.assertEqual(5, len(self.provider.requests))

    def test_provider_error_text_never_escapes(self):
        self.transport()
        self.provider.failure = RuntimeError('synthetic-access private traceback')
        result = self.call('models')
        self.assertFalse(result['ok'])
        self.assertNotIn('synthetic-access', json.dumps(result))
        self.assertNotIn('traceback', json.dumps(result))

    def test_reconstruction_refuses_paths_redaction_tamper_and_symlink(self):
        self.transport()
        result = self.call('infer', model='gpt-6.1-sol', reasoning='medium')['result']
        run = result['run_id']
        node = self.capture.root / (run + '.jsonl')
        before = node.read_text()
        node.write_text(before.replace('"input_tokens":8', '"input_tokens":9'))
        self.assertFalse(self.call('reconstruct', run_id=run)['ok'])
        node.write_text(before)
        self.capture.append(run, 'fixture', {'access_token': 'synthetic-access'})
        self.assertFalse(self.call('reconstruct', run_id=run)['ok'])
        node.unlink()
        node.symlink_to(self.store.root / 'accounts.json')
        self.assertFalse(self.call('reconstruct', run_id=run)['ok'])
        self.assertFalse(self.call('reconstruct', run_id='../state/accounts')['ok'])

    def test_capture_write_failure_no_success_or_emission(self):
        self.transport()
        original = self.capture.append
        def fail_response(run, kind, value):
            if kind == 'response':
                raise OSError('synthetic disk full')
            return original(run, kind, value)
        with patch.object(self.capture, 'append', side_effect=fail_response):
            self.assertFalse(self.call('infer', model='gpt-6.1-sol', reasoning='medium')['ok'])
        self.assertEqual(1, len(self.provider.requests))

    def test_setup_starts_admin_without_worker_activation(self):
        node = self.root / 'setup.sock'
        setup = make_server(self.root / 'other-state', 0, admin_path=node, admin_uid=os.getuid(), admin_gid=os.getgid())
        try:
            result = request(node, os.getuid(), packet('status'))
            self.assertFalse(result['result']['worker_inference'])
            self.assertEqual('capture_unavailable', request(node, os.getuid(), packet('models'))['error'])
        finally:
            setup.server_close()
        self.assertFalse(node.exists())

    def test_concurrent_clients_serialized(self):
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            results = list(pool.map(lambda _: self.call('status'), range(12)))
        self.assertTrue(all(r['ok'] for r in results))

    def test_client_subprocess_roundtrip_and_safe_exit(self):
        command = [sys.executable, '-m', 'cortex_broker.admin', '--socket', str(self.path),
                   '--broker-uid', str(os.getuid())]
        for payload, expected in [(packet('status'), 0), (packet('status', token='synthetic-access'), 1)]:
            completed = subprocess.run(command, input=json.dumps(payload), text=True,
                                       capture_output=True, timeout=5)
            self.assertEqual(expected, completed.returncode, completed.stderr)
            self.assertEqual(expected == 0, json.loads(completed.stdout)['ok'])
            self.assertNotIn('synthetic-access', completed.stdout + completed.stderr)

    def test_setup_cli_socket_and_sigterm_cleanup(self):
        node = self.root / 'cli.sock'
        command = [sys.executable, '-m', 'cortex_broker.setup', '--state', str(self.root / 'cli-state'),
                   '--port', '0', '--admin-socket', str(node),
                   '--admin-uid', str(os.getuid()), '--admin-gid', str(os.getgid())]
        env = {k: v for k, v in os.environ.items() if k not in {'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'XAI_API_KEY'}}
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(5), 'setup readiness timed out')
                self.assertIn(b'worker inference disabled', process.stdout.readline())
            result = request(node, os.getuid(), packet('status'))
            self.assertFalse(result['result']['worker_inference'])
            self.assertFalse(result['result']['session']['signed_in'])
            process.terminate()
            process.wait(timeout=5)
            self.assertEqual(0, process.returncode)
            self.assertFalse(node.exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_explicit_reasoning_downgrade_is_refused(self):
        self.transport()
        self.provider.events[0]['response']['reasoning'] = {'effort': 'medium'}
        self.assertEqual('inference_reasoning_mismatch', self.call('infer', model='gpt-6.1-sol', reasoning='high')['error'])

    def test_response_oversize_fails_without_partial_payload(self):
        with patch.object(self.controller, 'dispatch', return_value={'large': 'x' * 65536}):
            self.assertEqual({'ok': False, 'error': 'response_too_large'}, self.call('status'))
        self.assertTrue(self.call('status')['ok'])

    def test_metadata_never_echoes_credential(self):
        with self.store.lock():
            records = self.store.read('accounts.json')
            records['synthetic-account']['client_id'] = 'synthetic-access'
            self.store.write('accounts.json', records)
        result = self.call('status')
        self.assertFalse(result['ok'])
        self.assertNotIn('synthetic-access', json.dumps(result))

    def test_known_key_bounds_refused_and_logged_without_provider(self):
        self.transport()
        key = self.keys.mint('bound', 'builder', 'gpt-6.1-sol', 'medium', time.time() + 60, 1)
        for payload in [{'model': 'other', 'reasoning': {'effort': 'medium'}},
                        {'model': 'gpt-6.1-sol', 'reasoning': None}]:
            with self.assertRaises(Refusal):
                self.controller.transport.responses(key, payload, lambda *args: self.fail('must not emit'))
        rows = [json.loads(line) for line in (self.capture.root / 'bound.jsonl').read_text().splitlines()]
        self.assertEqual(['request.refused', 'request.refused'], [row['kind'] for row in rows])
        self.assertNotIn(key, json.dumps(rows))
        self.assertEqual([], self.provider.requests)

    def test_trailing_event_does_not_become_terminal_success(self):
        self.transport()
        self.provider.events.append({'type': 'response.output_text.delta', 'delta': 'too late'})
        self.assertFalse(self.call('infer', model='gpt-6.1-sol', reasoning='medium')['ok'])

    def test_bounded_provider_read(self):
        from cortex_broker.auth import bounded_body
        self.assertEqual(b'hello', bounded_body(io.BytesIO(b'hello'), 5, 1))
        with self.assertRaisesRegex(AuthError, 'provider_body_too_large'):
            bounded_body(io.BytesIO(b'too large'), 5, 1)
        with patch('cortex_broker.auth.time.monotonic', side_effect=[0, 2]):
            with self.assertRaisesRegex(AuthError, 'provider_deadline'):
                bounded_body(io.BytesIO(b'hello'), 5, 1)

    def test_codex_absent_is_explicit(self):
        self.transport()
        self.assertEqual('codex_unavailable', self.call('rate_limits')['error'])


class CodexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', Path.cwd()))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.binary = self.root / 'fixture-codex'

    def child(self, body):
        self.binary.write_text('#!' + sys.executable + '\n' + body)
        self.binary.chmod(0o700)
        return CodexLimits(self.binary, self.root, timeout=0.5)

    def test_real_bounded_child_documented_handshake_and_environment(self):
        child = self.child('''import json, os, sys
assert os.environ['HOME'] == os.environ['CODEX_HOME'] == os.getcwd()
assert 'OPENAI_API_KEY' not in os.environ
assert 'ANTHROPIC_API_KEY' not in os.environ
assert os.environ['ACCESS_TOKEN'] == 'synthetic-access'
assert 'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"' in sys.argv
assert 'model_providers.openai_chatgpt_plan.requires_openai_auth=false' in sys.argv
assert 'model_providers.openai_chatgpt_plan.wire_api="responses"' in sys.argv
m=json.loads(input()); assert m['id'] == 1 and m['method'] == 'initialize'
print(json.dumps({'id':1,'result':{}}),flush=True)
m=json.loads(input()); assert m == {'method':'initialized'}
m=json.loads(input()); assert m == {'id':2,'method':'account/rateLimits/read'}
print(json.dumps({'id':2,'result':{'rateLimits':{'primary':{'usedPercent':25,'windowDurationMins':15,'resetsAt':1730947200},'secondary':None},'access_token':'synthetic-access'}}),flush=True)
import time; time.sleep(30)
''')
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'must-not-inherit'}):
            result = child.read('synthetic-access')
        self.assertEqual(25, result['primary']['usedPercent'])
        self.assertNotIn('synthetic-access', json.dumps(result))
        self.assertEqual([self.binary], list(self.root.iterdir()))

    def test_timeout_oversize_malformed_wrong_id_and_errors(self):
        for body, expected in [
            ('import time; time.sleep(30)', 'codex_timeout'),
            ("print('x' * 300000, flush=True)", 'codex_protocol_error'),
            ("print('not json', flush=True)", 'codex_protocol_error'),
            ("print('{\"id\":9,\"result\":{}}', flush=True)", 'codex_protocol_error'),
            ("print('{\"id\":1,\"error\":{\"message\":\"synthetic-access\"}}', flush=True)", 'codex_rate_limits_unavailable')]:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(Refusal, expected):
                    self.child(body).read('synthetic-access')

    def test_missing_unsafe_executable_and_missing_windows(self):
        with self.assertRaisesRegex(Refusal, 'codex_unavailable'):
            CodexLimits(self.root / 'absent', self.root).read('synthetic-access')
        child = self.child('pass')
        self.binary.chmod(0o777)
        with self.assertRaisesRegex(Refusal, 'codex_unavailable'):
            child.read('synthetic-access')
        for value in [{}, {'rateLimits': {}}, {'rateLimits': {'primary': {'usedPercent': 'synthetic-access'}}}]:
            with self.assertRaises(Refusal):
                project_limits(value)


if __name__ == '__main__':
    unittest.main()
