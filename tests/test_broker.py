import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from cortex_broker.auth import Auth, AuthError, DIRECT, ISSUER, Store, TOKEN
from cortex_broker.protocol import Refusal, RunKeys, adapt, reconstruct_sse
from cortex_broker.setup import make_server


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        self.public['kid'] = 'fixture'
        self.calls = []
        self.claim_changes = {}
        self.scope = DIRECT + ' openid offline_access'
        self.auth = Auth(self.store, 'http://127.0.0.1:18741/auth/callback', self.fetch)

    def tearDown(self):
        self.tmp.cleanup()

    def fetch(self, url, form=None):
        self.calls.append((url, form))
        if url.endswith('openid-configuration'):
            return {'issuer': ISSUER, 'jwks_uri': ISSUER + '/jwks'}
        if url.endswith('/jwks'):
            return {'keys': [self.public]}
        assert url == TOKEN
        if form['grant_type'] == 'refresh_token':
            return {'access_token': 'fixture-next-access', 'refresh_token': 'fixture-next-refresh',
                    'expires_in': 3600, 'token_type': 'Bearer', 'scope': self.scope}
        claims = {'iss': ISSUER, 'sub': 'fixture-user', 'aud': form['client_id'], 'exp': int(time.time()) + 600,
                  'iat': int(time.time()), 'nonce': self.nonce, **self.claim_changes}
        return {'access_token': 'fixture-access', 'refresh_token': 'fixture-refresh', 'expires_in': 3600,
                'token_type': 'Bearer', 'scope': self.scope,
                'id_token': jwt.encode(claims, self.private, algorithm='RS256', headers={'kid': 'fixture'})}

    def begin(self, account=None):
        url = self.auth.begin(account)
        p = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.nonce = p['nonce'][0]
        return p

    def complete(self, account=None, **overrides):
        p = self.begin(account)
        return self.auth.callback({'state': p['state'][0], 'code': 'fixture-code', 'client_id': 'fixture-client', **overrides})

    def test_host_stable_before_authorization(self):
        self.assertEqual(self.auth.host_id, Auth(self.store, self.auth.redirect_uri).host_id)
        self.assertTrue(self.auth.host_id.startswith('urn:uuid:'))
        self.assertEqual([], self.calls)

    def test_pkce_and_issued_client_persist(self):
        result = self.complete()
        self.assertTrue(result['plan_scope'])
        self.assertEqual('fixture-client', self.auth.accounts()[0]['client_id'])
        self.assertEqual('fixture-access', self.auth.access())
        p = self.begin(result['account'])
        self.assertEqual(['fixture-client'], p['client_id'])
        self.assertNotIn('agent_name_hint', p)
        for f in Path(self.tmp.name).iterdir():
            self.assertEqual(0o600, f.stat().st_mode & 0o777)

    def test_state_mismatch_no_token_exchange(self):
        p = self.begin()
        with self.assertRaisesRegex(AuthError, 'state_mismatch'):
            self.auth.callback({'state': 'wrong', 'code': 'fixture-code'})
        self.assertFalse(self.calls)

    def test_duplicate_callback_rejected(self):
        p = self.begin()
        self.auth.callback({'state': p['state'][0], 'code': 'fixture-code', 'client_id': 'fixture-client'})
        with self.assertRaises(AuthError):
            self.auth.callback({'state': p['state'][0], 'code': 'fixture-code', 'client_id': 'fixture-client'})

    def test_required_scope(self):
        self.scope = 'openid email'
        with self.assertRaisesRegex(AuthError, 'plan_scope_not_granted'):
            self.complete()
        self.assertIsNone(self.store.read('active.json'))

    def test_nonce_and_audience(self):
        for changes in ({'nonce': 'wrong'}, {'aud': 'other'}, {'exp': 1}, {'iss': 'https://evil.example'}):
            self.claim_changes = changes
            with self.assertRaises(AuthError):
                self.complete()
            self.assertIsNone(self.store.read('active.json'))

    def test_returning_registration_mismatch(self):
        account = self.complete()['account']
        with self.assertRaisesRegex(AuthError, 'client_id_mismatch'):
            self.complete(account, client_id='wrong-client')
        self.assertEqual('fixture-access', self.auth.access())

    def test_new_registration_requires_issued_id(self):
        with self.assertRaisesRegex(AuthError, 'registration_incomplete'):
            self.complete(client_id='dynamic_agent_client')

    def test_refresh_serialized_and_atomic(self):
        self.complete()
        with self.store.lock():
            a = self.store.read('accounts.json')
            for v in a.values():
                v['expires_at'] = 1
            self.store.write('accounts.json', a)
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: self.auth.access(), range(8)))
        self.assertEqual(['fixture-next-access'] * 8, results)
        refresh = [f for _, f in self.calls if f and f.get('grant_type') == 'refresh_token']
        self.assertEqual(1, len(refresh))
        self.assertEqual(1, self.auth.accounts()[0]['refresh_count'])
        values = list(self.store.read('accounts.json').values())[0]
        self.assertEqual('fixture-next-refresh', values['refresh_token'])
        self.assertGreater(values['expires_at'], time.time())

    def test_failed_refresh_preserves_record(self):
        self.complete()
        before = (self.store.root / 'accounts.json').read_bytes()
        self.scope = 'openid'
        with self.assertRaises(AuthError):
            self.auth.access(force_refresh=True)
        self.assertEqual(before, (self.store.root / 'accounts.json').read_bytes())

    def test_symlink_and_permissive_state_refused(self):
        p = self.store.root / 'bad.json'
        p.symlink_to(self.store.root / 'host.json')
        with self.assertRaises(OSError):
            self.store.read('bad.json')
        os.chmod(self.store.root / 'host.json', 0o644)
        with self.assertRaises(AuthError):
            self.store.read('host.json')


class ProtocolTests(unittest.TestCase):
    def test_adaptation(self):
        original = {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'high'},
                    'input': [{'type': 'message', 'role': 'system', 'content': 'instructions'},
                              {'type': 'function_call_output', 'call_id': 'fixture', 'output': 'tool output'}],
                    'temperature': 0, 'max_output_tokens': 100, 'store': True, 'stream': False,
                    'tools': [{'type': 'function', 'name': 'terminal', 'parameters': {'type': 'object'}}]}
        out, changes = adapt(original)
        self.assertFalse(out['store']); self.assertTrue(out['stream'])
        self.assertNotIn('temperature', out); self.assertNotIn('max_output_tokens', out)
        self.assertEqual('developer', out['input'][0]['role'])
        self.assertEqual('tool output', out['input'][1]['output'])
        self.assertEqual('namespace', out['tools'][0]['type'])
        self.assertIn('tools:group_functions_namespace', changes)
        self.assertTrue(original['store'])

    def test_no_history_guess_or_unknown_tools(self):
        for request in [{'input': [], 'previous_response_id': 'fixture'}, {'input': 'hello'},
                        {'input': [{'role': 'user', 'content': 'hello'}], 'tools': [{'type': 'tool_search'}]}]:
            with self.assertRaises(Refusal):
                adapt(request)

    def test_admission_and_revocation(self):
        keys = RunKeys()
        key = keys.mint('fixture-run', 'builder', 'gpt-6.1-sol', 'medium', time.time()+60, 1)
        with self.assertRaises(Refusal):
            keys.admit(key, {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'high'}})
        keys.admit(key, {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'}})
        with self.assertRaises(Refusal):
            keys.admit(key, {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'}})
        keys.revoke_run('fixture-run')
        self.assertTrue(all(v['expires_at'] == 0 for v in keys.keys.values()))

    def test_no_model_substitution(self):
        with self.assertRaises(Refusal):
            RunKeys().mint('fixture', 'qa', 'other-model', 'high', time.time()+60, 10)

    def test_sse_completion_and_tool_capture(self):
        events = [{'type': 'response.output_item.done', 'output_index': 0, 'item': {'id': 'fc_fixture', 'type': 'function_call', 'arguments': '{"cmd":"true"}'}},

                  {'type': 'response.completed', 'response': {'output': [], 'usage': {'input_tokens': 1}}}]
        body = ''.join('data: '+json.dumps(e)+'\n\n' for e in events)
        got = reconstruct_sse(body)
        self.assertTrue(got['complete']); self.assertEqual(events, got['events'])
        self.assertFalse(reconstruct_sse('data: {"type":"response.failed"}\n\n')['complete'])
        self.assertFalse(reconstruct_sse('')['complete'])


class HttpTests(unittest.TestCase):
    def test_real_loopback_setup_only_no_provider(self):
        with tempfile.TemporaryDirectory() as d:
            server = make_server(d, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urllib.request.urlopen(server.origin + '/healthz') as response:
                    self.assertFalse(json.load(response)['worker_inference'])
                with urllib.request.urlopen(server.origin) as response:
                    page = response.read().decode()
                    self.assertIn('Continue with ChatGPT', page)
                    self.assertEqual('no-store', response.headers['Cache-Control'])
                request = urllib.request.Request(server.origin + '/v1/responses', data=b'{}', headers={'Origin': server.origin})
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request)
                self.assertEqual(503, error.exception.code)
                error.exception.close()
                request = urllib.request.Request(server.origin + '/auth/start', data=b'csrf=wrong', headers={'Origin': server.origin})
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request)
                self.assertEqual(403, error.exception.code)
                error.exception.close()
                self.assertFalse((Path(d) / 'accounts.json').exists())
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
