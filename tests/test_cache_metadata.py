"""Actual scanner plus synthetic provider; never credentials or provider calls."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from cortex_broker.cache_metadata import canonical, scan_response
from cortex_broker.protocol import RunKeys, Refusal, classify_response
from cortex_broker.scanner_diagnostics import scan
from cortex_broker.traffic import Capture, Transport
from test_traffic import AuthFixture, ProviderFixture

VALUE = '-'.join(('6cbad423', '94d5', '4ce3', 'bb87', '7c581e6ea917'))
OTHER = '-'.join(('9b1dfe37', '3f1a', '4f31', 'ad29', '1bc38def9ac2'))


def response(value=VALUE, output=None):
    obj = {'prompt_cache_key': value, 'output': output or [],
           'usage': {'input_tokens': 9, 'output_tokens': 2}}
    events = [{'type': t, 'response': obj} for t in
              ('response.created', 'response.in_progress', 'response.completed')]
    body = ''.join('data: ' + json.dumps(e) + '\n\n' for e in events)
    parsed, classification = classify_response(200, 'text/event-stream', body)
    return {'status': 200, 'body': body, 'reconstructed': parsed,
            'bytes': len(body.encode()), 'classification': classification}


class CachePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = os.environ['TEST_GITLEAKS']

    def check(self, value, expected=True, sent=VALUE):
        encoded = json.dumps(value, ensure_ascii=True).encode()
        self.assertIsNotNone(scan(self.scanner, encoded, self.root), 'fixture must trigger original scanner')
        verdict = scan_response(self.scanner, encoded, self.root, sent)
        self.assertEqual(verdict is None, expected)

    def test_same_uuid_and_approved_different_uuid(self):
        self.check(response())
        self.check(response(OTHER))

    def test_only_transport_context_enables_policy(self):
        cap = Capture(self.root, self.scanner, lambda: True)
        self.assertTrue(cap.append('test', 'response', response())['flags'])
        self.assertFalse(cap.append('test', 'response', response(), response_cache_uuid=VALUE)['flags'])
        self.assertTrue(cap.append('test', 'request.received', response(), response_cache_uuid=VALUE)['flags'])
        self.check(response(), False, sent='not-a-uuid')

    def test_noncanonical_fallback_refused(self):
        for bad in (VALUE.upper(), '{' + VALUE + '}', VALUE.replace('-', ''), VALUE + 'x'):
            self.assertFalse(canonical(bad))
            encoded = json.dumps(response(bad)).encode()
            before = scan(self.scanner, encoded, self.root)
            after = scan_response(self.scanner, encoded, self.root, VALUE)
            self.assertEqual(before is None, after is None)
        for value in (None, 1, True, 'not-a-uuid', VALUE.upper()):
            self.assertFalse(canonical(value))
        self.assertTrue(canonical(VALUE))

    def test_output_tool_request_and_mixed_occurrences_refused(self):
        for item in ({'type': 'message', 'content': [{'type': 'output_text',
                     'text': 'prompt_cache_key=' + VALUE + ';'}]},
                     {'type': 'function_call_output', 'output': 'prompt_cache_key=' + VALUE + ';'},
                     {'type': 'function_call', 'arguments': json.dumps({'text': 'prompt_cache_key=' + VALUE + ';'})}):
            self.check(response(output=[item]), False)
        value = response()
        value['request'] = {'prompt_cache_key': VALUE}
        self.check(value, False)
        value = response()
        value['untrusted'] = {'prompt_cache_key': VALUE}
        self.check(value, False)

    def test_bad_response_context_and_forged_reconstruction_refused(self):
        for change in ({'status': 400}, {'body': 'not SSE'}, {'classification': {}},
                       {'reconstructed': {'response': {'prompt_cache_key': VALUE}}}):
            self.check({**response(), **change}, False)

    def test_real_credential_detector_on_original_bytes(self):
        # Assemble a fake GitHub-format credential; never an actual credential.
        fake = 'ghp_' + ''.join(['A1b2C3d4E5f6G7h8', 'I9j0K1l2M3n4O5p6Q7r8'])
        value = response()
        value['untrusted'] = fake
        encoded = json.dumps(value).encode()
        original = scan(self.scanner, encoded, self.root)
        self.assertIn('github-pat', [r['rule_id'] for r in original['rules']])
        self.assertIsNotNone(scan_response(self.scanner, encoded, self.root, VALUE))
        self.check(response(fake), False)

    def test_unrelated_generic_secret_refused(self):
        value = response()
        value['untrusted'] = 'api_key=' + ''.join(('Ab3cD4eF5gH6iJ7kL8mN9', 'pQ0rS1tU2vW')) + ';'
        self.check(value, False)

    def test_auxiliary_failure_retains_refusal(self):
        with patch('cortex_broker.cache_metadata.run_scanner', side_effect=OSError()):
            self.check(response(), False)

    def test_duplicate_member_refused(self):
        encoded = json.dumps(response()).encode().replace(b'"status": 200', b'"status": 200, "status": 200')
        self.assertIsNotNone(scan_response(self.scanner, encoded, self.root, VALUE))

    def test_transport_overwrites_captures_and_reconstructs_sent_value(self):
        cap = Capture(self.root, self.scanner, lambda: True)
        keys = RunKeys()
        key = keys.mint('run', 'builder', 'gpt-6.1-sol', 'medium', time.time()+60, 3)
        request = {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'},
                   'input': [{'role': 'user', 'content': 'ordinary'}], 'prompt_cache_key': 'worker-value'}
        fixture = ProviderFixture(response(OTHER)['body'].encode())
        transport = Transport(AuthFixture(), keys, cap, lambda *a: None, fixture)
        for _ in range(2):
            transport.responses(key, request, lambda *a: None)
        sent = [json.loads(r.data) for r in fixture.requests]
        self.assertTrue(all(canonical(r['prompt_cache_key']) for r in sent))
        self.assertNotEqual(sent[0]['prompt_cache_key'], sent[1]['prompt_cache_key'])
        self.assertEqual('worker-value', request['prompt_cache_key'])
        rows = [json.loads(line) for line in (self.root/'run.jsonl').read_text().splitlines()]
        self.assertTrue(all(not r['flags'] for r in rows))
        for index, row in enumerate(r for r in rows if r['kind'] == 'request.upstream'):
            data = row['data']
            rebuilt = {**data['request'], 'prompt_cache_key': data['broker_cache_uuid']}
            self.assertEqual(sent[index], rebuilt)

    def test_flagged_request_prevents_dispatch(self):
        cap = Capture(self.root, self.scanner, lambda: True)
        keys = RunKeys()
        key = keys.mint('run', 'builder', 'gpt-6.1-sol', 'medium', time.time()+60, 1)
        fixture = ProviderFixture(response()['body'].encode())
        transport = Transport(AuthFixture(), keys, cap, lambda *a: None, fixture)
        request = {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'},
                   'input': [{'role': 'user', 'content': 'prompt_cache_key=' + VALUE + ';'}]}
        with self.assertRaises(Refusal):
            transport.responses(key, request, lambda *a: self.fail('must not emit'))
        self.assertEqual([], fixture.requests)

    def test_flagged_response_not_delivered(self):
        cap = Capture(self.root, self.scanner, lambda: True)
        keys = RunKeys()
        key = keys.mint('run', 'builder', 'gpt-6.1-sol', 'medium', time.time()+60, 1)
        bad = response(output=[{'type': 'message', 'content': [{'type': 'output_text',
                              'text': 'prompt_cache_key=' + VALUE + ';'}]}])
        fixture = ProviderFixture(bad['body'].encode())
        transport = Transport(AuthFixture(), keys, cap, lambda *a: None, fixture)
        with self.assertRaises(Refusal):
            transport.responses(key, {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'},
                'input': []}, lambda *a: self.fail('must not emit'))
