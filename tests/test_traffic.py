"""Synthetic transport tests: these do not call a provider or prove live FCs."""
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from cortex_broker.protocol import Refusal, RunKeys
from cortex_broker.traffic import Capture, Transport

SCANNER = os.environ.get('TEST_GITLEAKS') or shutil.which('gitleaks')


class Response(io.BytesIO):
    status = 200
    headers = {'Content-Type': 'text/event-stream'}


class ProviderFixture:
    def __init__(self, body):
        self.body = body
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return Response(self.body)


class AuthFixture:
    def access(self):
        return 'fixture-only-not-a-real-token'


@unittest.skipUnless(SCANNER, 'gitleaks binary required for capture integration')
class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.healthy = True
        self.capture = Capture(self.tmp.name, SCANNER, lambda: self.healthy)
        self.keys = RunKeys()
        self.key = self.keys.mint('fixture-run', 'builder', 'gpt-6.1-sol', 'medium', time.time()+60, 10)
        self.request = {'model': 'gpt-6.1-sol', 'reasoning': {'effort': 'medium'},
                        'input': [{'role': 'user', 'content': 'fixture prompt'},
                                  {'type': 'function_call_output', 'call_id': 'fixture-call', 'output': 'fixture tool result'}]}
        self.body = b'data: {"type":"response.completed","response":{"output":[],"usage":{"input_tokens":9,"output_tokens":2}}}\n\n'
        self.provider = ProviderFixture(self.body)
        self.limits = []
        self.transport = Transport(AuthFixture(), self.keys, self.capture, lambda *args: self.limits.append(args), self.provider)

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self):
        return [json.loads(line) for line in (Path(self.tmp.name)/'fixture-run.jsonl').read_text().splitlines()]

    def test_captured_full_request_sse_and_adaptations(self):
        delivered = []
        result = self.transport.responses(self.key, self.request, lambda *args: delivered.append(args))
        self.assertTrue(result['complete'])
        self.assertEqual(self.body, delivered[0][2])
        rows = self.rows()
        self.assertEqual(['request.received', 'request.upstream', 'response'], [r['kind'] for r in rows])
        self.assertEqual(self.request, rows[0]['data']['request'])
        self.assertFalse(rows[1]['data']['request']['store'])
        self.assertTrue(rows[1]['data']['request']['stream'])
        self.assertEqual(self.body.decode(), rows[2]['data']['body'])
        self.assertEqual(9, rows[2]['data']['reconstructed']['response']['usage']['input_tokens'])
        self.assertNotIn('fixture-only-not-a-real-token', json.dumps(rows))
        self.assertEqual('https://api.openai.com/v1/responses', self.provider.requests[0].full_url)

    def test_capture_down_prevents_dispatch(self):
        self.healthy = False
        with self.assertRaises(Refusal):
            self.transport.responses(self.key, self.request, lambda *args: None)
        self.assertEqual([], self.provider.requests)

    def test_explicit_credentials_redacted(self):
        row = self.capture.append('fixture-run', 'fixture', {'authorization': 'fixture secret', 'refresh_token': 'fixture private', 'body': 'Bearer abcdefghijklmnopqrstuvwxyz'})
        self.assertEqual(['secret'], row['flags'])
        text = json.dumps(row)
        for forbidden in ['fixture secret', 'fixture private', 'abcdefghijklmnopqrstuvwxyz']:
            self.assertNotIn(forbidden, text)

    def test_scanner_failure_prevents_dispatch(self):
        self.capture.scanner = '/usr/bin/false'
        # exit 1 means a match, so fail with a distinct scanner error.
        self.capture.scanner = '/path/that/does/not/exist'
        with self.assertRaises(OSError):
            self.transport.responses(self.key, self.request, lambda *args: None)
        self.assertEqual([], self.provider.requests)

    def test_limit_body_unchanged_and_callback(self):
        body = b'data: {"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}}\n\n'
        self.provider.body = body
        delivered = []
        result = self.transport.responses(self.key, self.request, lambda *args: delivered.append(args))
        self.assertFalse(result['complete'])
        self.assertEqual(body, delivered[0][2])
        self.assertEqual(1, len(self.limits))

    def test_interrupted_stream_not_success(self):
        self.provider.body = b'data: {"type":"response.output_text.delta","delta":"partial"}\n\n'
        result = self.transport.responses(self.key, self.request, lambda *args: None)
        self.assertFalse(result['complete'])
        self.assertEqual('interrupted', result['terminal'])
