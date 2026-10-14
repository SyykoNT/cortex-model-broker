"""Synthetic offline fixtures; no claim about the unretained live Content-Type."""

import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from cortex_broker.admin import Controller
from cortex_broker.protocol import Refusal, RunKeys
from cortex_broker.traffic import Capture, Transport

MODEL = 'gpt-6.1-sol'


def stream(events, newline='\n', named=True):
    return ''.join((('event: ' + event['type'] + newline) if named else '') +
                   'data: ' + json.dumps(event, ensure_ascii=False) + newline * 2
                   for event in events).encode()


def completed(effort='high'):
    return {'type': 'response.completed', 'response': {
        'id': 'resp_synthetic', 'status': 'completed', 'model': MODEL,
        'reasoning': {'effort': effort}, 'output': [{'text': 'Hello, world! — fixture'}],
        'usage': {'input_tokens': 13, 'output_tokens': 8}}}


class SyntheticAuth:
    def token_values(self):
        return {'synthetic-not-a-credential'}

    def access(self):
        return 'synthetic-not-a-credential'


class ChunkedResponse(io.BytesIO):
    def read1(self, size=-1):
        # Split both SSE frames and multibyte UTF-8 sequences.
        return self.read(7 if size < 0 else min(size, 7))


class Provider:
    def __init__(self, body, content_type, status=200):
        self.body, self.content_type, self.status = body, content_type, status
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        response = ChunkedResponse(self.body)
        response.status = self.status
        response.headers = {} if self.content_type is None else {'Content-Type': self.content_type}
        return response


class StreamCompositionTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.environ.get('TEST_GITLEAKS'), 'real scanner required')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.capture = Capture(self.root, os.environ['TEST_GITLEAKS'], lambda: True)
        self.keys = RunKeys()
        self.auth = SyntheticAuth()
        self.addCleanup(patch.stopall)
        patch('cortex_broker.auth.HTTP.open', side_effect=AssertionError('provider forbidden')).start()

    def wire(self, body, content_type=None, status=200):
        self.provider = Provider(body, content_type, status)
        self.transport = Transport(self.auth, self.keys, self.capture, lambda *a: None, self.provider)
        self.controller = Controller(self.auth, self.keys, self.transport)

    def infer(self, effort='high'):
        return self.controller.dispatch({'version': 1, 'command': 'infer', 'model': MODEL, 'reasoning': effort})

    def response_row(self, run):
        rows = [json.loads(line) for line in (self.root / (run + '.jsonl')).read_text().splitlines()]
        return next(row['data'] for row in rows if row['kind'] == 'response')

    def test_header_matrix_real_transport_admin_and_capture(self):
        for effort in ('high', 'medium'):
            for header in ('text/event-stream', 'Text/Event-Stream; charset=UTF-8',
                           ' text/event-stream ; charset=utf-8', None,
                           'application/octet-stream', 'text/plain', 'application/json',
                           '', 'text/event-streaming', 'application/json; text/event-stream'):
                with self.subTest(effort=effort, header=header):
                    body = stream([{'type': 'response.created', 'response': {'id': 'resp_synthetic'}},
                                   completed(effort)], newline='\r\n')
                    self.wire(body, header)
                    emitted = []
                    real_responses = self.transport.responses
                    def observed(key, request, emit):
                        def relay(*args):
                            emitted.append(args)
                            emit(*args)
                        return real_responses(key, request, relay)
                    with patch.object(self.transport, 'responses', side_effect=observed):
                        result = self.infer(effort)
                    row = self.response_row(result['run_id'])
                    self.assertEqual(body, emitted[0][2])
                    self.assertEqual(header if header is not None else 'application/octet-stream', emitted[0][1])
                    self.assertEqual(body, row['body'].encode())
                    self.assertEqual(len(body), row['bytes'])
                    metadata = row['classification']
                    self.assertEqual(header, metadata['content_type'])
                    self.assertEqual(1, metadata['version'])
                    media = header.split(';', 1)[0].strip().lower() if header is not None else None
                    self.assertEqual(media, metadata['media_type'])
                    self.assertEqual('sse-header' if media == 'text/event-stream' else 'sse-body', metadata['decision'])
                    self.assertEqual([] if media == 'text/event-stream' else ['content_type_mismatch'], metadata['notes'])
                    self.assertTrue(row['reconstructed']['complete'])
                    self.assertEqual(1, result['reconstruction']['verified_calls'])
                    # Cold controller replay must agree, not trust in-memory success.
                    cold = Controller(self.auth, self.keys, self.transport)
                    self.assertEqual(result['reconstruction'], cold.reconstruct(result['run_id']))
                    self.assertEqual(1, len(self.provider.requests))
                    sent = json.loads(self.provider.requests[0].data)
                    self.assertEqual(MODEL, sent['model'])
                    self.assertEqual({'effort': effort}, sent['reasoning'])
        self.assertTrue(all(key['expires_at'] == 0 for key in self.keys.keys.values()))

    def test_invalid_body_matrix_never_admin_success(self):
        good = stream([completed()])
        failures = [
            b'<html>upstream error</html>', b'{"error":{"message":"failure"}}', b'', b'\xff',
            good.rstrip(b'\n'), good[:-10], b'<html>\n\n' + good, good + b'<html>trailer</html>\n\n',
            good + good,
            stream([{'type': 'response.failed'}, completed()]),
            stream([completed(), {'type': 'response.incomplete'}]),
            stream([completed(), {'type': 'response.output_text.delta', 'delta': 'late'}]),
            good.replace(b'event: response.completed', b'event: response.failed'),
            good.replace(b'"status": "completed"', b'"status": "failed"'),
            stream([{'type': 'response.created', 'response': {'id': 'other'}}, completed()]),
            b'data: []\n\n' + good,
            b'data: {"type":"error","type":"response.created"}\n\n' + good,
            b'data: {"type":"response.created","x":NaN}\n\n' + good,
            b'data: [DONE]\n\n' + good,
            good + b'data: [DONE]\n\n' + good,
            good + b'event: response.failed\n\n',
        ]
        for header in (None, 'text/event-stream', 'application/json'):
            for index, body in enumerate(failures):
                with self.subTest(header=header, case=index):
                    self.wire(body, header)
                    with self.assertRaises(Refusal):
                        self.infer()
                    self.assertEqual(1, len(self.provider.requests))

    def test_non200_cannot_be_success_even_with_complete_sse(self):
        for status in (201, 400, 429, 500):
            self.wire(stream([completed()]), 'text/event-stream', status)
            key = self.keys.mint('status-' + str(status), 'acceptance', MODEL, 'high', time.time() + 60, 1)
            result = self.transport.responses(key, {'model': MODEL, 'reasoning': {'effort': 'high'},
                'input': [{'role': 'user', 'content': 'fixture'}]}, lambda *args: None)
            self.assertFalse(result['complete'])
            with self.assertRaises(Refusal):
                self.infer()

    def test_usage_model_and_reasoning_guards_survive_fallback(self):
        for field, value in [('usage', None), ('usage', {'input_tokens': True, 'output_tokens': 8}),
                             ('usage', {'input_tokens': 13, 'output_tokens': -1}),
                             ('model', 'other'), ('reasoning', {'effort': 'medium'})]:
            event = completed()
            event['response'][field] = value
            self.wire(stream([event]), None)
            with self.subTest(field=field, value=value), self.assertRaises(Refusal):
                self.infer()

    def test_read_failure_has_header_metadata_and_never_emits(self):
        self.wire(stream([completed()]), 'Text/Plain; charset=UTF-8')
        response = self.provider.open(None, 120)
        key = self.keys.mint('read-failure', 'acceptance', MODEL, 'high', time.time() + 60, 1)
        emitted = []
        with patch.object(self.provider, 'open', return_value=response), patch.object(
                response, 'read1', side_effect=[b'event: ', OSError('synthetic read failure')]):
            with self.assertRaises(Refusal):
                self.transport.responses(key, {'model': MODEL, 'reasoning': {'effort': 'high'},
                    'input': [{'role': 'user', 'content': 'fixture'}]}, lambda *args: emitted.append(args))
        self.assertEqual([], emitted)
        rows = [json.loads(line) for line in (self.root / 'read-failure.jsonl').read_text().splitlines()]
        self.assertEqual('response.interrupted', rows[-1]['kind'])
        self.assertEqual('Text/Plain; charset=UTF-8', rows[-1]['data']['classification']['content_type'])
        self.assertEqual('interrupted', rows[-1]['data']['classification']['decision'])
        with self.assertRaises(Refusal):
            self.controller.reconstruct('read-failure')

    def test_capture_failure_stops_emission_and_admin_acceptance(self):
        self.wire(stream([completed()]), None)
        original = self.capture.append
        def fail(run, kind, value):
            if kind == 'response':
                raise OSError('synthetic capture failure')
            return original(run, kind, value)
        key = self.keys.mint('capture-failure', 'acceptance', MODEL, 'high', time.time() + 60, 1)
        emitted = []
        with patch.object(self.capture, 'append', side_effect=fail):
            with self.assertRaises(Refusal):
                self.transport.responses(key, {'model': MODEL, 'reasoning': {'effort': 'high'},
                    'input': [{'role': 'user', 'content': 'fixture'}]}, lambda *args: emitted.append(args))
            with self.assertRaises(Refusal):
                self.infer()
        self.assertEqual([], emitted)

    def test_metadata_redaction_refuses_acceptance_without_secret_retention(self):
        self.wire(stream([completed()]), 'text/plain; synthetic-not-a-credential')
        with self.assertRaises(Refusal):
            self.infer()
        text = ''.join(node.read_text() for node in self.root.iterdir())
        self.assertNotIn('synthetic-not-a-credential', text)
        self.assertIn('[REDACTED]', text)

    def test_replay_validates_classification_and_byte_count(self):
        self.wire(stream([completed()]), None)
        result = self.infer()
        node = self.root / (result['run_id'] + '.jsonl')
        original = node.read_text()
        for field, value in [('classification', {'version': 1, 'content_type': None, 'decision': 'sse-header', 'media_type': None}),
                             ('bytes', 1), ('reconstructed', {'complete': True})]:
            rows = [json.loads(line) for line in original.splitlines()]
            next(row for row in rows if row['kind'] == 'response')['data'][field] = value
            node.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.subTest(field=field), self.assertRaises(Refusal):
                self.controller.reconstruct(result['run_id'])
        node.write_text(original)
        self.assertEqual(1, self.controller.reconstruct(result['run_id'])['verified_calls'])

    def test_legacy_failure_not_rewritten_as_success(self):
        self.wire(stream([completed()]), 'text/event-stream')
        result = self.infer()
        node = self.root / (result['run_id'] + '.jsonl')
        rows = [json.loads(line) for line in node.read_text().splitlines()]
        row = next(row['data'] for row in rows if row['kind'] == 'response')
        row.pop('classification', None)
        node.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        self.assertEqual(1, self.controller.reconstruct(result['run_id'])['verified_calls'])
        row['reconstructed'] = {'complete': False, 'terminal': 'http-error'}
        node.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with self.assertRaises(Refusal):
            self.controller.reconstruct(result['run_id'])

    def test_sse_comments_done_and_multiline_data(self):
        good = stream([completed()], named=False)
        body = b': keepalive\n\n' + good.replace(b'data: {', b'id: synthetic\nretry: 1000\ndata: {', 1)
        body = body.replace(b', "response":', b',\ndata: "response":') + b'data: [DONE]\n\n: end\n\n'
        self.wire(body, None)
        self.assertTrue(self.infer()['complete'])


if __name__ == '__main__':
    unittest.main()
