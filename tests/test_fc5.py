"""OFFLINE: synthetic loopback Responses, real Transport/Capture/admin UDS.

No provider credentials, no external network, no OS identity isolation claim.
"""
import copy
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest.mock import patch

from cortex_broker.admin import AdminServer, Controller, request
from cortex_broker.protocol import Refusal, RunKeys
from cortex_broker.traffic import Capture, Transport

MODEL = 'gpt-6.1-sol'
NAME = 'fc5_fixed_marker'
OUTPUT = '{"marker":"fc5-fixed-ok"}'
FINAL = 'FC5_OK'


def call_item():
    return {'type': 'function_call', 'id': 'fc_synthetic', 'call_id': 'call_synthetic',
            'name': NAME, 'arguments': '{"probe":"fc5"}', 'status': 'completed'}


def response(index):
    return {'id': 'resp_synthetic_' + str(index), 'status': 'completed', 'model': MODEL,
            'reasoning': {'effort': 'high'}, 'usage': {'input_tokens': 17, 'output_tokens': 11},
            'output': ([{'type': 'reasoning', 'id': 'rs_synthetic', 'summary': []}, call_item()]
                       if index == 0 else [{'type': 'message', 'id': 'msg_synthetic',
                           'role': 'assistant', 'status': 'completed',
                           'content': [{'type': 'output_text', 'text': FINAL, 'annotations': []}]}])}


def events(value):
    result = [{'type': 'response.created', 'response': {'id': value['id']}}]
    for index, item in enumerate(value['output']):
        if item.get('type') == 'function_call' and type(item.get('arguments')) is str:
            added = {**item, 'arguments': '', 'status': 'in_progress'}
            result.append({'type': 'response.output_item.added', 'output_index': index, 'item': added})
            for part in (item['arguments'][:5], item['arguments'][5:]):
                result.append({'type': 'response.function_call_arguments.delta', 'output_index': index,
                               'item_id': item.get('id'), 'delta': part})
            result.append({'type': 'response.function_call_arguments.done', 'output_index': index,
                           'item_id': item.get('id'), 'arguments': item['arguments']})
            result.append({'type': 'response.output_item.done', 'output_index': index, 'item': item})
    return result + [{'type': 'response.completed', 'response': value}]


def encode_events(items):
    return ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n' for e in items).encode()


def stream(value):
    return encode_events(events(value))


class SyntheticAuth:
    def __init__(self):
        self.refreshes = 0
        self.last = None

    def token_values(self):
        return {'synthetic-fc5-credential'}

    def access(self, force_refresh=False):
        if force_refresh:
            self.refreshes += 1
            self.last = time.time()
        return 'synthetic-fc5-credential'

    def status(self):
        return {'signed_in': True, 'client_id': 'synthetic-client', 'ext_agent_host_id': 'synthetic-host',
                'scopes': ['chatgpt.tokens.use.direct'], 'expires_at': 4000000000,
                'refresh_count': self.refreshes, 'last_refresh_at': self.last}


class Loopback:
    def __init__(self):
        self.responses = [response(0), response(1)]
        self.sent = []
        self.header = 'text/event-stream'
        self.raw = None
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = self.rfile.read(int(self.headers['Content-Length']))
                index = len(fixture.sent)
                fixture.sent.append(json.loads(data))
                body = fixture.raw if fixture.raw is not None else stream(fixture.responses[index % 2])
                self.send_response(200)
                if fixture.header is not None:
                    self.send_header('Content-Type', fixture.header)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                # Real HTTP transport; fragment SSE without altering retained bytes.
                for pos in range(0, len(body), 7):
                    self.wfile.write(body[pos:pos + 7])
                self.wfile.flush()

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def open(self, req, timeout):
        assert req.full_url == 'https://api.openai.com/v1/responses'
        local = urllib.request.Request('http://127.0.0.1:' + str(self.server.server_port) + '/responses',
                                       data=req.data, headers={'Content-Type': 'application/json'})
        return self.http.open(local, timeout=timeout)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class FC5Tests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.environ.get('TEST_GITLEAKS'), 'existing real scanner required')
        # Match the admin fixtures: the system default may have writable ancestors.
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', Path.cwd()))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.auth, self.keys, self.provider = SyntheticAuth(), RunKeys(), Loopback()
        self.addCleanup(self.provider.close)
        self.capture = Capture(self.root / 'capture', os.environ['TEST_GITLEAKS'], lambda: True)
        self.transport = Transport(self.auth, self.keys, self.capture, lambda *a: None, self.provider)
        self.controller = Controller(self.auth, self.keys, self.transport)
        self.socket = self.root / 'admin.sock'
        self.server = AdminServer(self.socket, os.getuid(), os.getgid(), self.controller).start()
        self.addCleanup(self.server.close)
        no_provider = patch('cortex_broker.auth.HTTP.open', side_effect=AssertionError('provider forbidden'))
        no_provider.start()
        self.addCleanup(no_provider.stop)

    def send(self, packet):
        return request(self.socket, os.getuid(), packet)

    def call(self, command='tool_probe', **fields):
        return self.send({'version': 1, 'command': command, **fields})

    def rows(self, run):
        return [json.loads(line) for line in (self.capture.root / (run + '.jsonl')).read_text().splitlines()]

    def test_fixture_parent_honors_tmpdir_or_cwd(self):
        self.assertEqual(
            Path(os.environ.get('TMPDIR', Path.cwd())).resolve(),
            self.root.parent.resolve(),
        )

    def test_two_calls_full_context_durable_replay_and_no_worker_admission(self):
        for header in ('text/event-stream', 'application/json', None):
            with self.subTest(header=header):
                self.provider.sent.clear()
                self.provider.header = header
                reply = self.call()
                self.assertTrue(reply['ok'], reply)
                result = reply['result']
                self.assertEqual(2, result['reconstruction']['verified_calls'])
                self.assertEqual(NAME, result['reconstruction']['tool']['name'])
                self.assertEqual(OUTPUT, result['reconstruction']['tool']['output'])
                self.assertEqual('call_synthetic', result['reconstruction']['tool']['call_id'])
                self.assertEqual(FINAL, result['reconstruction']['final_text'])
                first, second = self.provider.sent
                self.assertEqual('required', first['tool_choice'])
                self.assertEqual('none', second['tool_choice'])
                self.assertFalse(first['parallel_tool_calls'])
                self.assertEqual('namespace', first['tools'][0]['type'])
                self.assertEqual('functions', first['tools'][0]['name'])
                self.assertEqual(NAME, first['tools'][0]['tools'][0]['name'])
                self.assertEqual(first['input'] + self.provider.responses[0]['output'] + [
                    {'type': 'function_call_output', 'call_id': 'call_synthetic', 'output': OUTPUT}], second['input'])
                rows = self.rows(result['run_id'])
                self.assertEqual(2, sum(r['kind'] == 'response' for r in rows))
                for index, row in enumerate(r for r in rows if r['kind'] == 'response'):
                    self.assertEqual(stream(self.provider.responses[index]), row['data']['body'].encode())
                cold = Controller(self.auth, RunKeys(), self.transport)
                self.assertEqual(result['reconstruction'], cold.reconstruct(result['run_id']))
                self.assertEqual(result['reconstruction'], self.call('reconstruct', run_id=result['run_id'])['result'])
                self.assertFalse(self.call('status')['result']['worker_inference'])
                self.assertEqual('worker_admission_disabled', self.call('mint', run_id='worker', role='builder',
                    model=MODEL, reasoning='medium', expires_at=time.time() + 60, cap=1)['error'])
                self.assertTrue(all(k['expires_at'] == 0 and k['cap'] == 2 and k['used'] == 2
                                    for k in self.keys.keys.values()))

    def test_closed_socket_schema_and_peer_uid(self):
        for field, value in [('model', MODEL), ('reasoning', 'high'), ('input', []), ('tools', []),
                             ('url', 'http://127.0.0.1'), ('command_text', 'id'), ('run_id', 'chosen')]:
            self.assertEqual('invalid_request', self.call(**{field: value})['error'])
        self.server.allowed_uid = os.getuid() + 1
        self.assertEqual('peer_not_allowed', self.call()['error'])
        self.assertEqual([], self.provider.sent)

    def test_missing_extra_invalid_tool_or_malformed_args_stops_before_followup(self):
        good = response(0)
        variants = []
        for output in ([], [call_item(), call_item()], [{'type': 'web_search_call', 'id': 'ws'}],
                       [call_item(), response(1)['output'][0]]):
            v = copy.deepcopy(good); v['output'] = output; variants.append(v)
        for field, value in [('name', 'shell'), ('namespace', 'arbitrary'), ('call_id', ''), ('id', ''),
                             ('status', 'in_progress'), ('arguments', '{'), ('arguments', '{}'),
                             ('arguments', '{"probe":"other"}'), ('arguments', '{"probe":"fc5","extra":1}'),
                             ('arguments', '{"probe":"fc5","probe":"fc5"}'), ('arguments', 'NaN'),
                             ('arguments', {'probe': 'fc5'})]:
            v = copy.deepcopy(good); v['output'][1][field] = value; variants.append(v)
        for value in variants:
            with self.subTest(value=value):
                self.provider.sent.clear(); self.provider.responses[0] = value
                self.assertFalse(self.call()['ok'])
                self.assertEqual(1, len(self.provider.sent))
        self.assertTrue(all(k['expires_at'] == 0 for k in self.keys.keys.values()))

    def test_each_response_model_reasoning_usage_terminal_and_final_guards(self):
        for index in (0, 1):
            for field, value in [('model', 'other'), ('reasoning', None), ('reasoning', {'effort': 'medium'}),
                                 ('usage', None), ('usage', {'input_tokens': True, 'output_tokens': 1}),
                                 ('status', 'incomplete')]:
                with self.subTest(index=index, field=field):
                    self.provider.responses = [response(0), response(1)]
                    self.provider.responses[index][field] = value
                    self.provider.sent.clear()
                    self.assertFalse(self.call()['ok'])
                    self.assertEqual(index + 1, len(self.provider.sent))
        for output in ([], [call_item()], response(1)['output'] * 2,
                       [{'type': 'message', 'role': 'assistant', 'status': 'completed', 'content': [
                           {'type': 'output_text', 'text': 'not the marker'}]}]):
            self.provider.responses = [response(0), response(1)]
            self.provider.responses[1]['output'] = output
            self.provider.sent.clear()
            self.assertFalse(self.call()['ok'])
            self.assertEqual(2, len(self.provider.sent))
        self.provider.raw = stream(response(0)).rstrip(b'\n')
        self.provider.sent.clear()
        self.assertFalse(self.call()['ok'])
        self.assertEqual(1, len(self.provider.sent))

    def test_streamed_tool_identity_arguments_and_extra_calls_must_match_terminal(self):
        for kind, field, value in [
                ('response.output_item.added', 'output_index', 99),
                ('response.function_call_arguments.delta', 'item_id', 'fc_other'),
                ('response.function_call_arguments.delta', 'delta', 'forged'),
                ('response.function_call_arguments.done', 'arguments', '{}')]:
            items = events(response(0))
            next(e for e in items if e['type'] == kind)[field] = value
            self.provider.raw = encode_events(items)
            self.provider.sent.clear()
            with self.subTest(kind=kind, field=field):
                self.assertFalse(self.call()['ok'])
                self.assertEqual(1, len(self.provider.sent))
        items = events(response(0))
        items[1]['item']['call_id'] = 'call_unlinked'
        self.provider.raw = encode_events(items)
        self.provider.sent.clear()
        self.assertFalse(self.call()['ok'])
        self.assertEqual(1, len(self.provider.sent))
        for index in (1, 5):
            items = events(response(0))
            items.insert(index + 1, copy.deepcopy(items[index]))
            self.provider.raw = encode_events(items)
            self.provider.sent.clear()
            self.assertFalse(self.call()['ok'])
            self.assertEqual(1, len(self.provider.sent))

    def test_redaction_or_silent_capture_drop_blocks_followup(self):
        self.provider.responses[0]['output'][0]['summary'] = [{'type': 'summary_text',
            'text': 'synthetic-fc5-credential'}]
        self.assertFalse(self.call()['ok'])
        self.assertEqual(1, len(self.provider.sent))
        self.assertNotIn('synthetic-fc5-credential', ''.join(p.read_text() for p in self.capture.root.iterdir()))
        self.provider.responses = [response(0), response(1)]
        self.provider.sent.clear()
        original = self.capture.append
        def drop(run, kind, value):
            if kind != 'response':
                return original(run, kind, value)
        with patch.object(self.capture, 'append', side_effect=drop):
            self.assertFalse(self.call()['ok'])
        self.assertEqual(1, len(self.provider.sent))

    def test_capture_failures_stop_sequence_and_keys_are_revoked(self):
        original = self.capture.append
        for kind, occurrence, expected in [('admin.tool_probe', 1, 0), ('request.received', 1, 0),
                ('request.upstream', 1, 0), ('response', 1, 1), ('tool.result', 1, 1),
                ('request.received', 2, 1), ('request.upstream', 2, 1), ('response', 2, 2),
                ('admin.tool_probe.completed', 1, 2)]:
            seen = 0
            def fail(run, k, value):
                nonlocal seen
                if k == kind:
                    seen += 1
                    if seen == occurrence:
                        raise OSError('synthetic capture failure')
                return original(run, k, value)
            with self.subTest(kind=kind, occurrence=occurrence):
                self.provider.sent.clear()
                with patch.object(self.capture, 'append', side_effect=fail):
                    self.assertFalse(self.call()['ok'])
                self.assertEqual(expected, len(self.provider.sent))
                self.assertTrue(all(k['expires_at'] == 0 for k in self.keys.keys.values()))

    def test_reconstruction_tampering_rejected(self):
        reply = self.call()
        self.assertTrue(reply['ok'], reply)
        run = reply['result']['run_id']
        node = self.capture.root / (run + '.jsonl')
        original = self.rows(run)
        mutations = []
        for kind in ['admin.tool_probe', 'tool.result', 'admin.tool_probe.completed', 'response']:
            mutations.append([r for r in copy.deepcopy(original) if r['kind'] != kind])
        for kind, field, value in [('tool.result', 'output', 'forged'), ('tool.result', 'call_id', 'call_other'),
                                  ('tool.result', 'name', 'shell'), ('response', 'bytes', 1)]:
            rows = copy.deepcopy(original)
            next(r for r in rows if r['kind'] == kind)['data'][field] = value
            mutations.append(rows)
        for which in ('request.received', 'request.upstream'):
            for field, value in [('call_id', 'call_other'), ('output', 'forged')]:
                rows = copy.deepcopy(original)
                req = [r['data']['request'] for r in rows if r['kind'] == which][1]
                req['input'][-1][field] = value
                mutations.append(rows)
        rows = copy.deepcopy(original)
        for r in rows:
            if r['kind'] in ('request.received', 'request.upstream') and len(r['data']['request']['input']) > 1:
                r['data']['request']['input'][-1]['output'] = 'coupled forgery'
            if r['kind'] == 'tool.result':
                r['data']['output'] = 'coupled forgery'
        mutations.append(rows)
        mutations.append(copy.deepcopy(original) + [copy.deepcopy(original[-1])])
        rows = copy.deepcopy(original); rows[4], rows[5] = rows[5], rows[4]; mutations.append(rows)
        rows = copy.deepcopy(original)
        [r for r in rows if r['kind'] == 'request.received'][1]['data']['call_id'] = [
            r for r in rows if r['kind'] == 'request.received'][0]['data']['call_id']
        mutations.append(rows)
        for index, rows in enumerate(mutations):
            node.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            with self.subTest(case=index):
                self.assertEqual('reconstruction_unavailable', self.call('reconstruct', run_id=run)['error'])
        node.write_text(''.join(json.dumps(r) + '\n' for r in original))
        self.assertTrue(self.call('reconstruct', run_id=run)['ok'])
        self.assertEqual(2, len(self.provider.sent))


if __name__ == '__main__':
    unittest.main()
