"""Offline synthetic attribution; no provider traffic or raw reports retained."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cortex_broker import scanner_attribution as attribution
from cortex_broker.scanner_diagnostics import project, run_scanner, scan
from cortex_broker.traffic import Capture

# Deliberately synthetic and assembled so the fixture source is not a credential.
CANARY = 'gh' + 'p_' + '0123456789abcdef' * 2 + 'abcd'


def encode(value):
    return json.dumps(value, ensure_ascii=True).encode()


def locations(summary):
    return [loc for rule in summary['rules'] for loc in rule['locations']]


def finding(start, end, line=1):
    return {'RuleID': 'synthetic', 'Tags': [], 'StartLine': line, 'EndLine': line,
            'StartColumn': start + 1, 'EndColumn': end}


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = os.environ['TEST_GITLEAKS']

    def detected(self, value):
        result = scan(self.scanner, encode(value), self.root)
        self.assertIsNotNone(result)
        self.assertNotIn(CANARY, json.dumps(result))
        return locations(result)

    def test_real_request_unicode_escapes_and_duplicate_values(self):
        value = {'request': {'instructions': 'é😀\\\"\n' + CANARY,
                            'input': [{'role': 'user', 'content': CANARY},
                                      {'type': 'function_call_output', 'output': CANARY}]}}
        result = self.detected(value)
        self.assertEqual(['request.instructions', 'request.input[].content',
                          'request.input[].output'], [x['field_path'] for x in result])
        encoded = encode(value)
        for loc in result:
            self.assertEqual(CANARY.encode(), encoded[loc['start_column']-1:loc['end_column']])
            self.assertEqual('request_content', loc['field_class'])

    def test_real_typed_response_fields(self):
        for item_type, field, expected in [('message', 'id', 'message_id'),
                ('reasoning', 'id', 'reasoning_id'), ('function_call', 'id', 'function_call_id'),
                ('function_call', 'call_id', 'function_call_id'),
                ('reasoning', 'encrypted_content', 'encrypted_reasoning'),
                ('function_call', 'arguments', 'function_arguments')]:
            with self.subTest(item_type=item_type, field=field):
                result = self.detected({'reconstructed': {'response': {
                    'output': [{'type': item_type, field: CANARY}]}}})
                self.assertEqual('reconstructed.response.output[].' + field, result[0]['field_path'])
                self.assertEqual(expected, result[0]['field_class'])
        self.assertEqual('response_id', self.detected({'reconstructed': {'response': {'id': CANARY}}})[0]['field_class'])

    def test_real_sse_escaped_json_unicode_and_reconstructed_duplicates(self):
        for newline in ('\n', '\r\n', '\r'):
            event = {'type': 'response.completed', 'response': {'id': CANARY,
                     'output': [{'type': 'message', 'id': CANARY,
                                 'content': [{'type': 'output_text', 'text': 'é😀\\\"\n' + CANARY}]}]}}
            body = '\ufeff: comment' + newline + 'event: response.completed' + newline
            body += 'data: ' + json.dumps(event, ensure_ascii=False) + newline * 2
            value = {'body': body, 'reconstructed': {'events': [event], 'response': event['response']}}
            result = self.detected(value)
            self.assertEqual(9, len(result))
            self.assertEqual(['body.sse[].response.id', 'body.sse[].response.output[].id',
                             'body.sse[].response.output[].content[].text'],
                             [x['field_path'] for x in result[:3]])
            self.assertEqual(['response_id', 'message_id', 'output_text'] * 3,
                             [x['field_class'] for x in result])
            for loc in result:
                self.assertEqual(CANARY.encode(), encode(value)[loc['start_column']-1:loc['end_column']])

    def test_sse_multiline_data_and_done(self):
        body = ('event: response.output_item.done\ndata: {"type":"response.output_item.done",\n'
                'data: "item":{"type":"reasoning","encrypted_content":"' + CANARY + '"}}\n\n')
        result = self.detected({'body': body})
        self.assertEqual('body.sse[].item.encrypted_content', result[0]['field_path'])
        self.assertEqual('encrypted_reasoning', result[0]['field_class'])
        terminal = {'type': 'response.completed', 'response': {'id': CANARY}}
        self.assertEqual('body.sse[].response.id', self.detected({'body': 'data: ' + json.dumps(terminal) + '\n\ndata: [DONE]\n\n'})[0]['field_path'])

    def test_json_body_and_delta_fields(self):
        self.assertEqual('body.json.id', self.detected({'body': json.dumps({'object': 'response', 'id': CANARY})})[0]['field_path'])
        for typ, cls in [('response.output_text.delta', 'output_text'),
                         ('response.function_call_arguments.delta', 'function_arguments'),
                         ('response.reasoning_summary_text.delta', 'reasoning_text')]:
            result = self.detected({'body': 'data: ' + json.dumps({'type': typ, 'delta': CANARY}) + '\n\n'})
            self.assertEqual('body.sse[].delta', result[0]['field_path'])
            self.assertEqual(cls, result[0]['field_class'])

    def test_real_generic_rule_and_safe_projection(self):
        marker = 'api_key = ' + 'Ab3cD4eF5gH6iJ7kL8mN9pQ0rS1tU2vW'
        summary = scan(self.scanner, encode({'request': {'instructions': marker}}), self.root)
        self.assertEqual('generic-api-key', summary['rules'][0]['rule_id'])
        self.assertEqual('request.instructions', locations(summary)[0]['field_path'])
        self.assertNotIn(marker, json.dumps(summary))

    def test_unknown_keys_types_and_nested_model_controlled_schema(self):
        values = [{CANARY: 'value'}, {'attacker-key': CANARY},
                  {'request': {'tools': [{'parameters': {'properties': {'id': CANARY}}}]}},
                  {'reconstructed': {'response': {'output': [{'type': 'attacker-type', 'id': CANARY}]}}},
                  {'body': CANARY}, {'reconstructed': {'response': {'id': {'nested': CANARY}}}}]
        for value in values:
            with self.subTest(shape=list(value)):
                for loc in self.detected(value):
                    self.assertEqual('unknown', loc['field_path'])
                    self.assertEqual('unknown', loc['field_class'])

    def test_invalid_or_ambiguous_sse_stays_unknown(self):
        data = '{"type":"response.completed","response":{"id":"' + CANARY + '"}}'
        for body in ['data: ' + data, 'event: response.created\ndata: ' + data + '\n\n',
                     'data: ' + data.replace('"id":', '"id":"duplicate","id":') + '\n\n',
                     'data: ' + data + '\n\ninvalid: frame\n\n',
                     'data: [DONE]\n\ndata: ' + data + '\n\n']:
            self.assertTrue(all(x['field_path'] == 'unknown' for x in self.detected({'body': body})))

    def test_crossfield_out_of_range_multiline_and_key_only_unknown(self):
        raw = encode({'request': {'instructions': 'first', 'input': 'second'}})
        start, end = raw.index(b'first'), raw.index(b'second') + len(b'second')
        for f in [finding(start, end), finding(0, len(raw)+10), finding(start, start+2, 2),
                  finding(raw.index(b'instructions'), raw.index(b'instructions')+3)]:
            result = project(1, json.dumps([f]).encode(), raw)
            self.assertEqual('unknown', locations(result)[0]['field_path'])

    def test_outer_noncanonical_and_duplicate_json_unknown(self):
        for raw in [b'{"request":{"instructions":"x","instructions":"y"}}',
                    b'{\n"request":{"instructions":"x"}}',
                    '{"request":{"instructions":"é"}}'.encode(), b'not json']:
            result = project(1, json.dumps([finding(0, len(raw))]).encode(), raw)
            self.assertEqual('unknown', locations(result)[0]['field_path'])

    def test_budgets_and_attribution_failure_keep_whole_redaction(self):
        capture = Capture(self.root, self.scanner, lambda: True)
        for constant in ('MAX_INPUT', 'MAX_NODES', 'MAX_DEPTH', 'MAX_BODY'):
            with patch.object(attribution, constant, 1):
                value = {'body': 'data: ' + json.dumps({'type': 'response.completed', 'response': {'id': CANARY}}) + '\n\n'}
                cleaned, flags = capture.safe(value)
                self.assertEqual('gitleaks-match', cleaned['redacted_body'])
                self.assertEqual(['gitleaks'], flags)
                self.assertEqual('unknown', locations(cleaned['scanner_diagnostics'])[0]['field_path'])
        with patch.object(attribution, 'build_spans', side_effect=ValueError('unsafe-content')):
            cleaned, flags = capture.safe({'request': {'instructions': CANARY}})
            self.assertEqual('unknown', locations(cleaned['scanner_diagnostics'])[0]['field_path'])
            self.assertNotIn('unsafe-content', json.dumps(cleaned))

    def test_success_never_parses_or_mutates(self):
        capture = Capture(self.root, self.scanner, lambda: True)
        value = {'request': {'input': [{'content': 'é😀\\\"\n ordinary words'}]}}
        with patch.object(attribution, 'build_spans', side_effect=AssertionError):
            cleaned, flags = capture.safe(value)
        self.assertEqual(value, cleaned)
        self.assertEqual([], flags)

    def test_escape_boundary_map_all_ascii_and_unicode(self):
        # DEL, control escapes, literal backslash-u, lone surrogate and non-BMP.
        prefix = ''.join(chr(i) for i in range(128)) + 'é😀' + chr(0xd800) + r'\u00e9'
        event = {'type': 'response.completed', 'response': {'id': prefix + CANARY}}
        for ensure_ascii in (True, False):
            body = 'data: ' + json.dumps(event, ensure_ascii=ensure_ascii) + '\n\n'
            result = self.detected({'body': body})
            self.assertEqual('body.sse[].response.id', result[0]['field_path'])

    def test_sse_crossfield_crossframe_and_assignment_bounds(self):
        event = {'type': 'response.completed', 'response': {'id': 'first',
                 'output': [{'type': 'message', 'id': 'second'}]}}
        raw = encode({'body': 'data: ' + json.dumps(event) + '\n\n'})
        first, second = raw.index(b'first'), raw.index(b'second')
        for start, end in [(first, second+6), (first, len(raw)), (0, first+2)]:
            result = project(1, json.dumps([finding(start, end)]).encode(), raw)
            self.assertEqual('unknown', locations(result)[0]['field_path'])
        # Gitleaks can include a scalar member's assignment in its match.
        raw = encode({'reconstructed': {'response': {'id': 'synthetic'}}})
        start = raw.index(b'"id"')
        end = raw.index(b'synthetic') + len(b'synthetic') + 1
        result = project(1, json.dumps([finding(start, end)]).encode(), raw)
        self.assertEqual('reconstructed.response.id', locations(result)[0]['field_path'])

    def test_real_single_fragment_boundary_and_large_unknown(self):
        overhead = len(encode({'request': {'instructions': CANARY}}))
        for length in (8192, 16384, attribution.MAX_INPUT):
            raw = encode({'request': {'instructions': ' ' * (length - overhead) + CANARY}})
            self.assertEqual(length, len(raw))
            loc = locations(scan(self.scanner, raw, self.root))[0]
            self.assertEqual(CANARY.encode(), raw[loc['start_column']-1:loc['end_column']])
            self.assertEqual('request.instructions', loc['field_path'])
        # Large inputs may or may not fragment depending on pipe reads. Refuse
        # attribution regardless of whether reported columns happen to be global.
        # The controlled small-pipe test separately covers the harmful reset.
        for length in (32769, 65536, 1048576):
            raw = encode({'request': {'instructions': ' ' * (length - overhead) + CANARY}})
            summary = scan(self.scanner, raw, self.root)
            self.assertEqual(1, summary['finding_count'])
            loc = locations(summary)[0]
            self.assertEqual('unknown', loc['field_path'])
            self.assertEqual('unknown', loc['field_class'])

    def test_small_pipe_fragment_cannot_mislabel_output_as_reasoning(self):
        import subprocess
        value = {'reconstructed': {'response': {'output': [
            {'type': 'reasoning', 'encrypted_content': ' ' * 2000},
            {'type': 'message', 'content': [{'type': 'output_text', 'text': CANARY}]}]}}}
        target = 30000
        value['reconstructed']['response']['output'][1]['content'][0]['text'] = (
            ' ' * (target - encode(value).index(CANARY.encode())) + CANARY)
        raw = encode(value)
        self.assertEqual(30048, len(raw))
        self.assertEqual(target, raw.index(CANARY.encode()))
        original = subprocess.Popen
        def small_pipe(*args, **kwargs):
            kwargs['pipesize'] = 4096
            return original(*args, **kwargs)
        with patch('cortex_broker.scanner_diagnostics.subprocess.Popen', small_pipe):
            summary = scan(self.scanner, raw, self.root)
        self.assertEqual(1, summary['finding_count'])
        loc = locations(summary)[0]
        self.assertEqual('unknown', loc['field_class'])
        self.assertEqual('unknown', loc['field_path'])
        self.assertNotIn(CANARY, json.dumps(summary))

    def test_small_pipe_source_bound_and_first_byte_above_bound(self):
        import subprocess
        self.assertEqual(25000, attribution.MAX_INPUT)
        original = subprocess.Popen
        def small_pipe(*args, **kwargs):
            kwargs['pipesize'] = 4096
            return original(*args, **kwargs)
        overhead = len(encode({'request': {'instructions': CANARY}}))
        for length in (24999, 25000, 25001):
            with self.subTest(length=length):
                raw = encode({'request': {'instructions': ' ' * (length - overhead) + CANARY}})
                self.assertEqual(length, len(raw))
                with patch('cortex_broker.scanner_diagnostics.subprocess.Popen', small_pipe):
                    summary = scan(self.scanner, raw, self.root)
                self.assertEqual(1, summary['finding_count'])
                loc = locations(summary)[0]
                expected = 'request_content' if length <= 25000 else 'unknown'
                self.assertEqual(expected, loc['field_class'])
                if length <= 25000:
                    self.assertEqual(CANARY.encode(), raw[loc['start_column']-1:loc['end_column']])

    def test_decoded_and_unsupported_report_tags_unknown(self):
        import base64
        raw = encode({'request': {'instructions': base64.b64encode(CANARY.encode()).decode()}})
        self.assertEqual('unknown', locations(scan(self.scanner, raw, self.root))[0]['field_path'])
        raw = encode({'request': {'instructions': CANARY}})
        start = raw.index(CANARY.encode())
        for tags in (None, ['decoded:base64'], ['arbitrary-model-controlled-value'], 'invalid'):
            report = json.dumps([{**finding(start, start+len(CANARY)), 'Tags': tags}]).encode()
            result = project(1, report, raw)
            self.assertEqual('unknown', locations(result)[0]['field_path'])
            self.assertNotIn('arbitrary-model-controlled-value', json.dumps(result))

    def test_actual_node_depth_and_body_limits(self):
        raw = encode({'request': {'instructions': 'x'}, 'unknown': [0] * attribution.MAX_NODES})
        loc = locations(project(1, json.dumps([finding(raw.index(b'"x"')+1, raw.index(b'"x"')+2)]).encode(), raw))[0]
        self.assertEqual('unknown', loc['field_path'])
        raw = b'{"request":{"instructions":"x"},"unknown":' + b'[' * 50 + b'0' + b']' * 50 + b'}'
        loc = locations(project(1, json.dumps([finding(raw.index(b'"x"')+1, raw.index(b'"x"')+2)]).encode(), raw))[0]
        self.assertEqual('unknown', loc['field_path'])
        body = ':' + 'x' * attribution.MAX_BODY + '\n\ndata: ' + json.dumps({'type': 'response.completed', 'response': {'id': CANARY}}) + '\n\n'
        self.assertEqual('unknown', self.detected({'body': body})[0]['field_path'])

    def test_safe_persisted_projection_for_sse_and_request(self):
        capture = Capture(self.root, self.scanner, lambda: True)
        event = {'type': 'response.output_item.done', 'item': {'type': 'reasoning', 'id': CANARY}}
        for kind, value in [('response', {'body': 'data: ' + json.dumps(event) + '\n\n'}),
                            ('request.upstream', {'request': {'instructions': CANARY}})]:
            row = capture.append('safe-metadata', kind, value)
            self.assertEqual({'redacted_body', 'scanner_diagnostics'}, set(row['data']))
            self.assertEqual(['secret'], row['flags'])
            self.assertEqual(['gitleaks'], row['redactions'])
            self.assertNotEqual('unknown', locations(row['data']['scanner_diagnostics'])[0]['field_path'])
        text = (self.root / 'safe-metadata.jsonl').read_text()
        self.assertNotIn(CANARY, text)
        for forbidden in ('Secret', 'Match', 'Entropy', 'Fingerprint', 'Description', 'unsafe-content'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(['safe-metadata.jsonl'], [p.name for p in self.root.iterdir()])

    def test_real_pinned_scanner_coordinate_convention(self):
        # Gitleaks uses byte columns, inclusive end; lines >1 count the preceding
        # LF as column 1. Capture's ensure_ascii, unindented JSON has only line 1.
        for prefix, line, column in [('é😀 ', 1, 8), ('abc\nhello ', 2, 8), ('a\nb\nhello ', 3, 8)]:
            status, report = run_scanner(self.scanner, (prefix + CANARY).encode(), self.root)
            loc = locations(project(status, report))[0]
            self.assertEqual((line, column, column + len(CANARY)-1),
                             (loc['start_line'], loc['start_column'], loc['end_column']))
            self.assertEqual('unknown', loc['field_path'])


if __name__ == '__main__':
    unittest.main()
