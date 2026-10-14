"""Synthetic response shape/fallback regressions; no provider traffic."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cortex_broker import scanner_attribution as a
from cortex_broker import scanner_diagnostics as d
from cortex_broker.protocol import Refusal, classify_response
from cortex_broker.traffic import Capture
from test_content_origin import TOKEN, encode, evidence, report, rows
from test_auxiliary_scan import authority


class ResponseShapeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = os.environ['TEST_GITLEAKS']

    def scan(self, value, match=TOKEN, secondary=None):
        raw = encode(value)
        primary = report('REDACTED', EndColumn=len(match))
        with patch.object(d, 'run_scanner', side_effect=[(1, primary), secondary or (1, report(match))]) as run:
            result = d.scan(self.scanner, raw, self.root)
        self.assertEqual(authority(d.project(1, primary)), authority(result))
        for call in run.call_args_list:
            self.assertIs(raw, call.args[1])
        self.assertTrue(all(loc['field_class'] == 'unknown' for loc in rows(result)))
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(5, result['version'])
        return result

    def test_non200_json_error_markup_and_plain(self):
        for status, body, fmt in ((429, json.dumps({'error': {'code': 'PRIVATE-CODE', 'message': TOKEN}}), 'json'),
                                  (503, '<html>' + TOKEN + '</html>', 'markup'),
                                  (502, 'temporarily unavailable ' + TOKEN, 'plain')):
            reconstructed, classification = classify_response(status, None, body)
            result = self.scan(dict(status=status, body=body, reconstructed=reconstructed, classification=classification))
            self.assertEqual(dict(http_status=status, body_format=fmt, classification_decision='http-status-rejected'), result['response_shape'])
            self.assertEqual([dict(field_path='body', field_class='unclassified_response_body', attribution_reason='exact_all_occurrences')], evidence(result))
            self.assertNotIn('PRIVATE-CODE', json.dumps(result))

    def test_status_exact_integer_and_static_decisions(self):
        for status in (100, 200, 599, True, False, 99, 600, 200.0, '503', None, [], {}):
            result = self.scan(dict(status=status, body=TOKEN, classification={'decision': 'invalid-sse'}))
            self.assertEqual(status if type(status) is int and 100 <= status <= 599 else None, result['response_shape']['http_status'])
        for decision in ('http-status-rejected', 'invalid-sse', 'sse-header', 'sse-body', TOKEN, None, {}, 1):
            result = self.scan(dict(body=TOKEN, classification={'decision': decision}))
            self.assertEqual(decision if decision in ('http-status-rejected', 'invalid-sse', 'sse-header', 'sse-body') else 'unknown', result['response_shape']['classification_decision'])

    def test_missing_wrong_type_empty_and_json_scalars(self):
        for value, fmt in (({}, 'unknown'), ({'body': None}, 'unknown'), ({'body': {}}, 'unknown'),
                           ({'body': ''}, 'empty'), ({'body': '  \r\n'}, 'empty'),
                           ({'body': '[1,2]'}, 'json'), ({'body': 'null'}, 'json'), ({'body': '"hello"'}, 'json')):
            value['unsupported'] = TOKEN
            result = self.scan(value)
            self.assertEqual(dict(http_status=None, body_format=fmt, classification_decision='unknown'), result['response_shape'])

    def test_normal_sse_and_json_deeper_spans_no_fallback(self):
        response = {'object': 'response', 'id': TOKEN}
        bodies = [(json.dumps(response), 'json', 'body.json.id'),
                  ('data: ' + json.dumps({'type': 'response.completed', 'response': response}) + '\n\ndata: [DONE]\n\n', 'sse', 'body.sse[].response.id')]
        for body, fmt, path in bodies:
            result = self.scan({'status': 200, 'body': body, 'classification': {'decision': 'sse-body'}})
            self.assertEqual(fmt, result['response_shape']['body_format'])
            self.assertEqual(path, evidence(result)[0]['field_path'])
            self.assertEqual('response_id', evidence(result)[0]['field_class'])
            self.assertNotIn('unclassified_response_body', json.dumps(result))

    def test_no_overlap_or_unknown_sibling_fallback(self):
        body = json.dumps({'object': 'response', 'id': 'safe', 'unknown': TOKEN})
        result = self.scan({'body': body})
        self.assertEqual('unknown', evidence(result)[0]['field_class'])
        body = json.dumps({'object': 'response', 'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': TOKEN}]}]})
        self.assertEqual('output_text', evidence(self.scan({'body': body}))[0]['field_class'])
        self.assertEqual('request_content', evidence(self.scan({'request': {'instructions': TOKEN}, 'body': 'ordinary'}))[0]['field_class'])

    def test_malformed_duplicate_and_known_schema_not_promoted(self):
        bodies = ['{"error": "' + TOKEN + '"', '{"error":"' + TOKEN + '","error":0}',
                  '{"object":"response","id":"' + TOKEN + '","id":0}',
                  json.dumps({'object': 'response', 'output': TOKEN}),
                  json.dumps({'object': 'response', 'output': [{'type': 'message', 'content': TOKEN}]}),
                  'data: ' + json.dumps({'type': 'response.output_text.delta', 'delta': TOKEN}),
                  'data: ' + json.dumps({'type': 'response.output_text.delta', 'delta': TOKEN}) + '\n\nBAD\n\n',
                  'data: ' + json.dumps({'type': 'response.output_text.delta', 'delta': {'bad': TOKEN}}) + '\n\n']
        for body in bodies:
            result = self.scan({'body': body})
            self.assertEqual('unknown', evidence(result)[0]['field_class'])
            self.assertNotIn('unclassified_response_body', json.dumps(result))
        for body in bodies[:3] + bodies[5:7]:
            self.assertEqual('unknown', self.scan({'body': body})['response_shape']['body_format'])

    def test_outer_duplicates_invalid_and_budget_are_unknown(self):
        for raw in (b'{"body":"a","body":"b"}', b'{bad', encode({'body': TOKEN, 'nested': [[[[[]]]]]})):
            with patch.object(a, 'MAX_DEPTH', 2):
                shape = a.response_shape(raw)
            self.assertEqual(dict(http_status=None, body_format='unknown', classification_decision='unknown'), shape)
        for budget in ('MAX_INPUT', 'MAX_NODES', 'MAX_DEPTH', 'MAX_BODY'):
            with patch.object(a, budget, 0):
                result = self.scan({'status': 429, 'body': '{"error":"' + TOKEN + '"}'})
            self.assertEqual('unknown', result['response_shape']['body_format'])
            self.assertEqual('unknown', evidence(result)[0]['field_class'])

    def test_body_parse_node_exhaustion_never_falls_back(self):
        body = json.dumps({'error': [0] * 5000, 'message': TOKEN})
        result = self.scan({'status': 429, 'body': body})
        self.assertEqual('unknown', result['response_shape']['body_format'])
        self.assertEqual('unknown', evidence(result)[0]['field_class'])

    def test_all_occurrences_tags_and_search_limits_still_strict(self):
        for value in ({'body': TOKEN, 'unsupported': TOKEN}, {'body': TOKEN, 'request': {'instructions': TOKEN}}):
            self.assertEqual('unknown', evidence(self.scan(value))[0]['field_class'])
        for tags in (None, ['decoded:base64']):
            result = self.scan({'body': TOKEN}, secondary=(1, report(TOKEN, Tags=tags)))
            self.assertEqual('tags_unsupported', evidence(result)[0]['attribution_reason'])
        for budget in ('MAX_WORK', 'MAX_OCCURRENCES'):
            with patch.object(a, budget, 0):
                self.assertEqual('unknown', evidence(self.scan({'body': TOKEN}))[0]['field_class'])
        self.assertEqual('unclassified_response_body', evidence(self.scan({'body': TOKEN + ' ' + TOKEN}))[0]['field_class'])
        # Assignment to an empty body contains no value bytes.
        self.assertEqual('unknown', evidence(self.scan({'body': ''}, match='"body": ""'))[0]['field_class'])

    def test_arbitrary_keys_values_never_retained_and_persistence(self):
        marker = 'PRIVATE-MODEL-CONTROLLED'
        value = {'status': 403, 'body': json.dumps({marker: {marker: TOKEN}, 'error': marker}),
                 'classification': {'decision': marker, marker: marker}}
        capture = Capture(self.root, self.scanner, lambda: True)
        row = capture.append('shape', 'response', value)
        persisted = (self.root / 'shape.jsonl').read_text()
        self.assertNotIn(marker, persisted)
        self.assertNotIn(TOKEN, persisted)
        self.assertEqual(['secret'], row['flags'])
        result = row['data']['scanner_diagnostics']
        self.assertEqual(dict(http_status=403, body_format='json', classification_decision='unknown'), result['response_shape'])
        self.assertEqual('unclassified_response_body', evidence(result)[0]['field_class'])

    def test_secondary_failure_keeps_shape_and_primary_authority(self):
        for secondary in ((0, b'[]'), (1, b'invalid'), ValueError('PRIVATE'), (1, report(TOKEN, RuleID='other'))):
            result = self.scan({'status': 503, 'body': '<html>' + TOKEN}, secondary=secondary)
            self.assertEqual(dict(http_status=503, body_format='markup', classification_decision='unknown'), result['response_shape'])
            self.assertNotIn('field_evidence', result['rules'][0])

    def test_shape_failure_does_not_change_primary_or_secondary(self):
        with patch.object(d, 'response_shape', side_effect=ValueError('PRIVATE')):
            result = self.scan({'body': TOKEN})
        self.assertNotIn('response_shape', result)
        self.assertEqual('unclassified_response_body', evidence(result)[0]['field_class'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_reserved_envelopes_and_malformed_prefixes_do_not_fallback(self):
        for body in (json.dumps({'object': 42, 'id': TOKEN}),
                     json.dumps({'output': TOKEN}),
                     json.dumps({'type': 'response.output_text.delta', 'delta': TOKEN}),
                     '\ufeff' + json.dumps({'object': 'response', 'id': TOKEN}),
                     ' data: ' + json.dumps({'type': 'response.output_text.delta', 'delta': TOKEN}) + '\n\n',
                     'data ' + TOKEN + '\n\n'):
            result = self.scan({'body': body})
            self.assertEqual('unknown', evidence(result)[0]['field_class'])

    def test_unicode_plain_and_unsupported_valid_sse_fallback(self):
        for body, fmt in (('é😀 ' + TOKEN, 'plain'),
                          ('data: ' + json.dumps({'type': 'response.future_unknown', 'arbitrary': TOKEN}) + '\n\n', 'sse')):
            result = self.scan({'body': body})
            self.assertEqual(fmt, result['response_shape']['body_format'])
            self.assertEqual('unclassified_response_body', evidence(result)[0]['field_class'])

    def test_primary_clean_invalid_failure_skip_shape(self):
        with patch.object(d, 'response_shape') as shape:
            for outcome in ((0, b'[]'), (1, b'bad'), Refusal('redaction_scanner_unavailable')):
                with patch.object(d, 'run_scanner', side_effect=[outcome]) as run:
                    if outcome == (0, b'[]'):
                        self.assertIsNone(d.scan(self.scanner, encode({'body': TOKEN}), self.root))
                    else:
                        with self.assertRaises(Refusal):
                            d.scan(self.scanner, encode({'body': TOKEN}), self.root)
                self.assertEqual(1, run.call_count)
            shape.assert_not_called()

    def test_real_primary_bytes_counts_and_redaction_preserved(self):
        value = {'status': 502, 'body': 'upstream unavailable ' + TOKEN}
        raw = encode(value)
        status, wire = d.run_scanner(self.scanner, raw, self.root)
        expected = authority(d.project(status, wire, raw, content=False))
        capture = Capture(self.root, self.scanner, lambda: True)
        original = d.run_scanner
        with patch.object(d, 'run_scanner', wraps=original) as run:
            clean, flags = capture.safe(value)
        self.assertEqual(['gitleaks'], flags)
        self.assertEqual('gitleaks-match', clean['redacted_body'])
        self.assertEqual(expected, authority(clean['scanner_diagnostics']))
        self.assertEqual([raw, raw], [call.args[1] for call in run.call_args_list])
        self.assertEqual('unclassified_response_body', evidence(clean['scanner_diagnostics'])[0]['field_class'])
