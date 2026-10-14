"""NON-AUTHORITATIVE coverage; synthetic fixtures, actual pinned scanner."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cortex_broker import scanner_attribution as a
from cortex_broker import scanner_diagnostics as d
from cortex_broker.traffic import Capture
from test_auxiliary_scan import authority
from test_content_origin import encode, report, rows, evidence

VALUE = 'Ab3cD4eF5gH6iJ7kL8mN9pQ0rS1tU2vW'


def coverage(summary):
    return summary['rules'][0]['structural_coverage']


def groups(summary):
    return coverage(summary)['findings'][0]['occurrences']


class StructuralCoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = os.environ['TEST_GITLEAKS']

    def test_complete_match_crosses_request_and_output_boundaries_real_rule(self):
        fixtures = [({'request': {'instructions': 'access_token', VALUE: 'ordinary'}},
                     'request.instructions', 'request_content'),
                    ({'reconstructed': {'response': {'output': [{'type': 'message', 'content': [
                        {'type': 'output_text', 'text': 'access_token', VALUE: 'ordinary'}]}]}}},
                     'reconstructed.response.output[].content[].text', 'output_text')]
        for value, path, cls in fixtures:
            encoded = encode(value)
            status, raw = d.run_scanner(self.scanner, encoded, self.root, diagnostic=True)
            findings = json.loads(raw)
            self.assertEqual(1, status)
            self.assertEqual(['generic-api-key'], [f['RuleID'] for f in findings])
            # The real rule's comma assignment delimiter can capture the NEXT
            # member's synthetic key, not the known field's value.
            self.assertTrue(findings[0]['Secret'] == VALUE)
            self.assertTrue(findings[0]['Match'] == 'access_token", "' + VALUE + '"')
            summary = d.scan(self.scanner, encoded, self.root)
            self.assertEqual('occurrence_outside_field', evidence(summary)[0]['attribution_reason'])
            self.assertEqual('unknown', evidence(summary)[0]['field_class'])
            self.assertEqual([dict(relation='crosses_member_boundary', count=1,
                                   overlaps=[dict(field_path=path, field_class=cls)])], groups(summary))
            self.assertTrue(all(loc['field_class'] == 'unknown' for loc in rows(summary)))
            self.assertNotIn(VALUE, json.dumps(summary))

    def test_real_rule_response_id_encrypted_and_sse_unindexed(self):
        response = {'id': 'resp_api_key=' + VALUE + ';', 'output': [
            {'type': 'reasoning', 'encrypted_content': 'api_key=' + VALUE + ';'}]}
        event = {'type': 'response.completed', 'response': response}
        for value in ({'reconstructed': {'response': response}},
                      {'body': 'data: ' + json.dumps(event) + '\n\n'},
                      {'body': json.dumps({'object': 'response', **response})}):
            encoded = encode(value)
            status, raw = d.run_scanner(self.scanner, encoded, self.root, diagnostic=True)
            findings = json.loads(raw)
            self.assertEqual(1, status)
            self.assertEqual(2, len(findings))
            self.assertTrue(all(f['RuleID'] == 'generic-api-key' and f['Secret'] == VALUE
                                and f['Match'] != f['Secret'] for f in findings))
            summary = d.scan(self.scanner, encoded, self.root)
            self.assertEqual({'response_id', 'encrypted_reasoning'},
                             {o['field_class'] for f in coverage(summary)['findings']
                              for g in f['occurrences'] for o in g['overlaps']})
            self.assertTrue(all(g['relation'] == 'inside_value'
                                for f in coverage(summary)['findings'] for g in f['occurrences']))
        # Real generic rule in a valid, known SSE envelope's unsupported field.
        event = {'type': 'response.completed', 'response': {'metadata': {'unknown': 'api_key=' + VALUE + ';'}}}
        summary = d.scan(self.scanner, encode({'body': 'data: ' + json.dumps(event) + '\n\n'}), self.root)
        self.assertEqual('sse', summary['response_shape']['body_format'])
        self.assertEqual('occurrence_outside_field', evidence(summary)[0]['attribution_reason'])
        self.assertEqual([dict(relation='no_known_overlap', count=1, overlaps=[])], groups(summary))

    def test_real_four_57_byte_response_metadata_matches_remain_unproved(self):
        # Synthetic complete-capture layout, NOT a recovered historical body.
        # Assemble the deliberate synthetic value at runtime so source scanning
        # stays clean without suppressions; the real scanner still sees the exact
        # UUID-valued capture below and must detect all four findings.
        synthetic_uuid = '-'.join(('6cbad423', '94d5', '4ce3', 'bb87', '7c581e6ea917'))
        response = {'prompt_cache_key': synthetic_uuid}
        events = [{'type': typ, 'response': response} for typ in (
            'response.created', 'response.in_progress', 'response.completed')]
        value = {'body': ''.join('data: ' + json.dumps(event) + '\n\n' for event in events),
                 'reconstructed': {'response': response, 'events': events}}
        encoded = encode(value)
        status, raw = d.run_scanner(self.scanner, encoded, self.root, diagnostic=True)
        findings = json.loads(raw)
        self.assertEqual(1, status)
        self.assertEqual(4, len(findings))
        self.assertTrue(all(f['RuleID'] == 'generic-api-key' and len(f['Match']) == 57
                            and len(f['Secret']) == 36 and f['Match'] != f['Secret'] for f in findings))
        summary = d.scan(self.scanner, encoded, self.root)
        self.assertEqual([dict(field_path='unknown', field_class='unknown',
                               attribution_reason='occurrence_outside_field')], evidence(summary))
        self.assertEqual(4, len(coverage(summary)['findings']))
        for finding in coverage(summary)['findings']:
            self.assertEqual('complete', finding['status'])
            self.assertEqual(4, sum(g['count'] for g in finding['occurrences']))
            self.assertTrue(all(g['relation'] == 'inside_member' for g in finding['occurrences']))
            self.assertEqual({'reconstructed.response.prompt_cache_key',
                              'reconstructed.events[].response.prompt_cache_key'},
                             {o['field_path'] for g in finding['occurrences'] for o in g['overlaps']})
            self.assertEqual({'response_metadata'},
                             {o['field_class'] for g in finding['occurrences'] for o in g['overlaps']})
        self.assertEqual([], a.build_spans(encoded))
        self.assertTrue(a.build_spans(encoded, coverage_only=True))
        self.assertNotIn(response['prompt_cache_key'], json.dumps(summary))

    def test_metadata_whitelist_and_schema_cannot_relabel_response_text(self):
        for outer in ('direct', 'json', 'sse'):
            response = {'prompt_cache_key': 'VALUE', 'output': [{'type': 'message', 'content': [
                {'type': 'output_text', 'text': 'VALUE', 'prompt_cache_key': 'VALUE'}]}],
                'PRIVATE-KEY': 'VALUE'}
            value = ({'reconstructed': {'response': response}} if outer == 'direct' else
                     {'body': json.dumps({'object': 'response', **response})} if outer == 'json' else
                     {'body': 'data: ' + json.dumps({'type': 'response.completed', 'response': response}) + '\n\n'})
            summary = d.project(1, report('VALUE'), encode(value))
            self.assertEqual('unknown', rows(summary)[0]['field_class'])
            self.assertEqual({'response_metadata', 'output_text'},
                             {o['field_class'] for g in groups(summary) for o in g['overlaps']})
            self.assertEqual(2, sum(g['count'] for g in groups(summary) if g['relation'] == 'no_known_overlap'))
            self.assertNotIn('PRIVATE-KEY', json.dumps(summary))
        # Arbitrary JSON inside text is never reparsed as an opaque item/schema.
        value = {'reconstructed': {'response': {'output': [{'type': 'message', 'content': [
            {'type': 'output_text', 'text': json.dumps({'encrypted_content': 'VALUE', 'prompt_cache_key': 'VALUE'})}]}]}}}
        summary = d.project(1, report('VALUE'), encode(value))
        self.assertEqual({'output_text'}, {o['field_class'] for g in groups(summary) for o in g['overlaps']})

    def test_report_wide_budgets_and_later_finding_never_get_partial_groups(self):
        encoded = encode({'request': {'instructions': 'abc def'}})
        raw = json.dumps(json.loads(report('abc')) + json.loads(report('def'))).encode()
        for name in ('MAX_COVERAGE_GROUPS', 'MAX_COVERAGE_LABELS', 'MAX_COVERAGE_OCCURRENCES'):
            with patch.object(a, name, 1):
                summary = d.project(1, raw, encoded)
            findings = coverage(summary)['findings']
            self.assertEqual(['complete', 'occurrence_budget' if name.endswith('OCCURRENCES') else 'output_budget'],
                             sorted(f['status'] for f in findings))
            self.assertEqual(1, sum(len(f['occurrences']) for f in findings))
            self.assertTrue(all(loc['attribution_reason'] == 'exact_all_occurrences' for loc in rows(summary)))

    def test_all_occurrences_after_first_unknown_and_duplicate_aggregation(self):
        value = {'PRIVATE-KEY-CANARY': 'aaa', 'request': {'input': [
            {'content': 'aaaa'}, {'content': 'aaa'}]}}
        summary = d.project(1, report('aaa'), encode(value))
        self.assertEqual('occurrence_outside_field', rows(summary)[0]['attribution_reason'])
        self.assertEqual('complete', coverage(summary)['findings'][0]['status'])
        self.assertEqual({('no_known_overlap', 1), ('inside_value', 3)},
                         {(g['relation'], g['count']) for g in groups(summary)})
        self.assertNotIn('PRIVATE-KEY-CANARY', json.dumps(summary))

    def test_multiple_known_overlaps_never_promote_output_text_to_opaque(self):
        value = {'reconstructed': {'response': {'output': [
            {'type': 'reasoning', 'encrypted_content': 'OPAQUE-CANARY'},
            {'type': 'message', 'content': [{'type': 'output_text', 'text': 'OUTPUT-CANARY'}]}]}}}
        encoded = encode(value)
        start = encoded.index(b'OPAQUE-CANARY')
        end = encoded.index(b'OUTPUT-CANARY') + len(b'OUTPUT-CANARY')
        summary = d.project(1, report(encoded[start:end].decode()), encoded)
        self.assertEqual('unknown', rows(summary)[0]['field_class'])
        self.assertEqual('crosses_member_boundary', groups(summary)[0]['relation'])
        self.assertEqual({'encrypted_reasoning', 'output_text'},
                         {o['field_class'] for o in groups(summary)[0]['overlaps']})
        # Same exact Match in both values is mixed coverage, never one opaque class.
        value['reconstructed']['response']['output'][1]['content'][0]['text'] = 'OPAQUE-CANARY'
        summary = d.project(1, report('OPAQUE-CANARY'), encode(value))
        self.assertEqual('occurrence_ambiguous', rows(summary)[0]['attribution_reason'])
        self.assertEqual({'encrypted_reasoning', 'output_text'},
                         {o['field_class'] for g in groups(summary) for o in g['overlaps']})

    def test_inside_member_assignment_empty_and_key_only(self):
        for value, match, relation in [
                ('value', '"instructions": "value"', 'inside_member'),
                ('', '"instructions": ""', 'no_known_overlap'),
                ('value', 'instructions', 'no_known_overlap')]:
            summary = d.project(1, report(match), encode({'request': {'instructions': value}}))
            self.assertEqual(relation, groups(summary)[0]['relation'])

    def test_unknown_dynamic_keys_types_malformed_and_escaped_input_do_not_leak(self):
        for value in [
                {'unknown-private-key': 'PRIVATE-VALUE'},
                {'reconstructed': {'response': {'output': [{'type': 'PRIVATE-TYPE', 'encrypted_content': 'PRIVATE-VALUE'}]}}},
                {'body': '{"object":"response","id":"PRIVATE-VALUE","id":"again"}'},
                {'body': 'data: {"type":"response.completed","response":{"id":"PRIVATE-VALUE"}}'},
                {'body': 'data: {"type":"response.completed","response":{"PRIVATE-KEY":"PRIVATE-VALUE"}}\n\n'}]:
            summary = d.project(1, report('PRIVATE-VALUE'), encode(value))
            self.assertEqual([dict(relation='no_known_overlap', count=1, overlaps=[])], groups(summary))
            self.assertNotIn('PRIVATE', json.dumps(summary))
        event = {'type': 'response.output_text.delta', 'delta': 'é😀\\" PRIVATE-VALUE'}
        summary = d.project(1, report('PRIVATE-VALUE'), encode({'body': 'data: ' + json.dumps(event, ensure_ascii=False) + '\n\n'}))
        self.assertEqual('output_text', groups(summary)[0]['overlaps'][0]['field_class'])
        self.assertEqual('inside_value', groups(summary)[0]['relation'])

    def test_unsupported_absent_tags_and_structure_fail_closed(self):
        encoded = encode({'request': {'instructions': 'abc'}})
        cases = [(report(None), encoded, 'match_unsupported'),
                 (report('abc', EndColumn=2), encoded, 'match_unsupported'),
                 (report('abc', Tags=['decoded:base64']), encoded, 'tags_unsupported'),
                 (report('absent'), encoded, 'match_absent'),
                 (report('abc'), None, 'input_unsupported'),
                 (report('abc'), b'{broken', 'structure_unsupported_or_budget')]
        for raw, source, status in cases:
            finding = coverage(d.project(1, raw, source))['findings'][0]
            self.assertEqual(dict(status=status, occurrences=[]), finding)

    def test_coverage_budgets_discard_partial_finding_not_proof(self):
        encoded = encode({'request': {'input': [{'content': 'abc'}, {'content': 'abc'}]}})
        expected = rows(d.project(1, report('abc'), encoded))[0].copy()
        for name, limit, status in [('MAX_COVERAGE_WORK', 0, 'search_budget'),
                                    ('MAX_COVERAGE_OCCURRENCES', 1, 'occurrence_budget'),
                                    ('MAX_COVERAGE_VISITS', 0, 'overlap_budget'),
                                    ('MAX_COVERAGE_GROUPS', 0, 'output_budget'),
                                    ('MAX_COVERAGE_LABELS', 0, 'output_budget')]:
            with patch.object(a, name, limit):
                summary = d.project(1, report('abc'), encoded)
            self.assertEqual(expected, rows(summary)[0])
            self.assertEqual([dict(status=status, occurrences=[])], coverage(summary)['findings'])
        with patch.object(a, 'MAX_INPUT', 1):
            self.assertEqual('input_budget', coverage(d.project(1, report('abc'), encoded))['findings'][0]['status'])

    def test_sideband_failure_does_not_change_field_evidence_or_authority(self):
        encoded = encode({'request': {'instructions': 'abc'}})
        primary, secondary = report('REDACTED', EndColumn=3), report('abc')
        with patch.object(d, 'run_scanner', side_effect=[(1, primary), (1, secondary)]):
            expected = d.scan(self.scanner, encoded, self.root)
        with patch.object(d, 'run_scanner', side_effect=[(1, primary), (1, secondary)]), patch.object(
                d, 'structural_coverage', side_effect=ValueError('PRIVATE-ERROR')):
            summary = d.scan(self.scanner, encoded, self.root)
        self.assertEqual(authority(expected), authority(summary))
        self.assertEqual(evidence(expected), evidence(summary))
        self.assertEqual([dict(status='coverage_failure', occurrences=[])], coverage(summary)['findings'])
        self.assertNotIn('PRIVATE', json.dumps(summary))

    def test_no_primary_link_or_report_order_and_closed_serialized_keys(self):
        encoded = encode({'request': {'instructions': 'aaa'}, 'UNKNOWN-KEY': 'bbb'})
        secondary = json.loads(report('aaa')) + json.loads(report('bbb'))
        primary = json.dumps(json.loads(report('REDACTED', EndColumn=3)) * 2).encode()
        results = []
        for ordered in (secondary, secondary[::-1]):
            with patch.object(d, 'run_scanner', side_effect=[(1, primary), (1, json.dumps(ordered).encode())]):
                summary = d.scan(self.scanner, encoded, self.root)
            self.assertEqual(authority(d.project(1, primary)), authority(summary))
            self.assertTrue(all(set(loc) == {*d.LOCATIONS.values(), 'field_path', 'field_class',
                                            'coordinate_space', 'attribution_reason'} for loc in rows(summary)))
            c = coverage(summary)
            self.assertEqual({'authority', 'scope', 'findings'}, set(c))
            self.assertEqual('non_authoritative', c['authority'])
            self.assertEqual('secondary_complete_match_occurrences', c['scope'])
            for finding in c['findings']:
                self.assertEqual({'status', 'occurrences'}, set(finding))
                for group in finding['occurrences']:
                    self.assertEqual({'relation', 'count', 'overlaps'}, set(group))
                    for label in group['overlaps']:
                        self.assertEqual({'field_path', 'field_class'}, set(label))
            results.append(c)
        self.assertEqual(results[0], results[1])

    def test_secondary_mismatch_and_clean_primary_never_publish_coverage(self):
        encoded = encode({'request': {'instructions': 'abc'}})
        with patch.object(d, 'run_scanner', return_value=(0, b'[]')) as run, patch.object(d, 'structural_coverage') as cov:
            self.assertIsNone(d.scan(self.scanner, encoded, self.root))
        self.assertEqual(1, run.call_count)
        cov.assert_not_called()
        with patch.object(d, 'run_scanner', side_effect=[(1, report('REDACTED')), (1, report('abc', RuleID='different'))]):
            summary = d.scan(self.scanner, encoded, self.root)
        self.assertNotIn('structural_coverage', summary['rules'][0])

    def test_persisted_capture_remains_whole_redacted_no_values_or_dynamic_keys(self):
        value = {'request': {'instructions': 'access_token', VALUE: 'PRIVATE-VALUE'}}
        capture = Capture(self.root, self.scanner, lambda: True)
        row = capture.append('coverage', 'response', value)
        stored = (self.root / 'coverage.jsonl').read_text()
        self.assertNotIn(VALUE, stored)
        self.assertNotIn('PRIVATE-VALUE', stored)
        self.assertNotIn('access_token', stored)
        self.assertEqual('gitleaks-match', row['data']['redacted_body'])
        self.assertEqual(['secret'], row['flags'])
        self.assertEqual(['gitleaks'], row['redactions'])
        self.assertEqual('unknown', evidence(row['data']['scanner_diagnostics'])[0]['field_class'])
        self.assertEqual('crosses_member_boundary', groups(row['data']['scanner_diagnostics'])[0]['relation'])
