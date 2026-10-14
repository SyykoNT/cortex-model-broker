"""Content proof regressions; all inputs synthetic, raw reports memory-only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cortex_broker import scanner_attribution as a
from cortex_broker import scanner_diagnostics as d
from cortex_broker.protocol import Refusal
from cortex_broker.traffic import Capture

TOKEN = 'gh' + 'p_' + '0123456789abcdef' * 2 + 'abcd'


def encode(obj):
    return json.dumps(obj, ensure_ascii=True).encode()


def rows(summary):
    return [loc for rule in summary['rules'] for loc in rule['locations']]


def evidence(summary):
    return [item for rule in summary['rules'] for item in rule['field_evidence']]


def report(match, **changes):
    finding = dict(RuleID='synthetic', Tags=[], StartLine=1, EndLine=1,
                   StartColumn=1, EndColumn=max(1, len(match)) if isinstance(match, str) else 1,
                   Match=match, Secret='DO-NOT-USE-SECRET')
    finding.update(changes)
    return json.dumps([finding]).encode()


class ContentOriginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = os.environ['TEST_GITLEAKS']

    def test_large_unique_origin_ignores_plausible_wrong_columns(self):
        raw = encode({'reconstructed': {'response': {'output': [
            {'type': 'reasoning', 'encrypted_content': ' ' * 2000},
            {'type': 'message', 'content': [{'type': 'output_text', 'text': ' ' * 100000 + TOKEN}]}]}}})
        start = raw.index(b' ' * 100)
        summary = d.project(1, report(TOKEN, StartColumn=start+1, EndColumn=start+len(TOKEN)), raw)
        self.assertEqual('output_text', rows(summary)[0]['field_class'])
        self.assertEqual('scanner_local', rows(summary)[0]['coordinate_space'])
        self.assertEqual('exact_all_occurrences', rows(summary)[0]['attribution_reason'])
        self.assertEqual(len(raw), summary['encoded_byte_count'])

    def test_full_empty_string_assignment_cannot_prove_value_overlap(self):
        raw = encode({'reconstructed': {'response': {'output': [
            {'type': 'reasoning', 'encrypted_content': ''}]}}})
        # Direct proof API edge: the complete assignment is nonempty, its value is not.
        # The pinned scanner correctly reports this ordinary empty assignment clean.
        self.assertIsNone(d.scan(self.scanner, raw, self.root))
        loc = rows(d.project(1, report('"encrypted_content": ""'), raw))[0]
        self.assertEqual('unknown', loc['field_path'])
        self.assertEqual('unknown', loc['field_class'])
        self.assertEqual('occurrence_outside_field', loc['attribution_reason'])

    def test_same_match_cross_paths_classes_or_unknown_is_unknown(self):
        values = [
            {'request': {'instructions': TOKEN}, 'reconstructed': {'response': {'id': TOKEN}}},
            {'request': {'instructions': TOKEN, 'input': TOKEN}},
            {'request': {'instructions': TOKEN}, 'unrecognized': TOKEN},
            {'reconstructed': {'response': {'output': [
                {'type': 'message', 'id': TOKEN}, {'type': 'reasoning', 'id': TOKEN}]}}},
        ]
        for value in values:
            raw = encode(value)
            start = raw.index(TOKEN.encode())
            # Even content equality at these apparently global columns is not proof.
            loc = rows(d.project(1, report(TOKEN, StartColumn=start+1, EndColumn=start+len(TOKEN)), raw))[0]
            self.assertEqual('unknown', loc['field_class'])

    def test_repeated_same_static_path_and_class_is_proven(self):
        raw = encode({'request': {'input': [{'content': TOKEN}, {'content': TOKEN}]}})
        loc = rows(d.project(1, report(TOKEN), raw))[0]
        self.assertEqual('request.input[].content', loc['field_path'])
        self.assertEqual('exact_all_occurrences', loc['attribution_reason'])

    def test_full_match_not_secret_substring_normalization_or_regex(self):
        raw = encode({'request': {'instructions': 'api_key = ' + TOKEN}})
        for match in ['missing-prefix' + TOKEN, TOKEN + 'missing-suffix', '.*' + TOKEN,
                      TOKEN.upper(), ' api_key = ' + TOKEN]:
            loc = rows(d.project(1, report(match, Secret=TOKEN), raw))[0]
            self.assertEqual('unknown', loc['field_class'])
        self.assertEqual('request_content', rows(d.project(1, report('api_key = ' + TOKEN), raw))[0]['field_class'])

    def test_missing_empty_malformed_truncated_and_tagged_match_unknown(self):
        raw = encode({'request': {'instructions': TOKEN}})
        cases = [report(None), report(''), report(10), report([TOKEN]),
                 report(TOKEN[:-1], EndColumn=len(TOKEN)), report(TOKEN, Tags=None),
                 report(TOKEN, Tags=['decoded:base64']), report(TOKEN, EndLine=2)]
        missing = json.loads(report(TOKEN)); del missing[0]['Match']
        cases.append(json.dumps(missing).encode())
        for wire in cases:
            summary = d.project(1, wire, raw)
            self.assertEqual('unknown', rows(summary)[0]['field_class'])
            self.assertNotIn(TOKEN, json.dumps(summary))

    def test_work_and_occurrence_limits_unknown_without_changing_redaction(self):
        capture = Capture(self.root, self.scanner, lambda: True)
        for budget in ('MAX_WORK', 'MAX_OCCURRENCES'):
            with patch.object(a, budget, 0):
                cleaned, flags = capture.safe({'request': {'instructions': TOKEN}})
            self.assertEqual(['gitleaks'], flags)
            self.assertEqual('gitleaks-match', cleaned['redacted_body'])
            self.assertEqual('unknown', rows(cleaned['scanner_diagnostics'])[0]['field_class'])
            self.assertIn('budget', evidence(cleaned['scanner_diagnostics'])[0]['attribution_reason'])

    def test_all_overlapping_occurrences_must_be_safe(self):
        raw = encode({'request': {'instructions': 'aaaa'}, 'unknown': 'aaa'})
        self.assertEqual('unknown', rows(d.project(1, report('aaa'), raw))[0]['field_class'])
        with patch.object(a, 'MAX_OCCURRENCES', 1):
            raw = encode({'request': {'instructions': 'aaaa'}})
            self.assertEqual('unknown', rows(d.project(1, report('aaa'), raw))[0]['field_class'])

    def test_real_large_default_and_small_pipe(self):
        popen = subprocess.Popen
        for size in (30048, 65536, 1048576):
            for pipe in (None, 4096):
                value = {'request': {'instructions': TOKEN}}
                value['request']['instructions'] = ' ' * (size-len(encode(value))) + TOKEN
                raw = encode(value)
                def launch(*args, **kwargs):
                    if pipe is not None:
                        kwargs['pipesize'] = pipe
                    return popen(*args, **kwargs)
                with patch.object(d.subprocess, 'Popen', launch):
                    summary = d.scan(self.scanner, raw, self.root)
                self.assertEqual(1, summary['finding_count'])
                self.assertEqual('unknown', rows(summary)[0]['field_class'])
                self.assertEqual('request_content', evidence(summary)[0]['field_class'])
                self.assertNotIn(TOKEN, json.dumps(summary))

    def test_real_duplicates_across_reset_never_trust_offset_equality(self):
        value = {'reconstructed': {'response': {'output': [
            {'type': 'reasoning', 'encrypted_content': TOKEN},
            {'type': 'message', 'content': [{'type': 'output_text', 'text': ' '*60000 + TOKEN}]}]}}}
        popen = subprocess.Popen
        def small(*args, **kwargs):
            return popen(*args, pipesize=4096, **kwargs)
        with patch.object(d.subprocess, 'Popen', small):
            summary = d.scan(self.scanner, encode(value), self.root)
        self.assertEqual(2, summary['finding_count'])
        self.assertTrue(all(loc['field_class'] == 'unknown' for loc in rows(summary)))
        self.assertTrue(all(e['field_class'] == 'unknown' for e in evidence(summary)))

    def test_real_large_unicode_sse_and_json_escape_maps(self):
        event = {'type': 'response.completed', 'response': {'id': 'é😀\\\"\n' + ' '*50000 + TOKEN}}
        for body in ('data: ' + json.dumps(event, ensure_ascii=False) + '\n\n',
                     json.dumps({'object': 'response', **event['response']}, ensure_ascii=False)):
            summary = d.scan(self.scanner, encode({'body': body}), self.root)
            self.assertEqual('unknown', rows(summary)[0]['field_class'])
            self.assertEqual('response_id', evidence(summary)[0]['field_class'])

    def test_actual_input_limit_and_scan_beyond_it(self):
        for size in (a.MAX_INPUT, a.MAX_INPUT + 1):
            value = {'request': {'instructions': TOKEN}}
            value['request']['instructions'] = ' ' * (size-len(encode(value))) + TOKEN
            raw = encode(value)
            summary = d.scan(self.scanner, raw, self.root)
            self.assertEqual(1, summary['finding_count'])
            self.assertEqual(size, summary['encoded_byte_count'])
            self.assertEqual('unknown', rows(summary)[0]['field_class'])
            loc = evidence(summary)[0]
            self.assertEqual('request_content' if size <= a.MAX_INPUT else 'unknown', loc['field_class'])
            if size > a.MAX_INPUT:
                self.assertEqual('input_budget', loc['attribution_reason'])

    def test_dynamic_node_budget_and_depth_limit(self):
        value = {'request': {'instructions': TOKEN}, 'padding': ' '*1000000,
                 'unknown': [{'x': 0} for _ in range(6000)]}
        self.assertEqual('request_content', rows(d.project(1, report(TOKEN), encode(value)))[0]['field_class'])
        with patch.object(a, 'MAX_NODES', 4096):
            self.assertEqual('unknown', rows(d.project(1, report(TOKEN), encode(value)))[0]['field_class'])

    def test_real_duplicate_same_path_and_class_is_proven(self):
        raw = encode({'request': {'input': [{'content': TOKEN}, {'content': TOKEN}]}})
        summary = d.scan(self.scanner, raw, self.root)
        self.assertEqual(2, summary['finding_count'])
        self.assertTrue(all(loc['field_path'] == 'unknown' for loc in rows(summary)))
        self.assertEqual(['request.input[].content'], [e['field_path'] for e in evidence(summary)])

    def test_detector_status_counts_and_locations_identical_with_redacted_report(self):
        # Fixed small pipe controls reader fragments across both invocations.
        # Neither invocation persists its report, even in this test.
        import base64
        popen = subprocess.Popen
        values = [ {'request': {'instructions': 'ordinary text'}},
                   {'request': {'instructions': TOKEN}},
                   {'request': {'instructions': 'api_key = ' + 'Ab3cD4eF5gH6iJ7kL8mN9pQ0rS1tU2vW'}},
                   {'request': {'instructions': base64.b64encode(TOKEN.encode()).decode()}},
                   {'request': {'instructions': ' '*60000 + TOKEN}} ]
        for value in values:
            raw = encode(value)
            def launch(*args, **kwargs):
                return popen(*args, pipesize=4096, **kwargs)
            with patch.object(d.subprocess, 'Popen', launch):
                new_status, new_report = d.run_scanner(self.scanner, raw, self.root, diagnostic=True)
            with patch.object(d.subprocess, 'Popen', launch):
                old_status, old_report = d.run_scanner(self.scanner, raw, self.root)
            self.assertEqual(old_status, new_status)
            def numeric(wire):
                return sorted((f['RuleID'], *(f[k] for k in d.LOCATIONS)) for f in json.loads(wire))
            self.assertEqual(numeric(old_report), numeric(new_report))

    def test_report_values_never_escape_capture_or_failure_chain(self):
        import io
        marker = 'PRIVATE-REPORT-ONLY-CANARY'
        raw = encode({'request': {'instructions': TOKEN}})
        wire = report(TOKEN, Secret=marker, Line=marker, Description=marker, Extra={marker: marker})
        capture = Capture(self.root, self.scanner, lambda: True)
        with patch.object(d, 'run_scanner', return_value=(1, wire)):
            row = capture.append('projection', 'response', {'request': {'instructions': TOKEN}})
        persisted = (self.root / 'projection.jsonl').read_text()
        self.assertNotIn(marker, persisted)
        self.assertNotIn(TOKEN, persisted)
        self.assertEqual(['secret'], row['flags'])
        for payload in (b'not-json-' + marker.encode(), wire[:-1]):
            try:
                d.project(1, payload, raw)
            except Refusal as exc:
                self.assertIsNone(exc.__context__)
                tb = exc.__traceback__
                while tb:
                    if tb.tb_frame.f_globals.get('__name__') == d.__name__:
                        self.assertNotIn(marker, repr(tb.tb_frame.f_locals))
                    tb = tb.tb_next
            else:
                self.fail('malformed report accepted')
        for failure in ('read', 'overflow', 'timeout'):
            output = io.StringIO()
            with patch('sys.stdout', output), patch('sys.stderr', output):
                try:
                    if failure == 'read':
                        # Popen itself uses os.read for its exec error pipe.
                        # Inject only after launch, at the scanner stdout fd.
                        popen, os_read, stdout_fd = subprocess.Popen, os.read, [None]
                        def launch(*args, **kwargs):
                            process = popen(*args, **kwargs)
                            stdout_fd[0] = process.stdout.fileno()
                            return process
                        def fail_read(fd, size):
                            if fd == stdout_fd[0]:
                                raise ValueError(marker)
                            return os_read(fd, size)
                        with patch.object(d.subprocess, 'Popen', launch), patch.object(d.os, 'read', fail_read):
                            d.scan(self.scanner, raw, self.root)
                    elif failure == 'overflow':
                        with patch.object(d, 'MAX_REPORT', 1):
                            d.scan(self.scanner, raw, self.root)
                    else:
                        with patch.object(d, 'TIMEOUT', 0):
                            d.scan(self.scanner, raw, self.root)
                except Refusal as exc:
                    self.assertIsNone(exc.__context__)
                    self.assertNotIn(marker, str(exc))
                else:
                    self.fail('scanner failure accepted')
            self.assertEqual('', output.getvalue())
        self.assertEqual(['projection.jsonl'], [p.name for p in self.root.iterdir()])

    def test_arbitrary_attribution_error_preserves_detection(self):
        with patch.object(d, 'attribute', side_effect=ValueError('UNSAFE-EXCEPTION-CANARY')):
            summary = d.project(1, report(TOKEN), encode({'request': {'instructions': TOKEN}}))
        self.assertEqual(1, summary['finding_count'])
        self.assertEqual('attribution_failure', rows(summary)[0]['attribution_reason'])
        self.assertEqual('unknown', rows(summary)[0]['field_path'])
        self.assertNotIn('UNSAFE-EXCEPTION-CANARY', json.dumps(summary))

    def test_scanner_failure_exception_does_not_retain_raw_report(self):
        # Cause/context chaining must not retain JSONDecodeError.doc.
        try:
            d.project(1, b'UNSAFE-REPORT-CANARY')
        except Refusal as exc:
            self.assertIsNone(exc.__context__)
            self.assertIsNone(exc.__cause__)
            self.assertNotIn('UNSAFE-REPORT-CANARY', str(exc))
        else:
            self.fail('did not refuse')


if __name__ == '__main__':
    unittest.main()
