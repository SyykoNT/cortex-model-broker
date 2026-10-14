"""OFFLINE synthetic gitleaks detections; raw scanner reports never saved/logged."""
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from cortex_broker.protocol import Refusal
from cortex_broker.traffic import Capture


class ScannerDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.environ.get('TEST_GITLEAKS'))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.capture = Capture(self.root, os.environ['TEST_GITLEAKS'], lambda: True)

    def test_real_scanner_detection_retains_only_rule_counts_numeric_locations(self):
        canary = 'gh' + 'p_' + secrets.token_hex(18)
        row = self.capture.append('synthetic-detection', 'response', {'body': canary})
        self.assertEqual(['secret'], row['flags'])
        self.assertEqual(['gitleaks'], row['redactions'])
        self.assertEqual('gitleaks-match', row['data']['redacted_body'])
        diagnostics = row['data']['scanner_diagnostics']
        self.assertEqual({'version', 'finding_count', 'rules', 'encoded_byte_count', 'response_shape'}, set(diagnostics))
        self.assertEqual(1, diagnostics['finding_count'])
        self.assertEqual('github-pat', diagnostics['rules'][0]['rule_id'])
        self.assertEqual(1, diagnostics['rules'][0]['count'])
        for location in diagnostics['rules'][0]['locations']:
            self.assertEqual({'start_line', 'end_line', 'start_column', 'end_column',
                              'field_path', 'field_class', 'coordinate_space', 'attribution_reason'}, set(location))
            self.assertTrue(all(type(location[k]) is int and location[k] > 0
                                for k in ('start_line', 'end_line', 'start_column', 'end_column')))
            self.assertEqual('unknown', location['field_path'])
            self.assertEqual('unknown', location['field_class'])
        text = (self.root / 'synthetic-detection.jsonl').read_text()
        self.assertNotIn(canary, text)
        for forbidden in ('Secret', 'Match', 'Entropy', 'File', 'Fingerprint', 'Description'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(['synthetic-detection.jsonl'], [p.name for p in self.root.iterdir()])

    def test_detected_response_stays_nonreconstructable_and_stops_fc5_followup(self):
        from test_fc5 import FC5Tests
        f = FC5Tests('test_closed_socket_schema_and_peer_uid')
        f.setUp()
        self.addCleanup(f.doCleanups)
        canary = 'gh' + 'p_' + secrets.token_hex(18)
        f.provider.responses[0]['output'][0]['summary'] = [{'type': 'summary_text', 'text': canary}]
        reply = f.call()
        self.assertEqual('reconstruction_unavailable', reply['error'])
        self.assertEqual(1, len(f.provider.sent))
        files = list(f.capture.root.iterdir())
        self.assertEqual(1, len(files))
        text = files[0].read_text()
        self.assertNotIn(canary, text)
        rows = [json.loads(line) for line in text.splitlines()]
        response = next(r for r in rows if r['kind'] == 'response')
        self.assertEqual(['secret'], response['flags'])
        self.assertIn('scanner_diagnostics', response['data'])
        self.assertNotIn('body', response['data'])
        self.assertNotIn('classification', response['data'])
        self.assertEqual('reconstruction_unavailable', f.call('reconstruct', run_id=rows[0]['run_id'])['error'])

    def test_exit_one_without_report_is_failure_not_an_accepted_detection(self):
        self.capture.scanner = '/usr/bin/false'
        with self.assertRaisesRegex(Refusal, 'redaction_scanner_unavailable'):
            self.capture.append('missing-report', 'response', {'body': 'clean'})
        self.assertEqual([], list(self.root.iterdir()))

    def test_successful_capture_schema_and_value_unchanged(self):
        value = {'call_id': 'synthetic-call', 'status': 200, 'body': 'data: clean\n\n',
                 'bytes': 13, 'classification': {'content_type': None}}
        row = self.capture.append('clean', 'response', value)
        self.assertEqual(value, row['data'])
        self.assertEqual([], row['flags'])
        self.assertEqual([], row['redactions'])
        self.assertNotIn('scanner_diagnostics', row['data'])

    def test_report_projector_is_closed_and_strict(self):
        from cortex_broker.scanner_diagnostics import project
        finding = {'RuleID': 'github-pat', 'StartLine': 1, 'EndLine': 1, 'StartColumn': 2,
                   'EndColumn': 41, 'Secret': 'never-retain', 'Match': 'never-retain',
                   'File': 'never-retain', 'Description': 'never-retain', 'Entropy': 4.2}
        summary = project(1, json.dumps([finding, finding]).encode())
        self.assertEqual(2, summary['finding_count'])
        self.assertEqual(2, summary['rules'][0]['count'])
        self.assertNotIn('never-retain', json.dumps(summary))
        self.assertIsNone(project(0, b'[]'))
        invalid = [(1, b''), (0, b''), (1, b'[]'), (0, json.dumps([finding]).encode()),
                   (2, b'[]'), (1, b'{}'), (1, b'not json'), (1, b'[{"RuleID":"x","RuleID":"y"}]'),
                   (1, b'[{"RuleID":"x","StartLine":NaN}]')]
        for field, value in [('RuleID', 'unsafe\nvalue'), ('RuleID', ''), ('StartLine', True),
                             ('EndLine', 0), ('StartColumn', -1), ('EndColumn', '42')]:
            bad = {**finding, field: value}
            invalid.append((1, json.dumps([bad]).encode()))
        for status, raw in invalid:
            with self.subTest(status=status, length=len(raw)), self.assertRaises(Refusal):
                project(status, raw)

    def test_unparseable_report_blocks_capture_without_persisting_content(self):
        from cortex_broker import scanner_diagnostics
        for rc, raw in [(1, b'never-retain raw report'), (0, b'never-retain raw report'), (2, b'[]')]:
            with patch.object(scanner_diagnostics, 'run_scanner', return_value=(rc, raw)):
                with self.assertRaises(Refusal):
                    self.capture.append('invalid', 'response', {'body': 'clean'})
        self.assertEqual([], list(self.root.iterdir()))

    def test_pipe_report_size_and_deadline_fail_closed(self):
        from cortex_broker import scanner_diagnostics
        with patch.object(scanner_diagnostics, 'MAX_REPORT', 1):
            with self.assertRaises(Refusal):
                self.capture.append('oversize', 'response', {'body': 'clean'})
        with patch.object(scanner_diagnostics, 'TIMEOUT', 0):
            with self.assertRaises(Refusal):
                self.capture.append('timeout', 'response', {'body': 'clean'})
        self.assertEqual([], list(self.root.iterdir()))


if __name__ == '__main__':
    unittest.main()
