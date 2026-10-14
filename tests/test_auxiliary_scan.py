"""Auxiliary failure cannot change primary authority; synthetic reports memory-only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cortex_broker import scanner_diagnostics as d
from cortex_broker.protocol import Refusal
from cortex_broker.traffic import Capture
from test_content_origin import TOKEN, encode, evidence, report, rows


def authority(summary):
    return (summary['finding_count'], [(r['rule_id'], r['count'], [
        tuple(loc[k] for k in d.LOCATIONS.values()) for loc in r['locations']])
        for r in summary['rules']])


class AuxiliaryScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = os.environ['TEST_GITLEAKS']
        self.value = {'request': {'instructions': TOKEN}}
        self.encoded = encode(self.value)
        self.primary = report('REDACTED', EndColumn=len(TOKEN), StartColumn=1)
        self.expected = (1, [('synthetic', 1, [(1, 1, 1, len(TOKEN))])])

    def test_clean_primary_does_not_run_secondary(self):
        with patch.object(d, 'run_scanner', return_value=(0, b'[]')) as run:
            self.assertIsNone(d.scan(self.scanner, self.encoded, self.root))
        self.assertEqual(1, run.call_count)
        self.assertEqual({}, run.call_args.kwargs)

    def test_primary_failure_does_not_run_secondary_or_suppress_failure(self):
        for failure in (Refusal('redaction_scanner_unavailable'), OSError('missing scanner')):
            with patch.object(d, 'run_scanner', side_effect=failure) as run:
                with self.assertRaises(type(failure)):
                    d.scan(self.scanner, self.encoded, self.root)
            self.assertEqual(1, run.call_count)
        for invalid in ((1, b'bad'), (1, b'[]'), (0, self.primary), (2, b'[]')):
            with patch.object(d, 'run_scanner', return_value=invalid) as run:
                with self.assertRaises(Refusal):
                    d.scan(self.scanner, self.encoded, self.root)
            self.assertEqual(1, run.call_count)

    def test_secondary_invalid_clean_counts_rules_and_exceptions_preserve_primary(self):
        twice = json.dumps(json.loads(report(TOKEN)) * 2).encode()
        cases = [(0, b'[]'), (1, b'malformed-PRIVATE-DIAGNOSTIC'), (1, twice),
                 (1, report(TOKEN, RuleID='other-rule')), (2, b'[]'),
                 (1, report(TOKEN, StartColumn=0)), (1, b'[]'),
                 (1, b'x' * (d.MAX_REPORT + 1)),
                 ValueError('PRIVATE-DIAGNOSTIC'), OSError('PRIVATE-DIAGNOSTIC'),
                 subprocess.TimeoutExpired('PRIVATE-DIAGNOSTIC', 0),
                 Refusal('redaction_scanner_unavailable')]
        capture = Capture(self.root, self.scanner, lambda: True)
        for i, secondary in enumerate(cases):
            with self.subTest(case=i), patch.object(d, 'run_scanner', side_effect=[(1, self.primary), secondary]) as run:
                cleaned, flags = capture.safe(self.value)
            summary = cleaned['scanner_diagnostics']
            self.assertEqual(self.expected, authority(summary))
            self.assertEqual(['gitleaks'], flags)
            self.assertEqual('gitleaks-match', cleaned['redacted_body'])
            self.assertEqual(2, run.call_count)
            self.assertTrue(run.call_args.kwargs['diagnostic'])
            self.assertEqual('unknown', rows(summary)[0]['field_path'])
            self.assertTrue(rows(summary)[0]['attribution_reason'].startswith('secondary_'))
            self.assertNotIn('PRIVATE-DIAGNOSTIC', json.dumps(cleaned))
            self.assertNotIn(TOKEN, json.dumps(cleaned))
            self.assertNotIn('field_evidence', summary['rules'][0])

    def test_same_input_redacted_primary_before_optional_raw_pass(self):
        popen = subprocess.Popen
        commands = []
        def launch(argv, *args, **kwargs):
            commands.append(list(argv))
            return popen(argv, *args, **kwargs)
        with patch.object(d.subprocess, 'Popen', launch):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(2, len(commands))
        self.assertIn('--redact', commands[0])
        self.assertIn('--redact=0', commands[1])
        self.assertEqual('unknown', rows(summary)[0]['field_class'])
        self.assertEqual('request_content', evidence(summary)[0]['field_class'])
        self.assertEqual('secondary_evidence_unlinked', rows(summary)[0]['attribution_reason'])

    def test_real_redacted_fits_raw_oversize_keeps_detection(self):
        # Actual scanner bytes remain local, never printed or saved.
        status, primary = d.run_scanner(self.scanner, self.encoded, self.root)
        raw_status, diagnostic = d.run_scanner(self.scanner, self.encoded, self.root, diagnostic=True)
        self.assertEqual((1, 1), (status, raw_status))
        self.assertLess(len(primary), len(diagnostic))
        cap = len(primary)
        expected = authority(d.project(status, primary))
        primary = diagnostic = None
        with patch.object(d, 'MAX_REPORT', cap):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(expected, authority(summary))
        self.assertEqual('unknown', rows(summary)[0]['field_class'])
        self.assertEqual('secondary_unavailable', rows(summary)[0]['attribution_reason'])

    def test_real_secondary_timeout_does_not_refuse_primary_detection(self):
        original = d.run_scanner
        calls = []
        def run(*args, **kwargs):
            calls.append(kwargs)
            if kwargs.get('diagnostic'):
                with patch.object(d, 'TIMEOUT', 0):
                    return original(*args, **kwargs)
            return original(*args, **kwargs)
        with patch.object(d, 'run_scanner', run):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(2, len(calls))
        self.assertEqual(1, summary['finding_count'])
        self.assertEqual('secondary_unavailable', rows(summary)[0]['attribution_reason'])

    def test_same_rule_count_different_valid_field_sets_never_link_primary(self):
        other = 'gh' + 'p_' + 'fedcba9876543210' * 2 + 'dcba'
        encoded = encode({'request': {'instructions': TOKEN},
                          'reconstructed': {'response': {'output': [
                              {'type': 'reasoning', 'encrypted_content': other}]}}})
        # Both matches are valid in the SAME input, but different fragment splits
        # can select different surviving finding sets, not merely permute a set.
        for primary_match, secondary_match, primary_class, secondary_class in (
                (TOKEN, other, 'request_content', 'encrypted_reasoning'),
                (other, TOKEN, 'encrypted_reasoning', 'request_content')):
            with self.subTest(primary_class=primary_class):
                primary_start = encoded.index(primary_match.encode()) + 1
                primary_raw = report(primary_match, StartColumn=primary_start,
                                     EndColumn=primary_start + len(primary_match) - 1)
                secondary_raw = report(secondary_match)
                direct_primary = d.project(1, primary_raw, encoded)
                direct_secondary = d.project(1, secondary_raw, encoded)
                self.assertEqual(primary_class, rows(direct_primary)[0]['field_class'])
                self.assertEqual(secondary_class, rows(direct_secondary)[0]['field_class'])
                # Mock the actual redacted primary wire and separate raw diagnostic.
                primary = report('REDACTED', StartColumn=primary_start,
                                 EndColumn=primary_start + len(primary_match) - 1)
                with patch.object(d, 'run_scanner', side_effect=[
                        (1, primary), (1, secondary_raw)]):
                    summary = d.scan(self.scanner, encoded, self.root)
                self.assertEqual(authority(direct_primary), authority(summary))
                loc = rows(summary)[0]
                self.assertEqual('unknown', loc['field_path'])
                self.assertEqual('unknown', loc['field_class'])
                self.assertEqual('secondary_evidence_unlinked', loc['attribution_reason'])
                self.assertEqual([dict(field_path=rows(direct_secondary)[0]['field_path'],
                                       field_class=secondary_class,
                                       attribution_reason='exact_all_occurrences')],
                                 summary['rules'][0]['field_evidence'])
                self.assertNotIn(primary_match, json.dumps(summary))
                self.assertNotIn(secondary_match, json.dumps(summary))

    def test_mixed_fields_never_zip_even_equal_coordinates_and_reordered_reports(self):
        other = 'gh' + 'p_' + 'fedcba9876543210' * 2 + 'dcba'
        encoded = encode({'request': {'instructions': TOKEN},
                          'reconstructed': {'response': {'output': [
                              {'type': 'reasoning', 'encrypted_content': other}]}}})
        primary = json.dumps(json.loads(self.primary) * 2).encode()
        diagnostic = json.loads(report(other)) + json.loads(report(TOKEN))
        for ordered in (diagnostic, diagnostic[::-1]):
            with patch.object(d, 'run_scanner', side_effect=[(1, primary), (1, json.dumps(ordered).encode())]):
                summary = d.scan(self.scanner, encoded, self.root)
            self.assertEqual(authority(d.project(1, primary)), authority(summary))
            self.assertTrue(all(loc['field_class'] == 'unknown' for loc in rows(summary)))
            self.assertTrue(all(loc['attribution_reason'] == 'secondary_evidence_unlinked' for loc in rows(summary)))
            evidence = summary['rules'][0]['field_evidence']
            self.assertEqual({'request_content', 'encrypted_reasoning'}, {e['field_class'] for e in evidence})
            self.assertTrue(all(set(e) == {'field_path', 'field_class', 'attribution_reason'} for e in evidence))

    def test_real_mixed_fields_with_small_pipe_have_only_rule_level_evidence(self):
        other = 'gh' + 'p_' + 'fedcba9876543210' * 2 + 'dcba'
        encoded = encode({'reconstructed': {'response': {'output': [
            {'type': 'reasoning', 'encrypted_content': TOKEN},
            {'type': 'message', 'content': [{'type': 'output_text', 'text': ' '*60000 + other}]}]}}})
        popen = subprocess.Popen
        def small(*args, **kwargs):
            return popen(*args, pipesize=4096, **kwargs)
        with patch.object(d.subprocess, 'Popen', small):
            summary = d.scan(self.scanner, encoded, self.root)
        self.assertEqual(2, summary['finding_count'])
        self.assertTrue(all(loc['field_class'] == 'unknown' for loc in rows(summary)))
        self.assertEqual({'encrypted_reasoning', 'output_text'},
                         {e['field_class'] for e in summary['rules'][0]['field_evidence']})
        self.assertNotIn(TOKEN, json.dumps(summary))
        self.assertNotIn(other, json.dumps(summary))

    def test_default_four_megabyte_cap_on_real_child_pipe_preserves_primary(self):
        # Synthetic scanner protocol double, not a real gitleaks detection.
        # The raw diagnostic is GENERATED into its pipe, never saved as a file.
        import sys
        script = self.root / 'synthetic-scanner'
        script.write_text('#!' + sys.executable + '\n' +
            'import json, sys\n'
            'sys.stdin.buffer.read()\n'
            'raw = "--redact=0" in sys.argv\n'
            'match = "X" * 4000000 if raw else "REDACTED"\n'
            'row = dict(RuleID="synthetic", Tags=[], StartLine=1, EndLine=1, '
            'StartColumn=1, EndColumn=4000000, Match=match)\n'
            'sys.stdout.write(json.dumps([row]))\n'
            'sys.stdout.flush()\n'
            'sys.exit(1)\n')
        script.chmod(0o700)
        self.assertEqual(4_000_000, d.MAX_REPORT)
        summary = d.scan(str(script), self.encoded, self.root)
        self.assertEqual((1, [('synthetic', 1, [(1, 1, 1, 4000000)])]), authority(summary))
        self.assertEqual('secondary_unavailable', rows(summary)[0]['attribution_reason'])
        self.assertEqual('unknown', rows(summary)[0]['field_class'])

    def test_per_rule_count_mismatch_with_identical_totals_discards_secondary(self):
        one, two = json.loads(self.primary), json.loads(report('REDACTED', RuleID='other'))
        primary = json.dumps(one + two + two).encode()
        secondary = json.dumps(one + one + two).encode()
        with patch.object(d, 'run_scanner', side_effect=[(1, primary), (1, secondary)]):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(authority(d.project(1, primary)), authority(summary))
        self.assertTrue(all(loc['attribution_reason'] == 'secondary_mismatch' for loc in rows(summary)))
        self.assertTrue(all('field_evidence' not in rule for rule in summary['rules']))

    def test_same_encoded_bytes_and_root_passed_to_both_runs(self):
        with patch.object(d, 'run_scanner', side_effect=[(1, self.primary), (1, report(TOKEN))]) as run:
            d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(2, run.call_count)
        for call in run.call_args_list:
            self.assertEqual((self.scanner, self.encoded, self.root), call.args)
            self.assertIs(self.encoded, call.args[1])

    def test_unexpected_enrichment_exception_leaves_primary_untouched(self):
        with patch.object(d, 'run_scanner', return_value=(1, self.primary)) as run, patch.object(
                d, '_enrich', side_effect=RuntimeError('PRIVATE-ENRICHMENT-CANARY')):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(1, run.call_count)
        self.assertEqual(self.expected, authority(summary))
        self.assertEqual('unknown', rows(summary)[0]['field_class'])
        self.assertEqual('secondary_unavailable', rows(summary)[0]['attribution_reason'])
        self.assertNotIn('PRIVATE-ENRICHMENT-CANARY', json.dumps(summary))

    def test_secondary_coordinates_never_replace_primary_coordinates(self):
        with patch.object(d, 'run_scanner', side_effect=[(1, self.primary),
                (1, report(TOKEN, StartColumn=900, EndColumn=899 + len(TOKEN))) ]):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual(self.expected, authority(summary))
        self.assertEqual('unknown', rows(summary)[0]['field_class'])
        self.assertEqual('request_content', evidence(summary)[0]['field_class'])

    def test_partial_evidence_and_primary_tags_cannot_become_individual_claims(self):
        secondary = json.dumps(json.loads(report(TOKEN)) + json.loads(report(None))).encode()
        primary = json.dumps(json.loads(self.primary) * 2).encode()
        with patch.object(d, 'run_scanner', side_effect=[(1, primary), (1, secondary)]):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertTrue(all(loc['field_class'] == 'unknown' for loc in rows(summary)))
        self.assertIn('request_content', {e['field_class'] for e in summary['rules'][0]['field_evidence']})
        with patch.object(d, 'run_scanner', side_effect=[
                (1, report('REDACTED', Tags=['decoded:base64'])), (1, report(TOKEN))]):
            summary = d.scan(self.scanner, self.encoded, self.root)
        self.assertEqual('unknown', rows(summary)[0]['field_class'])
        self.assertEqual('primary_unsupported_tags', rows(summary)[0]['attribution_reason'])

    def test_secondary_failure_persistence_and_no_output(self):
        import io
        output = io.StringIO()
        capture = Capture(self.root, self.scanner, lambda: True)
        with patch('sys.stdout', output), patch('sys.stderr', output), patch.object(d, 'run_scanner',
                side_effect=[(1, self.primary), ValueError('PRIVATE-FAILURE-CANARY')]):
            row = capture.append('aux-failure', 'response', self.value)
        text = (self.root / 'aux-failure.jsonl').read_text()
        self.assertEqual('', output.getvalue())
        self.assertNotIn('PRIVATE-FAILURE-CANARY', text)
        self.assertNotIn(TOKEN, text)
        self.assertEqual(['secret'], row['flags'])
        self.assertEqual(self.expected, authority(row['data']['scanner_diagnostics']))


if __name__ == '__main__':
    unittest.main()
