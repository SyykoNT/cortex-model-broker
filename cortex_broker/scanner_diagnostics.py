"""Secret-safe gitleaks metadata. Reports exist only in bounded pipes/memory.

Public scan/project results never contain report bytes, Secret, Match or values.
Only rule IDs, counts, numeric locations, sizes and static diagnostic labels escape.
"""
import json
import os
import re
import selectors
import subprocess
import time

from .protocol import Refusal
from .scanner_attribution import attribute

MAX_REPORT = 4_000_000
MAX_FINDINGS = 4096
TIMEOUT = 30
RULE = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
LOCATIONS = {'StartLine': 'start_line', 'EndLine': 'end_line',
             'StartColumn': 'start_column', 'EndColumn': 'end_column'}


def unavailable():
    raise Refusal('redaction_scanner_unavailable') from None


def run_scanner(scanner, encoded, root, *, diagnostic=False):
    # Primary retains the original redacted command and bounds. Only an optional
    # diagnostic pass disables report redaction. No file, shell or stderr capture.
    # Concurrent nonblocking input/output avoids large-input pipe deadlocks;
    # oversize/timeout kills and reaps before refusing. Missing executables retain
    # their existing OSError behavior at the trusted local boundary.
    process = subprocess.Popen([scanner, 'stdin', '--redact=0' if diagnostic else '--redact',
                                '--no-banner', '--log-level', 'error',
                                '--report-format', 'json', '--report-path', '-'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               cwd=root, env={'PATH': '/usr/bin:/bin', 'HOME': str(root)})
    report = bytearray()
    offset = 0
    result = None
    deadline = time.monotonic() + TIMEOUT
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    unavailable()
                ready = selector.select(remaining)
                if not ready:
                    unavailable()
                for key, _ in ready:
                    if key.fileobj is process.stdin:
                        try:
                            count = os.write(process.stdin.fileno(), encoded[offset:offset + 16384])
                            offset += count
                        except BrokenPipeError:
                            offset = len(encoded)
                        if offset == len(encoded):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), min(65536, MAX_REPORT + 1 - len(report)))
                        if not chunk:
                            selector.unregister(process.stdout)
                        else:
                            report.extend(chunk)
                            if len(report) > MAX_REPORT:
                                unavailable()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                unavailable()
            result = process.wait(timeout=remaining), bytes(report)
    except Exception:
        result = None
        try:
            process.kill()
            process.wait()
        except Exception:
            pass
    finally:
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except Exception:
                result = None
        report.clear()
        encoded = chunk = None
    # Raise outside the handler: the private exception may hold raw bytes.
    if result is None:
        unavailable()
    return result


def _project(status, raw, encoded, content):
    """Private transient parser; only an explicit public whitelist can escape."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def constant(_):
        raise ValueError()

    try:
        if type(status) is not int or status not in (0, 1) or not 0 < len(raw) <= MAX_REPORT:
            unavailable()
        report = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        if type(report) is not list or len(report) > MAX_FINDINGS:
            unavailable()
        if status == 0:
            if report:
                unavailable()
            return None
        if not report:
            unavailable()
        rules = {}
        transient = []
        for finding in report:
            if type(finding) is not dict:
                unavailable()
            rule = finding['RuleID']
            if type(rule) is not str or RULE.fullmatch(rule) is None:
                unavailable()
            location = {}
            for source, target in LOCATIONS.items():
                number = finding[source]
                if type(number) is not int or not 1 <= number <= 2**63 - 1:
                    unavailable()
                location[target] = number
            if (location['end_line'] < location['start_line'] or
                    (location['end_line'] == location['start_line'] and
                     location['end_column'] < location['start_column'])):
                unavailable()
            rules.setdefault(rule, []).append(location)
            # Raw evidence is separate from public locations, never merged into
            # the summary. Only the complete Match is used (never Secret).
            if content:
                transient.append((location, finding.get('Match'), finding.get('Tags') == []))
            else:
                location.update(field_path='unknown', field_class='unknown',
                                coordinate_space='scanner_local', attribution_reason=(
                                    'secondary_not_run' if finding.get('Tags') == []
                                    else 'primary_unsupported_tags'))
        summary = {'version': 4, 'finding_count': len(report), 'rules': [
            {'rule_id': rule, 'count': len(locations), 'locations': locations}
            for rule, locations in sorted(rules.items())]}
        # Discard every other raw finding field before content verification.
        del finding, report
        if not content:
            summary['encoded_byte_count'] = len(encoded) if type(encoded) is bytes else None
            return summary
        try:
            attribute(summary, encoded, transient)
        except Exception:
            # Metadata-only failure must not change the already detected result.
            summary['encoded_byte_count'] = len(encoded) if type(encoded) is bytes else None
            for location, _, _ in transient:
                location.update(field_path='unknown', field_class='unknown',
                                coordinate_space='scanner_local', attribution_reason='attribution_failure')
        transient.clear()
        return summary
    except Exception:
        # No private exception, raw report, decoded JSON, or traceback escapes.
        # In particular JSONDecodeError.doc must not become Refusal.__context__.
        return False


def project(status, raw, encoded=None, *, content=True):
    """Public projection boundary; failure messages contain no raw content."""
    result = _project(status, raw, encoded, content)
    raw = encoded = None
    if result is False:
        unavailable()
    return result


def _secondary(scanner, encoded, root):
    """Optional private boundary: exceptions and raw report never escape."""
    raw = None
    try:
        status, raw = run_scanner(scanner, encoded, root, diagnostic=True)
        result = _project(status, raw, encoded, True)
        if result is False:
            return None, 'secondary_invalid_report'
        if result is None:
            return None, 'secondary_clean'
        return result, None
    except Exception:
        return None, 'secondary_unavailable'
    finally:
        raw = encoded = None


def _enrich(primary, scanner, encoded, root):
    """Compute detached diagnostic annotations; never pair report locations.

    Count/rule agreement is only an admission check, NOT an identity join.
    Fragment splits can change which findings survive, even with equal counts
    and uniform secondary labels. Evidence never labels a primary location.
    """
    import copy
    result = copy.deepcopy(primary)
    secondary, reason = _secondary(scanner, encoded, root)
    if secondary is not None:
        signature = lambda summary: (summary['finding_count'], [
            (r['rule_id'], r['count']) for r in summary['rules']])
        if signature(primary) != signature(secondary):
            reason = 'secondary_mismatch'
            secondary = None
    if secondary is None:
        for rule in result['rules']:
            for loc in rule['locations']:
                loc['attribution_reason'] = reason
        return result
    evidence_by_rule = {r['rule_id']: r for r in secondary['rules']}
    for rule in result['rules']:
        evidence = sorted({(loc['field_path'], loc['field_class'], loc['attribution_reason'])
                           for loc in evidence_by_rule[rule['rule_id']]['locations']})
        rule['field_evidence'] = [dict(field_path=path, field_class=cls, attribution_reason=why)
                                  for path, cls, why in evidence]
        for loc in rule['locations']:
            if loc['attribution_reason'] != 'primary_unsupported_tags':
                loc['attribution_reason'] = 'secondary_evidence_unlinked'
    return result


def _optional(primary, scanner, encoded, root):
    # Even unexpected aggregation failures cannot partially mutate authority.
    try:
        return _enrich(primary, scanner, encoded, root)
    except Exception:
        for rule in primary['rules']:
            for loc in rule['locations']:
                loc['attribution_reason'] = 'secondary_unavailable'
        return primary


def scan(scanner, encoded, root):
    report = None
    try:
        # No optional code runs until the unchanged primary command/report is
        # validated. Clean returns immediately; ordinary failures still escape.
        status, report = run_scanner(scanner, encoded, root)
        primary = project(status, report, encoded, content=False)
        report = None
        if primary is None:
            return None
        return _optional(primary, scanner, encoded, root)
    finally:
        # Avoid retaining raw report/input in an escaping exception's frame.
        report = encoded = None
