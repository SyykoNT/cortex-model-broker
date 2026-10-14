"""Secret-safe gitleaks metadata. Reports exist only in bounded pipes/memory.

Never return/print/persist report bytes, Secret, Match, context or value fields.
Only scanner rule IDs, counts, numeric locations and static schema labels escape.
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


def run_scanner(scanner, encoded, root):
    # No report file, shell, inherited config environment, or captured stderr.
    # Concurrent nonblocking input/output avoids large-input pipe deadlocks;
    # oversize/timeout kills and reaps before refusing. Missing executables retain
    # their existing OSError behavior at the trusted local boundary.
    process = subprocess.Popen([scanner, 'stdin', '--redact', '--no-banner', '--log-level', 'error',
                                '--report-format', 'json', '--report-path', '-'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               cwd=root, env={'PATH': '/usr/bin:/bin', 'HOME': str(root)})
    report = bytearray()
    offset = 0
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
            return process.wait(timeout=remaining), bytes(report)
    except Exception:
        process.kill()
        process.wait()
        unavailable()
    finally:
        process.stdin.close()
        process.stdout.close()


def project(status, raw, encoded=None):
    """Drop all unapproved fields before returning; malformed reports fail closed."""
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
        unsupported = []
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
            # Decoded findings and future/unknown report tags are not proven
            # direct scanner-input spans. Never copy tag strings into metadata.
            if finding.get('Tags') != []:
                unsupported.append(location)
        summary = {'version': 2, 'finding_count': len(report), 'rules': [
            {'rule_id': rule, 'count': len(locations), 'locations': locations}
            for rule, locations in sorted(rules.items())]}
        # Attribution sees only projected numeric locations and the in-memory
        # scanner input. It never receives Secret/Match or the raw report.
        del report
        attribute(summary, encoded)
        for location in unsupported:
            location.update(field_path='unknown', field_class='unknown')
        return summary
    except Exception:
        unavailable()


def scan(scanner, encoded, root):
    status, report = run_scanner(scanner, encoded, root)
    return project(status, report, encoded)
