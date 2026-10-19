"""Narrow operator-approved response cache UUID policy; no content exemptions.

Transport supplies the sent UUID out of band, never from request JSON. Original
credential-format findings veto the policy. Complete-Match all-occurrence proof
and a second full scan with only admitted UUID value bytes masked are both
required; diagnostic field coverage is never used as authority.
"""
import json
import uuid

from .protocol import classify_response
from .scanner_attribution import build_spans
from .scanner_diagnostics import scan, run_scanner, project


def canonical(value):
    if type(value) is not str or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def scan_response(scanner, encoded, root, sent_uuid):
    original = scan(scanner, encoded, root)
    if original is None or not canonical(sent_uuid):
        return original
    # Every detector, including credential-format detectors, sees original bytes.
    if any(r['rule_id'] != 'generic-api-key' for r in original['rules']):
        return original
    raw = None
    try:
        value = json.loads(encoded)
        if type(value.get('status')) is not int or value['status'] != 200:
            return original
        parsed, classification = classify_response(value['status'], value['classification']['content_type'], value['body'])
        if (not parsed.get('complete') or parsed != value['reconstructed']
                or classification != value['classification']):
            return original
        spans = []
        for left, right, start, end, path, cls in build_spans(encoded, coverage_only=True):
            if cls == 'response_metadata' and path in {
                    'reconstructed.response.prompt_cache_key',
                    'reconstructed.events[].response.prompt_cache_key',
                    'body.sse[].response.prompt_cache_key'}:
                value = encoded[start:end].decode('ascii')
                # Equal is the broker-owned value; a different canonical UUID is
                # the explicitly approved response-context fallback. Never decode
                # or normalize a noncanonical spelling into admission.
                if canonical(value):
                    spans.append((left, right, start, end))
        if not spans:
            return original
        status, raw = run_scanner(scanner, encoded, root, diagnostic=True)
        validated = project(status, raw, encoded, content=False)
        if validated is None or any(r['rule_id'] != 'generic-api-key' for r in validated['rules']):
            return original
        findings = json.loads(raw)
        budget = 64_000_000
        occurrences = 4096
        for finding in findings:
            match = finding.get('Match')
            if (finding.get('Tags') != [] or type(match) is not str or not match
                    or not match.isascii()):
                return original
            needle = match.encode('ascii')
            cursor, found = 0, False
            while True:
                budget -= len(encoded) - cursor + len(needle)
                if budget < 0:
                    return original
                start = encoded.find(needle, cursor)
                if start < 0:
                    break
                occurrences -= 1
                if occurrences < 0:
                    return original
                end = start + len(needle)
                if not any(left <= start < end <= right and start < ve and end > vs
                           for left, right, vs, ve in spans):
                    return original
                found, cursor = True, start + 1
            if not found:
                return original
        masked = bytearray(encoded)
        for _, _, start, end in spans:
            masked[start:end] = b'0' * (end - start)
        # This independent full scan closes missing/fragment-dependent generic
        # evidence: any remaining content detection retains the original refusal.
        if scan(scanner, bytes(masked), root) is not None:
            return original
        return None
    except Exception:
        return original
    finally:
        raw = encoded = None
