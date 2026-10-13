"""Provider transport with fail-closed capture. Not enabled by the setup server."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import urllib.error
import urllib.request
import uuid

from .auth import HTTP
from .protocol import Refusal, adapt, reconstruct_sse


class Capture:
    """Append-only broker-owned JSONL; deployment supplies orchestrator/proxy health."""
    def __init__(self, directory, scanner, capture_health):
        self.root = Path(directory)
        self.root.mkdir(mode=0o750, parents=True, exist_ok=True)
        self.scanner = scanner
        self.capture_health = capture_health
        self.lock = threading.Lock()

    def safe(self, value):
        # Header dictionaries are never passed by the transport. Explicit credential
        # fields are removed even if a detector would miss their particular format.
        redactions = []
        def clean(obj):
            if isinstance(obj, dict):
                result = {}
                for k, v in obj.items():
                    if k.lower() in {'authorization', 'proxy-authorization', 'access_token', 'refresh_token', 'id_token', 'api_key', 'password', 'client_secret'}:
                        result[k] = '[REDACTED]'; redactions.append('credential-field')
                    else:
                        result[k] = clean(v)
                return result
            if isinstance(obj, list):
                return [clean(v) for v in obj]
            if isinstance(obj, str):
                value, count = re.subn(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', obj)
                if count:
                    redactions.append('bearer-value')
                return value
            return obj
        cleaned = clean(value)
        encoded = json.dumps(cleaned, ensure_ascii=True).encode()
        result = subprocess.run([self.scanner, 'stdin', '--redact', '--no-banner', '--log-level', 'error'],
                                input=encoded, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root)})
        if result.returncode == 1:
            # Never put a detected secret in an artifact, including a scanner report.
            cleaned = {'redacted_body': 'gitleaks-match'}
            redactions.append('gitleaks')
        elif result.returncode != 0:
            raise Refusal('redaction_scanner_unavailable')
        return cleaned, redactions

    def append(self, run_id, kind, value):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', run_id):
            raise Refusal('invalid_run_id')
        # No stubs or existence-only readiness: the deployment callback must test
        # all three live capture sources. Failure propagates before model dispatch.
        if self.capture_health() is not True:
            raise Refusal('capture_unavailable')
        cleaned, redactions = self.safe(value)
        row = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'run_id': run_id, 'kind': kind, 'data': cleaned,
               'flags': ['secret'] if redactions else [], 'redactions': redactions}
        line = (json.dumps(row, separators=(',', ':')) + '\n').encode()
        with self.lock:
            fd = os.open(self.root / (run_id + '.jsonl'), os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
            try:
                with os.fdopen(fd, 'ab', closefd=False) as f:
                    f.write(line); f.flush(); os.fsync(fd)
            finally:
                os.close(fd)
        return row


class Transport:
    """No API-key argument, backend-api route, retries or model fallback."""
    def __init__(self, auth, keys, capture, on_limit, opener=HTTP):
        self.auth, self.keys, self.capture, self.on_limit, self.opener = auth, keys, capture, on_limit, opener

    def models(self, run_id):
        self.capture.append(run_id, 'models.request', {'endpoint': 'https://api.openai.com/v1/models'})
        request = urllib.request.Request('https://api.openai.com/v1/models', headers={'Authorization': 'Bearer ' + self.auth.access()})
        try:
            with self.opener.open(request, timeout=60) as response:
                body = response.read(8_000_001)
                if len(body) > 8_000_000:
                    raise Refusal('model_catalog_too_large')
                data = json.loads(body)
        except Exception:
            self.capture.append(run_id, 'models.failed', {'error': 'provider_request_failed'})
            raise Refusal('provider_request_failed') from None
        self.capture.append(run_id, 'models.response', data)
        if not isinstance(data.get('models'), list):
            raise Refusal('unexpected_model_catalog')
        return data

    def responses(self, run_key, request, emit):
        admission = self.keys.admit(run_key, request)
        run = admission['run_id']
        call_id = str(uuid.uuid4())
        self.capture.append(run, 'request.received', {'call_id': call_id, 'request': request, 'admission': admission})
        payload, changes = adapt(request)
        self.capture.append(run, 'request.upstream', {'call_id': call_id, 'request': payload, 'adaptations': changes})
        upstream = urllib.request.Request('https://api.openai.com/v1/responses', data=json.dumps(payload).encode(),
            headers={'Authorization': 'Bearer ' + self.auth.access(), 'Content-Type': 'application/json', 'Accept': 'text/event-stream'})
        chunks = []
        size = 0
        status = None
        try:
            try:
                response = self.opener.open(upstream, timeout=120)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.status
                while True:
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 64_000_000:
                        raise Refusal('response_capture_limit')
                    chunks.append(chunk)
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
            body = b''.join(chunks)
            text = body.decode('utf-8')
            reconstructed = reconstruct_sse(text) if 'text/event-stream' in content_type else {'complete': False, 'terminal': 'http-error'}
            self.capture.append(run, 'response', {'call_id': call_id, 'status': status,
                'body': text, 'reconstructed': reconstructed, 'bytes': size})
            if status == 429 or any(s in text for s in ['subscription_sharing_usage_limit_exceeded', 'subscription_sharing_usage_unavailable']):
                self.on_limit(run, {'call_id': call_id, 'status': status})
            # Buffer through the terminal event so redaction sees secrets split over
            # SSE chunks. The consumer receives the unmodified provider SSE bytes.
            emit(status, content_type, body)
            return reconstructed
        except Exception:
            self.capture.append(run, 'response.interrupted', {'call_id': call_id, 'status': status,
                'body': b''.join(chunks).decode('utf-8', errors='replace'), 'bytes': size})
            raise Refusal('provider_or_capture_failure') from None
