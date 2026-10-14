"""Provider transport with fail-closed capture; worker admission is separate."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import urllib.error
import urllib.request
import uuid

from .auth import HTTP, bounded_body
from .protocol import Refusal, adapt, classify_response
from .scanner_diagnostics import scan


class Capture:
    """Append-only broker-owned JSONL; deployment supplies orchestrator/proxy health."""
    def __init__(self, directory, scanner, capture_health):
        self.root = Path(directory)
        self.root.mkdir(mode=0o750, parents=True, exist_ok=True)
        s = self.root.lstat()
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o027):
            raise Refusal('capture_unavailable')
        self.root_identity = (s.st_dev, s.st_ino)
        self.scanner = scanner
        self.capture_health = capture_health
        self.lock = threading.Lock()
        self.secrets = set()

    def remember_secrets(self, values):
        with self.lock:
            self.secrets.update(v for v in values if isinstance(v, str) and v)

    def safe(self, value):
        # Header dictionaries are never passed by the transport. Explicit credential
        # fields are removed even if a detector would miss their particular format.
        redactions = []
        with self.lock:
            known = sorted(self.secrets, key=len, reverse=True)
        def clean(obj):
            if isinstance(obj, dict):
                result = {}
                for k, v in obj.items():
                    if k.lower() in {'authorization', 'proxy-authorization', 'access_token', 'refresh_token', 'id_token', 'api_key', 'password', 'client_secret'}:
                        result[k] = '[REDACTED]'; redactions.append('credential-field')
                    else:
                        result[clean(k)] = clean(v)
                return result
            if isinstance(obj, list):
                return [clean(v) for v in obj]
            if isinstance(obj, str):
                for secret in known:
                    if secret in obj:
                        obj = obj.replace(secret, "[REDACTED]")
                        redactions.append("known-credential")
                value, count = re.subn(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', obj)
                if count:
                    redactions.append('bearer-value')
                return value
            return obj
        cleaned = clean(value)
        encoded = json.dumps(cleaned, ensure_ascii=True).encode()
        diagnostics = scan(self.scanner, encoded, self.root)
        if diagnostics is not None:
            # Never put a detected secret in an artifact, including a scanner report.
            cleaned = {'redacted_body': 'gitleaks-match', 'scanner_diagnostics': diagnostics}
            redactions.append('gitleaks')
        return cleaned, redactions

    def append(self, run_id, kind, value):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', run_id):
            raise Refusal('invalid_run_id')
        # Readiness is scoped by composition: broker-only fixed admin acceptance
        # is not worker admission. Worker traffic requires all three sources.
        if self.capture_health() is not True:
            raise Refusal('capture_unavailable')
        cleaned, redactions = self.safe(value)
        row = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'run_id': run_id, 'kind': kind, 'data': cleaned,
               'flags': ['secret'] if redactions else [], 'redactions': redactions}
        line = (json.dumps(row, separators=(',', ':')) + '\n').encode()
        with self.lock:
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                s = os.fstat(directory)
                if ((s.st_dev, s.st_ino) != self.root_identity or s.st_uid != os.geteuid()
                        or s.st_mode & 0o027):
                    raise Refusal('capture_unavailable')
                fd = os.open(run_id + '.jsonl', os.O_APPEND | os.O_CREAT | os.O_WRONLY
                             | os.O_NOFOLLOW | os.O_NONBLOCK, 0o640, dir_fd=directory)
                try:
                    s = os.fstat(fd)
                    if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid()
                            or s.st_nlink != 1 or s.st_mode & 0o027):
                        raise Refusal('capture_unavailable')
                    with os.fdopen(fd, 'ab', closefd=False) as f:
                        f.write(line); f.flush(); os.fsync(fd)
                    # A newly created run must survive a directory replay too.
                    os.fsync(directory)
                finally:
                    os.close(fd)
            finally:
                os.close(directory)
        return row


class Transport:
    """No API-key argument, backend-api route, retries or model fallback."""
    def __init__(self, auth, keys, capture, on_limit, opener=HTTP):
        self.auth, self.keys, self.capture, self.on_limit, self.opener = auth, keys, capture, on_limit, opener

    def access(self):
        token = self.auth.access()
        values = self.auth.token_values() if hasattr(self.auth, "token_values") else {token}
        self.capture.remember_secrets(values | {token})
        return token

    def models(self, run_id):
        self.capture.append(run_id, 'models.request', {'endpoint': 'https://api.openai.com/v1/models'})
        request = urllib.request.Request('https://api.openai.com/v1/models', headers={'Authorization': 'Bearer ' + self.access()})
        try:
            with self.opener.open(request, timeout=60) as response:
                body = bounded_body(response, 8_000_000, 60)
                data = json.loads(body)
        except Exception:
            self.capture.append(run_id, 'models.failed', {'error': 'provider_request_failed'})
            raise Refusal('provider_request_failed') from None
        self.capture.append(run_id, 'models.response', data)
        if not isinstance(data.get('models'), list):
            raise Refusal('unexpected_model_catalog')
        return data

    def responses(self, run_key, request, emit):
        try:
            admission = self.keys.admit(run_key, request)
        except Refusal as error:
            run = self.keys.run_for_key(run_key) or "denied-" + uuid.uuid4().hex
            self.capture.append(run, "request.refused", {"error": str(error)})
            raise
        run = admission['run_id']
        call_id = str(uuid.uuid4())
        self.capture.append(run, 'request.received', {'call_id': call_id, 'request': request, 'admission': admission})
        payload, changes = adapt(request)
        self.capture.append(run, 'request.upstream', {'call_id': call_id, 'request': payload, 'adaptations': changes})
        upstream = urllib.request.Request('https://api.openai.com/v1/responses', data=json.dumps(payload).encode(),
            headers={'Authorization': 'Bearer ' + self.access(), 'Content-Type': 'application/json', 'Accept': 'text/event-stream'})
        deadline = time.monotonic() + 120
        chunks = []
        size = 0
        status = None
        content_type = None
        try:
            try:
                response = self.opener.open(upstream, timeout=120)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.status
                content_type = response.headers.get('Content-Type')
                while True:
                    if time.monotonic() >= deadline:
                        raise Refusal('provider_deadline')
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 64_000_000:
                        raise Refusal('response_capture_limit')
                    chunks.append(chunk)
            body = b''.join(chunks)
            text = body.decode('utf-8')
            reconstructed, classification = classify_response(status, content_type, text)
            self.capture.append(run, 'response', {'call_id': call_id, 'status': status,
                'body': text, 'reconstructed': reconstructed, 'bytes': size,
                'classification': classification})
            if status == 429 or any(s in text for s in ['subscription_sharing_usage_limit_exceeded', 'subscription_sharing_usage_unavailable']):
                self.on_limit(run, {'call_id': call_id, 'status': status})
            # Buffer through the terminal event so redaction sees secrets split over
            # SSE chunks. The consumer receives the unmodified provider SSE bytes.
            emit(status, content_type if content_type is not None else 'application/octet-stream', body)
            return reconstructed
        except Exception:
            self.capture.append(run, 'response.interrupted', {'call_id': call_id, 'status': status,
                'body': b''.join(chunks).decode('utf-8', errors='replace'), 'bytes': size,
                'classification': {'version': 1, 'content_type': content_type, 'decision': 'interrupted'}})
            raise Refusal('provider_or_capture_failure') from None
