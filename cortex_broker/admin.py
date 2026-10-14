"""Linux-only, one-request admin protocol. Never expose this socket to workers."""
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
import time
import uuid

from .protocol import Refusal, classify_response, reconstruct_sse
from . import fc5

MAX_REQUEST = 16_384
MAX_RESPONSE = 65_536
IO_TIMEOUT = 3
RUN = re.compile(r'[A-Za-z0-9_-]{1,160}\Z')
MODEL = re.compile(r'[A-Za-z0-9_.-]{1,128}\Z')
PROMPT = 'Say exactly: Hello, world!'


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def protected_directory(path):
    # Reject symlinks and writable ancestors, not just the final directory.
    for item in (path, *path.parents):
        s = item.lstat()
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid not in {0, os.geteuid()}
                or s.st_mode & 0o022):
            raise Refusal('unsafe_admin_directory')
    if path.stat().st_uid != os.geteuid():
        raise Refusal('unsafe_admin_directory')


class AdminServer:
    """Serial bounded ingress; filesystem ACL AND kernel UID are mandatory.

    Parent must exist, be broker-owned, and not group/world writable. Never
    unlink an existing node: a stale socket requires explicit operator handling.
    """
    def __init__(self, path, allowed_uid, group_gid, controller):
        self.path = Path(path)
        if (not self.path.is_absolute() or '..' in self.path.parts
                or len(os.fsencode(self.path)) > 100
                or type(allowed_uid) is not int or allowed_uid < 0 or allowed_uid == 65534
                or type(group_gid) is not int or group_gid < 0 or group_gid == 65534):
            raise Refusal('invalid_admin_configuration')
        protected_directory(self.path.parent)
        self.allowed_uid, self.controller = allowed_uid, controller
        self.stopping = threading.Event()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.identity = None
        self.thread = None
        try:
            # Bind under a private temporary directory, then publish the already
            # restricted socket without clobbering any existing filesystem node.
            import tempfile
            with tempfile.TemporaryDirectory(prefix='.admin-', dir=self.path.parent) as temporary:
                node = Path(temporary) / 'socket'
                self.socket.bind(str(node))
                os.chown(node, os.geteuid(), group_gid)
                os.chmod(node, 0o660)
                self.socket.listen(8)
                os.link(node, self.path, follow_symlinks=False)
                s = self.path.lstat()
                self.identity = (s.st_dev, s.st_ino)
            self.socket.settimeout(0.2)
        except Exception:
            self.socket.close()
            self._unlink_owned()
            raise

    def start(self):
        self.thread = threading.Thread(target=self.serve, name='broker-admin', daemon=True)
        self.thread.start()
        return self

    def serve(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                self.handle(connection)

    def handle(self, connection):
        result = {'ok': False, 'error': 'invalid_request'}
        try:
            if peer_uid(connection) != self.allowed_uid:
                raise Refusal('peer_not_allowed')
            # A JSON line followed by write-half EOF, no pipelining. The absolute
            # deadline prevents a same-UID slow-drip client pinning this listener.
            deadline = time.monotonic() + IO_TIMEOUT
            raw = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refusal('request_timeout')
                connection.settimeout(remaining)
                chunk = connection.recv(min(4096, MAX_REQUEST + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > MAX_REQUEST:
                    raise Refusal('request_too_large')
            if not raw.endswith(b'\n') or b'\n' in raw[:-1]:
                raise Refusal('invalid_request')
            request = strict_json(raw.decode('utf-8'))
            result = {'ok': True, 'result': self.controller.dispatch(request)}
        except Refusal as error:
            # Only our enumerated codes cross this boundary, never exception text
            # from a provider, filesystem, subprocess or caller-supplied field.
            code = str(error)
            result = {'ok': False, 'error': code if code in SAFE_ERRORS else 'operation_failed'}
        except TimeoutError:
            result = {"ok": False, "error": "request_timeout"}
        except (ValueError, TypeError, UnicodeError, RecursionError):
            result = {'ok': False, 'error': 'invalid_request'}
        except Exception:
            result = {'ok': False, 'error': 'operation_failed'}
        try:
            encoded = (json.dumps(result, allow_nan=False, separators=(',', ':')) + '\n').encode()
            if len(encoded) > MAX_RESPONSE:
                encoded = b'{"ok":false,"error":"response_too_large"}\n'
            connection.settimeout(IO_TIMEOUT)
            connection.sendall(encoded)
        except Exception:
            pass

    def _unlink_owned(self):
        if self.identity:
            try:
                s = self.path.lstat()
                if (s.st_dev, s.st_ino) == self.identity:
                    self.path.unlink()
            except FileNotFoundError:
                pass

    def close(self):
        self.stopping.set()
        self.socket.close()
        if self.thread:
            self.thread.join(timeout=300)
            if self.thread.is_alive():
                raise Refusal("admin_shutdown_incomplete")
        self._unlink_owned()


SAFE_ERRORS = set('''invalid_request peer_not_allowed request_timeout request_too_large
response_too_large operation_failed capture_unavailable worker_admission_disabled
invalid_run_id unapproved_model_or_reasoning invalid_budget reconstruction_unavailable
inference_not_completed inference_model_mismatch inference_reasoning_mismatch usage_unavailable codex_unavailable
codex_timeout codex_protocol_error codex_rate_limits_unavailable tool_probe_invalid'''.split())


def validate_run(run):
    if not isinstance(run, str) or not RUN.fullmatch(run):
        raise Refusal('invalid_run_id')


def summary(reconstructed, model, effort):
    response = reconstructed.get('response')
    if (not reconstructed.get('complete') or reconstructed.get('terminal') != 'response.completed'
            or not isinstance(response, dict)):
        raise Refusal('inference_not_completed')
    if response.get('model') != model:
        raise Refusal('inference_model_mismatch')
    if 'reasoning' in response and (not isinstance(response['reasoning'], dict)
                                    or response['reasoning'].get('effort') != effort):
        raise Refusal('inference_reasoning_mismatch')
    usage = response.get('usage', {})
    if not isinstance(usage, dict) or any(type(usage.get(k)) is not int or usage[k] < 0
                                         for k in ('input_tokens', 'output_tokens')):
        raise Refusal('usage_unavailable')
    return {'complete': True, 'terminal': 'response.completed', 'model': model,
            'usage': {k: usage[k] for k in ('input_tokens', 'output_tokens')}}


class Controller:
    """Trusted composition, not configuration by the socket caller.

    No Transport means no operational capture readiness. No callback means no
    worker admission. Setup never supplies a true callback or a fake Transport.
    """
    def __init__(self, auth, keys, transport=None, worker_ready=None, codex=None):
        self.auth, self.keys, self.transport = auth, keys, transport
        self.worker_ready = worker_ready
        self.codex = codex

    def captured(self, run, kind, value):
        if self.transport is None:
            raise Refusal('capture_unavailable')
        return self.transport.capture.append(run, kind, value)

    def dispatch(self, request):
        # Cache old and newly rotated values for response/capture nonexposure.
        values = self.auth.token_values()
        if self.transport is not None:
            self.transport.capture.remember_secrets(values)
        result = self._dispatch(request)
        values |= self.auth.token_values()
        encoded = json.dumps(result, allow_nan=False)
        if any(value in encoded for value in values):
            raise Refusal("operation_failed")
        return result

    def _dispatch(self, request):
        schemas = {'status': set(), 'models': set(), 'refresh': set(), 'rate_limits': set(), 'tool_probe': set(),
                   'infer': {'model', 'reasoning'}, 'reconstruct': {'run_id'},
                   'mint': {'run_id', 'role', 'model', 'reasoning', 'expires_at', 'cap'},
                   'revoke': {'run_id'}}
        if (not isinstance(request, dict) or request.get('version') != 1
                or type(request.get('version')) is not int or not isinstance(request.get('command'), str)):
            raise Refusal('invalid_request')
        command = request['command']
        if command not in schemas or set(request) != {'version', 'command'} | schemas[command]:
            raise Refusal('invalid_request')
        if command == 'status':
            return {'mode': 'setup', 'worker_inference': False, 'session': self.auth.status()}
        if command == 'revoke':
            validate_run(request['run_id'])
            # Revocation must remain available even during capture outages.
            self.keys.revoke_run(request['run_id'])
            return {'revoked': True, 'run_id': request['run_id']}
        if command == 'mint':
            validate_run(request['run_id'])
            if (self.worker_ready is None or self.worker_ready() is not True):
                raise Refusal('worker_admission_disabled')
            if (type(request['expires_at']) not in (int, float) or not math.isfinite(request['expires_at'])
                    or type(request['cap']) is not int or not 1 <= request['cap'] <= 10000
                    or not all(isinstance(request[k], str) for k in ('role', 'model', 'reasoning'))):
                raise Refusal('invalid_budget')
            self.captured(request['run_id'], 'admin.mint', {k: v for k, v in request.items() if k not in {'version', 'command'}})
            key = self.keys.mint(**{k: request[k] for k in schemas[command]})
            # The sole capability response: a per-run key, never a provider token.
            return {'run_key': key, 'run_id': request['run_id']}
        if command == 'reconstruct':
            validate_run(request['run_id'])
            if self.transport is None:
                raise Refusal('capture_unavailable')
            return self.reconstruct(request['run_id'])
        if command == 'infer':
            if request['model'] != 'gpt-6.1-sol' or request['reasoning'] not in ('medium', 'high'):
                raise Refusal('unapproved_model_or_reasoning')
        run = 'admin-' + uuid.uuid4().hex
        self.captured(run, 'admin.' + command, {'command': command})
        if command == 'models':
            catalog = self.transport.models(run)
            # Never relay arbitrary provider fields or error bodies to an admin.
            models = [m['slug'] for m in catalog['models'] if isinstance(m, dict)
                      and isinstance(m.get('slug'), str) and MODEL.fullmatch(m['slug'])
                      and m.get('visibility') == 'list']
            return {'run_id': run, 'models': models}
        if command == 'refresh':
            self.auth.access(force_refresh=True)
            result = self.auth.status()
            self.captured(run, 'admin.refresh.completed', result)
            return {'run_id': run, 'session': result}
        if command == 'rate_limits':
            if self.codex is None:
                raise Refusal('codex_unavailable')
            result = self.codex.read(self.auth.access())
            self.captured(run, 'admin.rate_limits.completed', result)
            return {'run_id': run, 'rate_limits': result}
        if command == 'tool_probe':
            key = self.keys.mint(run, 'acceptance', fc5.MODEL, fc5.EFFORT, time.time() + 300, 2)
            try:
                def infer(payload):
                    delivered = []
                    result = self.transport.responses(key, payload, lambda status, mime, body: delivered.append(status))
                    if delivered != [200]:
                        raise Refusal('inference_not_completed')
                    return result

                first = fc5.first_request()
                response = infer(first)
                tool = fc5.tool_result(response, strict_json, summary)
                self.captured(run, 'tool.result', tool)
                # Refuse loss/redaction of the first response before followup.
                # The final replay below also verifies every retained byte/link.
                self.reconstruct(run, _tool_prefix=True)
                final = infer(fc5.next_request(first, response, tool))
                fc5.final_response(final, summary)
                self.captured(run, 'admin.tool_probe.completed', {'command': 'tool_probe', 'complete': True})
                return {'run_id': run, 'reasoning': fc5.EFFORT, 'reconstruction': self.reconstruct(run)}
            finally:
                self.keys.revoke_run(run)
        if command == 'infer':
            key = self.keys.mint(run, 'acceptance', request['model'], request['reasoning'], time.time() + 300, 1)
            try:
                payload = {'model': request['model'], 'reasoning': {'effort': request['reasoning']},
                           'input': [{'role': 'user', 'content': PROMPT}], 'store': False, 'stream': True}
                delivered = []
                result = self.transport.responses(key, payload, lambda status, mime, body: delivered.append((status, mime)))
                # Transport and retained replay validate SSE; MIME is a hint,
                # not an independent acceptance gate or a rewritten observation.
                if len(delivered) != 1 or delivered[0][0] != 200:
                    raise Refusal('inference_not_completed')
                return {'run_id': run, 'reasoning': request['reasoning'], **summary(result, request['model'], request['reasoning']),
                        'reconstruction': self.reconstruct(run)}
            finally:
                self.keys.revoke_run(run)
        raise Refusal('invalid_request')

    def reconstruct(self, run, *, _tool_prefix=False):
        """Re-read retained capture, not an in-memory successful response claim."""
        try:
            fd = os.open(self.transport.capture.root / (run + '.jsonl'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as f:
                s = os.fstat(f.fileno())
                if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_nlink != 1
                        or s.st_mode & 0o027 or s.st_size > 128_000_000):
                    raise ValueError()
                raw = f.read(128_000_001)
            if len(raw) > 128_000_000 or not raw.endswith(b'\n'):
                raise ValueError()
            rows = [strict_json(line) for line in raw.splitlines()]
            for row in rows:
                if row['run_id'] != run or row['flags'] != [] or row['redactions'] != []:
                    raise ValueError()
            if _tool_prefix or fc5.is_probe(rows):
                return fc5.replay(rows, run, strict_json, summary, partial=_tool_prefix)
            calls = {}
            completed = []
            for row in rows:
                kind, data = row['kind'], row['data']
                if kind == 'request.received':
                    call = data['call_id']
                    if call in calls:
                        raise ValueError()
                    calls[call] = {'received': data['request']}
                elif kind == 'request.upstream':
                    call = calls[data['call_id']]
                    if 'upstream' in call:
                        raise ValueError()
                    call['upstream'] = data['request']
                elif kind == 'response':
                    call = calls[data['call_id']]
                    if 'done' in call or data['status'] != 200:
                        raise ValueError()
                    received, upstream = call['received'], call['upstream']
                    model, effort = received['model'], received['reasoning']['effort']
                    if (model != 'gpt-6.1-sol' or effort not in ('medium', 'high')
                            or upstream['model'] != model or upstream['reasoning']['effort'] != effort
                            or upstream['store'] is not False or upstream['stream'] is not True):
                        raise ValueError()
                    if data['bytes'] != len(data['body'].encode('utf-8')):
                        raise ValueError()
                    if 'classification' in data:
                        parsed, classification = classify_response(
                            data['status'], data['classification']['content_type'], data['body'])
                        if classification != data['classification']:
                            raise ValueError()
                    else:
                        # Legacy capture has no header observation. Never invent
                        # one or reinterpret its recorded failed classification.
                        parsed = reconstruct_sse(data['body'])
                    if parsed != data['reconstructed']:
                        raise ValueError()
                    completed.append({'reasoning': effort, **summary(parsed, model, effort)})
                    call['done'] = True
                elif kind == 'response.interrupted':
                    raise ValueError()
            if not calls or len(completed) != len(calls):
                raise ValueError()
            return {'run_id': run, 'verified_calls': len(completed), 'calls': completed}
        except Exception:
            raise Refusal('reconstruction_unavailable') from None


def request(path, broker_uid, packet):
    """Local client with mutual kernel-UID verification; never reads credentials."""
    node = Path(path).lstat()
    if (not stat.S_ISSOCK(node.st_mode) or node.st_uid != broker_uid
            or stat.S_IMODE(node.st_mode) != 0o660 or broker_uid == 65534):
        raise Refusal('unsafe_admin_socket')
    raw = (json.dumps(packet, allow_nan=False, separators=(',', ':')) + '\n').encode()
    if len(raw) > MAX_REQUEST:
        raise Refusal('request_too_large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(300)
        connection.connect(str(path))
        if peer_uid(connection) != broker_uid:
            raise Refusal('peer_not_allowed')
        connection.sendall(raw)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        deadline = time.monotonic() + 300
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refusal('request_timeout')
            connection.settimeout(remaining)
            try:
                chunk = connection.recv(min(4096, MAX_RESPONSE + 1 - len(response)))
            except ConnectionResetError:
                if not response:
                    raise Refusal('admin_connection_closed') from None
                break
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_RESPONSE:
                raise Refusal('response_too_large')
        return strict_json(response)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Broker admin: one bounded JSON request on stdin')
    parser.add_argument('--socket', required=True)
    parser.add_argument('--broker-uid', required=True, type=int)
    args = parser.parse_args()
    import sys
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise ValueError()
        result = request(args.socket, args.broker_uid, strict_json(raw))
        print(json.dumps(result, allow_nan=False))
        raise SystemExit(0 if result.get('ok') is True else 1)
    except Exception:
        print('{"ok":false,"error":"admin_client_failed"}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
