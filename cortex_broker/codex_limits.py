"""Optional documented Codex RPC, never a direct undocumented quota endpoint.

A custom SIWC provider may not support account/rateLimits/read. Refuse explicitly
in that case: never switch auth modes, sign in to Codex, or fabricate capacity.
"""
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time

from .admin import strict_json
from .protocol import Refusal

MAX_OUTPUT = 262_144
PROVIDER_CONFIG = (
    'model_provider="openai_chatgpt_plan"',
    'model_providers.openai_chatgpt_plan.name="ChatGPT plan"',
    'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"',
    'model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN"',
    'model_providers.openai_chatgpt_plan.wire_api="responses"',
    'model_providers.openai_chatgpt_plan.requires_openai_auth=false',
    'model_providers.openai_chatgpt_plan.supports_websockets=false',
)


def project_limits(result):
    # No arbitrary strings, account IDs, credits, provider messages, or token
    # shaped fields can escape. Unknown/missing windows are not zero utilization.
    if not isinstance(result, dict) or not isinstance(result.get('rateLimits'), dict):
        raise Refusal('codex_rate_limits_unavailable')
    out = {}
    for name in ('primary', 'secondary'):
        window = result['rateLimits'].get(name)
        if window is None:
            out[name] = None
            continue
        if not isinstance(window, dict):
            raise Refusal('codex_protocol_error')
        values = {k: window.get(k) for k in ('usedPercent', 'windowDurationMins', 'resetsAt')}
        if (type(values['usedPercent']) not in (int, float) or not math.isfinite(values['usedPercent'])
                or not 0 <= values['usedPercent'] <= 100
                or any(type(values[k]) is not int or values[k] < 0 for k in ('windowDurationMins', 'resetsAt'))):
            raise Refusal('codex_protocol_error')
        out[name] = values
    if all(v is None for v in out.values()):
        raise Refusal('codex_rate_limits_unavailable')
    return out


class CodexLimits:
    def __init__(self, executable, scratch, timeout=15):
        # Executable and scratch are service-owner configuration, not RPC inputs.
        self.executable, self.scratch, self.timeout = Path(executable), Path(scratch), timeout

    def read(self, token):
        try:
            for parent in self.executable.parents:
                s = parent.lstat()
                if (not stat.S_ISDIR(s.st_mode) or s.st_uid not in {0, os.geteuid()}
                        or s.st_mode & 0o022):
                    raise Refusal('codex_unavailable')
            s = self.executable.lstat()
            if (not self.executable.is_absolute() or not stat.S_ISREG(s.st_mode)
                    or s.st_uid not in {0, os.geteuid()} or s.st_mode & 0o022 or not s.st_mode & 0o111):
                raise Refusal('codex_unavailable')
        except OSError:
            raise Refusal('codex_unavailable') from None
        # Fresh private HOME/CODEX_HOME and cwd: do not load an operator's auth,
        # projects, MCP servers, plugins, shell startup, or inherited API keys.
        with tempfile.TemporaryDirectory(prefix='quota-', dir=self.scratch) as home:
            command = [str(self.executable), 'app-server', '--listen', 'stdio://']
            for value in PROVIDER_CONFIG:
                command.extend(['-c', value])
            env = {'HOME': home, 'CODEX_HOME': home, 'TMPDIR': home,
                   'PATH': '/usr/bin:/bin', 'ACCESS_TOKEN': token}
            process = None
            try:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, cwd=home, env=env,
                                           start_new_session=True, close_fds=True)
                return self.exchange(process)
            except Refusal:
                raise
            except Exception:
                raise Refusal('codex_unavailable') from None
            finally:
                if process is not None:
                    # Kill the entire child group even on a normal RPC response;
                    # no persistent agent or inference thread is ever started.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                    process.stdin.close()
                    process.stdout.close()

    def exchange(self, process):
        deadline = time.monotonic() + self.timeout
        pending = bytearray()
        consumed = 0
        notifications = 0
        def send(message):
            process.stdin.write((json.dumps(message, separators=(',', ':')) + '\n').encode())
            process.stdin.flush()
        send({'id': 1, 'method': 'initialize', 'params': {'clientInfo': {
            'name': 'Cortex Model Broker', 'title': 'Cortex Model Broker', 'version': '0.1.0'}}})
        expected = 1
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise Refusal('codex_timeout')
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    raise Refusal('codex_protocol_error')
                consumed += len(chunk)
                if consumed > MAX_OUTPUT:
                    raise Refusal('codex_protocol_error')
                pending.extend(chunk)
                while b'\n' in pending:
                    line, _, pending = pending.partition(b'\n')
                    try:
                        message = strict_json(line)
                    except Exception:
                        raise Refusal('codex_protocol_error') from None
                    if not isinstance(message, dict):
                        raise Refusal('codex_protocol_error')
                    if 'id' not in message:
                        notifications += 1
                        if notifications > 32 or 'method' not in message:
                            raise Refusal('codex_protocol_error')
                        continue
                    if type(message['id']) is not int or message['id'] != expected or 'method' in message:
                        raise Refusal('codex_protocol_error')
                    if 'error' in message:
                        raise Refusal('codex_rate_limits_unavailable')
                    if not isinstance(message.get('result'), dict):
                        raise Refusal('codex_protocol_error')
                    if expected == 1:
                        send({'method': 'initialized'})
                        send({'id': 2, 'method': 'account/rateLimits/read'})
                        expected = 2
                    else:
                        return project_limits(message['result'])
