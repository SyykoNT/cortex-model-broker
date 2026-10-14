"""Responses preview adaptation and offline-testable run admission."""
import copy
import hashlib
import json
import secrets
import threading
import time

UNSUPPORTED = set("background conversation max_output_tokens max_tool_calls metadata moderation multi_agent prompt prompt_cache_retention safety_identifier temperature top_logprobs top_p truncation user".split())
ALLOWED = {"model", "input", "instructions", "reasoning", "tools", "tool_choice", "parallel_tool_calls", "text", "include", "store", "stream", "service_tier", "prompt_cache_key"}


class Refusal(Exception):
    pass


def adapt(request):
    out = copy.deepcopy(request)
    changes = []
    if out.get("previous_response_id"):
        raise Refusal("full_input_required_no_server_history")
    if "previous_response_id" in out:
        out.pop("previous_response_id")
        changes.append("omit:previous_response_id")
    for name in sorted(UNSUPPORTED & out.keys()):
        out.pop(name)
        changes.append("omit:" + name)
    unknown = set(out) - ALLOWED
    if unknown:
        raise Refusal("unsupported_fields:" + ",".join(sorted(unknown)))
    if not isinstance(out.get("input"), list) or not out["input"]:
        raise Refusal("full_input_array_required")
    for i, item in enumerate(out["input"]):
        if not isinstance(item, dict):
            raise Refusal("invalid_input_item")
        if item.get("role") == "system":
            item["role"] = "developer"
            changes.append(f"input[{i}].role:system->developer")
    if out.get("store") is not False:
        changes.append("store:false")
    if out.get("stream") is not True:
        changes.append("stream:true")
    out["store"], out["stream"] = False, True
    flat = []
    grouped = []
    for tool in out.get("tools", []):
        if tool.get("type") in {"function", "custom"}:
            flat.append(tool)
        elif tool.get("type") == "namespace":
            if not tool.get("name") or any(t.get("type") not in {"function", "custom"} for t in tool.get("tools", [])):
                raise Refusal("unsupported_namespace_tool")
            grouped.append(tool)
        elif tool.get("type") == "web_search":
            grouped.append(tool)
        else:
            raise Refusal("unsupported_tool")
    if flat:
        if any(t.get("name") == "functions" for t in grouped):
            raise Refusal("namespace_collision")
        grouped.append({"type": "namespace", "name": "functions", "tools": flat})
        changes.append("tools:group_functions_namespace")
    if "tools" in out:
        out["tools"] = grouped
    return out, changes


class RunKeys:
    """In-memory keys intentionally die with the broker process; no stale reactivation."""
    def __init__(self):
        self.lock = threading.Lock()
        self.keys = {}

    def mint(self, run_id, role, model, reasoning, expires_at, cap):
        import re
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", run_id):
            raise Refusal("invalid_run_id")
        allowed = {"lead": {"high"}, "builder": {"medium", "high"}, "qa": {"high"}, "reviewer": {"high"}, "acceptance": {"medium", "high"}}
        if role not in allowed or model != "gpt-6.1-sol" or reasoning not in allowed[role]:
            raise Refusal("unapproved_model_or_reasoning")
        if type(cap) is not int or cap <= 0 or not time.time() < expires_at <= time.time() + 7200:
            raise Refusal("invalid_budget")
        key = secrets.token_urlsafe(48)
        with self.lock:
            self.keys[hashlib.sha256(key.encode()).hexdigest()] = dict(run_id=run_id, role=role, model=model,
                reasoning=reasoning, expires_at=expires_at, cap=cap, used=0)
        return key

    def run_for_key(self, key):
        with self.lock:
            record = self.keys.get(hashlib.sha256(key.encode()).hexdigest())
            return record["run_id"] if record else None

    def admit(self, key, request):
        if not isinstance(request, dict) or not isinstance(request.get("reasoning", {}), dict):
            raise Refusal("invalid_request")
        with self.lock:
            k = self.keys.get(hashlib.sha256(key.encode()).hexdigest())
            if not k or k["expires_at"] <= time.time() or k["used"] >= k["cap"]:
                raise Refusal("expired_revoked_or_exhausted_key")
            if request.get("model") != k["model"] or request.get("reasoning", {}).get("effort") != k["reasoning"]:
                raise Refusal("model_or_reasoning_mismatch")
            k["used"] += 1
            return dict(k)

    def worker_key_active(self, key):
        with self.lock:
            k = self.keys.get(hashlib.sha256(key.encode()).hexdigest())
            return bool(k and k['role'] != 'acceptance' and k['expires_at'] > time.time()
                        and k['used'] < k['cap'])

    def revoke_run(self, run_id):
        with self.lock:
            for k in self.keys.values():
                if k["run_id"] == run_id:
                    k["expires_at"] = 0


def reconstruct_sse(body):
    """Validate the entire Responses SSE envelope, not just selected data lines.

    A MIME hint cannot authorize completion. Reject malformed/unterminated frames,
    ambiguous JSON and conflicting event identities even for canonical headers.
    Keep all parsed events and the caller's original body for capture/replay.
    """
    events = []
    valid, done = True, False
    response_ids = set()

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate field')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('nonfinite number')

    # SSE permits CRLF, CR, LF and an initial UTF-8 BOM. Never rewrite capture.
    normalized = body.removeprefix('\ufeff').replace('\r\n', '\n').replace('\r', '\n')
    blocks = normalized.split('\n\n')
    try:
        # EOF does not dispatch an unfinished frame, including a complete JSON
        # object without its blank-line delimiter.
        if blocks[-1].strip('\n'):
            raise ValueError('unterminated frame')
        for block in blocks[:-1]:
            data, name = [], None
            for line in block.split('\n'):
                if not line or line.startswith(':'):
                    continue
                field, separator, value = line.partition(':')
                if value.startswith(' '):
                    value = value[1:]
                if not separator or field not in {'data', 'event', 'id', 'retry'}:
                    raise ValueError('invalid SSE field')
                if field == 'data':
                    data.append(value)
                elif field == 'event':
                    if name is not None:
                        raise ValueError('duplicate event name')
                    name = value
                elif field == 'id' and '\x00' in value:
                    raise ValueError('invalid event id')
                elif field == 'retry' and (not value.isascii() or not value.isdigit()):
                    raise ValueError('invalid retry')
            if not data:
                if name is not None:
                    raise ValueError('event without data')
                continue
            if done:
                raise ValueError('data after DONE')
            raw = '\n'.join(data)
            if raw == '[DONE]':
                if name is not None or not events or events[-1]['type'] not in {
                        'response.completed', 'response.failed', 'response.incomplete', 'error'}:
                    raise ValueError('premature DONE')
                done = True
                continue
            event = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
            if (not isinstance(event, dict) or not isinstance(event.get('type'), str)
                    or not (event['type'].startswith('response.') or event['type'] == 'error')
                    or (name is not None and name != event['type'])):
                raise ValueError('invalid or conflicting event type')
            response = event.get('response')
            if isinstance(response, dict) and 'id' in response:
                if not isinstance(response['id'], str) or not response['id']:
                    raise ValueError('invalid response id')
                response_ids.add(response['id'])
                if len(response_ids) > 1:
                    raise ValueError('conflicting response ids')
            if event['type'] == 'response.completed' and (
                    not isinstance(response, dict)
                    or response.get('status', 'completed') != 'completed'
                    or response.get('error') is not None
                    or response.get('incomplete_details') is not None):
                raise ValueError('conflicting completion')
            events.append(event)
    except (ValueError, TypeError, RecursionError):
        valid = False
    completed = [e for e in events if e.get('type') == 'response.completed']
    failures = [e for e in events if e.get('type') in {'response.failed', 'response.incomplete', 'error'}]
    return {'events': events, 'response': completed[-1].get('response') if completed else None,
            'complete': valid and len(completed) == 1 and not failures and events[-1] is completed[0],
            'terminal': ('invalid-sse' if not valid else failures[-1]['type'] if failures
                         else 'response.completed' if completed else 'interrupted')}


def classify_response(status, content_type, body):
    """One transport/replay decision; header observation is never synthesized.

    Only this single noncredential header enters Capture.safe, not a header map.
    A missing header remains None; normalization is separate from observation.
    """
    media_type = content_type.split(';', 1)[0].strip().lower() if content_type is not None else None
    reconstructed = reconstruct_sse(body)
    if status != 200:
        reconstructed = {**reconstructed, 'complete': False, 'terminal': 'http-error'}
        decision = 'http-status-rejected'
    elif reconstructed['terminal'] == 'invalid-sse' or not reconstructed['events']:
        decision = 'invalid-sse'
    else:
        decision = 'sse-header' if media_type == 'text/event-stream' else 'sse-body'
    return reconstructed, {'version': 1, 'content_type': content_type,
                           'media_type': media_type, 'decision': decision,
                           'notes': ['content_type_mismatch'] if reconstructed['complete']
                           and media_type != 'text/event-stream' else []}
