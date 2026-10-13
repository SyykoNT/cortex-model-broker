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

    def admit(self, key, request):
        with self.lock:
            k = self.keys.get(hashlib.sha256(key.encode()).hexdigest())
            if not k or k["expires_at"] <= time.time() or k["used"] >= k["cap"]:
                raise Refusal("expired_revoked_or_exhausted_key")
            if request.get("model") != k["model"] or request.get("reasoning", {}).get("effort") != k["reasoning"]:
                raise Refusal("model_or_reasoning_mismatch")
            k["used"] += 1
            return dict(k)

    def revoke_run(self, run_id):
        with self.lock:
            for k in self.keys.values():
                if k["run_id"] == run_id:
                    k["expires_at"] = 0


def reconstruct_sse(body):
    events = []
    for block in body.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip(" ") for line in block.splitlines() if line.startswith("data:"))
        if data and data != "[DONE]":
            events.append(json.loads(data))
    completed = [e for e in events if e.get("type") == "response.completed"]
    failures = [e for e in events if e.get("type") in {"response.failed", "response.incomplete", "error"}]
    return {"events": events, "response": completed[-1].get("response") if completed else None,
            "complete": len(completed) == 1 and not failures,
            "terminal": failures[-1].get("type") if failures else ("response.completed" if completed else "interrupted")}
