"""Diagnostic-only exact-content origin proof; NEVER a scanner exemption.

Index static syntax, then verify ALL exact occurrences of the complete transient
scanner Match. Scanner-local columns are not source offsets, even when content
at those columns happens to match. Raw values never enter the public projection.
"""
from array import array
from bisect import bisect_right
from dataclasses import dataclass, field
import json
import re

# Diagnostic budgets, independent of scanner input (which is never truncated).
# Input/body cap matches the existing 4 MB report budget; search work is capped
# at the transport's 64 MB response ceiling. Nodes scale at <=1 per 64 input
# bytes, with the prior 4096-node floor and a bounded 65,536-node ceiling.
MAX_INPUT = 4_000_000
MAX_BODY = MAX_INPUT
MAX_NODES = 65_536
MAX_WORK = 64_000_000
MAX_OCCURRENCES = 4096
MAX_DEPTH = 48
SPACE = re.compile(r'[ \t\r\n]*')
DECODER = json.JSONDecoder(parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
TERMINALS = {'response.completed', 'response.failed', 'response.incomplete', 'error'}
RESPONSE_EVENTS = TERMINALS | {'response.created', 'response.in_progress'}
ITEM_EVENTS = {'response.output_item.added', 'response.output_item.done'}
PART_EVENTS = {'response.content_part.added', 'response.content_part.done'}
TEXT_EVENTS = {'response.output_text.delta', 'response.output_text.done'}
ARG_EVENTS = {'response.function_call_arguments.delta', 'response.function_call_arguments.done'}
REASON_EVENTS = {'response.reasoning_summary_text.delta', 'response.reasoning_summary_text.done',
                 'response.reasoning_text.delta', 'response.reasoning_text.done'}
EVENTS = RESPONSE_EVENTS | ITEM_EVENTS | PART_EVENTS | TEXT_EVENTS | ARG_EVENTS | REASON_EVENTS


@dataclass
class Node:
    start: int
    end: int
    kind: str
    value: object = None
    children: object = field(default_factory=dict)
    member: int = 0


class Parser:
    def __init__(self, size):
        self.remaining = min(MAX_NODES, max(4096, size // 64))

    def parse(self, text):
        def ws(i):
            return SPACE.match(text, i).end()

        def node(i, depth):
            self.remaining -= 1
            if self.remaining < 0 or depth > MAX_DEPTH:
                raise ValueError()
            i = ws(i)
            start = i
            ch = text[i]
            if ch in '{[':
                obj = ch == '{'
                close = '}' if obj else ']'
                children = {} if obj else []
                i = ws(i + 1)
                if text[i] != close:
                    while True:
                        member = i
                        if obj:
                            if text[i] != '"':
                                raise ValueError()
                            key, i = DECODER.raw_decode(text, i)
                            if key in children:
                                raise ValueError()
                            i = ws(i)
                            if text[i] != ':':
                                raise ValueError()
                            i += 1
                        child, i = node(i, depth + 1)
                        child.member = member
                        if obj:
                            children[key] = child
                        else:
                            children.append(child)
                        i = ws(i)
                        if text[i] == close:
                            break
                        if text[i] != ',':
                            raise ValueError()
                        i = ws(i + 1)
                return Node(start, i+1, 'object' if obj else 'array', children=children, member=start), i+1
            value, end = DECODER.raw_decode(text, i)
            # Containers must pass our depth/node/duplicate checks above.
            if isinstance(value, (dict, list)):
                raise ValueError()
            return Node(start, end, 'string' if isinstance(value, str) else 'scalar', value, member=start), end

        result, end = node(0, 0)
        if ws(end) != len(text):
            raise ValueError()
        return result


def literal(node, key):
    child = node.children.get(key) if node.kind == 'object' else None
    return child.value if child is not None and child.kind == 'string' else None


def build_spans(encoded):
    """Return nonoverlapping positions + static labels, never source strings."""
    if type(encoded) is not bytes or len(encoded) > MAX_INPUT or not encoded.isascii() or b'\n' in encoded or b'\r' in encoded:
        raise ValueError()
    text = encoded.decode('ascii')
    parser = Parser(len(encoded))
    root = parser.parse(text)
    spans = []

    def add(node, path, cls, mapping):
        if node.kind != 'string':
            return
        # Include a known schema member's key/colon for detectors whose match
        # includes the assignment, but require overlap with its VALUE below.
        bounds = mapping(node.member, node.end, node.start + 1, node.end - 1)
        if bounds is not None:
            spans.append((*bounds, path, cls))

    def walk(node, state, path, mapping):
        if node.kind != 'object':
            return
        typ = literal(node, 'type')
        if state == 'event' and typ not in EVENTS:
            return
        if state == 'item' and typ not in {'message', 'reasoning', 'function_call', 'function_call_output'}:
            return
        if state == 'part' and typ not in {'output_text', 'refusal', 'summary_text', 'reasoning_text'}:
            return
        for key, child in node.children.items():
            # No data-derived key is ever used in a returned label. Each branch
            # below first admits a literal key and a schema-specific parent.
            next_state = None
            cls = None
            if state == 'root':
                next_state = {'request': 'request', 'reconstructed': 'reconstructed'}.get(key)
                if key == 'body' and child.kind == 'string':
                    body_spans(child)
            elif state == 'reconstructed':
                next_state = {'response': 'response', 'events': 'event[]'}.get(key)
            elif state == 'request':
                if key == 'input':
                    next_state = 'request_item[]' if child.kind == 'array' else None
                    cls = 'request_content'
                elif key in {'instructions', 'model', 'previous_response_id', 'prompt_cache_key'}:
                    cls = 'request_content'
            elif state == 'request_item':
                if key == 'content' and child.kind == 'array':
                    next_state = 'request_item[]'
                elif key in {'content', 'text', 'output', 'arguments', 'encrypted_content', 'refusal'}:
                    cls = 'request_content'
                elif key in {'id', 'call_id'}:
                    cls = 'request_identifier'
            elif state == 'response':
                if key == 'id':
                    cls = 'response_id'
                elif key == 'output':
                    next_state = 'item[]'
            elif state == 'item':
                if key == 'id':
                    cls = {'message': 'message_id', 'reasoning': 'reasoning_id',
                           'function_call': 'function_call_id', 'function_call_output': 'function_call_id'}[typ]
                elif key == 'call_id' and typ in {'function_call', 'function_call_output'}:
                    cls = 'function_call_id'
                elif key == 'encrypted_content' and typ == 'reasoning':
                    cls = 'encrypted_reasoning'
                elif key == 'arguments' and typ == 'function_call':
                    cls = 'function_arguments'
                elif key == 'output' and typ == 'function_call_output':
                    cls = 'tool_output'
                elif (key == 'content' and typ == 'message') or (key in {'summary', 'content'} and typ == 'reasoning'):
                    next_state = 'part[]'
            elif state == 'part':
                if key == 'text':
                    cls = 'output_text' if typ == 'output_text' else 'reasoning_text' if typ in {'summary_text', 'reasoning_text'} else None
                elif key == 'refusal' and typ == 'refusal':
                    cls = 'output_text'
            elif state == 'event':
                if key == 'response' and typ in RESPONSE_EVENTS:
                    next_state = 'response'
                elif key == 'item' and typ in ITEM_EVENTS:
                    next_state = 'item'
                elif key == 'part' and typ in PART_EVENTS:
                    next_state = 'part'
                elif key in {'delta', 'text', 'arguments'}:
                    # Pair the field with its specific event schema, not just
                    # any model-controlled delta/text/arguments property.
                    if typ in TEXT_EVENTS and key == ('delta' if typ.endswith('.delta') else 'text'):
                        cls = 'output_text'
                    elif typ in ARG_EVENTS and key == ('delta' if typ.endswith('.delta') else 'arguments'):
                        cls = 'function_arguments'
                    elif typ in REASON_EVENTS and key == ('delta' if typ.endswith('.delta') else 'text'):
                        cls = 'reasoning_text'
                elif key == 'item_id' and typ in (TEXT_EVENTS | ARG_EVENTS | REASON_EVENTS | PART_EVENTS):
                    cls = 'output_item_reference'
            if cls is not None:
                add(child, path + '.' + key if path else key, cls, mapping)
            if next_state is not None:
                prefix = path + '.' + key if path else key
                if next_state.endswith('[]'):
                    if child.kind == 'array':
                        for item in child.children:
                            walk(item, next_state[:-2], prefix + '[]', mapping)
                else:
                    walk(child, next_state, prefix, mapping)

    def body_spans(node):
        body = node.value
        if len(body) > MAX_BODY:
            return
        # The outer serializer is fixed. Verify it before constructing the
        # exact decoded-character -> scanner-byte boundary map (surrogate pairs
        # become one character; escaped backslashes/quotes stay distinguishable).
        if json.dumps(body, ensure_ascii=True) != text[node.start:node.end]:
            return
        offsets = array('I', [node.start + 1])
        for char in body:
            cp = ord(char)
            width = (2 if char in '"\\\b\f\n\r\t' else 6 if cp < 32 or 127 <= cp <= 65535
                     else 12 if cp > 65535 else 1)
            offsets.append(offsets[-1] + width)
        if offsets[-1] != node.end - 1:
            return
        initial = len(spans)
        try:
            if body.lstrip().startswith('{'):
                parsed = parser.parse(body)
                if literal(parsed, 'object') == 'response':
                    walk(parsed, 'response', 'body.json', lambda *p: tuple(offsets[i] for i in p))
                return
            frames = []
            data, name = [], None
            done = False
            previous_type = None
            body_start = 1 if body.startswith('\ufeff') else 0
            for match in re.finditer(r'([^\r\n]*)(\r\n|\r|\n|$)', body[body_start:]):
                line, newline = match.groups()
                line_start = body_start + match.start()
                if not newline:
                    if line or data or name is not None:
                        raise ValueError()
                    continue
                if not line:
                    if data:
                        if done:
                            raise ValueError()
                        raw = '\n'.join(s for s, _ in data)
                        if raw == '[DONE]':
                            if name is not None or previous_type not in TERMINALS:
                                raise ValueError()
                            done = True
                        else:
                            parsed = parser.parse(raw)
                            typ = literal(parsed, 'type')
                            if typ is None or not (typ.startswith('response.') or typ == 'error') or (name is not None and name != typ):
                                raise ValueError()
                            segments = []
                            pos = 0
                            for chunk, origin in data:
                                segments.append((pos, pos + len(chunk), origin))
                                pos += len(chunk) + 1
                            frames.append((parsed, segments))
                            previous_type = typ
                    elif name is not None:
                        raise ValueError()
                    data, name = [], None
                    continue
                if line.startswith(':'):
                    continue
                key, sep, value = line.partition(':')
                if not sep or key not in {'data', 'event', 'id', 'retry'}:
                    raise ValueError()
                origin = line_start + len(key) + 1
                if value.startswith(' '):
                    value = value[1:]
                    origin += 1
                if key == 'data':
                    data.append((value, origin))
                elif key == 'event':
                    if name is not None:
                        raise ValueError()
                    name = value
                elif key == 'id' and '\x00' in value:
                    raise ValueError()
                elif key == 'retry' and (not value.isascii() or not value.isdigit()):
                    raise ValueError()
            for parsed, segments in frames:
                starts = [s[0] for s in segments]

                def mapping(*points):
                    i = bisect_right(starts, points[0]) - 1
                    if i < 0:
                        return None
                    start, end, origin = segments[i]
                    # A member crossing data lines includes SSE framing bytes
                    # in scanner input. Do not pretend the inserted LF is real.
                    if any(not start <= p <= end for p in points):
                        return None
                    return tuple(offsets[origin + p - start] for p in points)

                walk(parsed, 'event', 'body.sse[]', mapping)
        except (ValueError, TypeError, IndexError, RecursionError, OverflowError):
            del spans[initial:]

    walk(root, 'root', '', lambda *points: points)
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError()
    return spans


def attribute(summary, encoded, transient):
    """Consume private (location, Match, supported-tags) triples; return labels only.

    Every exact overlapping occurrence must fit one known scalar member, overlap
    its value, and agree on BOTH normalized path and class. No reported offset is
    used for origin recovery. Length only detects incomplete/malformed Match data.
    Search and occurrence budgets are shared across the entire report.
    """
    summary['encoded_byte_count'] = len(encoded) if type(encoded) is bytes else None
    for location, _, _ in transient:
        location.update(field_path='unknown', field_class='unknown',
                        coordinate_space='scanner_local', attribution_reason='input_unsupported')
    if type(encoded) is not bytes:
        return summary
    if len(encoded) > MAX_INPUT:
        for location, _, _ in transient:
            location['attribution_reason'] = 'input_budget'
        return summary
    try:
        spans = build_spans(encoded)
    except Exception:
        for location, _, _ in transient:
            location['attribution_reason'] = 'structure_unsupported_or_budget'
        return summary
    starts = [s[0] for s in spans]
    work, occurrences = MAX_WORK, MAX_OCCURRENCES
    for location, match, supported in transient:
        location['attribution_reason'] = 'match_unsupported'
        if not supported:
            location['attribution_reason'] = 'tags_unsupported'
            continue
        # The capture is ASCII single-line JSON. For an untagged pinned scanner
        # report the complete Match has exactly this byte width, even when the
        # columns reset. Never repair, strip, decode or search a Match substring.
        if (type(match) is not str or not match or not match.isascii() or
                location['start_line'] != 1 or location['end_line'] != 1 or
                len(match) != location['end_column'] - location['start_column'] + 1):
            continue
        needle = match.encode('ascii')
        cursor, label = 0, None
        reason = 'match_absent'
        while True:
            # Charge conservatively for every find, including its absent tail.
            cost = len(encoded) - cursor + len(needle)
            if cost > work:
                reason = 'search_budget'
                break
            work -= cost
            start = encoded.find(needle, cursor)
            if start < 0:
                if label is not None:
                    reason = 'exact_all_occurrences'
                break
            if occurrences <= 0:
                reason = 'occurrence_budget'
                break
            occurrences -= 1
            end = start + len(needle)
            i = bisect_right(starts, start) - 1
            if i < 0:
                reason = 'occurrence_outside_field'
                break
            left, right, value_start, value_end, path, cls = spans[i]
            if not (left <= start < end <= right and value_start < value_end
                    and start < value_end and end > value_start):
                reason = 'occurrence_outside_field'
                break
            if label is not None and label != (path, cls):
                reason = 'occurrence_ambiguous'
                break
            label = (path, cls)
            cursor = start + 1  # Include overlapping exact occurrences.
        location['attribution_reason'] = reason
        if reason == 'exact_all_occurrences':
            location.update(field_path=label[0], field_class=label[1])
    return summary
