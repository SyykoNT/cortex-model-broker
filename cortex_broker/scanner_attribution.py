"""Bounded, ephemeral source positions; only static schema labels may escape.

This is diagnostics, NEVER a scanner exemption or a redaction decision. We index
syntax, not matching values: repeated strings retain distinct source positions.
Capture emits unindented ensure_ascii JSON. Only its single-line byte coordinates
are supported (gitleaks 8.30.1 has a different column origin after an actual LF).
Unknown keys, shapes, overlapping fields, invalid framing and budgets stay unknown.
"""
from array import array
from bisect import bisect_right
from dataclasses import dataclass, field
import json
import re

# Pinned stdin scanning resets columns in larger fragments without publishing
# their byte origins. Do not infer global offsets from those reports. This is
# an attribution-only cap: the unchanged scanner still sees the ENTIRE value.
# v8.30.1 sources/common.go extends any nonempty initial read by up to 25,000
# bytes. Our ASCII/no-CR-or-LF input <=25,000 therefore reaches EOF within the
# first fragment regardless of short pipe reads. Sender write size is NOT a
# reader-boundary guarantee. See docs/scanner-diagnostics.md for pinned source.
MAX_INPUT = 25_000
MAX_BODY = 32_768
MAX_NODES = 4096
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
    def __init__(self):
        self.remaining = MAX_NODES

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
    parser = Parser()
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


def attribute(summary, encoded):
    """Metadata failure cannot turn a scanner match into an accepted value."""
    spans = []
    try:
        spans = build_spans(encoded)
    except Exception:
        # No exception text (which might include content) enters diagnostics.
        pass
    starts = [s[0] for s in spans]
    for rule in summary['rules']:
        for location in rule['locations']:
            location.update(field_path='unknown', field_class='unknown')
            if location['start_line'] != 1 or location['end_line'] != 1:
                continue
            start, end = location['start_column'] - 1, location['end_column']
            i = bisect_right(starts, start) - 1
            if i < 0:
                continue
            left, right, value_start, value_end, path, cls = spans[i]
            if left <= start < end <= right and start < value_end and end > value_start:
                location.update(field_path=path, field_class=cls)
    return summary
