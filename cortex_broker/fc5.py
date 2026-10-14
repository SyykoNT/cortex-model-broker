"""Fixed two-request FC5 probe. No caller payload, dynamic tool or execution hook.

The only local function returns a literal. Live dispatch and cold disk replay use
one contract, anchored to these constants rather than mutually editable logs.
"""
import copy
import json
import re

from .protocol import Refusal, adapt, classify_response

MODEL = 'gpt-6.1-sol'
EFFORT = 'high'
NAME = 'fc5_fixed_marker'
ARGUMENTS = {'probe': 'fc5'}
OUTPUT = '{"marker":"fc5-fixed-ok"}'
FINAL = 'FC5_OK'
PROMPT = ('Call functions.fc5_fixed_marker exactly once with {"probe":"fc5"}. '
          'After its output, respond with exactly FC5_OK and no other text.')
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,160}\Z')
CALL = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
KINDS = ['admin.tool_probe', 'request.received', 'request.upstream', 'response',
         'tool.result', 'request.received', 'request.upstream', 'response', 'admin.tool_probe.completed']


def require(condition):
    if not condition:
        raise Refusal('tool_probe_invalid')


def same(left, right):
    # Python's bool == int equality is not schema equality.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def identifier(value):
    require(type(value) is str and IDENTIFIER.fullmatch(value) is not None)


def first_request():
    return {'model': MODEL, 'reasoning': {'effort': EFFORT},
            'input': [{'role': 'user', 'content': PROMPT}], 'store': False, 'stream': True,
            # Preserve stateless reasoning context in the second full-input request.
            'include': ['reasoning.encrypted_content'],
            'tools': [{'type': 'function', 'name': NAME,
                       'description': 'Return the fixed FC5 acceptance marker; no external effects.',
                       'strict': True, 'parameters': {'type': 'object', 'properties': {
                           'probe': {'type': 'string', 'enum': ['fc5']}},
                           'required': ['probe'], 'additionalProperties': False}}],
            'tool_choice': 'required', 'parallel_tool_calls': False}


def response_contract(parsed, summarize):
    result = summarize(parsed, MODEL, EFFORT)
    response = parsed['response']
    require(response.get('status') == 'completed')
    # Unlike legacy tool-less inference, FC5 requires an observed reasoning echo.
    if not isinstance(response.get('reasoning'), dict) or response['reasoning'].get('effort') != EFFORT:
        raise Refusal('inference_reasoning_mismatch')
    identifier(response.get('id'))
    output = response.get('output')
    require(type(output) is list and bool(output))
    ids = []
    for item in output:
        require(type(item) is dict)
        identifier(item.get('id'))
        ids.append(item['id'])
    require(len(ids) == len(set(ids)))
    # Where intermediate streamed item/argument events exist, bind them to the
    # terminal output too. No guessed association from ordering or tool names.
    deltas = {}
    done = set()
    added, finished = set(), set()
    for event in parsed['events']:
        kind = event['type']
        if kind.startswith('response.function_call_arguments.'):
            require(kind in {'response.function_call_arguments.delta', 'response.function_call_arguments.done'})
        if kind in {'response.output_item.added', 'response.output_item.done',
                    'response.function_call_arguments.delta', 'response.function_call_arguments.done'}:
            index = event.get('output_index')
            require(type(index) is int and 0 <= index < len(output))
            item = output[index]
            if kind.startswith('response.output_item.'):
                observed = event.get('item')
                require(type(observed) is dict and observed.get('id') == item['id']
                        and observed.get('type') == item['type'])
                if kind.endswith('.done'):
                    require(index not in finished and same(observed, item))
                    finished.add(index)
                else:
                    require(index not in added and index not in finished)
                    added.add(index)
                    if item['type'] == 'function_call':
                        require(all(observed.get(k) == item.get(k) for k in ('call_id', 'name'))
                                and observed.get('namespace', 'functions') == item.get('namespace', 'functions'))
            else:
                require(item['type'] == 'function_call' and event.get('item_id') == item['id']
                        and index not in done and index not in finished)
                if kind.endswith('.delta'):
                    require(type(event.get('delta')) is str)
                    deltas[index] = deltas.get(index, '') + event['delta']
                else:
                    require(event.get('arguments') == item['arguments'])
                    done.add(index)
    for index, arguments in deltas.items():
        require(arguments == output[index]['arguments'])
    return {'reasoning': EFFORT, **result}


def tool_result(parsed, strict_json, summarize):
    response_contract(parsed, summarize)
    output = parsed['response']['output']
    require(all(item.get('type') in {'reasoning', 'function_call'} for item in output))
    calls = [item for item in output if item['type'] == 'function_call']
    require(len(calls) == 1)
    call = calls[0]
    identifier(call.get('call_id'))
    require(call.get('name') == NAME and call.get('namespace', 'functions') == 'functions'
            and call.get('status') == 'completed')
    require(type(call.get('arguments')) is str and len(call['arguments']) <= 256)
    try:
        arguments = strict_json(call['arguments'])
    except (ValueError, TypeError, RecursionError):
        raise Refusal('tool_probe_invalid') from None
    require(same(arguments, ARGUMENTS))
    # This literal return is the entire tool implementation, not a dispatcher.
    return {'name': NAME, 'call_id': call['call_id'], 'arguments': dict(ARGUMENTS), 'output': OUTPUT}


def next_request(first, parsed, tool):
    require(same(first, first_request()))
    require(tool['name'] == NAME and tool['output'] == OUTPUT and same(tool['arguments'], ARGUMENTS))
    result = copy.deepcopy(first)
    result['tool_choice'] = 'none'
    result['input'] += copy.deepcopy(parsed['response']['output']) + [
        {'type': 'function_call_output', 'call_id': tool['call_id'], 'output': OUTPUT}]
    return result


def final_response(parsed, summarize):
    response_contract(parsed, summarize)
    output = parsed['response']['output']
    require(all(item.get('type') in {'reasoning', 'message'} for item in output))
    messages = [item for item in output if item['type'] == 'message']
    require(len(messages) == 1)
    message = messages[0]
    require(message.get('role') == 'assistant' and message.get('status') == 'completed')
    content = message.get('content')
    require(type(content) is list and len(content) == 1 and type(content[0]) is dict
            and content[0].get('type') == 'output_text' and content[0].get('text') == FINAL)
    return FINAL


def is_probe(rows):
    # A deleted/renamed opening marker must not downgrade a tool transcript into
    # legacy tool-less reconstruction. Existing tool-less schemas stay unchanged.
    for row in rows:
        if row['kind'] in {'admin.tool_probe', 'admin.tool_probe.completed', 'tool.result'}:
            return True
        if row['kind'] in {'request.received', 'request.upstream'}:
            req = row['data']['request']
            if 'tools' in req or any(item.get('type') == 'function_call_output' for item in req.get('input', [])):
                return True
        if row['kind'] == 'response':
            parsed = row['data'].get('reconstructed', {})
            if any(item.get('type') == 'function_call' for item in (parsed.get('response') or {}).get('output', [])):
                return True
    return False


def replay(rows, run, strict_json, summarize, *, partial=False):
    require([row['kind'] for row in rows] == (KINDS[:5] if partial else KINDS))
    require(same(rows[0]['data'], {'command': 'tool_probe'}))
    if not partial:
        require(same(rows[-1]['data'], {'command': 'tool_probe', 'complete': True}))
    calls, parsed_calls, seen = [], [], set()
    first = first_request()
    tool = None
    expiry = None
    for index, start in enumerate((1,) if partial else (1, 5)):
        received, upstream, response = [row['data'] for row in rows[start:start + 3]]
        call = received['call_id']
        require(type(call) is str and CALL.fullmatch(call) is not None and call not in seen)
        seen.add(call)
        require(upstream['call_id'] == response['call_id'] == call)
        require(set(received) == {'call_id', 'request', 'admission'}
                and set(upstream) == {'call_id', 'request', 'adaptations'}
                and set(response) == {'call_id', 'status', 'body', 'reconstructed', 'bytes', 'classification'})
        admission = received['admission']
        if index == 0:
            expiry = admission['expires_at']
            require(type(expiry) in (int, float) and expiry > 0)
        require(same(admission, {'run_id': run, 'role': 'acceptance', 'model': MODEL,
                                'reasoning': EFFORT, 'expires_at': expiry, 'cap': 2, 'used': index + 1}))
        expected = first if index == 0 else next_request(first, parsed_calls[0], tool)
        require(same(received['request'], expected))
        adapted, changes = adapt(expected)
        require(same(upstream['request'], adapted) and same(upstream['adaptations'], changes))
        require(type(response['status']) is int and response['status'] == 200
                and type(response['bytes']) is int and response['bytes'] == len(response['body'].encode('utf-8')))
        parsed, classification = classify_response(response['status'], response['classification']['content_type'], response['body'])
        require(same(parsed, response['reconstructed']) and same(classification, response['classification']))
        calls.append(response_contract(parsed, summarize))
        parsed_calls.append(parsed)
        if index == 0:
            tool = tool_result(parsed, strict_json, summarize)
            require(same(rows[4]['data'], tool))
        else:
            require(parsed['response']['id'] != parsed_calls[0]['response']['id'])
            final_response(parsed, summarize)
    return {'run_id': run, 'verified_calls': len(calls), 'calls': calls, 'tool': tool,
            'final_text': None if partial else FINAL}
