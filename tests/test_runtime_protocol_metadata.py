"""Injected protocol events only; not evidence of a real model execution."""
import asyncio
import json
from pathlib import Path
import pytest
from audit3.agents import RuntimePaused
from audit3.runtime_diagnostics import CONTRACT_ITEM_TYPES
from audit3.tools import ToolContext
from test_codex_runtime import rig
from test_runtime_tool_budget import scripted, final_events, controlled_clock

ALLOWED = {'userMessage', 'agentMessage', 'reasoning', 'dynamicToolCall'}
LIFECYCLE = {'contextCompaction'}


def test_diagnostic_names_match_pinned_contract_without_authorizing_them():
    contract = json.loads((Path(__file__).parent/'contracts/ThreadResumeResponse.json').read_text())
    names = {v for item in contract['definitions']['ThreadItem']['oneOf'] for v in item['properties']['type']['enum']}
    assert CONTRACT_ITEM_TYPES == names
    assert ALLOWED < names


@pytest.mark.parametrize('method', ['item/started', 'item/completed'])
@pytest.mark.parametrize('kind', sorted(CONTRACT_ITEM_TYPES - ALLOWED - LIFECYCLE) + ['futureUnknownItem', None])
def test_forbidden_item_metadata_interrupts_without_private_content(make_run, method, kind):
    store, m, runtime, rpc, tools = rig(make_run)
    tools.context = ToolContext(m.run_id, 'auditor', 'initial-0000', tools.context.invocation_id, 1)
    secret = 'sk-' + 'sensitive_private_payload_' * 3
    def events(base):
        return [{'method': method, 'params': {**base, 'item': {
            'type': kind, 'id': secret, 'text': secret, 'arguments': {'credential': secret},
            'reasoning': secret}}}] + final_events(base)
    scripted(rpc, events)
    with pytest.raises(RuntimePaused, match='isolamento incompatível'):
        asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    saved = store.get(m.run_id, 'codex-turns/' + tools.context.invocation_id)
    d = saved['protocol_failure']
    assert d['method'] == method and d['reason'] == 'native_item'
    assert d['item_type'] == (kind if kind in CONTRACT_ITEM_TYPES else None)
    assert d['role'] == 'auditor' and d['phase'] == 'initial-0000' and d['attempt'] == 1
    assert d['invocation_id'] == tools.context.invocation_id
    assert d['thread_id'] == saved['thread_id'] and d['turn_id'] == saved['turn_id']
    events = [store.get(m.run_id, 'events/'+n) for n in store.names(m.run_id, 'events')]
    assert next(e['data'] for e in events if e['kind'] == 'runtime_protocol_rejected') == d
    assert secret not in json.dumps(saved) and secret not in json.dumps(events)
    assert saved['status'] == 'ambiguous' and rpc.closed
    assert any(name == 'turn/interrupt' for name, _ in rpc.calls)
    assert not store.exists(m.run_id, 'barrier')
    assert store.get(m.run_id, 'ledger')['unknown_cost_calls'] == 1
    assert 'output' not in saved


@pytest.mark.parametrize('kind', sorted(ALLOWED))
def test_existing_allowed_item_types_keep_their_classification(make_run, kind):
    store, m, runtime, rpc, tools = rig(make_run)
    def events(base):
        return [{'method': method, 'params': {**base, 'item': {'type': kind}}}
                for method in ('item/started', 'item/completed')] + final_events(base)
    scripted(rpc, events)
    asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    saved = store.get(m.run_id, 'codex-turns/' + tools.context.invocation_id)
    assert saved['status'] == 'completed' and 'protocol_failure' not in saved


def test_native_request_is_denied_with_hashed_peer_identifiers(make_run):
    store, m, runtime, rpc, tools = rig(make_run)
    secret = 'untrusted-secret-request-id'
    def events(base):
        return [{'id': secret, 'method': 'item/commandExecution/requestApproval',
                 'params': {**base, 'command': 'private command content'}}]
    scripted(rpc, events)
    with pytest.raises(RuntimePaused, match='Solicitação nativa'):
        asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    d = store.get(m.run_id, 'codex-turns/'+tools.context.invocation_id)['protocol_failure']
    assert d['method'] == 'item/commandExecution/requestApproval' and d['reason'] == 'native_request'
    assert secret not in json.dumps(d) and 'private command content' not in json.dumps(d)
    assert 'request_id_sha256' in d
    assert rpc.responses[0]['error']['code'] == -32601


def test_diagnostic_survives_failed_denial_write_and_redacts_unknown_method(make_run):
    store, m, runtime, rpc, tools = rig(make_run)
    secret = 'sk-' + 'private_identifier_123' * 2
    scripted(rpc, lambda base: [{'id': secret, 'method': secret, 'params': {**base, 'content': secret}}])
    async def failed_write(data):
        raise ConnectionError('MOCK lost pipe during denial')
    rpc.send = failed_write
    with pytest.raises(RuntimePaused, match='Solicitação nativa'):
        asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    saved = store.get(m.run_id, 'codex-turns/'+tools.context.invocation_id)
    assert saved['protocol_failure']['method'] is None
    assert 'method_sha256' in saved['protocol_failure']
    assert secret not in json.dumps(saved)
    assert saved['status'] == 'ambiguous' and rpc.closed
