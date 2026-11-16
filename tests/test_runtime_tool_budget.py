"""Synthetic controller/tool-budget regressions. No official client or models."""
import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest
from audit3.agents import BudgetExceeded, RuntimePaused, AmbiguousTurn
from audit3.config import Config
from audit3.investigation import validate_initial_output
from audit3.schemas import Opinion
from audit3.security import PolicyError
from audit3.tools import SourceTools, ToolContext
from audit3.turn_planning import initial_read_plan
from audit3.workflow import Workflow, batches
from test_codex_runtime import rig, FakeRPC


@pytest.fixture(autouse=True)
def controlled_clock(monkeypatch):
    """Synthetic clock: host NTP steps must not change a protocol test's facts."""
    anchor, instant = time.monotonic(), datetime.now(timezone.utc)
    def current():
        return instant + timedelta(seconds=time.monotonic() - anchor)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            value = current()
            return value.astimezone(tz) if tz else value.replace(tzinfo=None)
    monkeypatch.setattr('audit3.codex_policy.datetime', Clock)
    for module in ('audit3.security', 'audit3.evidence', 'audit3.workflow', 'audit3.codex_runtime', 'test_codex_runtime'):
        monkeypatch.setattr(module + '.now', lambda: current().isoformat())


def scripted(rpc, make_events):
    original = rpc.request
    async def request(method, params, **kwargs):
        response = await original(method, params, **kwargs)
        if method == 'turn/start':
            while not rpc.events.empty():
                rpc.events.get_nowait()
            base = {'threadId': params['threadId'], 'turnId': response['turn']['id']}
            for event in make_events(base):
                rpc.events.put_nowait(event)
        return response
    rpc.request = request


def final_events(base):
    output = Opinion(summary='MOCK transport only', inspections=[], findings=[], positions=[], limitations=[]).model_dump_json()
    return [
        {'method': 'item/completed', 'params': {**base, 'item': {'type': 'agentMessage', 'phase': 'final_answer', 'text': output}}},
        {'method': 'turn/completed', 'params': {**base, 'turn': {'id': base['turnId'], 'status': 'completed'}}}]


@pytest.mark.parametrize('count', [32, 33])
def test_32_33_boundary_interrupts_before_executing_refused_tool(make_run, count):
    store, m, runtime, rpc, tools = rig(make_run)
    runtime.config.limits.max_turns = 32
    def events(base):
        return [{'id': i, 'method': 'item/tool/call', 'params': {
            **base, 'tool': 'list_source', 'arguments': {}}} for i in range(count)] + final_events(base)
    scripted(rpc, events)
    async def exercise():
        if count == 32:
            await runtime.invoke('auditor', 'initial-0000', {}, tools)
        else:
            with pytest.raises(RuntimePaused, match='Limite de passos'):
                await runtime.invoke('auditor', 'initial-0000', {}, tools)
            with pytest.raises(AmbiguousTurn):
                await runtime.invoke('auditor', 'initial-0000', {}, tools)
    asyncio.run(exercise())
    executions = [store.get(m.run_id, 'events/' + n) for n in store.names(m.run_id, 'events')]
    assert sum(e['kind'] == 'tool' and e['data']['tool'] == 'list_source' for e in executions) == 32
    assert len(rpc.responses) == 32
    budget = json.loads(rpc.responses[-1][1]['contentItems'][1]['text'])['controller_tool_budget']
    assert budget['requested_tool_calls'] == 32 and budget['remaining_tool_calls'] == 0
    saved = store.get(m.run_id, 'codex-turns/' + tools.context.invocation_id)
    assert len(store.get(m.run_id, 'ledger')['calls']) == 1
    assert sum(method == 'turn/start' for method, _ in rpc.calls) == 1
    assert not store.exists(m.run_id, 'barrier')
    if count == 33:
        assert saved['status'] == 'ambiguous' and saved['tool_requests'] == 33
        assert saved['protocol_failure']['reason'] == 'tool_step_limit'
        assert saved['protocol_failure']['tool'] == 'list_source'
        assert saved['protocol_failure']['tool_limit'] == 32
        assert ('turn/interrupt', {'threadId': saved['thread_id'], 'turnId': saved['turn_id']}) in rpc.calls
        assert rpc.closed
        assert store.get(m.run_id, 'ledger')['unknown_cost_calls'] == 1


def test_turn_limits_are_explicit_and_override_untrusted_payload(make_run):
    store, m, runtime, rpc, tools = rig(make_run)
    runtime.config.limits.max_turns = 32
    runtime.config.limits.read_lines = 500
    payload = {'controller_turn_limits': {'max_tool_calls': 1000}}
    asyncio.run(runtime.invoke('auditor', 'initial-0000', payload, tools))
    request = next(p for method, p in rpc.calls if method == 'turn/start')
    sent = json.loads(request['input'][0]['text'])
    assert sent['controller_turn_limits']['max_tool_calls'] == 32
    assert sent['controller_turn_limits']['max_read_lines'] == 500
    assert sent['controller_turn_limits']['max_source_response_bytes'] == 16000
    assert payload['controller_turn_limits']['max_tool_calls'] == 1000
    instructions = next(p['developerInstructions'] for method, p in rpc.calls if method == 'thread/start')
    assert 'controller_turn_limits' in instructions and 'passos restantes' in instructions


def test_tool_error_still_reports_consumed_step(make_run):
    store, m, runtime, rpc, tools = rig(make_run)
    runtime.config.limits.max_turns = 32
    asyncio.run(runtime.dispatch_tool({'id': 1, 'method': 'item/tool/call', 'params': {
        'threadId': 't', 'turnId': 'u', 'tool': 'read_source', 'arguments': {'path': 'missing.py'}}}, tools, 't', 'u', 1))
    response = rpc.responses[0][1]
    assert response['success'] is False
    assert json.loads(response['contentItems'][1]['text'])['controller_tool_budget']['remaining_tool_calls'] == 31


def plan_rig(make_run, content, config=None, role='auditor', phase='initial-0000'):
    cfg = config or Config()
    cfg.limits.max_turns = 32
    store, manifest = make_run(content=content, config=cfg)
    tools = SourceTools(store, manifest, cfg, None, ToolContext(manifest.run_id, role, phase, 'plan'))
    return store, manifest, tools, batches(manifest, cfg.limits.batch_lines)[0]


def test_plan_matches_byte_and_line_caps_without_minting_read_evidence(make_run):
    cfg = Config(); cfg.limits.batch_lines = 4000; cfg.limits.read_lines = 500
    store, m, tools, assigned = plan_rig(make_run, {'a.py': ('#' + 'x' * 299 + '\n') * 80}, cfg)
    before = store.names(m.run_id, 'events')
    plan = initial_read_plan(tools, assigned, [])
    assert plan['mandatory_reads_fit'] and plan['minimum_tool_calls'] == 2
    assert [(r['start'], r['end']) for r in plan['source_read_calls']] == [(1, 53), (54, 80)]
    assert store.names(m.run_id, 'events') == before
    with pytest.raises(PolicyError, match='investigação cega incompleta'):
        validate_initial_output(Opinion(summary='MOCK no inspection', inspections=[], findings=[], positions=[], limitations=[]), tools, assigned)
    for ref in plan['source_read_calls']:
        result = tools.read_source(ref['path'], ref['start'], ref['end'])
        assert not result['truncated']
    assert initial_read_plan(tools, assigned, [])['source_read_calls'] == []
    # Actual reads alone still do not constitute semantic inspection.
    with pytest.raises(PolicyError, match='investigação cega incompleta'):
        validate_initial_output(Opinion(summary='MOCK read only', inspections=[], findings=[], positions=[], limitations=[]), tools, assigned)


@pytest.mark.parametrize('role,phase,run_patch,source_patch,expected_calls', [
    ('auditor', 'initial-0000', False, False, 0),
    ('defensor', 'initial-0000', False, False, 1),
    ('auditor', 'contest', False, False, 1),
    ('auditor', 'initial-0000', True, False, 1),
    ('auditor', 'initial-0000', False, True, 1)])
def test_plan_only_reuses_authentic_own_blind_reads(make_run, role, phase, run_patch, source_patch, expected_calls):
    store, m, tools, assigned = plan_rig(make_run, {'a.py': '# synthetic\n'})
    other = SourceTools(store, m, tools.config, None, ToolContext(m.run_id, role, phase, 'previous'))
    other.read_source('a.py', 1, 1)
    if run_patch or source_patch:
        event_name = next(n for n in store.names(m.run_id, 'events') if store.get(m.run_id, 'events/'+n)['kind'] == 'tool')
        event = store.get(m.run_id, 'events/'+event_name)
        event['data']['run_id' if run_patch else 'source_id'] = 'wrong'
        store.put(m.run_id, 'events/'+event_name, event)  # Deliberately invalid synthetic identity.
    assert len(initial_read_plan(tools, assigned, [])['source_read_calls']) == expected_calls


@pytest.mark.parametrize('content', [
    {f'f{i:02d}.py': '# one line\n' for i in range(33)},
    {'a.py': '#' + 'x' * 16000 + '\n'}])
def test_unviable_batch_stops_before_reservation_or_model_call(make_run, content):
    cfg = Config(); cfg.limits.max_turns = 32; cfg.limits.batch_lines = 4000
    store, m = make_run(content=content, config=cfg)
    runtime = SimpleNamespace(mode='codex-app-server')
    store.put(m.run_id, 'baseline', {'ids': []})
    workflow = Workflow(store, m.run_id, runtime=runtime)
    with pytest.raises(BudgetExceeded, match='lote inicial inviável'):
        asyncio.run(workflow.invoke('auditor', 'initial-0000', batches(m, cfg.limits.batch_lines)[0]))
    assert store.get(m.run_id, 'ledger')['calls'] == []
    assert store.names(m.run_id, 'roles/auditor/attempts') == []
    assert not store.exists(m.run_id, 'barrier')


def test_workflow_sends_plan_and_reuses_prior_reads_without_waiving_inspection(make_run):
    from helpers import initial_investigation
    store, m, runtime, rpc, tools = rig(make_run)
    store.put(m.run_id, 'baseline', {'ids': []})
    opinion = initial_investigation(store, m, 'auditor')
    rpc.output = opinion.model_dump_json()
    before = {n for n in store.names(m.run_id, 'events')
              if store.get(m.run_id, 'events/'+n)['kind'] == 'tool'}
    result = asyncio.run(Workflow(store, m.run_id, runtime=runtime).invoke(
        'auditor', 'initial-0000', batches(m, runtime.config.limits.batch_lines)[0]))
    assert result['inspections'] and result['findings'] == []
    sent = json.loads(next(p for method, p in rpc.calls if method == 'turn/start')['input'][0]['text'])
    assert sent['initial_read_plan']['minimum_tool_calls'] == 0
    assert sent['initial_read_plan']['previously_returned_intervals']
    assert sent['controller_turn_limits']['attempt'] == 0
    after = {n for n in store.names(m.run_id, 'events')
             if store.get(m.run_id, 'events/'+n)['kind'] == 'tool'}
    assert before == after  # No new read, and no manufactured read event.


def test_later_impossible_batch_blocks_before_first_model_turn(make_run):
    cfg = Config(); cfg.limits.max_turns = 32; cfg.limits.batch_lines = 4000; cfg.limits.read_lines = 500
    content = {'a.py': '# synthetic\n' * 4000, **{f'z{i:02d}.py': '# short\n' for i in range(33)}}
    store, m = make_run(content=content, config=cfg)
    store.put(m.run_id, 'baseline', {'ids': []})
    async def no_preflight():
        raise AssertionError('No account query or model call is needed to detect impossible source reads')
    runtime = SimpleNamespace(mode='codex-app-server', preflight=no_preflight)
    with pytest.raises(BudgetExceeded, match='auditor/initial-0001'):
        asyncio.run(Workflow(store, m.run_id, runtime=runtime).body())
    assert store.get(m.run_id, 'ledger')['calls'] == []
    assert store.names(m.run_id, 'roles/auditor/attempts') == []
