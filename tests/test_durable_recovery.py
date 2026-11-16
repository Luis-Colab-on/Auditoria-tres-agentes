"""Offline crash injection through the normal workflow; no real model/Docker."""
import asyncio
import json
from types import SimpleNamespace
import pytest
from audit3.agents import RuntimePaused
from audit3.codex_rpc import DispatchExpired
from audit3.schemas import Opinion, TestRequest as Request
from audit3.security import now, object_hash
from audit3.workflow import Workflow
from audit3.cli import main
from helpers import MockRuntime, initial_investigation
from test_codex_runtime import rig
from test_runtime_tool_budget import controlled_clock


async def prepare_barrier(store, manifest):
    w = Workflow(store, manifest.run_id, runtime=MockRuntime())
    for role in ('auditor', 'defensor', 'juiz'):
        await w.independent(role)
    store.put(manifest.run_id, 'barrier', {'published_at': now(), 'initial_hashes': {
        role: object_hash(store.get(manifest.run_id, f'roles/{role}/initial'))
        for role in ('auditor', 'defensor', 'juiz')}}, immutable=True)


@pytest.mark.parametrize('phase', ['initial-0000', 'contest'])
def test_completed_response_recovers_original_input_after_new_reads_or_receipt(make_run, monkeypatch, phase):
    store, m, runtime, rpc, _ = rig(make_run)
    store.put(m.run_id, 'baseline', {'ids': []})
    monkeypatch.setattr('audit3.executor.shutil.which', lambda _: None)
    workflow = Workflow(store, m.run_id, runtime=runtime)
    request = rpc.request
    async def create_evidence(method, params, **kwargs):
        if method == 'turn/start':
            if phase == 'initial-0000':
                rpc.output = initial_investigation(store, m, 'auditor').model_dump_json()
            else:
                # Authentic Executor format, explicitly not executed; no audited host code.
                await workflow.executor.execute(Request(kind='python', script='print(1)', purpose='MOCK new receipt'), 'auditor', phase)
        response = await request(method, params, **kwargs)
        if method == 'turn/start':
            payload = json.loads(params['input'][0]['text'])
            finish = []
            while not rpc.events.empty():
                finish.append(rpc.events.get_nowait())
            for i, page in enumerate(payload.get('required_context_pages', [])):
                rpc.events.put_nowait({'id': i, 'method': 'item/tool/call', 'params': {
                    'threadId': params['threadId'], 'turnId': response['turn']['id'],
                    'tool': 'read_evidence', 'arguments': {'evidence_id': page}}})
            for event in finish:
                rpc.events.put_nowait(event)
        return response
    rpc.request = create_evidence
    original = store.put
    fail = [True]
    def crash(run_id, name, value, **kwargs):
        if name == f'roles/auditor/phases/{phase}' and fail[0]:
            fail[0] = False
            raise OSError('MOCK crash before phase publication')
        return original(run_id, name, value, **kwargs)
    async def exercise():
        if phase == 'contest':
            await prepare_barrier(store, m)
        monkeypatch.setattr(store, 'put', crash)
        with pytest.raises(RuntimePaused, match='Persistência local'):
            await workflow.invoke('auditor', phase)
        monkeypatch.setattr(store, 'put', original)
        before = len(rpc.calls)
        first = await workflow.invoke('auditor', phase)
        assert await workflow.invoke('auditor', phase) == first
        assert len(rpc.calls) == before  # Includes zero preflight, resume or turn calls.
    asyncio.run(exercise())
    assert sum(method == 'turn/start' for method, _ in rpc.calls) == 1
    assert store.get(m.run_id, 'state')['completed'].count('auditor/' + phase) == 1


def test_persisted_phase_reconciles_missing_completed_index(make_run, monkeypatch):
    store, m, runtime, rpc, _ = rig(make_run)
    store.put(m.run_id, 'baseline', {'ids': []})
    rpc.output = initial_investigation(store, m, 'auditor').model_dump_json()
    workflow = Workflow(store, m.run_id, runtime=runtime)
    original = store.put
    fail = [True]
    def crash(run_id, name, value, **kwargs):
        if name == 'state' and 'auditor/initial-0000' in value.get('completed', []) and fail[0]:
            fail[0] = False
            raise OSError('MOCK crash after phase publication')
        return original(run_id, name, value, **kwargs)
    async def exercise():
        monkeypatch.setattr(store, 'put', crash)
        with pytest.raises(RuntimePaused, match='Persistência local'):
            await workflow.invoke('auditor', 'initial-0000')
        monkeypatch.setattr(store, 'put', original)
        calls = len(rpc.calls)
        await workflow.invoke('auditor', 'initial-0000')
        await workflow.invoke('auditor', 'initial-0000')
        assert len(rpc.calls) == calls
    asyncio.run(exercise())
    assert store.get(m.run_id, 'state')['completed'] == ['auditor/initial-0000']


@pytest.mark.parametrize('location', ['ledger', 'event'])
def test_local_failure_never_reclassifies_confirmed_response(make_run, monkeypatch, location):
    store, m, runtime, rpc, tools = rig(make_run)
    original = runtime.budget.finish if location == 'ledger' else store.event
    fail = [True]
    if location == 'ledger':
        async def failing(*args, **kwargs):
            if fail[0]:
                fail[0] = False
                raise OSError('MOCK local ledger outage')
            return await original(*args, **kwargs)
        monkeypatch.setattr(runtime.budget, 'finish', failing)
    else:
        def failing(run_id, kind, data):
            if kind == 'runner_completed' and fail[0]:
                fail[0] = False
                raise OSError('MOCK local event outage')
            return original(run_id, kind, data)
        monkeypatch.setattr(store, 'event', failing)
        original_once = store.event_once
        def failing_once(run_id, kind, identity, data):
            if kind == 'runner_completed' and fail[0]:
                fail[0] = False
                raise OSError('MOCK local event outage')
            return original_once(run_id, kind, identity, data)
        monkeypatch.setattr(store, 'event_once', failing_once)
    async def exercise():
        with pytest.raises(RuntimePaused, match='[Pp]ersistência local'):
            await runtime.invoke('auditor', 'initial-0000', {}, tools)
        cp = store.get(m.run_id, 'codex-turns/' + tools.context.invocation_id)
        assert cp['status'] == 'completed'
        count = len(rpc.calls)
        result = await runtime.invoke('auditor', 'initial-0000', {}, tools)
        assert json.loads(result)['summary'] == 'MOCK contract result'
        assert len(rpc.calls) == count
    asyncio.run(exercise())
    assert len(store.get(m.run_id, 'ledger')['calls']) == 1
    assert store.get(m.run_id, 'ledger')['calls'][0]['status'] == 'completed'
    assert not any(method == 'turn/interrupt' for method, _ in rpc.calls)


def test_not_sent_has_local_cli_recovery_without_new_inference(make_run, monkeypatch, capsys):
    store, m, runtime, rpc, _ = rig(make_run)
    store.put(m.run_id, 'baseline', {'ids': []})
    request = rpc.request
    async def no_write(method, params, **kwargs):
        if method == 'turn/start':
            raise DispatchExpired('MOCK deadline before any write')
        return await request(method, params, **kwargs)
    rpc.request = no_write
    with pytest.raises(RuntimePaused):
        asyncio.run(Workflow(store, m.run_id, runtime=runtime).invoke('auditor', 'initial-0000'))
    invocation = store.get(m.run_id, 'roles/auditor/attempts/initial-0000-0')['invocation_id']
    before = store.path(m.run_id, 'codex-turns/' + invocation + '.json').read_bytes()
    assert main(['--store', str(store.root), 'recover', m.run_id,
                 '--invocation', invocation, '--allow-next-attempt']) == 0
    assert main(['--store', str(store.root), 'recover', m.run_id,
                 '--invocation', invocation, '--allow-next-attempt']) == 0
    assert len(store.get(m.run_id, 'ledger')['calls']) == 1
    assert store.path(m.run_id, 'codex-turns/' + invocation + '.json').read_bytes() == before
    assert not any(method == 'turn/start' for method, _ in rpc.calls)
