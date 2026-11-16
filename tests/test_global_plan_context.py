"""Synthetic full-project planning/context regressions; no model or Docker."""
import asyncio
import json
import pytest
from audit3.schemas import Opinion
from audit3.security import now, object_hash, PolicyError
from helpers import MockRuntime
from audit3.agent_context import agent_manifest
from audit3.completion import protocol_phases
from audit3.config import Config
from audit3.workflow import Workflow, batches
from test_codex_runtime import FakeRPC
from audit3.codex_runtime import CodexRuntime
from audit3.tools import SourceTools, ToolContext
from test_codex_runtime import proof
from test_runtime_tool_budget import controlled_clock


def test_prepare_estimate_matches_effective_whole_project_protocol(make_run):
    store, m = make_run(content={f'f{i:02d}.py': '# synthetic\n' * 301 for i in range(24)})
    assert len(batches(m, 600)) == 24
    assert len(protocol_phases(m, Config())) == 55
    assert m.estimated_calls == 55


def test_infeasible_scope_stops_before_any_inference(make_run, monkeypatch):
    store, m = make_run(content={f'f{i:02d}.py': '# synthetic\n' * 301 for i in range(24)})
    monkeypatch.setattr('audit3.executor.shutil.which', lambda _: None)
    runtime = CodexRuntime(store, m.run_id, Config()); rpc = FakeRPC(runtime.home); runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    state = asyncio.run(Workflow(store, m.run_id, runtime=runtime).run())
    assert not any(method == 'turn/start' for method, _ in rpc.calls)
    assert len(store.get(m.run_id, 'ledger')['calls']) == 0
    assert any('55' in text and '48' in text for text in state['limitations'])


def test_first_large_catalog_uses_pages_without_exceeding_input_cap(make_run):
    cfg = Config()
    store, m = make_run(content={f'module/component_{i:04d}.py': '# synthetic\n' for i in range(1800)}, config=cfg)
    runtime = CodexRuntime(store, m.run_id, cfg); rpc = FakeRPC(runtime.home); runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    tools = SourceTools(store, m, cfg, None, ToolContext(m.run_id, 'auditor', 'initial-0000', 'a'*24))
    payload = {'role': 'auditor', 'phase': 'initial-0000', 'manifest': agent_manifest(store, m, False)}
    assert len(json.dumps(payload).encode()) > cfg.limits.max_input_bytes
    asyncio.run(runtime.invoke('auditor', 'initial-0000', payload, tools))
    sent = next(params['input'][0]['text'] for method, params in rpc.calls if method == 'turn/start')
    assert len(sent.encode()) <= cfg.limits.max_input_bytes
    view = json.loads(sent)['manifest']
    assert 'files' not in view and view['inventory']['visible_count'] == 1800
    records, offset = [], 0
    while offset is not None:
        page = tools.list_source(offset, 200)
        records.extend(page['files']); offset = page['next_offset']
    assert len(records) == 1800 and not list(tools.source_read_events())


@pytest.mark.parametrize('consult', [True, False])
def test_large_debate_input_is_verifiable_and_cannot_be_skipped(make_run, consult):
    store, m = make_run()
    store.put(m.run_id, 'baseline', {'ids': []})
    class VerboseMock(MockRuntime):
        async def invoke(self, *args, **kwargs):
            value = await super().invoke(*args, **kwargs)
            value.summary = 'Synthetic argument. ' * 8000
            return value
    async def initialize():
        w = Workflow(store, m.run_id, runtime=VerboseMock())
        for role in ('auditor', 'defensor', 'juiz'):
            await w.independent(role)
        store.put(m.run_id, 'barrier', {'published_at': now(), 'initial_hashes': {
            role: object_hash(store.get(m.run_id, f'roles/{role}/initial')) for role in ('auditor','defensor','juiz')}})
    asyncio.run(initialize())
    cfg = Config();runtime = CodexRuntime(store, m.run_id, cfg); rpc = FakeRPC(runtime.home);runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    request = rpc.request
    async def scripted_request(method, params, **kwargs):
        response = await request(method, params, **kwargs)
        if method == 'turn/start' and consult:
            p = json.loads(params['input'][0]['text']);finish=[]
            while not rpc.events.empty():finish.append(rpc.events.get_nowait())
            for n,page in enumerate(p['required_context_pages']):
                rpc.events.put_nowait({'id':n,'method':'item/tool/call','params':{
                    'threadId':params['threadId'],'turnId':response['turn']['id'],
                    'tool':'read_evidence','arguments':{'evidence_id':page}}})
            for event in finish:rpc.events.put_nowait(event)
        return response
    rpc.request=scripted_request
    w=Workflow(store,m.run_id,runtime=runtime)
    if consult:
        asyncio.run(w.invoke('auditor','contest'))
        sent=json.loads(next(p['input'][0]['text'] for method,p in rpc.calls if method=='turn/start'))
        assert sent['required_context_pages'] and len(json.dumps(sent).encode())<cfg.limits.max_input_bytes
        ref=sent['published_opinions'];parts=[]
        from audit3.security import digest
        for page in ref['page_ids']:parts.append(store.get(m.run_id,'context-pages/'+page)['text'])
        text=''.join(parts)
        assert digest(text.encode())==ref['content_sha256']
        assert json.loads(text)['published_opinions']['defensor'][0]['summary']=='Synthetic argument. '*8000
    else:
        with pytest.raises(PolicyError,match='limite de correções'):
            asyncio.run(w.invoke('auditor','contest'))
        assert not store.exists(m.run_id,'roles/auditor/phases/contest')
