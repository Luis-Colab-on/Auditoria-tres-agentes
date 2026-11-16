"""Synthetic context/transport regressions; no client, models or audited host code."""
import asyncio
import json
from collections import Counter
import pytest
from audit3.agent_context import agent_manifest, prepare_turn_context, inventory_reference
from audit3.agents import AmbiguousTurn, RuntimePaused, BudgetExceeded
from audit3.codex_runtime import CodexRuntime, tool_specs
from audit3.config import Config
from audit3.schemas import FileRecord, InspectionRecord, Opinion, SourceRef
from audit3.security import PolicyError, object_hash
from audit3.tools import SourceTools, ToolContext
from audit3.workflow import Workflow, batches
from audit3.investigation import validate_saved_initial
from test_codex_runtime import rig, FakeRPC
from test_context_compaction import compaction_events
from test_runtime_tool_budget import scripted, final_events, controlled_clock


def payload(store, manifest, role='auditor', phase='initial-0000'):
    return {'role': role, 'phase': phase, 'manifest': agent_manifest(store, manifest, False),
            'financial_restriction': 'MOCK included-only restriction preserved',
            'assignment': batches(manifest, 600)[0], 'baseline_receipts': [], 'own_observations': []}


def new_tools(tools, ident, role='auditor', phase='initial-0000'):
    return SourceTools(tools.store, tools.manifest, tools.config, tools.executor,
                       ToolContext(tools.context.run_id, role, phase, ident))


def sent_inputs(rpc):
    return [json.loads(p['input'][0]['text']) for m, p in rpc.calls if m == 'turn/start']


def test_compact_view_keeps_objective_constraints_and_all_readable_files(make_run):
    content = {'main.py': '# entry\n', 'includes/dependency.py': '# dependency\n'}
    content.update({f'vendor/pkg/f{n}.php': '<?php /* inert dependency metadata */\n' for n in range(300)})
    store, m = make_run(content=content)
    before = store.path(m.run_id, 'manifest.json').read_bytes()
    view = agent_manifest(store, m, False)
    assert view['manifest_ref']['sha256'] == object_hash(store.get(m.run_id, 'manifest'))
    for key, value in m.model_dump(mode='json').items():
        if key != 'files':
            assert view[key] == value
    expected = [f for f in m.files if f.category not in {'excluded', 'prior_report'}]
    assert view['files'] == [{k: f.model_dump()[k] for k in ('path', 'sha256', 'lines', 'category')} for f in expected]
    assert view['inventory']['visible_count'] == len(m.files)
    assert view['inventory']['lookup'] == {'tool': 'list_source', 'offset': 0, 'limit': 200}
    tools = SourceTools(store, m, Config(), None, ToolContext(m.run_id, 'auditor', 'initial-0000', 'catalog'))
    records, offset = [], 0
    while offset is not None:
        page = tools.list_source(offset, 200)
        assert page['page_sha256'] == object_hash(page['files'])
        assert page['inventory_ref']['inventory_sha256'] == view['inventory']['inventory_sha256']
        records.extend(page['files']); offset = page['next_offset']
    assert records == [f.model_dump(mode='json') for f in m.files]
    assert store.path(m.run_id, 'manifest.json').read_bytes() == before
    assert not list(tools.source_read_events())  # Catalogs never manufacture source reads.
    assert len(json.dumps(view).encode()) < len(json.dumps(m.model_dump(mode='json')).encode()) / 2
    assert set(next(s for s in tool_specs() if s['name'] == 'list_source')['inputSchema']['properties']) == {'offset', 'limit'}


def test_dependency_outside_batch_remains_discoverable_and_directly_readable(make_run):
    cfg = Config(); cfg.limits.batch_lines = 50
    store, m = make_run(content={'a.py': '# entry\n'*50, 'z/dependency.py': '# required dependency\n'}, config=cfg)
    view = agent_manifest(store, m, False); assigned = batches(m, 50)[0]
    dep = next(f for f in view['files'] if f['path'] not in {r['path'] for r in assigned})
    tools = SourceTools(store, m, cfg, None, ToolContext(m.run_id, 'auditor', 'initial-0000', 'outside'))
    result = tools.read_source(dep['path'], 1, 1)
    assert result['sha256'] == dep['sha256'] and result['lines']
    assert tools.search_source('required dependency')['matches']
    tools.validate_ref(SourceRef(path=dep['path'], start=1, end=1, sha256=dep['sha256']))


def test_blind_view_and_lookup_do_not_disclose_quarantined_report(make_run):
    store, m = make_run()
    m.files.append(FileRecord(path='secret-prior-report.md', sha256='a'*64, size=1, lines=1, category='prior_report'))
    store.put(m.run_id, 'manifest', m)
    view = agent_manifest(store, m, False)
    tools = SourceTools(store, m, Config(), None, ToolContext(m.run_id, 'juiz', 'blind', 'private'))
    assert 'secret-prior-report' not in json.dumps(view) + json.dumps(tools.list_source())
    with pytest.raises(PolicyError, match='não disponível'):
        tools.read_source('secret-prior-report.md')
    assert any(f['path']=='secret-prior-report.md' for f in agent_manifest(store, m, True)['files'])
    assert view['catalog_id'] != agent_manifest(store, m, True)['catalog_id']


def test_completed_delivery_suppresses_only_catalog_on_same_role_session(make_run):
    store, m, runtime, rpc, tools = rig(make_run); p = payload(store, m)
    async def exercise():
        await runtime.invoke('auditor', 'initial-0000', p, tools)
        await runtime.invoke('auditor', 'initial-0001', {**p, 'phase': 'initial-0001'},
                             new_tools(tools, 'b'*24, phase='initial-0001'))
    asyncio.run(exercise())
    first, second = sent_inputs(rpc)
    assert first['manifest']['files']
    assert 'files' not in second['manifest']
    assert second['manifest']['catalog_delivery']['previous_completed_invocation_id'] == tools.context.invocation_id
    for key in ('requirements', 'limitations', 'config_hash', 'profile_hash', 'prompt_hashes', 'source_id', 'manifest_ref'):
        assert first['manifest'][key] == second['manifest'][key] == p['manifest'][key]
    for item in (first, second):
        assert item['financial_restriction'] == p['financial_restriction']
        assert item['financial_context']['additional_spending_authorized'] is False
        assert item['controller_turn_limits']['max_tool_calls'] == runtime.config.limits.max_turns
        assert 'published_opinions' not in item
    assert p['manifest']['files']  # Logical payload wasn't mutated by the transport.
    assert len(store.get(m.run_id, 'ledger')['calls']) == 2


@pytest.mark.parametrize('change', ['ambiguous', 'not_sent', 'running', 'other_role', 'other_thread',
    'catalog_hash', 'manifest_hash', 'inventory_hash', 'reference_only', 'wrong_invocation'])
def test_undemonstrated_delivery_never_suppresses_catalog(make_run, change):
    store, m, runtime, rpc, tools = rig(make_run); p = payload(store, m)
    asyncio.run(runtime.invoke('auditor', 'initial-0000', p, tools))
    name = 'codex-turns/'+tools.context.invocation_id; prior = store.get(m.run_id, name)
    if change in {'ambiguous', 'not_sent', 'running'}: prior['status'] = change
    elif change == 'other_role': prior['role'] = 'defensor'
    elif change == 'other_thread': prior['thread_id'] = 'other'
    elif change == 'reference_only': prior['agent_context']['catalog_included'] = False
    elif change == 'wrong_invocation': prior['invocation_id'] = 'other'
    else: prior['agent_context'][{'catalog_hash':'catalog_id','manifest_hash':'manifest_sha256','inventory_hash':'inventory_sha256'}[change]] = 'wrong'
    store.put(m.run_id, name, prior)  # Deliberately incompatible synthetic record.
    prepared, meta = prepare_turn_context(store, m, p, 'auditor', 'thread-0', False)
    assert meta['catalog_included'] is True and prepared['manifest']['files']


@pytest.mark.parametrize('change', ['objective', 'file_hash', 'manifest_ref', 'inventory_ref', 'version'])
def test_invalid_or_stale_view_refused_before_reservation(make_run, change):
    store, m, runtime, rpc, tools = rig(make_run); p = payload(store, m)
    if change == 'objective': p['manifest']['requirements'] = 'other objective'
    if change == 'file_hash': p['manifest']['files'][0]['sha256'] = 'wrong'
    if change == 'manifest_ref': p['manifest']['manifest_ref']['sha256'] = 'wrong'
    if change == 'inventory_ref': p['manifest']['inventory']['inventory_sha256'] = 'wrong'
    if change == 'version': p['manifest']['representation'] = 'unknown'
    with pytest.raises(PolicyError, match='representação'):
        asyncio.run(runtime.invoke('auditor', 'initial-0000', p, tools))
    assert not sent_inputs(rpc) and store.get(m.run_id, 'ledger')['calls'] == []


def test_resume_same_session_after_compaction_uses_references_and_tools(make_run):
    store, m, runtime, rpc, tools = rig(make_run); p = payload(store, m)
    async def exercise():
        first = await runtime.invoke('auditor', 'initial-0000', p, tools)
        count = len(rpc.calls)
        assert await runtime.invoke('auditor', 'initial-0000', p, tools) == first
        assert len(rpc.calls) == count  # Cached result, not a second delivery/generation.
        restored = CodexRuntime(store, m.run_id, runtime.config); resumed = FakeRPC(restored.home); restored.rpc = resumed
        target = next(f for f in m.files if f.category != 'excluded')
        def events(base):
            return compaction_events(base) + [
                {'id': 1, 'method':'item/tool/call','params':{**base,'tool':'list_source','arguments':{'offset':0,'limit':200}}},
                {'id': 2, 'method':'item/tool/call','params':{**base,'tool':'read_source','arguments':{'path':target.path,'start':1,'end':1}}},
            ] + final_events(base)
        scripted(resumed, events)
        t = new_tools(tools, 'b'*24, phase='initial-0001')
        await restored.invoke('auditor', 'initial-0001', {**p,'phase':'initial-0001'}, t)
        assert not any(method=='thread/start' for method,_ in resumed.calls)
        resume = next(params for method,params in resumed.calls if method=='thread/resume')
        assert resume['threadId']=='thread-0' and resume['excludeTurns'] is True
        assert not {'history','path','initialTurnsPage'} & set(resume)
        assert 'files' not in sent_inputs(resumed)[0]['manifest']
        rec = store.get(m.run_id,'codex-turns/'+'b'*24)
        assert rec['tool_requests']==2 and rec['context_compaction']['completed']==1
        assert len(list(t.source_read_events()))==1 and not store.exists(m.run_id,'barrier')
        listed = json.loads(resumed.responses[0][1]['contentItems'][0]['text'])
        assert listed['inventory_ref']==inventory_reference(store,m,False)
        assert listed['files']
    asyncio.run(exercise())


def test_reference_delivery_does_not_allow_repeating_interrupted_turn(make_run):
    store, m, runtime, rpc, tools = rig(make_run);p=payload(store,m)
    async def exercise():
        await runtime.invoke('auditor','initial-0000',p,tools)
        rpc.mode='transport';t=new_tools(tools,'b'*24,phase='initial-0001');q={**p,'phase':'initial-0001'}
        with pytest.raises(RuntimePaused):await runtime.invoke('auditor','initial-0001',q,t)
        with pytest.raises(AmbiguousTurn):await runtime.invoke('auditor','initial-0001',q,t)
    asyncio.run(exercise())
    assert len(sent_inputs(rpc))==2 and len(store.get(m.run_id,'ledger')['calls'])==2
    assert store.get(m.run_id,'codex-turns/'+'b'*24)['status']=='ambiguous'


def test_new_objective_requires_fresh_catalog_even_in_same_session(make_run):
    store,m,runtime,rpc,tools=rig(make_run);p=payload(store,m)
    asyncio.run(runtime.invoke('auditor','initial-0000',p,tools))
    m.requirements += '\nAdditional synthetic requirement.'
    store.put(m.run_id,'manifest',m)
    changed=payload(store,m)
    prepared,meta=prepare_turn_context(store,m,changed,'auditor','thread-0',False)
    assert meta['catalog_included'] and prepared['manifest']['files']
    assert meta['catalog_id']!=p['manifest']['catalog_id']


def test_monotonic_activity_and_byte_metrics_never_count_as_reading(make_run):
    store,m,runtime,rpc,tools=rig(make_run);p=payload(store,m)
    scripted(rpc,lambda base:compaction_events(base)+[
        {'id':1,'method':'item/tool/call','params':{**base,'tool':'list_source','arguments':{}}}]+final_events(base))
    asyncio.run(runtime.invoke('auditor','initial-0000',p,tools))
    cp=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    wire=next(params['input'][0]['text'] for method,params in rpc.calls if method=='turn/start')
    assert cp['payload_measurement']['utf8_bytes']==len(wire.encode())
    assert cp['payload_measurement']['object_sha256']==object_hash(json.loads(wire))
    events=[store.get(m.run_id,'events/'+n) for n in store.names(m.run_id,'events')]
    timing=[e['data'] for e in events if e['kind']=='runtime_activity']
    assert {e['stage'] for e in timing}=={'dispatch_preparation_finished','turn_start_returned','tool_request_consumed','tool_result_returned'}
    assert all(e['elapsed_monotonic_seconds']>=0 for e in timing)
    compact=[e['data'] for e in events if e['kind']=='context_compaction']
    assert len(compact)==2 and all(e['elapsed_monotonic_seconds']>=0 for e in compact)
    assert cp['tool_requests']==1 and not list(tools.source_read_events())
    assert 'output' not in json.dumps(timing) and 'arguments' not in json.dumps(timing)
    assert store.get(m.run_id,'ledger')['calls'][0]['input_tokens'] is None


def test_effective_byte_limit_includes_mandatory_runtime_financial_context(make_run):
    store,m,runtime,rpc,tools=rig(make_run)
    runtime.config.limits.max_input_bytes=1000
    with pytest.raises(BudgetExceeded,match='entrada efetiva'):
        asyncio.run(runtime.invoke('auditor','initial-0000',{'text':'x'*800},tools))
    assert not sent_inputs(rpc)
    cp=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert cp['status']=='not_sent' and cp['payload_measurement']['utf8_bytes']>1000
    assert len(store.get(m.run_id,'ledger')['calls'])==1  # Reservation isn't erased.


def test_fifty_batches_each_role_keep_every_interval_and_saved_phase_validation(make_run):
    cfg=Config();cfg.limits.batch_lines=50;cfg.limits.max_calls=240;cfg.limits.max_turns=32
    store,m=make_run(content={f'f{n:02d}.py':'# inert source\n'*50 for n in range(50)},config=cfg)
    runtime=CodexRuntime(store,m.run_id,cfg);rpc=FakeRPC(runtime.home);runtime.rpc=rpc
    from test_codex_runtime import proof
    store.put(m.run_id,'financial-confirmation',proof());store.put(m.run_id,'baseline',{'ids':[]})
    original=rpc.request
    async def request(method,params,**kwargs):
        response=await original(method,params,**kwargs)
        if method=='turn/start':
            while not rpc.events.empty():rpc.events.get_nowait()
            p=json.loads(params['input'][0]['text']);refs=p['assignment'];base={'threadId':params['threadId'],'turnId':response['turn']['id']}
            assert len(refs)==1  # Only the assigned interval is synthesized as read/analyzed.
            opinion=Opinion(summary='MOCK assigned interval',findings=[],positions=[],limitations=[],inspections=[
                InspectionRecord(refs=[SourceRef(**ref)],requirement='Synthetic invariant',analysis='MOCK interval inspection',flow_verified=False,flow_description='',limitations=[]) for ref in refs])
            for n,ref in enumerate(refs):rpc.events.put_nowait({'id':n,'method':'item/tool/call','params':{**base,'tool':'read_source','arguments':{k:ref[k] for k in ('path','start','end')}}})
            finish=final_events(base);finish[0]['params']['item']['text']=opinion.model_dump_json()
            for event in finish:rpc.events.put_nowait(event)
        return response
    rpc.request=request;workflow=Workflow(store,m.run_id,runtime=runtime)
    async def exercise():
        for role in ('auditor','defensor'):await workflow.independent(role)
    asyncio.run(exercise())
    assert len(sent_inputs(rpc))==100 and len(store.get(m.run_id,'ledger')['calls'])==100
    assert sum('files' in p['manifest'] for p in sent_inputs(rpc))==2
    for role in ('auditor','defensor'):
        for i,ref in enumerate(batches(m,50)):
            validate_saved_initial(store,m,cfg,role,f'initial-{i:04d}',ref)
        events=[store.get(m.run_id,'events/'+n)['data'] for n in store.names(m.run_id,'events') if store.get(m.run_id,'events/'+n)['kind']=='tool']
        reads=[e for e in events if e['role']==role and e['tool']=='read_source']
        assert Counter(e['path'] for e in reads)==Counter(f.path for f in m.files)
    assert not store.exists(m.run_id,'barrier') and len(store.get(m.run_id,'state')['completed'])==100
