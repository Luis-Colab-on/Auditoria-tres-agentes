"""Offline reconstructed protocol fixtures. No real compaction/client inference."""
import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from audit3.agents import RuntimePaused, AmbiguousTurn
from audit3.schemas import Opinion, InspectionRecord, SourceRef
from audit3.security import PolicyError, object_hash
from audit3.workflow import Workflow
from test_codex_runtime import rig
from test_runtime_tool_budget import scripted, final_events, controlled_clock

FIXTURE = Path(__file__).parent/'protocol_fixtures/context_compaction.json'


def compaction_events(base):
    events = copy.deepcopy(json.loads(FIXTURE.read_text())['events'])
    for event in events:
        event['params'].update(base)
    return events


def test_recorded_compaction_type_can_finish_without_becoming_tool_or_answer(make_run):
    store, m, runtime, rpc, tools = rig(make_run)
    scripted(rpc, lambda base: compaction_events(base) + final_events(base))
    result = asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    assert json.loads(result)['summary'] == 'MOCK transport only'
    checkpoint = store.get(m.run_id, 'codex-turns/'+tools.context.invocation_id)
    assert checkpoint['status'] == 'completed' and checkpoint['tool_requests'] == 0
    assert not rpc.responses
    assert not store.exists(m.run_id, 'barrier')
    assert checkpoint['context_compaction']['started'] == checkpoint['context_compaction']['completed'] == 1


def test_compaction_fixture_fields_match_pinned_contract_and_disclose_reconstruction():
    fixture = json.loads(FIXTURE.read_text())
    assert fixture['provenance']['recorded_values'] == {'method': 'item/started', 'item_type': 'contextCompaction'}
    assert '/events/0/params/item/id' in fixture['provenance']['reconstructed_fields']
    assert '/events/0/params/startedAtMs' in fixture['provenance']['reconstructed_fields']
    assert '/events/1' in fixture['provenance']['reconstructed_fields']
    for name, event in zip(('ItemStartedNotification', 'ItemCompletedNotification'), fixture['events'], strict=True):
        contract = json.loads((Path(__file__).parent/'contracts'/f'{name}.json').read_text())
        assert set(event['params']) == set(contract['required'])
        variant = next(v for v in contract['definitions']['ThreadItem']['oneOf'] if v['title'] == 'ContextCompactionThreadItem')
        assert set(event['params']['item']) == set(variant['required']) == {'id', 'type'}


@pytest.mark.parametrize('count', [32, 33])
def test_compaction_does_not_consume_or_reset_tool_budget(make_run, count):
    store, m, runtime, rpc, tools = rig(make_run);runtime.config.limits.max_turns = 32
    def events(base):
        middle = compaction_events(base)
        for e in middle:e['params']['item']['id'] += '-second'
        requests = [{'id': n, 'method': 'item/tool/call', 'params': {**base, 'tool': 'list_source', 'arguments': {}}} for n in range(count)]
        return compaction_events(base) + requests[:16] + middle + requests[16:] + final_events(base)
    scripted(rpc, events)
    if count == 32:
        asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    else:
        with pytest.raises(RuntimePaused, match='Limite de passos'):
            asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    assert len(rpc.responses) == 32
    assert json.loads(rpc.responses[-1][1]['contentItems'][1]['text'])['controller_tool_budget']['remaining_tool_calls'] == 0
    saved = store.get(m.run_id, 'codex-turns/'+tools.context.invocation_id)
    assert saved['tool_requests'] == count and saved['context_compaction']['completed'] == 2
    events = [store.get(m.run_id, 'events/'+n) for n in store.names(m.run_id, 'events')]
    assert sum(e['kind']=='tool' and e['data']['tool']=='list_source' for e in events) == 32
    assert sum(e['kind']=='context_compaction' for e in events) == 4
    assert not list(tools.source_read_events())


def test_compaction_then_source_tools_and_valid_initial_inspection(make_run):
    store, m, runtime, rpc, tools = rig(make_run);store.put(m.run_id, 'baseline', {'ids': []})
    refs = [SourceRef(path=f.path, start=1, end=f.lines, sha256=f.sha256) for f in m.files if f.lines and f.category!='excluded']
    opinion = Opinion(summary='MOCK independently inspected', findings=[], positions=[], limitations=[],
        inspections=[InspectionRecord(refs=[r], requirement='Synthetic input invariant', analysis='MOCK explicit source examination',
            flow_verified=False, flow_description='', limitations=[]) for r in refs])
    def events(base):
        finish = final_events(base);finish[0]['params']['item']['text'] = opinion.model_dump_json()
        return compaction_events(base) + [{'id': n, 'method':'item/tool/call','params':{
            **base,'tool':'read_source','arguments':{'path':r.path,'start':r.start,'end':r.end}}} for n,r in enumerate(refs)] + finish
    scripted(rpc, events)
    workflow = Workflow(store, m.run_id, runtime=runtime)
    result = asyncio.run(workflow.invoke('auditor', 'initial-0000'))
    assert result['findings'] == [] and len(result['inspections']) == len(refs)
    assert len(list(tools.source_read_events())) == len(refs)
    assert store.get(m.run_id, 'state')['completed'] == ['auditor/initial-0000']
    wire = json.loads(next(p for method,p in rpc.calls if method=='turn/start')['input'][0]['text'])
    assert 'published_opinions' not in wire and not store.exists(m.run_id, 'barrier')


def test_compaction_never_supplies_missing_blind_inspection(make_run):
    store, m, runtime, rpc, tools = rig(make_run);store.put(m.run_id, 'baseline', {'ids': []})
    scripted(rpc, lambda base: compaction_events(base) + final_events(base))
    with pytest.raises(PolicyError, match='saída inválida após limite'):
        asyncio.run(Workflow(store, m.run_id, runtime=runtime).invoke('auditor','initial-0000'))
    assert not store.get(m.run_id, 'state')['completed'] and not store.exists(m.run_id,'barrier')
    assert not list(tools.source_read_events())


@pytest.mark.parametrize('change', ['missing_stamp','bool_stamp','float_stamp','string_stamp','overflow_stamp',
    'missing_id','empty_id','integer_id','text','arguments','phase','bad_shared_stamp','params_list','params_none','item_list',
    'other_thread','other_turn','extra_turn','unknown_method','rpc_request'])
def test_malformed_or_unbound_compaction_is_refused_without_content(make_run, change):
    store, m, runtime, rpc, tools = rig(make_run)
    secret = 'sk-' + 'private_payload_'*3
    def events(base):
        e = compaction_events(base)[0];p=e['params'];i=p['item']
        if change=='missing_stamp':p.pop('startedAtMs')
        elif change=='bool_stamp':p['startedAtMs']=True
        elif change=='float_stamp':p['startedAtMs']=1.5
        elif change=='string_stamp':p['startedAtMs']='1700000000000'
        elif change=='overflow_stamp':p['startedAtMs']=2**63
        elif change=='missing_id':i.pop('id')
        elif change=='empty_id':i['id']=''
        elif change=='integer_id':i['id']=1
        elif change in ('text','arguments','phase'):i[change]=secret
        elif change=='bad_shared_stamp':i['startedAtMs']='bad'
        elif change=='params_list':e['params']=[]
        elif change=='params_none':e['params']=None
        elif change=='item_list':p['item']=[]
        elif change=='other_thread':p['threadId']='MOCK-other-thread'
        elif change=='other_turn':p['turnId']='MOCK-other-turn'
        elif change=='extra_turn':p['turn']=[]
        elif change=='unknown_method':e['method']='item/futureCompact'
        elif change=='rpc_request':e['id']='MOCK-request'
        return [e]+final_events(base)
    scripted(rpc, events)
    with pytest.raises(RuntimePaused):asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['status']=='ambiguous' and saved['tool_requests']==0 and 'output' not in saved
    assert secret not in json.dumps(saved)
    assert any(method=='turn/interrupt' for method,_ in rpc.calls) and rpc.closed


@pytest.mark.parametrize('change',['orphan_complete','different_id','duplicate_start','duplicate_complete','changed_type','prior_item_collision'])
def test_compaction_item_correlation_is_required(make_run, change):
    store,m,runtime,rpc,tools=rig(make_run)
    def events(base):
        pair=compaction_events(base)
        if change=='orphan_complete':pair=pair[1:]
        elif change=='different_id':pair[1]['params']['item']['id']='MOCK-other-item'
        elif change=='duplicate_start':pair.insert(1,copy.deepcopy(pair[0]))
        elif change=='duplicate_complete':pair.append(copy.deepcopy(pair[1]))
        elif change=='changed_type':pair[1]['params']['item']={'id':pair[0]['params']['item']['id'],'type':'reasoning'}
        elif change=='prior_item_collision':pair.insert(0,{'method':'item/started','params':{**base,'item':{'id':pair[0]['params']['item']['id'],'type':'reasoning'}}})
        return pair+final_events(base)
    scripted(rpc,events)
    with pytest.raises(RuntimePaused):asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['protocol_failure']['reason']=='context_compaction_item'
    assert 'output' not in saved and saved['tool_requests']==0


@pytest.mark.parametrize('case',['no_final','unfinished','transport','interrupted'])
def test_compaction_is_not_a_final_response_or_success_on_interruption(make_run,case):
    store,m,runtime,rpc,tools=rig(make_run)
    def events(base):
        pair=compaction_events(base)
        if case=='no_final':return pair+[{'method':'turn/completed','params':{**base,'turn':{'id':base['turnId'],'status':'completed'}}}]
        if case=='unfinished':return pair[:1]+final_events(base)
        if case=='transport':return pair[:1]+[{'method':'audit3/transportLost'}]
        return pair[:1]+[{'method':'turn/completed','params':{**base,'turn':{'id':base['turnId'],'status':'interrupted'}}}]
    scripted(rpc,events)
    with pytest.raises(RuntimePaused):asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    with pytest.raises(AmbiguousTurn):asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['status']=='ambiguous' and 'output' not in saved
    assert len(store.get(m.run_id,'ledger')['calls'])==1


def test_external_cancellation_during_compaction_interrupts_and_preserves_reservation(make_run,monkeypatch):
    store,m,runtime,rpc,tools=rig(make_run);started=asyncio.Event();original=store.event
    def event(run_id,kind,data):
        original(run_id,kind,data)
        if kind=='context_compaction':started.set()
    monkeypatch.setattr(store,'event',event)
    scripted(rpc,lambda base:compaction_events(base)[:1])
    async def exercise():
        task=asyncio.create_task(runtime.invoke('auditor','initial-0000',{},tools))
        await started.wait();task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(exercise())
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['context_compaction']['started']==1 and saved['context_compaction']['completed']==0
    assert saved['status']=='ambiguous' and rpc.closed
    assert any(method=='turn/interrupt' for method,_ in rpc.calls)


@pytest.mark.parametrize('origin',['global','turn'])
def test_elapsed_deadline_is_not_renewed_by_compaction_or_a_full_event_queue(make_run,monkeypatch,origin):
    store,m,runtime,rpc,tools=rig(make_run)
    runtime.config.limits.call_timeout=1
    clock={'anchor':None,'elapsed':0}
    class AsyncioProxy:
        def __getattr__(self,name):return getattr(asyncio,name)
        def get_running_loop(self):
            return SimpleNamespace(time=lambda:clock['anchor']+clock['elapsed'])
    # One controlled monotonic domain for runtime and dispatch. Only this mock
    # advances; the real event loop, configuration and financial facts do not.
    monkeypatch.setattr('audit3.codex_runtime.asyncio',AsyncioProxy())
    monkeypatch.setattr('audit3.codex_rpc.asyncio',AsyncioProxy())
    original=store.event
    def event(run_id,kind,data):
        original(run_id,kind,data)
        if kind=='context_compaction' and data['method']=='item/started':clock['elapsed']=.1 if origin=='global' else 1.1
    monkeypatch.setattr(store,'event',event)
    scripted(rpc,lambda base:compaction_events(base)+[{'id':1,'method':'item/tool/call','params':{**base,'tool':'list_source','arguments':{}}}]+final_events(base))
    async def exercise():
        clock['anchor']=asyncio.get_running_loop().time()
        if origin=='global':runtime.global_deadline=clock['anchor']+.05
        with pytest.raises(RuntimePaused,match='Timeout'):await runtime.invoke('auditor','initial-0000',{},tools)
    asyncio.run(exercise())
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['timeout']['origin']==origin+'_deadline'
    assert saved['context_compaction']['completed']==0 and saved['tool_requests']==0 and not rpc.responses
    assert saved['operational_limits']['turn_limit_seconds']==1


def test_financial_expiry_during_compaction_blocks_queued_tools_without_renewal(make_run,monkeypatch):
    store,m,runtime,rpc,tools=rig(make_run);proof=store.get(m.run_id,'financial-confirmation');expired=False
    original=store.event
    def event(run_id,kind,data):
        nonlocal expired
        original(run_id,kind,data)
        if kind=='context_compaction':expired=True
    def remaining(checked_at):
        assert checked_at==proof['checked_at']
        if expired:raise RuntimePaused('MOCK factual confirmation expired during compaction')
        return 30
    monkeypatch.setattr(store,'event',event);monkeypatch.setattr('audit3.codex_runtime.financial_remaining',remaining)
    scripted(rpc,lambda base:compaction_events(base)+[{'id':1,'method':'item/tool/call','params':{**base,'tool':'list_source','arguments':{}}}]+final_events(base))
    with pytest.raises(RuntimePaused,match='expired'):asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    assert store.get(m.run_id,'financial-confirmation')==proof and not rpc.responses
    ledger=store.get(m.run_id,'ledger');assert ledger['unknown_cost_calls']==1 and ledger['known_cost_usd'] is None and ledger['tokens'] is None


def test_quota_loss_during_compaction_still_uses_official_snapshot_guard(make_run):
    store,m,runtime,rpc,tools=rig(make_run)
    def events(base):
        rpc.quota['ordinaryUsageAllowed']=False
        pair=compaction_events(base)
        return pair[:1]+[{'method':'account/rateLimits/updated','params':{}}]+pair[1:]+final_events(base)
    scripted(rpc,events)
    with pytest.raises(RuntimePaused):asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    assert sum(method=='account/rateLimits/read' for method,_ in rpc.calls)==2
    assert store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)['status']=='ambiguous'


def test_compaction_timestamps_are_metadata_and_do_not_replace_deadlines(make_run):
    store,m,runtime,rpc,tools=rig(make_run);before=store.get(m.run_id,'financial-confirmation')
    def events(base):
        pair=compaction_events(base);pair[0]['params']['startedAtMs']=2**62;pair[1]['params']['completedAtMs']=0
        pair[0]['params']['item']['startedAtMs']=None
        pair[1]['params']['item'].update(startedAtMs=None,completedAtMs=0)
        return pair+final_events(base)
    scripted(rpc,events);asyncio.run(runtime.invoke('auditor','initial-0000',{},tools))
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['financial_context']['checked_at']==before['checked_at']
    assert store.get(m.run_id,'financial-confirmation')==before


def test_lossless_payload_minification_retains_all_required_context(make_run):
    store,m,runtime,rpc,tools=rig(make_run)
    payload={'manifest':m.model_dump(mode='json'),'assignment':[{'path':'app.py','start':1,'end':2}],
        'financial_restriction':'NENHUM GASTO  ADICIONAL — espaços obrigatórios',
        'baseline_receipts':['a'*24],'instruction':'Independent blind source inspection; sem pareceres alheios.'}
    original=copy.deepcopy(payload)
    scripted(rpc,lambda base:compaction_events(base)+final_events(base))
    asyncio.run(runtime.invoke('auditor','initial-0000',payload,tools))
    text=next(p for method,p in rpc.calls if method=='turn/start')['input'][0]['text'];wire=json.loads(text)
    assert all(wire[k]==v for k,v in original.items()) and payload==original
    assert len(text.encode())<len(json.dumps(wire,ensure_ascii=False).encode())
    saved=store.get(m.run_id,'codex-turns/'+tools.context.invocation_id)
    assert saved['input_hash']==object_hash(original) and saved['wire_input_hash']==object_hash(wire)
