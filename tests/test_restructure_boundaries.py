"""Crash, paging and package contracts using synthetic controller data only."""
import asyncio
import copy
import json
from types import SimpleNamespace
import pytest
from audit3.agents import RuntimePaused, BudgetExceeded
from audit3.batch_distribution import build_distribution, register_distribution, effective_batches
from audit3.codex_rpc import StdioRPC, TurnDispatch, encode_message
from audit3.config import Config
from audit3.context_pages import create_reference
from audit3.recovery import recover, pending_attempts
from audit3.security import PolicyError, digest, now
from audit3.tools import SourceTools, ToolContext
from audit3.turn_planning import global_plan
from audit3.workflow import Workflow
from helpers import initial_investigation
from test_codex_runtime import rig
from test_runtime_tool_budget import controlled_clock


def test_distribution_before_baseline_reserves_it_and_remains_valid(make_run):
    store, m = make_run(content={f'f{i:02d}.py': '# synthetic\n' for i in range(33)})
    cfg = Config()
    before = global_plan(store, m, cfg, check_tools=True)
    assert not before['viable']
    record = build_distribution(store, m, cfg, 'Synthetic operator')
    assert record['baseline_reserve'] == 1 and record['baseline_ids'] == []
    register_distribution(store, m, cfg, record)
    store.put(m.run_id, 'baseline', {'ids': ['a'*24]})
    assert effective_batches(store, m, cfg) == record['batches']
    after = global_plan(store, m, cfg, check_tools=True)
    assert after['viable'] and after['required_phase_count'] == 2 * len(record['batches']) + 7
    assert not after['completed_phases']
    from audit3.turn_planning import source_plans
    assert all(t['plan']['required_tool_capacity'] <= cfg.limits.max_turns for t in source_plans(store,m,cfg))


def test_minimum_and_contingency_share_existing_call_budget(make_run):
    cfg = Config(); cfg.limits.max_calls = 9
    store, m = make_run(config=cfg)
    plan = global_plan(store, m, cfg)
    assert plan['viable'] and plan['minimum_new_calls'] == 9
    assert plan['additional_round_phases'] == 4 and plan['contingency_calls_available'] == 0
    store.put(m.run_id, 'material-review', {'additional_round': True})
    after = global_plan(store, m, cfg)
    assert not after['viable'] and after['minimum_new_calls'] == 13


@pytest.mark.parametrize('boundary', ['reservation', 'sending', 'dispatching'])
def test_crash_before_or_during_dispatch_preserves_reservation(make_run, monkeypatch, boundary):
    store,m,runtime,rpc,_ = rig(make_run); store.put(m.run_id,'baseline',{'ids':[]})
    put = store.put
    def crash(rid,name,value,**kwargs):
        if boundary == 'reservation' and name == 'ledger' and value['calls']:
            raise OSError('Synthetic crash after durable reservation')
        if name.startswith('codex-turns/') and value.get('status') == ('sending' if boundary == 'sending' else 'running'):
            raise OSError('Synthetic crash at checkpoint boundary')
        return put(rid,name,value,**kwargs)
    if boundary == 'dispatching':
        request = rpc.request
        async def lost(method,params,**kwargs):
            if method == 'turn/start':
                kwargs['dispatch'].write_attempted=True
                raise ConnectionError('Synthetic loss after write-ahead intent')
            return await request(method,params,**kwargs)
        rpc.request = lost
    else:
        monkeypatch.setattr(store,'put',crash)
    with pytest.raises((OSError, RuntimePaused)):
        asyncio.run(Workflow(store,m.run_id,runtime=runtime).invoke('auditor','initial-0000'))
    monkeypatch.setattr(store,'put',put)
    invocation=store.get(m.run_id,'roles/auditor/attempts/initial-0000-0')['invocation_id']
    async def exercise():
        if boundary == 'dispatching':
            with pytest.raises(RuntimePaused, match='desconhecido/ativo'):
                await recover(Workflow(store,m.run_id,runtime=runtime),invocation,allow_next=True)
        else:
            r=await recover(Workflow(store,m.run_id,runtime=runtime),invocation,allow_next=True)
            assert r['decision']['next_existing_slot']==1
            assert await runtime.budget.reconcile()==await runtime.budget.reconcile()
        assert len(store.get(m.run_id,'ledger')['calls'])==1
    asyncio.run(exercise())
    if boundary == 'dispatching': assert pending_attempts(store,m)
    assert not store.exists(m.run_id,'barrier')


@pytest.mark.parametrize('tamper', ['role','phase','next','text','index'])
def test_paged_arguments_reject_wrong_context_or_altered_page(make_run,tamper):
    store,m=make_run();cfg=Config();store.put(m.run_id,'barrier',{'published_at':now()})
    ref=create_reference(store,m,cfg,{'argument':'synthetic ' * 15000},phase='contest',audience=['auditor'],kind='discussion')
    role,phase='auditor','contest';page=ref['page_ids'][0]
    if tamper=='role':role='defensor'
    elif tamper=='phase':phase='blind'
    else:
        record=store.get(m.run_id,'context-pages/'+page)
        record[{'next':'next_page','text':'text','index':'index'}[tamper]]={'next':None,'text':'changed','index':-1}[tamper]
        store.put(m.run_id,'context-pages/'+page,record)
    tools=SourceTools(store,m,cfg,None,ToolContext(m.run_id,role,phase,'a'*24))
    with pytest.raises(PolicyError):tools.read_evidence(page)
    assert not list(tools.source_read_events())


def test_large_receipt_requires_all_pages_for_consultation(make_run,monkeypatch):
    from audit3.executor import Executor
    from audit3.config import Profile
    from audit3.schemas import TestRequest
    store,m=make_run();cfg=Config()
    monkeypatch.setattr('audit3.executor.shutil.which',lambda _:None)
    receipt=asyncio.run(Executor(store,m,cfg,Profile(name='synthetic')).execute(
        TestRequest(kind='python',script='# synthetic\n',purpose='Not executed'), 'auditor','initial-0000'))
    # Synthetic growth of a controller receipt, not a historical or real record.
    value=receipt.model_dump(mode='json');value['stdout']='Synthetic transcript\n'*10000
    value['stdout_sha256']=digest(value['stdout'].encode());store.put(m.run_id,'receipts/'+receipt.id,value)
    tools=SourceTools(store,m,cfg,None,ToolContext(m.run_id,'auditor','initial-0000','a'*24))
    result=tools.read_evidence(receipt.id);ref=result['receipt_reference']
    assert len(ref['page_ids'])>1
    with pytest.raises(PolicyError,match='não consultada'):tools.require_evidence_consulted(receipt.id)
    for page in ref['page_ids'][1:]:tools.read_evidence(page)
    tools.require_evidence_consulted(receipt.id)
    assert not list(tools.source_read_events())
    other=SourceTools(store,m,cfg,None,ToolContext(m.run_id,'defensor','initial-0000','b'*24))
    with pytest.raises(PolicyError):other.read_evidence(ref['page_ids'][0])


def test_transport_caps_actual_serialized_request_before_write():
    writes=[]
    class Pipe:
        def write(self,data):writes.append(data)
        async def drain(self):pass
    rpc=StdioRPC('never-executed',None,None);rpc.proc=SimpleNamespace(stdin=Pipe())
    request={'id':1,'method':'turn/start','params':{'input':'"'*100}}
    async def exercise():
        guard=TurnDispatch(asyncio.get_running_loop().time()+1,'turn_deadline',lambda:None,
                           max_request_bytes=len(encode_message(request))-1)
        with pytest.raises(BudgetExceeded):await rpc.send(request,dispatch=guard)
        assert guard.status=='not_sent' and not writes
        guard.max_request_bytes=len(encode_message(request))
        await rpc.send(request,dispatch=guard)
        assert writes==[encode_message(request)] and guard.wire_bytes==len(writes[0])
    asyncio.run(exercise())


def test_report_does_not_construct_workflow_and_original_input_survives_barrier(make_run,monkeypatch):
    from audit3.report import build_report
    store,m,runtime,rpc,_=rig(make_run);store.put(m.run_id,'baseline',{'ids':[]})
    rpc.output=initial_investigation(store,m,'auditor').model_dump_json()
    asyncio.run(Workflow(store,m.run_id,runtime=runtime).invoke('auditor','initial-0000'))
    from test_durable_recovery import prepare_barrier
    asyncio.run(prepare_barrier(store,m))
    before=copy.deepcopy(store.get(m.run_id,'roles/auditor/phases/initial-0000'))
    asyncio.run(Workflow(store,m.run_id,runtime=runtime).reconcile())
    def forbidden(*a,**kw):raise AssertionError('Report cannot instantiate Workflow')
    monkeypatch.setattr(Workflow,'__init__',forbidden)
    assert build_report(store,m.run_id)['schema_version']=='2.0'
    assert store.get(m.run_id,'roles/auditor/phases/initial-0000')==before


def test_official_turn_query_matches_archived_pinned_contract():
    from pathlib import Path
    contracts=Path(__file__).parent/'contracts'
    params=json.loads((contracts/'ThreadTurnsListParams.json').read_text())
    response=json.loads((contracts/'ThreadTurnsListResponse.json').read_text())
    assert params['required']==['threadId']
    assert {'threadId','cursor','limit','itemsView'} <= set(params['properties'])
    assert {x['enum'][0] for x in params['definitions']['TurnItemsView']['oneOf']}=={'notLoaded','summary','full'}
    assert {'data','nextCursor'} <= set(response['properties'])
    assert set(response['definitions']['TurnStatus']['enum'])=={'completed','interrupted','failed','inProgress'}


@pytest.mark.parametrize('boundary',['completed_checkpoint','settled_ledger'])
def test_confirmation_survives_each_following_write_boundary(make_run,monkeypatch,boundary):
    store,m,runtime,rpc,tools=rig(make_run);put=store.put;fail=[True]
    def crash(rid,name,value,**kwargs):
        target=(name.startswith('codex-turns/') and value.get('status')=='completed') if boundary=='completed_checkpoint' else (
            name=='ledger' and value['calls'] and value['calls'][-1]['status']=='completed')
        if target and fail[0]:fail[0]=False;raise OSError('Synthetic post-confirmation persistence outage')
        return put(rid,name,value,**kwargs)
    monkeypatch.setattr(store,'put',crash)
    async def exercise():
        with pytest.raises(RuntimePaused,match='Persistência local'):await runtime.invoke('auditor','initial-0000',{},tools)
        count=len(rpc.calls)
        result=await runtime.invoke('auditor','initial-0000',{},tools)
        assert json.loads(result)['summary']=='MOCK contract result' and len(rpc.calls)==count
        assert len(store.get(m.run_id,'ledger')['calls'])==1
        assert store.get(m.run_id,'ledger')['calls'][0]['status']=='completed'
        assert len([n for n in store.names(m.run_id,'events') if store.get(m.run_id,'events/'+n)['kind']=='runner_completed'])==1
    asyncio.run(exercise())
