"""Official recovery contract is simulated; no CLI client/model is launched."""
import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
import pytest
from audit3.agents import RuntimePaused
from audit3.codex_runtime import CodexRuntime
from audit3.recovery import recover
from audit3.schemas import Opinion, Judgment, InspectionRecord, SourceRef
from audit3.security import PolicyError
from audit3.workflow import Workflow
from helpers import initial_investigation
from test_codex_runtime import rig, FakeRPC, proof
from test_runtime_tool_budget import controlled_clock


@pytest.mark.parametrize('official', ['interrupted', 'completed', 'inProgress', 'unknown_target'])
def test_official_observation_preserves_ambiguity_or_recovers_without_generation(make_run, official):
    store,m,runtime,rpc,_=rig(make_run);store.put(m.run_id,'baseline',{'ids':[]})
    opinion=initial_investigation(store,m,'auditor')
    rpc.mode='transport'
    with pytest.raises(RuntimePaused):asyncio.run(Workflow(store,m.run_id,runtime=runtime).invoke('auditor','initial-0000'))
    inv=store.get(m.run_id,'roles/auditor/attempts/initial-0000-0')['invocation_id']
    cp=store.get(m.run_id,'codex-turns/'+inv);before_cp=store.path(m.run_id,'codex-turns/'+inv+'.json').read_bytes()
    before_calls=copy.deepcopy(store.get(m.run_id,'ledger')['calls'])
    stale=proof();stale['checked_at']=(datetime.now(timezone.utc)-timedelta(minutes=31)).isoformat()
    store.put(m.run_id,'financial-confirmation',stale)
    observer=FakeRPC(runtime.home);runtime.rpc=observer;request=observer.request
    async def metadata(method,params,**kwargs):
        if method=='thread/turns/list':
            observer.calls.append((method,params))
            if official=='unknown_target':return {'data':[],'nextCursor':None}
            return {'data':[{'id':cp['turn_id'],'status':official,'items':[
                {'id':'MOCK-final','type':'agentMessage','phase':'final_answer','text':opinion.model_dump_json()}
            ] if params['itemsView']=='full' else []}],'nextCursor':None}
        return await request(method,params,**kwargs)
    observer.request=metadata;w=Workflow(store,m.run_id,runtime=runtime)
    async def exercise():
        if official=='unknown_target':
            with pytest.raises(RuntimePaused,match='não observável'):
                await recover(w,inv,check_official=True,allow_next=True)
        elif official=='inProgress':
            with pytest.raises(RuntimePaused,match='desconhecido/ativo'):
                await recover(w,inv,check_official=True,allow_next=True)
        else:
            result=await recover(w,inv,check_official=True,allow_next=True)
            assert result['new_model_calls']==0
            count=len(observer.calls)
            again=await recover(w,inv,check_official=True,allow_next=True)
            assert again['new_model_calls']==0 and len(observer.calls)==count
    asyncio.run(exercise())
    assert store.path(m.run_id,'codex-turns/'+inv+'.json').read_bytes()==before_cp
    assert store.get(m.run_id,'ledger')['calls']==before_calls
    assert store.get(m.run_id,'financial-confirmation')==stale
    assert not any(method in {'turn/start','thread/start','thread/resume'} for method,_ in observer.calls)
    if official=='completed':
        assert store.exists(m.run_id,'roles/auditor/phases/initial-0000')
        assert store.get(m.run_id,'confirmed-results/'+inv)['finished_at']==cp['stopped_at']
    if official in {'inProgress','unknown_target'}:assert not store.exists(m.run_id,'recovery-decisions/'+inv)


def test_whole_run_resume_after_confirmed_final_requires_no_financial_refresh(make_run,monkeypatch):
    store,m,runtime,rpc,_=rig(make_run);store.put(m.run_id,'baseline',{'ids':[]});request=rpc.request
    async def synthetic_agent(method,params,**kwargs):
        reads=[]
        if method=='turn/start':
            p=json.loads(params['input'][0]['text']);phase=p['phase']
            if phase.startswith('initial-'):reads=p['assignment']
            elif phase=='blind':
                f=next(f for f in m.files if f.category!='excluded' and f.lines)
                reads=[{'path':f.path,'sha256':f.sha256,'start':1,'end':f.lines}]
            if phase=='final':output=Judgment(summary='MOCK synthetic final',verdicts=[],new_findings=[],limitations=[])
            else:output=Opinion(summary='MOCK synthetic opinion',findings=[],positions=[],limitations=[],inspections=[
                InspectionRecord(refs=[SourceRef(**r)],requirement='Synthetic requirement',analysis='MOCK source inspection',flow_verified=False,flow_description='',limitations=[]) for r in reads])
            rpc.output=output.model_dump_json()
        response=await request(method,params,**kwargs)
        if method=='turn/start':
            finish=[]
            while not rpc.events.empty():finish.append(rpc.events.get_nowait())
            events=[('read_source',{k:r[k] for k in ('path','start','end')}) for r in reads]
            events += [('read_evidence',{'evidence_id':page}) for page in p.get('required_context_pages',[])]
            for i,(tool,args) in enumerate(events):rpc.events.put_nowait({'id':i,'method':'item/tool/call','params':{
                'threadId':params['threadId'],'turnId':response['turn']['id'],'tool':tool,'arguments':args}})
            for e in finish:rpc.events.put_nowait(e)
        return response
    rpc.request=synthetic_agent;put=store.put;fail=[True]
    def crash(rid,name,value,**kwargs):
        if name=='roles/juiz/phases/final' and fail[0]:
            fail[0]=False;raise OSError('MOCK final publication crash')
        return put(rid,name,value,**kwargs)
    monkeypatch.setattr(store,'put',crash)
    first=asyncio.run(Workflow(store,m.run_id,runtime=runtime).run())
    assert first['status']=='blocked' and len(store.get(m.run_id,'ledger')['calls'])==9
    assert first['operational_blockers'][0]['kind']=='local_persistence'
    monkeypatch.setattr(store,'put',put)
    stale=proof();stale['checked_at']=(datetime.now(timezone.utc)-timedelta(minutes=31)).isoformat();store.put(m.run_id,'financial-confirmation',stale)
    restored=CodexRuntime(store,m.run_id,runtime.config)
    async def forbidden():raise AssertionError('Pure local recovery must not start the official client')
    monkeypatch.setattr(restored,'start',forbidden)
    second=asyncio.run(Workflow(store,m.run_id,runtime=restored).run(resume=True))
    third=asyncio.run(Workflow(store,m.run_id,runtime=restored).run(resume=True))
    assert second['phase']==third['phase']=='done'
    assert len(second['completed'])==9 and len(set(second['completed']))==9
    assert len(store.get(m.run_id,'ledger')['calls'])==9
    assert store.get(m.run_id,'financial-confirmation')==stale
    assert store.get(m.run_id,'judgment')['summary']=='MOCK synthetic final'
    assert store.get(m.run_id,'roles/juiz/state')['phase']=='final'
    assert second['operational_blockers']==[] and second['reconciliation_records']
    from audit3.report import build_report
    report=build_report(store,m.run_id)
    assert not any(x['text'].startswith('Persistência local') for x in report['completion_assessment']['limitations'])


def test_official_completion_does_not_accept_reads_added_after_interruption(make_run):
    store,m,runtime,rpc,_=rig(make_run);store.put(m.run_id,'baseline',{'ids':[]});rpc.mode='transport'
    with pytest.raises(RuntimePaused):asyncio.run(Workflow(store,m.run_id,runtime=runtime).invoke('auditor','initial-0000'))
    inv=store.get(m.run_id,'roles/auditor/attempts/initial-0000-0')['invocation_id']
    cp=store.get(m.run_id,'codex-turns/'+inv)
    # A legitimate synthetic tool read, but too late to support the original answer.
    opinion=initial_investigation(store,m,'auditor')
    observer=FakeRPC(runtime.home);runtime.rpc=observer;request=observer.request
    async def official(method,params,**kwargs):
        if method=='thread/turns/list':
            return {'data':[{'id':cp['turn_id'],'status':'completed','items':[
                {'id':'MOCK-final','type':'agentMessage','phase':'final_answer','text':opinion.model_dump_json()}
            ] if params['itemsView']=='full' else []}],'nextCursor':None}
        return await request(method,params,**kwargs)
    observer.request=official
    result=asyncio.run(recover(Workflow(store,m.run_id,runtime=runtime),inv,check_official=True))
    assert any(p['status']=='completed_output_invalid' for p in result['pending'])
    assert not store.exists(m.run_id,'roles/auditor/phases/initial-0000')
    assert store.get(m.run_id,'confirmed-results/'+inv)['finished_at']==cp['stopped_at']
