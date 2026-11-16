"""Synthetic slot-3 authorization and transport tests; no official inference."""
import asyncio
import copy
import json
import pytest
from audit3.agents import RuntimePaused, AmbiguousTurn
from audit3.batch_distribution import build_distribution, register_distribution, RECORD
from audit3.codex_policy import account_identity
from audit3.codex_runtime import CodexRuntime
from audit3.config import Config
from audit3.recovery_authorization import VERSION, CONTROLLER_VERSION, package_hashes, authorization_name
from audit3.security import PolicyError, object_hash, now
from audit3.workflow import Workflow
from helpers import initial_investigation
from test_codex_runtime import FakeRPC, ACCOUNT, proof
from test_runtime_tool_budget import controlled_clock, scripted, final_events
from test_context_compaction import compaction_events


def reseal(value):
    value['id'] = object_hash({k:v for k,v in value.items() if k!='id'})
    return value


def setup_chain(make_run):
    cfg=Config();cfg.limits.max_turns=32;cfg.limits.read_lines=500;cfg.limits.batch_lines=4000
    cfg.limits.max_calls=240;cfg.limits.total_seconds=14400;cfg.limits.call_timeout=300
    store,m=make_run(config=cfg);rid=m.run_id
    binding={'backend':'codex-app-server','client_version':'0.167.0','model':'gpt-6-astra','effort':'max',
             'account_fingerprint':account_identity(ACCOUNT),'snapshot':m.source_id}
    session={'role':'auditor','run_id':rid,**binding,'thread_id':'MOCK-thread'}
    store.put(rid,'runtime-binding',binding,immutable=True);store.put(rid,'roles/auditor/codex-session',session,immutable=True)
    store.put(rid,'baseline',{'ids':[]});calls=[]
    for slot in range(3):
        inv=str(slot+1)*24;name=f'roles/auditor/attempts/initial-0000-{slot}'
        attempt={'invocation_id':inv,'input_hash':'MOCK historic input','started_at':now()}
        cp={'role':'auditor','phase':'initial-0000','status':'ambiguous','dispatch_status':'written',
            'thread_id':session['thread_id'],'turn_id':f'MOCK-old-turn-{slot}','call_id':inv}
        marker={'source':'official_app_server_thread_read','status':'interrupted','invocation_id':inv,
                'thread_id':cp['thread_id'],'turn_id':cp['turn_id']}
        official={**marker,'run_id':rid,'slot':slot,'generation_requests':0,'checked_at':now(),
                  'checkpoint_hash':object_hash(cp),'runtime_binding_hash':object_hash(binding)}
        store.put(rid,name,attempt,immutable=True);store.put(rid,'codex-turns/'+inv,cp,immutable=True)
        store.put(rid,name+'-interrupted',marker,immutable=True)
        store.put(rid,f'operational/recovery-official-status/slot3-{slot}',official,immutable=True)
        calls.append({'id':inv,'invocation_id':inv,'role':'auditor','status':'error','dispatch_status':'written',
                      'cost_usd':None,'input_tokens':None,'output_tokens':None})
    store.put(rid,'ledger',{'calls':calls,'known_cost_usd':None,'tokens':None,'unknown_cost_calls':3})
    state=store.get(rid,'state');state['elapsed_seconds']=142.41566506499657;store.put(rid,'state',state)
    distribution=build_distribution(store,m,cfg,'MOCK operator');register_distribution(store,m,cfg,distribution)
    parent_name='roles/auditor/attempts/initial-0000-extra-authorization'
    parent={'source':'explicit_operator_authorization','run_id':rid,'role':'auditor','phase':'initial-0000',
            'additional_attempts':1,'attempt_slot':2,'config_hash':m.config_hash,'previous_invocation_id':'2'*24}
    store.put(rid,parent_name,parent,immutable=True)
    version_name='operational/controller-continuation-version-slot3'
    version={'version':CONTROLLER_VERSION,'run_id':rid,'source_id':m.source_id,'config_hash':m.config_hash,
             'profile_hash':m.profile_hash,'batch_distribution_id':distribution['id'],
             'authorized_scope':{'role':'auditor','phase':'initial-0000','slot':3,'count':1},
             'package_hashes':package_hashes(),'original_call_hashes':[object_hash(c) for c in calls],
             'original_elapsed_seconds':state['elapsed_seconds']}
    store.put(rid,version_name,version,immutable=True)
    prior=[]
    for slot in range(3):
        name=f'roles/auditor/attempts/initial-0000-{slot}';a=store.get(rid,name);cp=store.get(rid,'codex-turns/'+a['invocation_id']);official_name=f'operational/recovery-official-status/slot3-{slot}'
        prior.append({'slot':slot,'invocation_id':a['invocation_id'],'attempt_hash':object_hash(a),
                      'checkpoint_hash':object_hash(cp),'interruption_hash':object_hash(store.get(rid,name+'-interrupted')),
                      'official_record':official_name,'official_hash':object_hash(store.get(rid,official_name))})
    auth=reseal({'version':VERSION,'source':'explicit_operator_authorization','run_id':rid,'role':'auditor',
        'phase':'initial-0000','attempt_slot':3,'additional_attempts':1,'source_id':m.source_id,
        'config_hash':m.config_hash,'profile_hash':m.profile_hash,'parent_name':parent_name,'parent_hash':object_hash(parent),
        'batch_distribution_id':distribution['id'],'assignment_hash':object_hash(distribution['batches'][0]),
        'runtime_binding_hash':object_hash(binding),'role_session_hash':object_hash(session),
        'controller_version_record':version_name,'controller_version_hash':object_hash(version),
        'past_call_hashes':version['original_call_hashes'],'elapsed_floor':state['elapsed_seconds'],'prior_attempts':prior})
    auth_name=authorization_name('auditor','initial-0000');store.put(rid,auth_name,auth,immutable=True)
    runtime=CodexRuntime(store,rid,cfg);rpc=FakeRPC(runtime.home);runtime.rpc=rpc
    store.put(rid,'financial-confirmation',proof())
    return store,m,runtime,rpc,auth_name,auth


def test_slot3_after_compaction_accepts_only_valid_own_inspection_and_reuses_cache(make_run):
    store,m,runtime,rpc,name,auth=setup_chain(make_run);rid=m.run_id
    opinion=initial_investigation(store,m,'auditor');old_calls=copy.deepcopy(store.get(rid,'ledger')['calls'])
    before={key:store.get(rid,key) for key in ['roles/auditor/attempts/initial-0000-extra-authorization']+
            [f'roles/auditor/attempts/initial-0000-{n}' for n in range(3)]+['codex-turns/'+str(n+1)*24 for n in range(3)]}
    def events(base):
        finish=final_events(base);finish[0]['params']['item']['text']=opinion.model_dump_json()
        return compaction_events(base)+finish
    scripted(rpc,events);workflow=Workflow(store,rid,runtime=runtime)
    result=asyncio.run(workflow.invoke('auditor','initial-0000'))
    assert result['inspections'] and not result['findings']
    asyncio.run(workflow.invoke('auditor','initial-0000'))
    ledger=store.get(rid,'ledger');assert len(ledger['calls'])==4 and ledger['calls'][:3]==old_calls
    assert sum(method=='turn/start' for method,_ in rpc.calls)==1
    assert not store.exists(rid,'roles/auditor/attempts/initial-0000-4')
    assert store.get(rid,'state')['elapsed_seconds']==142.41566506499657
    assert all(store.get(rid,k)==v for k,v in before.items())
    assert store.get(rid,name)==auth and not store.exists(rid,'barrier')
    inv=store.get(rid,'roles/auditor/attempts/initial-0000-3')['invocation_id']
    assert store.get(rid,'codex-turns/'+inv)['context_compaction']['completed']==1


@pytest.mark.parametrize('mode',['transport','native','invalid'])
def test_failed_fourth_call_never_gets_another_slot_or_starts_other_roles(make_run,mode):
    store,m,runtime,rpc,_,_=setup_chain(make_run);rid=m.run_id;rpc.mode=mode if mode!='invalid' else 'complete'
    if mode=='invalid':rpc.output='{'
    workflow=Workflow(store,rid,runtime=runtime)
    state=asyncio.run(workflow.run(resume=True))
    assert state['status'] in {'blocked','partial'} and state['elapsed_seconds']>=142.41566506499657
    assert len(store.get(rid,'ledger')['calls'])==4
    assert sum(method=='turn/start' for method,_ in rpc.calls)==1
    assert not store.exists(rid,'roles/defensor/codex-session') and not store.exists(rid,'roles/juiz/codex-session')
    assert not store.exists(rid,'roles/auditor/attempts/initial-0000-4')
    with pytest.raises(PolicyError):asyncio.run(workflow.invoke('auditor','initial-0000'))
    assert sum(method=='turn/start' for method,_ in rpc.calls)==1


@pytest.mark.parametrize('field,value',[
    ('source','automatic_retry'),('role','defensor'),('phase','contest'),('attempt_slot',4),('additional_attempts',2),
    ('run_id','0'*24),('source_id','wrong'),('config_hash','wrong'),('profile_hash','wrong'),('parent_hash','wrong'),
    ('batch_distribution_id','wrong'),('assignment_hash','wrong'),('runtime_binding_hash','wrong'),('role_session_hash','wrong'),
    ('controller_version_record','operational/other'),('controller_version_hash','wrong'),('elapsed_floor',0)])
def test_invalid_resealed_authorization_spends_no_call(make_run,field,value):
    store,m,runtime,rpc,name,auth=setup_chain(make_run);bad=copy.deepcopy(auth);bad[field]=value
    store.put(m.run_id,name,reseal(bad))  # Malformed synthetic authority, not a real record rewrite.
    with pytest.raises(RuntimePaused,match='encadeada inválida'):
        asyncio.run(Workflow(store,m.run_id,runtime=runtime).invoke('auditor','initial-0000'))
    assert not rpc.calls and len(store.get(m.run_id,'ledger')['calls'])==3


@pytest.mark.parametrize('change',['prior_hash','missing_prior','official_completed','official_active','other_session','other_turn','checkpoint_not_sent','code_version','old_calls','elapsed_reset'])
def test_chain_requires_three_official_interruptions_and_unchanged_accounting(make_run,change):
    store,m,runtime,rpc,name,auth=setup_chain(make_run);rid=m.run_id
    if change=='prior_hash':auth['prior_attempts'][0]['checkpoint_hash']='wrong';store.put(rid,name,reseal(auth))
    elif change=='missing_prior':auth['prior_attempts'].pop(0);store.put(rid,name,reseal(auth))
    elif change in ('official_completed','official_active','other_session','other_turn'):
        official_name='operational/recovery-official-status/slot3-0';value=store.get(rid,official_name)
        if change=='official_completed':value['status']='completed'
        if change=='official_active':value['status']='inProgress'
        if change=='other_session':value['thread_id']='MOCK-other'
        if change=='other_turn':value['turn_id']='MOCK-other'
        store.put(rid,official_name,value)
    elif change=='checkpoint_not_sent':
        value=store.get(rid,'codex-turns/'+'1'*24);value['dispatch_status']='not_sent';store.put(rid,'codex-turns/'+'1'*24,value)
    elif change=='code_version':
        version=store.get(rid,auth['controller_version_record']);version['package_hashes']['codex_runtime.py']='wrong';store.put(rid,auth['controller_version_record'],version)
        auth['controller_version_hash']=object_hash(version);store.put(rid,name,reseal(auth))
    elif change=='old_calls':
        value=store.get(rid,'ledger');value['calls'].pop(0);store.put(rid,'ledger',value)
    elif change=='elapsed_reset':
        value=store.get(rid,'state');value['elapsed_seconds']=0;store.put(rid,'state',value)
    with pytest.raises(PolicyError):asyncio.run(Workflow(store,rid,runtime=runtime).invoke('auditor','initial-0000'))
    assert not any(method=='turn/start' for method,_ in rpc.calls)


def test_copying_scope_to_another_role_cannot_grant_an_extra_attempt(make_run):
    store,m,runtime,rpc,name,auth=setup_chain(make_run)
    store.put(m.run_id,authorization_name('defensor','initial-0000'),auth)
    with pytest.raises(RuntimePaused):asyncio.run(Workflow(store,m.run_id,runtime=runtime).invoke('defensor','initial-0000'))
    assert not rpc.calls
