"""Local synthetic distributions and mocked continuation; no audited host code."""
import asyncio
import copy
from pathlib import Path
import pytest
from audit3.batch_distribution import (RECORD, RESERVES, build_distribution, validate_distribution,
    register_distribution, effective_batches, assignment_for_phase)
from audit3.config import Config, Profile
from audit3.executor import Executor
from audit3.schemas import TestRequest as Request, Opinion, Judgment, InspectionRecord, SourceRef
from audit3.security import PolicyError, object_hash, now
from audit3.workflow import Workflow, batches
from audit3.investigation import assess_independent_investigation, validate_saved_initial
from audit3.report import build_report
from audit3.completion import context_hash
from audit3.codex_runtime import CodexRuntime
from audit3.agents import RuntimePaused, AmbiguousTurn
from helpers import MockRuntime, initial_investigation
from test_codex_runtime import FakeRPC, proof
from test_runtime_tool_budget import controlled_clock


def fixture(make_run, monkeypatch):
    cfg = Config(); cfg.limits.max_turns = 32; cfg.limits.read_lines = 500
    cfg.limits.batch_lines = 4000; cfg.limits.max_calls = 240; cfg.limits.total_seconds = 14400; cfg.limits.call_timeout = 300
    content = {'a.py': '# synthetic\n' * 4000, **{f'z{i:02d}.py': '# synthetic\n' for i in range(33)}}
    store, m = make_run(content=content, config=cfg)
    monkeypatch.setattr('audit3.executor.shutil.which', lambda _: None)
    # Ordinary Executor emits an explicitly unexecuted baseline. No Docker or
    # audited source is executed. Protocol completion remains a MOCK result.
    receipt = asyncio.run(Executor(store, m, cfg, Profile(name='synthetic')).execute(
        Request(kind='baseline', purpose='MOCK planning baseline, not executed'), 'baseline', 'baseline'))
    store.put(m.run_id, 'baseline', {'ids': [receipt.id]})
    return store, m, cfg


def signed(record):
    record['id'] = object_hash({k: v for k, v in record.items() if k != 'id'})
    return record


def history(store, m):
    return {str(p): p.read_bytes() for p in store.path(m.run_id).rglob('*') if p.is_file()}


def assigned_runtime():
    """Opt-in positive mock: only its assigned work, not whole-source auto coverage."""
    async def handler(role, phase, payload, tools, final):
        from helpers import read_phase_context
        read_phase_context(payload, tools)
        if final:
            return Judgment(summary='MOCK phase completion', verdicts=[], new_findings=[], limitations=[])
        records = []
        assignment = payload['assignment'] if phase.startswith('initial-') else []
        if phase == 'blind':
            f = next(f for f in tools.manifest.files if f.lines and f.category != 'excluded')
            assignment = [{'path': f.path, 'start': 1, 'end': 1, 'sha256': f.sha256}]
        for ref in assignment:
            cursor = ref['start']
            while cursor <= ref['end']:
                response = tools.read_source(ref['path'], cursor, ref['end'])
                end = response['lines'][-1]['line']
                records.append(InspectionRecord(refs=[SourceRef(path=ref['path'], start=cursor, end=end, sha256=ref['sha256'])],
                    requirement='Synthetic assigned invariant', analysis='MOCK explicit assigned inspection',
                    flow_verified=False, flow_description='', limitations=[]))
                cursor = end + 1
        return Opinion(summary='MOCK assigned phase', inspections=records, findings=[], positions=[], limitations=[])
    return MockRuntime(handler)


def test_split_preserves_original_scope_history_and_reserved_capacity(make_run, monkeypatch):
    store, m, cfg = fixture(make_run, monkeypatch)
    original = batches(m, cfg.limits.batch_lines)
    assert effective_batches(store, m, cfg) == original
    before = history(store, m)
    record = build_distribution(store, m, cfg, 'MOCK operator')
    assert history(store, m) == before
    assert len(original) == 2 and len(record['batches']) == 3
    assert record['original_batches'] == original and record['batches'][0] == original[0]
    assert record['mapping'] == {'initial-0000': ['initial-0000'], 'initial-0001': ['initial-0001', 'initial-0002']}
    assert record['reserves'] == RESERVES
    assert [c['minimum_source_calls'] for c in record['costs']] == [8, 17, 16]
    assert all(c['required_tool_capacity'] <= 32 and c['reserved_tool_calls'] == 7 for c in record['costs'])
    register_distribution(store, m, cfg, record)
    assert effective_batches(store, m, cfg) == record['batches']
    assert all(Path(p).read_bytes() == data for p, data in before.items())
    assert not store.get(m.run_id, 'state')['completed']
    assert not assess_independent_investigation(store, m)['valid']
    assert not store.exists(m.run_id, 'barrier')


@pytest.mark.parametrize('change', ['lost', 'duplicate', 'parent', 'source', 'mapping', 'cost', 'reserve', 'original'])
def test_resealed_invalid_distribution_is_refused(make_run, monkeypatch, change):
    store, m, cfg = fixture(make_run, monkeypatch)
    r = build_distribution(store, m, cfg, 'MOCK operator')
    if change == 'lost': r['batches'][-1].pop()
    if change == 'duplicate': r['batches'][-1].append(copy.deepcopy(r['batches'][-1][0]))
    if change == 'parent': r['parents'][-1] = 0
    if change == 'source': r['source_id'] = 'wrong'
    if change == 'mapping': r['mapping']['initial-0000'] = ['initial-0002']
    if change == 'cost': r['costs'][-1]['minimum_source_calls'] = 0
    if change == 'reserve': r['reserves'] = {}
    if change == 'original': r['original_batches'][0][0]['end'] -= 1
    with pytest.raises(PolicyError): validate_distribution(store, m, cfg, signed(r))
    assert not store.exists(m.run_id, RECORD)


def test_started_batch_cannot_be_renumbered_or_split(make_run, monkeypatch):
    store, m, cfg = fixture(make_run, monkeypatch)
    store.put(m.run_id, 'roles/auditor/attempts/initial-0001-0', {'invocation_id': 'MOCK started'})
    with pytest.raises(PolicyError, match='fase já iniciada'):
        build_distribution(store, m, cfg, 'MOCK operator')


@pytest.mark.parametrize('phase', ['initial--001', 'initial-1', 'initial-00000', 'initial-9999', 'initial-xyz'])
def test_noncanonical_or_missing_batch_ids_are_refused(make_run, monkeypatch, phase):
    store, m, cfg = fixture(make_run, monkeypatch)
    r = build_distribution(store, m, cfg, 'MOCK operator'); register_distribution(store, m, cfg, r)
    with pytest.raises(PolicyError, match='lote inicial inexistente'):
        assignment_for_phase(store, m, cfg, phase)


def test_all_versioned_phases_finish_and_missing_child_remains_blocking(make_run, monkeypatch):
    store, m, cfg = fixture(make_run, monkeypatch)
    r = build_distribution(store, m, cfg, 'MOCK operator'); register_distribution(store, m, cfg, r)
    runtime = assigned_runtime()
    state = asyncio.run(Workflow(store, m.run_id, runtime=runtime).run())
    assert state['phase'] == 'done'
    assert assess_independent_investigation(store, m)['valid']
    report = build_report(store, m.run_id)
    assert report['batch_distribution']['id'] == r['id']
    for role in ('auditor', 'defensor'):
        assert f'{role}/initial-0002' in report['required_phases']
        assert store.get(m.run_id, f'roles/{role}/phases/initial-0002')['batch_distribution_id'] == r['id']
    assert store.get(m.run_id, 'barrier')['batch_distribution_id'] == r['id']
    assert report['completion_assessment']['status'] == 'partial'  # MOCK/unexecuted baseline stay explicit.
    last = store.path(m.run_id, 'roles/defensor/phases/initial-0002.json')
    last.unlink()  # Synthetic missing-phase failure injection only.
    assert not assess_independent_investigation(store, m)['valid']
    assert build_report(store, m.run_id)['completion_assessment']['status'] == 'partial'
    before = len(runtime.calls)
    with pytest.raises(PolicyError): asyncio.run(Workflow(store, m.run_id, runtime=runtime).run(resume=True))
    assert len(runtime.calls) == before


def test_phase_version_and_review_context_cannot_be_reused_after_change(make_run, monkeypatch):
    store, m, cfg = fixture(make_run, monkeypatch)
    r = build_distribution(store, m, cfg, 'MOCK operator'); register_distribution(store, m, cfg, r)
    asyncio.run(Workflow(store, m.run_id, runtime=assigned_runtime()).independent('auditor'))
    name = 'roles/auditor/phases/initial-0000'
    phase = store.get(m.run_id, name);phase.pop('batch_distribution_id');store.put(m.run_id, name, phase)
    with pytest.raises(PolicyError, match='vínculo à distribuição'):
        validate_saved_initial(store, m, cfg, 'auditor', 'initial-0000')
    report = {'batch_distribution': r}
    old = context_hash(report); report['batch_distribution'] = {**r, 'reviewer': 'different'}
    assert context_hash(report) != old


def two_stopped_attempts(store, m):
    prior = []
    calls = []
    for slot in (0, 1):
        inv = str(slot + 1) * 24; name = f'roles/auditor/attempts/initial-0000-{slot}'
        attempt = {'invocation_id': inv}; checkpoint = {'role': 'auditor', 'phase': 'initial-0000',
            'status': 'ambiguous', 'thread_id': 'MOCK-old-thread', 'turn_id': f'MOCK-old-{slot}'}
        store.put(m.run_id, name, attempt, immutable=True)
        store.put(m.run_id, 'codex-turns/'+inv, checkpoint, immutable=True)
        store.put(m.run_id, name+'-interrupted', {'source': 'official_app_server_thread_read', 'status': 'interrupted',
            'invocation_id': inv, 'thread_id': checkpoint['thread_id'], 'turn_id': checkpoint['turn_id']}, immutable=True)
        calls.append({'id': inv, 'role': 'auditor', 'status': 'error', 'invocation_id': inv,
                      'cost_usd': None, 'input_tokens': None, 'output_tokens': None})
        prior.append({'slot': slot, 'invocation_id': inv, 'attempt_hash': object_hash(attempt), 'checkpoint_hash': object_hash(checkpoint)})
    store.put(m.run_id, 'ledger', {'calls': calls, 'known_cost_usd': None, 'tokens': None, 'unknown_cost_calls': 2})
    state = store.get(m.run_id, 'state');state['elapsed_seconds'] = 134.94579965699813;store.put(m.run_id, 'state', state)
    return prior


@pytest.mark.parametrize('mode', ['complete', 'transport', 'native'])
def test_exact_one_extra_attempt_preserves_history_and_never_retries(make_run, monkeypatch, mode):
    store, m, cfg = fixture(make_run, monkeypatch)
    prior = two_stopped_attempts(store, m)
    r = build_distribution(store, m, cfg, 'MOCK operator');register_distribution(store, m, cfg, r)
    auth = {'source': 'explicit_operator_authorization', 'run_id': m.run_id, 'role': 'auditor',
        'phase': 'initial-0000', 'additional_attempts': 1, 'attempt_slot': 2, 'config_hash': m.config_hash,
        'previous_invocation_id': prior[-1]['invocation_id'], 'prior_attempts': prior}
    store.put(m.run_id, 'roles/auditor/attempts/initial-0000-extra-authorization', auth, immutable=True)
    original = {n: store.get(m.run_id, n) for n in r['protected_records']}
    runtime = CodexRuntime(store, m.run_id, cfg);rpc = FakeRPC(runtime.home);runtime.rpc = rpc;rpc.mode = mode
    store.put(m.run_id, 'financial-confirmation', proof())
    rpc.output = initial_investigation(store, m, 'auditor').model_dump_json()
    workflow = Workflow(store, m.run_id, runtime=runtime)
    if mode == 'complete':
        asyncio.run(workflow.invoke('auditor', 'initial-0000'))
        asyncio.run(workflow.invoke('auditor', 'initial-0000'))
    else:
        with pytest.raises(RuntimePaused): asyncio.run(workflow.invoke('auditor', 'initial-0000'))
        with pytest.raises(AmbiguousTurn): asyncio.run(workflow.invoke('auditor', 'initial-0000'))
        if mode == 'native':
            inv = store.get(m.run_id, 'roles/auditor/attempts/initial-0000-2')['invocation_id']
            assert store.get(m.run_id, 'codex-turns/'+inv)['protocol_failure']['attempt'] == 2
    assert sum(method == 'turn/start' for method, _ in rpc.calls) == 1
    assert len(store.get(m.run_id, 'ledger')['calls']) == 3
    assert store.get(m.run_id, 'state')['elapsed_seconds'] == 134.94579965699813
    assert all(store.get(m.run_id, n) == value for n, value in original.items())
    assert not store.exists(m.run_id, 'roles/auditor/attempts/initial-0000-3')
    assert not store.exists(m.run_id, 'roles/defensor/attempts/initial-0000-extra-authorization')
    assert not store.exists(m.run_id, 'barrier')


@pytest.mark.parametrize('change', ['old_call', 'elapsed', 'checkpoint', 'attempt'])
def test_distribution_refuses_recycled_history_or_counters(make_run, monkeypatch, change):
    store, m, cfg = fixture(make_run, monkeypatch);two_stopped_attempts(store, m)
    r = build_distribution(store, m, cfg, 'MOCK operator')
    if change == 'old_call':
        ledger = store.get(m.run_id, 'ledger');ledger['calls'].pop(0);store.put(m.run_id, 'ledger', ledger)
    elif change == 'elapsed':
        state = store.get(m.run_id, 'state');state['elapsed_seconds'] = 0;store.put(m.run_id, 'state', state)
    else:
        name = 'codex-turns/'+'1'*24 if change == 'checkpoint' else 'roles/auditor/attempts/initial-0000-0'
        old = store.get(m.run_id, name);old['altered'] = True;store.put(m.run_id, name, old)
    with pytest.raises(PolicyError): validate_distribution(store, m, cfg, r)


def test_failed_authorized_auditor_slot_stops_before_other_roles(make_run, monkeypatch):
    store, m, cfg = fixture(make_run, monkeypatch);prior = two_stopped_attempts(store, m)
    r = build_distribution(store, m, cfg, 'MOCK operator');register_distribution(store, m, cfg, r)
    auth = {'source': 'explicit_operator_authorization', 'run_id': m.run_id, 'role': 'auditor',
        'phase': 'initial-0000', 'additional_attempts': 1, 'attempt_slot': 2, 'config_hash': m.config_hash,
        'previous_invocation_id': prior[-1]['invocation_id'], 'prior_attempts': prior}
    store.put(m.run_id, 'roles/auditor/attempts/initial-0000-extra-authorization', auth, immutable=True)
    runtime = CodexRuntime(store, m.run_id, cfg);rpc = FakeRPC(runtime.home);runtime.rpc = rpc;rpc.mode = 'transport'
    store.put(m.run_id, 'financial-confirmation', proof())
    state = asyncio.run(Workflow(store, m.run_id, runtime=runtime).run(resume=True))
    assert state['status'] == 'blocked' and state['elapsed_seconds'] >= 134.94579965699813
    assert len(store.get(m.run_id, 'ledger')['calls']) == 3
    assert sum(method == 'turn/start' for method, _ in rpc.calls) == 1
    assert not store.exists(m.run_id, 'roles/defensor/codex-session')
    assert not store.exists(m.run_id, 'roles/juiz/codex-session')


@pytest.mark.parametrize('reserved', [False, True])
def test_prepared_unsent_slot_keeps_identity_and_old_context(make_run, monkeypatch, reserved):
    store, m, cfg = fixture(make_run, monkeypatch)
    inv = 'd'*24;name = 'roles/defensor/attempts/initial-0000-0'
    old = {'invocation_id': inv, 'input_hash': 'old-prepared-input', 'started_at': now()}
    store.put(m.run_id, name, old, immutable=True)
    if reserved:
        ledger = store.get(m.run_id, 'ledger');ledger['calls'] = [{'id': 'e'*24, 'invocation_id': inv, 'role': 'defensor', 'status': 'in_flight'}]
        # Build the distribution before the injected reservation: this case
        # simulates a later interrupted reservation, not approval of active work.
        r = build_distribution(store, m, cfg, 'MOCK operator');register_distribution(store, m, cfg, r)
        store.put(m.run_id, 'ledger', ledger)
    else:
        r = build_distribution(store, m, cfg, 'MOCK operator');register_distribution(store, m, cfg, r)
    runtime = CodexRuntime(store, m.run_id, cfg);rpc = FakeRPC(runtime.home);runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    rpc.output = initial_investigation(store, m, 'defensor').model_dump_json()
    if reserved:
        with pytest.raises(RuntimePaused, match='Reserva anterior sem checkpoint'):
            asyncio.run(Workflow(store, m.run_id, runtime=runtime).invoke('defensor', 'initial-0000'))
        assert not rpc.calls
        assert len(store.get(m.run_id, 'ledger')['calls']) == 1
    else:
        asyncio.run(Workflow(store, m.run_id, runtime=runtime).invoke('defensor', 'initial-0000'))
        assert store.get(m.run_id, 'ledger')['calls'][0]['invocation_id'] == inv
        continuation = store.get(m.run_id, name+'-distribution-continuation')
        assert continuation['original_attempt_hash'] == object_hash(old)
        assert continuation['batch_distribution_id'] == r['id']
        assert sum(method == 'turn/start' for method, _ in rpc.calls) == 1
        assert not store.exists(m.run_id, 'roles/defensor/attempts/initial-0000-1')
    assert store.get(m.run_id, name) == old
