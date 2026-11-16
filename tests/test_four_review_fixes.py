"""Offline regressions A–D; explicit fake transport, synthetic source only."""
import asyncio
import copy
import json
from pathlib import Path
import pytest
from audit3.agents import RuntimePaused
from audit3.cli import main
from audit3.codex_runtime import CodexRuntime
from audit3.config import Config
from audit3.context_pages import create_reference
from audit3.recovery import recover
from audit3.report import build_report
from audit3.reprocess import OverlayStore
from audit3.schemas import Opinion, Judgment, InspectionRecord, SourceRef
from audit3.security import PolicyError, object_hash
from audit3.tools import SourceTools, ToolContext
from audit3.turn_planning import global_plan
from audit3.workflow import Workflow
from helpers import MockRuntime, initial_investigation, read_phase_context
from test_codex_runtime import FakeRPC, proof
from test_decisions_comparisons import verdict
from test_runtime_tool_budget import controlled_clock
from test_tools_schemas import finding


def synthetic_transport(home, manifest):
    """Provide contract responses and authentic tool dispatch, never inference."""
    rpc = FakeRPC(home)
    request = rpc.request
    async def respond(method, params, **kwargs):
        reads = []
        if method == 'turn/start':
            payload = json.loads(params['input'][0]['text'])
            phase = payload['phase']
            if phase.startswith('initial-'):
                reads = payload['assignment']
            elif phase == 'blind':
                f = next(f for f in manifest.files if f.lines and f.category != 'excluded')
                reads = [{'path': f.path, 'start': 1, 'end': 1, 'sha256': f.sha256}]
            output = (Judgment(summary='MOCK final', baseline_assessment='MOCK baseline limitations retained',
                               verdicts=[], new_findings=[], limitations=[]) if phase == 'final' else
                      Opinion(summary='MOCK opinion', findings=[], positions=[], limitations=[], inspections=[
                          InspectionRecord(refs=[SourceRef(**r)], requirement='Synthetic invariant',
                              analysis='MOCK own source inspection', flow_verified=False,
                              flow_description='', limitations=[]) for r in reads]))
            rpc.output = output.model_dump_json()
        result = await request(method, params, **kwargs)
        if method == 'turn/start':
            finish = []
            while not rpc.events.empty(): finish.append(rpc.events.get_nowait())
            calls = [('read_source', {k: r[k] for k in ('path', 'start', 'end')}) for r in reads]
            calls += [('read_evidence', {'evidence_id': p}) for p in payload.get('required_context_pages', [])]
            calls += [('read_evidence', {'evidence_id': p}) for p in payload['baseline_receipts']]
            for i, (tool, args) in enumerate(calls):
                rpc.events.put_nowait({'id': i, 'method': 'item/tool/call', 'params': {
                    'threadId': params['threadId'], 'turnId': result['turn']['id'], 'tool': tool, 'arguments': args}})
            for event in finish: rpc.events.put_nowait(event)
        return result
    rpc.request = respond
    return rpc


def frozen_records(store, rid, names):
    return {n: store.path(rid, n + '.json').read_bytes() for n in names}


def test_a_cli_run_recover_resume_settles_unsent_reservation(make_run, monkeypatch, capsys):
    store, m = make_run()
    monkeypatch.setattr('audit3.executor.shutil.which', lambda _: None)
    instances = []
    async def fake_start(runtime):
        if runtime.rpc is None:
            runtime.rpc = synthetic_transport(runtime.home, m)
            instances.append(runtime.rpc)
    monkeypatch.setattr(CodexRuntime, 'start', fake_start)
    store.put(m.run_id, 'financial-confirmation', proof())  # Synthetic facts only.
    put = store.put
    def fail_ledger(rid, name, value, **kwargs):
        if name == 'ledger' and value['calls']:
            raise OSError('MOCK crash after durable reservation, before ledger')
        return put(rid, name, value, **kwargs)
    # CLI constructs its own Store instance; intercept the same write boundary.
    from audit3.evidence import Store
    original = Store.put
    def crash(self, rid, name, value, **kwargs):
        if self.root == store.root: return fail_ledger(rid, name, value, **kwargs)
        return original(self, rid, name, value, **kwargs)
    monkeypatch.setattr(Store, 'put', crash)
    assert main(['--store', str(store.root), 'run', '--prepared', m.run_id]) == 2
    monkeypatch.setattr(Store, 'put', original)
    assert not any(method == 'turn/start' for rpc in instances for method, _ in rpc.calls)
    attempt = 'roles/auditor/attempts/initial-0000-0'
    inv = store.get(m.run_id, attempt)['invocation_id']
    reservation = store.names(m.run_id, 'accounting/reservations')[0]
    immutable = frozen_records(store, m.run_id, [attempt, 'accounting/reservations/' + reservation, 'config', 'manifest'])
    # Recovery is local even when factual confirmation is expired.
    facts = store.get(m.run_id, 'financial-confirmation')
    expired = {**facts, 'checked_at': '2000-01-01T00:00:00+00:00'}
    store.put(m.run_id, 'financial-confirmation', expired)
    observed = sum(len(rpc.calls) for rpc in instances)
    args = ['--store', str(store.root), 'recover', m.run_id, '--invocation', inv, '--allow-next-attempt']
    assert main(args) == 0
    decision = frozen_records(store, m.run_id, ['recovery-decisions/' + inv])
    assert main(args) == 0
    assert sum(len(rpc.calls) for rpc in instances) == observed
    assert store.get(m.run_id, 'financial-confirmation') == expired
    assert frozen_records(store, m.run_id, list(decision)) == decision
    store.put(m.run_id, 'financial-confirmation', facts)  # Restore only this mocked test observation.
    assert main(['--store', str(store.root), 'resume', m.run_id]) == 2  # Unexecuted baseline remains partial.
    report = build_report(store, m.run_id)
    assert report['state']['phase'] == 'done' and len(report['state']['completed']) == 9
    assert sum(method == 'turn/start' for rpc in instances for method, _ in rpc.calls) == 9
    ledger = report['usage']
    assert len(ledger['calls']) == 10 and ledger['calls'][0]['invocation_id'] == inv
    assert report['structural_checks']['limits_valid'], report['structural_checks']
    assert ledger['calls'][0]['status'] == 'not_sent'
    assert ledger['calls'][0]['input_tokens'] is ledger['calls'][0]['output_tokens'] is None
    assert ledger['tokens'] is ledger['known_cost_usd'] is None
    assert frozen_records(store, m.run_id, list(immutable)) == immutable
    assert report['completion_assessment']['status'] == 'partial'
    assert report['state'].get('operational_blockers', []) == []
    assert report['operational_history']


def judge_run(make_run, monkeypatch, origin, *, omit=None, change_mechanism=False):
    monkeypatch.setattr('audit3.executor.shutil.which', lambda _: None)
    store, m = make_run({'app.py': 'def refund(balance, amount):\n    return balance + amount\n'})
    f = finding(m, id='juiz-refund', refs=[SourceRef(path='app.py', start=1, end=2, sha256=m.files[0].sha256)],
                mechanism='Addition contradicts required subtraction')
    async def handler(role, phase, payload, tools, final):
        read_phase_context(payload, tools)
        if role + '/' + phase == omit:
            return Opinion(summary='MOCK missing position, intentional negative', inspections=[], findings=[], positions=[], limitations=[])
        if (phase == 'blind' and origin == 'blind_repeated') or phase == 'review':
            tools.read_source('app.py')
            opinion = initial_investigation(store, m, role) if phase == 'blind' else Opinion(
                summary='MOCK review', inspections=[], positions=[], findings=[], limitations=[])
            opinion.findings = [copy.deepcopy(f)]
            if phase == 'review' and change_mechanism:
                opinion.findings[0].mechanism = 'Different mechanism: intentionally invalid ID reuse'
            return opinion
        if final:
            tools.read_source('app.py')
            return Judgment(summary='MOCK static judgment', verdicts=[verdict(f.id, cause=None)], new_findings=[], limitations=[])
    runtime = MockRuntime(handler)
    state = asyncio.run(Workflow(store, m.run_id, runtime=runtime).run())
    return store, m, f, runtime, state


@pytest.mark.parametrize('origin', ['blind_repeated', 'review_new'])
def test_b_judge_finding_uses_its_effective_debate_round(make_run, monkeypatch, origin):
    store, m, f, runtime, state = judge_run(make_run, monkeypatch, origin)
    assert state['phase'] == 'done', state
    gate = store.get(m.run_id, 'material-review')
    assert gate['additional_round'] == (origin == 'review_new')
    assert gate['new_finding_ids'] == ([f.id] if origin == 'review_new' else [])
    phases = [c['phase'] for c in runtime.calls]
    assert phases.count('extra-contest') == (2 if origin == 'review_new' else 0)
    report = build_report(store, m.run_id)
    assert report['structural_checks']['final_validation'], report['structural_checks']
    assert report['judgment']['verdicts'][0]['finding_id'] == f.id


@pytest.mark.parametrize('origin,omit', [('blind_repeated', 'defensor/reply'), ('review_new', 'defensor/extra-reply')])
def test_b_omitted_contradiction_is_still_blocking(make_run, monkeypatch, origin, omit):
    store, m, f, runtime, state = judge_run(make_run, monkeypatch, origin, omit=omit)
    assert state['status'] == 'partial' and not store.exists(m.run_id, 'judgment')
    rejections = [store.get(m.run_id, 'roles/juiz/attempts/' + n)
                  for n in store.names(m.run_id, 'roles/juiz/attempts') if n.endswith('-rejected')]
    assert rejections and all('sem contraditório obrigatório em ' + omit in r['feedback'] for r in rejections)
    assert len([c for c in runtime.calls if c['phase'] == 'final']) == 2


def test_b_reused_id_for_a_different_mechanism_stays_rejected(make_run, monkeypatch):
    store, m, f, runtime, state = judge_run(make_run, monkeypatch, 'blind_repeated', change_mechanism=True)
    assert state['status'] == 'partial' and not store.exists(m.run_id, 'judgment')
    assert 'ID reaproveitado para mecanismo diferente' in state['limitations']
    assert not any(c['phase'] == 'final' for c in runtime.calls)


def test_b_report_checks_new_finding_against_material_record_without_writes(make_run, monkeypatch):
    store, m, f, runtime, state = judge_run(make_run, monkeypatch, 'review_new')
    assert state['phase'] == 'done'
    original = frozen_records(store, m.run_id, ['material-review', 'roles/juiz/phases/final'])
    view = OverlayStore(store, m.run_id, {'material-review': {'additional_round': False, 'new_finding_ids': [], 'new_receipt_ids': []}})
    checks = build_report(view, m.run_id)['structural_checks']
    assert not checks['final_validation'] and 'sem registro material' in checks['final_validation_error']
    assert frozen_records(store, m.run_id, list(original)) == original


def padded_opinion(opinion, size, multibyte):
    opinion.summary = 'MOCK '
    missing = size - len(opinion.model_dump_json().encode('utf-8'))
    opinion.summary += ('á' * (missing // 2) + 'x' * (missing % 2)) if multibyte else ('x ' * (missing // 2) + 'x' * (missing % 2))
    raw = opinion.model_dump_json()
    assert len(raw.encode('utf-8')) == size
    return raw


@pytest.mark.parametrize('delta', [-1, 0, 1])
@pytest.mark.parametrize('multibyte', [False, True])
def test_c_remote_recovery_obeys_exact_utf8_output_cap(make_run, delta, multibyte):
    store, m = make_run(); cfg = Config()
    store.put(m.run_id, 'baseline', {'ids': []})
    runtime = CodexRuntime(store, m.run_id, cfg); rpc = FakeRPC(runtime.home); runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    raw = padded_opinion(initial_investigation(store, m, 'auditor'), cfg.limits.max_output_bytes + delta, multibyte)
    rpc.mode = 'transport'
    with pytest.raises(RuntimePaused):
        asyncio.run(Workflow(store, m.run_id, runtime=runtime).invoke('auditor', 'initial-0000'))
    inv = store.get(m.run_id, 'roles/auditor/attempts/initial-0000-0')['invocation_id']
    cp = store.get(m.run_id, 'codex-turns/' + inv)
    original = frozen_records(store, m.run_id, ['codex-turns/' + inv, 'ledger'])
    observer = FakeRPC(runtime.home); runtime.rpc = observer; request = observer.request
    async def metadata(method, params, **kwargs):
        if method == 'thread/turns/list':
            observer.calls.append((method, params))
            return {'data': [{'id': cp['turn_id'], 'status': 'completed', 'items': [
                {'id': 'MOCK-final', 'type': 'agentMessage', 'phase': 'final_answer', 'text': raw}
            ] if params['itemsView'] == 'full' else []}], 'nextCursor': None}
        return await request(method, params, **kwargs)
    observer.request = metadata
    async def exercise():
        if delta > 0:
            with pytest.raises(RuntimePaused, match='Saída excede'):
                await recover(Workflow(store, m.run_id, runtime=runtime), inv, check_official=True)
            assert not store.exists(m.run_id, 'confirmed-results/' + inv)
            assert not store.exists(m.run_id, 'roles/auditor/phases/initial-0000')
        else:
            await recover(Workflow(store, m.run_id, runtime=runtime), inv, check_official=True)
            assert store.get(m.run_id, 'confirmed-results/' + inv)['output'] == raw
            assert store.exists(m.run_id, 'roles/auditor/phases/initial-0000')
        assert frozen_records(store, m.run_id, list(original)) == original
    asyncio.run(exercise())
    assert not any(method in {'turn/start', 'thread/start', 'thread/resume'} for method, _ in observer.calls)


@pytest.mark.parametrize('maximum', [1024, 2048, 2303, 2304, 2305, 64000])
def test_d_plan_and_cli_detect_unusable_page_budget(make_run, maximum, capsys):
    cfg = Config(); cfg.limits.max_output_bytes = maximum
    store, m = make_run(config=cfg)
    plan = global_plan(store, m, cfg, check_tools=True)
    assert plan['viable'] == (maximum >= 2304), plan
    assert store.get(m.run_id, 'planning/initial')['viable'] == plan['viable']
    if maximum < 2304:
        assert any(str(maximum) in b for b in plan['blockers'])
        with pytest.raises(PolicyError, match='página verificável'):
            create_reference(store, m, cfg, {'value': 'MOCK'}, phase='contest', audience=['auditor'], kind='own_history')
    else:
        ref = create_reference(store, m, cfg, {'value': 'MOCK'}, phase='contest', audience=['auditor'], kind='own_history')
        tools = SourceTools(store, m, cfg, None, ToolContext(m.run_id, 'auditor', 'contest', 'a' * 24))
        assert len(json.dumps(tools.read_evidence(ref['page_ids'][0]), ensure_ascii=False).encode()) <= maximum
    before = {str(p): p.read_bytes() for p in store.path(m.run_id).rglob('*') if p.is_file()}
    assert main(['--store', str(store.root), 'plan', m.run_id]) == (0 if plan['viable'] else 2)
    assert main(['--store', str(store.root), 'status', m.run_id]) == 0
    assert main(['--store', str(store.root), 'report', m.run_id]) == 0
    assert {str(p): p.read_bytes() for p in store.path(m.run_id).rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('boundary', ['decision', 'link', 'settlement', 'ledger', 'state'])
def test_a_recovery_write_failures_are_locally_reconciled_once(make_run, monkeypatch, boundary):
    store, m = make_run(); cfg = Config(); store.put(m.run_id, 'baseline', {'ids': []})
    runtime = CodexRuntime(store, m.run_id, cfg); rpc = FakeRPC(runtime.home); runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    put = store.put
    def reserve_crash(rid, name, value, **kwargs):
        if name == 'ledger' and value['calls']: raise OSError('MOCK reservation ledger failure')
        return put(rid, name, value, **kwargs)
    monkeypatch.setattr(store, 'put', reserve_crash)
    workflow = Workflow(store, m.run_id, runtime=runtime)
    state = asyncio.run(workflow.run())
    monkeypatch.setattr(store, 'put', put)
    assert state['status'] == 'blocked'
    inv = store.get(m.run_id, 'roles/auditor/attempts/initial-0000-0')['invocation_id']
    protected = frozen_records(store, m.run_id, ['roles/auditor/attempts/initial-0000-0',
        'accounting/reservations/' + store.names(m.run_id, 'accounting/reservations')[0]])
    unrelated = {'kind': 'unresolved_controller_error', 'message': 'MOCK separate unresolved limitation'}
    state['operational_blockers'].append(unrelated)
    state['limitations'].append(unrelated['message'])
    store.put(m.run_id, 'state', state)  # Explicit negative fixture; never a historical run.
    facts = {**proof(), 'checked_at': '2000-01-01T00:00:00+00:00'}
    store.put(m.run_id, 'financial-confirmation', facts)
    once = [True]
    def recovery_crash(rid, name, value, **kwargs):
        selected = ((boundary == 'decision' and name.startswith('recovery-decisions/'))
            or (boundary == 'link' and name.startswith('accounting/reconciliations/'))
            or (boundary == 'settlement' and name.startswith('accounting/settlements/'))
            or (boundary == 'ledger' and name == 'ledger' and value['calls'][0]['status'] == 'not_sent')
            or (boundary == 'state' and name == 'state' and value.get('operational_blockers') == [unrelated]))
        result = put(rid, name, value, **kwargs)
        if selected and once[0]:
            once[0] = False
            raise OSError('MOCK interruption between recovery writes')
        return result
    monkeypatch.setattr(store, 'put', recovery_crash)
    before_rpc = len(rpc.calls)
    with pytest.raises(OSError, match='between recovery writes'):
        asyncio.run(recover(workflow, inv, allow_next=True))
    monkeypatch.setattr(store, 'put', put)
    async def finish():
        await workflow.reconcile()  # No financial/preflight request, even before repeating recover.
        first = await recover(workflow, inv, allow_next=True)
        snapshot = {str(p): p.read_bytes() for p in store.path(m.run_id).rglob('*') if p.is_file() and p.suffix == '.json'}
        again = await recover(workflow, inv, allow_next=True)
        assert first == again and first['pending'] == []
        assert {str(p): p.read_bytes() for p in store.path(m.run_id).rglob('*') if p.is_file() and p.suffix == '.json'} == snapshot
    asyncio.run(finish())
    assert not once[0] and len(rpc.calls) == before_rpc
    assert not any(method == 'turn/start' for method, _ in rpc.calls)
    ledger = store.get(m.run_id, 'ledger')
    assert len(ledger['calls']) == 1 and ledger['calls'][0]['status'] == 'not_sent'
    assert ledger['tokens'] is ledger['known_cost_usd'] is None
    assert ledger['calls'][0]['input_tokens'] is ledger['calls'][0]['output_tokens'] is None
    assert store.get(m.run_id, 'state')['operational_blockers'] == [unrelated]
    assert store.get(m.run_id, 'state')['status'] == 'blocked'
    assert store.get(m.run_id, 'state')['limitations'] == [unrelated['message']]
    assert store.get(m.run_id, 'financial-confirmation') == facts
    assert frozen_records(store, m.run_id, list(protected)) == protected
    assert not store.exists(m.run_id, 'roles/auditor/attempts/initial-0000-1')


@pytest.mark.parametrize('maximum', [1024, 2048, 2303])
def test_d_cli_prepare_and_run_block_before_client_or_executor(tmp_path, monkeypatch, capsys, maximum):
    import zipfile
    from audit3.evidence import Store
    cfg = Config(); cfg.limits.max_output_bytes = maximum
    config_path = tmp_path / 'config.json'; config_path.write_text(cfg.model_dump_json())
    archive = tmp_path / 'synthetic.zip'
    with zipfile.ZipFile(archive, 'w') as z: z.writestr('app.py', '# synthetic, never executed\n')
    root = tmp_path / 'state'
    assert main(['--store', str(root), 'prepare', '--repo', str(archive), '--config', str(config_path)]) == 2
    prepared = json.loads(capsys.readouterr().out)
    assert not prepared['planning']['viable']
    invoked = []
    async def forbidden(*args, **kwargs):
        invoked.append(True)
        raise AssertionError('Invalid page budget must block before external dependencies')
    monkeypatch.setattr(CodexRuntime, 'start', forbidden)
    monkeypatch.setattr('audit3.executor.Executor.execute', forbidden)
    assert main(['--store', str(root), 'run', '--prepared', prepared['prepared']]) == 2
    state = json.loads(capsys.readouterr().out)
    assert not invoked and any(str(maximum) in text for text in state['limitations'])
    store = Store(root)
    assert store.get(prepared['prepared'], 'ledger')['calls'] == []
    assert not store.names(prepared['prepared'], 'codex-turns')


@pytest.mark.parametrize('delta', [-1, 0, 1])
def test_c_normal_transport_uses_the_same_utf8_boundary(make_run, delta):
    store, m = make_run(); cfg = Config()
    runtime = CodexRuntime(store, m.run_id, cfg); rpc = FakeRPC(runtime.home); runtime.rpc = rpc
    store.put(m.run_id, 'financial-confirmation', proof())
    raw = padded_opinion(Opinion(summary='MOCK transport only', findings=[], positions=[], inspections=[], limitations=[]),
                         cfg.limits.max_output_bytes + delta, True)
    rpc.output = raw
    inv = 'a' * 24
    tools = SourceTools(store, m, cfg, None, ToolContext(m.run_id, 'auditor', 'initial-0000', inv))
    async def exercise():
        if delta > 0:
            with pytest.raises(RuntimePaused, match='Saída excede limite de bytes UTF-8'):
                await runtime.invoke('auditor', 'initial-0000', {}, tools)
            assert not store.exists(m.run_id, 'confirmed-results/' + inv)
        else:
            assert await runtime.invoke('auditor', 'initial-0000', {}, tools) == raw
        await runtime.close()
    asyncio.run(exercise())
    assert sum(method == 'turn/start' for method, _ in rpc.calls) == 1
