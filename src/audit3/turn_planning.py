"""Read-only planning; a plan never creates source-read or inspection evidence."""
from .tools import SOURCE_READ_MAX_BYTES

VERSION = 'initial-read-plan-1'


def batches(manifest, line_limit: int):
    result, batch, size = [], [], 0
    for f in manifest.files:
        if f.category in {"excluded", "prior_report"} or not f.lines:
            continue
        for start in range(1, max(1, f.lines) + 1, line_limit):
            end = min(f.lines, start + line_limit - 1)
            if size and size + end - start + 1 > line_limit:
                result.append(batch)
                batch, size = [], 0
            batch.append({"path": f.path, "start": start, "end": end, "sha256": f.sha256})
            size += max(1, end - start + 1)
    if batch:
        result.append(batch)
    return result or [[]]



def _ranges(values):
    result = []
    for value in sorted(values):
        if result and value == result[-1][1] + 1:
            result[-1][1] = value
        else:
            result.append([value, value])
    return result


def initial_read_plan(tools, assignment, baseline_ids, *, reuse_reads=True, reserves=None):
    """Plan assigned intervals against both actual tool truncation limits.

    Only authenticated same-role/run/source blind reads can reduce the plan.
    Planning reads frozen bytes as controller data, without logging model reads.
    All original inspection/coverage requirements remain in force.
    """
    prior = {}
    for event in tools.source_read_events() if reuse_reads else ():
        data = event['data']
        prior.setdefault(data['path'], set()).update(range(data['start'], data['end'] + 1))
    chunks, reused, blocked = [], [], []
    for ref in assignment:
        path = ref['path']
        lines = tools.source_bytes_for_validation(path).decode('utf-8').splitlines()
        assigned = set(range(ref['start'], ref['end'] + 1))
        returned = assigned & prior.get(path, set())
        reused.extend({'path': path, 'start': a, 'end': b, 'sha256': ref['sha256']}
                      for a, b in _ranges(returned))
        for start, end in _ranges(assigned - returned):
            cursor = start
            while cursor <= end:
                last, size = cursor - 1, 0
                for n in range(cursor, min(end, cursor + tools.config.limits.read_lines - 1) + 1):
                    length = len(lines[n - 1].encode('utf-8'))
                    if size + length > SOURCE_READ_MAX_BYTES:
                        break
                    size += length
                    last = n
                if last < cursor:
                    blocked.append({'path': path, 'line': cursor,
                                    'reason': 'line_exceeds_source_response_bytes'})
                    cursor += 1
                    continue
                chunks.append({'path': path, 'start': cursor, 'end': last, 'sha256': ref['sha256']})
                cursor = last + 1
    evidence, consulted = [], []
    from .security import PolicyError
    for eid in baseline_ids:
        try:
            if not reuse_reads:
                raise PolicyError('cold planning: no past consultation presumed')
            tools.require_evidence_consulted(eid)
        except PolicyError:
            evidence.append(eid)
        else:
            consulted.append(eid)
    minimum = len(chunks) + len(evidence)
    maximum = tools.config.limits.max_turns
    reserves = dict(reserves or {})
    capacity = minimum + sum(reserves.values())
    return {'version': VERSION, 'source_read_calls': chunks,
            'previously_returned_intervals': reused,
            'baseline_receipts_to_consult': evidence, 'baseline_receipts_already_consulted': consulted,
            'unreadable_lines': blocked, 'minimum_tool_calls': minimum,
            'max_tool_calls': maximum, 'mandatory_reads_fit': capacity <= maximum and not blocked,
            'reserved_tool_calls': reserves, 'required_tool_capacity': capacity,
            'unallocated_tool_calls': max(0, maximum - capacity),
            'remaining_for_other_tools': max(0, maximum - minimum),
            'interpretation': 'Plano de leituras obrigatórias, não prova de investigação nem garantia de conclusão. '
                'Leia os intervalos pendentes e registre análise de todo o lote. Intervalos já devolvidos '
                'ao próprio papel na etapa cega podem ser reutilizados; nenhuma inspeção é fabricada. '
                'Buscas, testes, consultas, erros e continuações por truncamento também consomem passos. '
                'Finalize o contrato antes de esgotar o teto; não reduza a cobertura exigida.'}


def source_plans(store, manifest, config):
    """Check all outstanding initial batches before spending a model call.

    This lower bound covers source reads. Each actual turn separately includes
    baseline receipts not yet consulted by its role. No future read is presumed.
    """
    from .batch_distribution import effective_batches, tool_reserves
    from .tools import SourceTools, ToolContext
    result = []
    reserves = tool_reserves(store, manifest, config)
    has_baseline = store.exists(manifest.run_id, 'baseline')
    baseline_ids = store.get(manifest.run_id, 'baseline')['ids'] if has_baseline else []
    if not has_baseline:
        reserves['pending_baseline_consultation'] = 1
    for role in ('auditor', 'defensor'):
        tools = SourceTools(store, manifest, config, None,
                            ToolContext(manifest.run_id, role, 'initial-0000', 'controller-planning'))
        for n, assignment in enumerate(effective_batches(store, manifest, config)):
            phase = f'initial-{n:04d}'
            if store.exists(manifest.run_id, f'roles/{role}/phases/{phase}'):
                continue
            result.append({'role': role, 'phase': phase, 'plan': initial_read_plan(tools, assignment, baseline_ids, reserves=reserves)})
    return result


def global_plan(store, manifest, config, *, initial_batches=None, check_tools=False):
    """One protocol topology for preparation, dispatch and completion.

    Minimum work has priority. Corrections share only the remaining operational
    capacity; no remote quota reservation or guarantee of duration is implied.
    """
    import re
    from .batch_distribution import effective_batches
    from .completion import protocol_phases
    from .security import object_hash
    assignments = initial_batches if initial_batches is not None else effective_batches(store, manifest, config)
    extra = (store.exists(manifest.run_id, 'material-review')
             and store.get(manifest.run_id, 'material-review').get('additional_round', False))
    required = protocol_phases(manifest, config, extra, initial_batches=assignments)
    possible = protocol_phases(manifest, config, True, initial_batches=assignments)
    completed, pending, exhausted, attempt_slots = [], [], [], {}
    calls = store.get(manifest.run_id, 'ledger')['calls'] if store.exists(manifest.run_id, 'ledger') else []
    ids = {c['id'] for c in calls}
    if store.exists(manifest.run_id, 'ledger'):
        for name in store.names(manifest.run_id, 'accounting/reservations'):
            ids.add(store.get(manifest.run_id, 'accounting/reservations/' + name)['entry']['id'])
    for item in possible:
        role, phase = item.split('/')
        path = f'roles/{role}/phases/{phase}'
        saved = store.get(manifest.run_id, path) if store.exists(manifest.run_id, path) else None
        if saved and saved.get('role') == role and saved.get('phase') == phase and isinstance(saved.get('output'), dict):
            completed.append(item)
            continue
        if item in required:
            pending.append(item)
        limit = config.limits.invalid_output_retries + 1
        # Existing scope-bound authorizations remain subject to their strict
        # dispatch validator. Reading a plan never grants an extra slot.
        for suffix in ('-extra-authorization', '-extra-authorization-v2'):
            name = f'roles/{role}/attempts/{phase}' + suffix
            if store.exists(manifest.run_id, name):
                a = store.get(manifest.run_id, name)
                if (a.get('source') == 'explicit_operator_authorization' and a.get('run_id') == manifest.run_id
                    and a.get('role') == role and a.get('phase') == phase and a.get('config_hash') == manifest.config_hash
                    and type(a.get('attempt_slot')) is int and a.get('additional_attempts') == 1):
                    limit = max(limit, a['attempt_slot'] + 1)
        spent = set()
        for name in store.names(manifest.run_id, f'roles/{role}/attempts'):
            match = re.fullmatch(re.escape(phase) + r'-(\d+)', name)
            if not match:
                continue
            a = store.get(manifest.run_id, f'roles/{role}/attempts/' + name)
            if (store.exists(manifest.run_id, 'codex-turns/' + a['invocation_id'])
                or any(c.get('invocation_id') == a['invocation_id'] for c in calls)
                or store.exists(manifest.run_id, f'roles/{role}/attempts/' + name + '-rejected')):
                spent.add(int(match[1]))
        available = len(set(range(limit)) - spent)
        attempt_slots[item] = available
        if item in required and not available:
            exhausted.append(item)
    available_calls = max(0, config.limits.max_calls - len(ids))
    elapsed = store.get(manifest.run_id, 'state').get('elapsed_seconds', 0) if store.exists(manifest.run_id, 'state') else 0
    from .operational import total_seconds
    effective_seconds = total_seconds(store, manifest.run_id, config)
    seconds = max(0, effective_seconds - elapsed)
    blockers = []
    from .recovery import pending_attempts
    unresolved = pending_attempts(store, manifest)
    for attempt in unresolved:
        if attempt['status'] in {'ambiguous', 'not_sent', 'reserved_not_dispatched'}:
            blockers.append('Tentativa pendente de recuperação: ' + attempt['invocation_id'] + ' (' + attempt['status'] + ')')
    if len(pending) > available_calls:
        blockers.append(f'Fases obrigatórias restantes {len(pending)} excedem chamadas disponíveis {available_calls} '
                        f'(protocolo {len(required)}, consumidas {len(ids)}, limite {config.limits.max_calls})')
    if exhausted:
        blockers.append('Tentativas consumidas nas fases: ' + ', '.join(exhausted))
    if pending and seconds <= 0:
        blockers.append('Tempo global acumulado esgotado; somente reconciliação local disponível')
    tool_plans = source_plans(store, manifest, config) if check_tools else []
    for entry in tool_plans:
        if not entry['plan']['mandatory_reads_fit']:
            blockers.append(f"Lote inviável {entry['role']}/{entry['phase']}: capacidade "
                            f"{entry['plan']['required_tool_capacity']}/{config.limits.max_turns}; "
                            f"linhas impossíveis {len(entry['plan']['unreadable_lines'])}")
    result = {'version': 'global-protocol-plan-1', 'run_id': manifest.run_id, 'source_id': manifest.source_id,
              'batches_per_role': len(assignments), 'required_phases': required, 'possible_phases': possible,
              'required_phase_count': len(required), 'additional_round_phases': len(set(possible) - set(required)),
              'completed_phases': completed, 'pending_phases': pending, 'minimum_new_calls': len(pending),
              'calls_consumed': len(ids), 'calls_available': available_calls, 'max_calls': config.limits.max_calls,
              'maximum_new_calls_permitted_by_slots': sum(attempt_slots.values()),
              'contingency_calls_available': max(0, available_calls - len(pending)),
              'contingency_policy': 'minimum_first_shared_contingency', 'available_attempt_slots': attempt_slots,
              'elapsed_seconds': elapsed, 'seconds_available': seconds, 'total_seconds_limit': effective_seconds,
              'mean_seconds_available_per_required_phase': seconds / len(pending) if pending else None,
              'time_assumption': 'Duração real dos agentes/testes desconhecida; saldo médio não garante conclusão',
              'tool_plans_checked': check_tools, 'blockers': blockers, 'viable': not blockers}
    result['recovery_pending'] = unresolved
    if check_tools:
        result['initial_tool_plans'] = tool_plans
    result['id'] = object_hash(result)
    return result


def ensure_global_capacity(store, manifest, config):
    from .agents import BudgetExceeded
    plan = global_plan(store, manifest, config)
    if not plan['viable']:
        raise BudgetExceeded('; '.join(plan['blockers']))
    return plan
