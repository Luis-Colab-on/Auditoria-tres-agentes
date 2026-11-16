"""Read-only planning; a plan never creates source-read or inspection evidence."""
from .tools import SOURCE_READ_MAX_BYTES

VERSION = 'initial-read-plan-1'


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
    baseline_ids = store.get(manifest.run_id, 'baseline')['ids'] if reserves and store.exists(manifest.run_id, 'baseline') else []
    for role in ('auditor', 'defensor'):
        tools = SourceTools(store, manifest, config, None,
                            ToolContext(manifest.run_id, role, 'initial-0000', 'controller-planning'))
        for n, assignment in enumerate(effective_batches(store, manifest, config)):
            phase = f'initial-{n:04d}'
            if store.exists(manifest.run_id, f'roles/{role}/phases/{phase}'):
                continue
            result.append({'role': role, 'phase': phase, 'plan': initial_read_plan(tools, assignment, baseline_ids, reserves=reserves)})
    return result
