"""Explicit, authenticated replacement of unstarted initial batches. No inference."""
from collections import defaultdict
import re
from .security import PolicyError, object_hash, now
from .tools import SourceTools, ToolContext
from .turn_planning import initial_read_plan

VERSION = 'initial-batch-distribution-1'
RECORD = 'operational/initial-batch-distribution'
# Capacity reserves, not a requirement to invent findings or execute every test.
RESERVES = {'source_followup': 2, 'additional_evidence': 2, 'test_submission': 2}


def _original(manifest, config):
    from .workflow import batches
    return batches(manifest, config.limits.batch_lines)


def _coverage(refs):
    by_file = defaultdict(list)
    for ref in refs:
        if set(ref) != {'path', 'start', 'end', 'sha256'}:
            raise PolicyError('campos inválidos no intervalo de lote')
        a, b = ref['start'], ref['end']
        if type(a) is not int or type(b) is not int or not 1 <= a <= b:
            raise PolicyError('intervalo inválido na distribuição')
        by_file[(ref['path'], ref['sha256'])].append((a, b))
    result = {}
    for key, intervals in by_file.items():
        merged = []
        for a, b in sorted(intervals):
            if merged and a <= merged[-1][1]:
                raise PolicyError('intervalo duplicado/sobreposto na distribuição')
            if merged and a == merged[-1][1] + 1:
                merged[-1][1] = b
            else:
                merged.append([a, b])
        result[key] = merged
    return result


def _merge(chunks):
    result = []
    for ref in chunks:
        if result and result[-1]['path'] == ref['path'] and result[-1]['sha256'] == ref['sha256'] and result[-1]['end'] + 1 == ref['start']:
            result[-1]['end'] = ref['end']
        else:
            result.append(dict(ref))
    return result


def _bindings(manifest, config):
    return {'run_id': manifest.run_id, 'source_id': manifest.source_id,
            'config_hash': manifest.config_hash, 'profile_hash': manifest.profile_hash,
            'objective_hash': object_hash(manifest.requirements), 'prompt_hashes': manifest.prompt_hashes,
            'limits': {k: getattr(config.limits, k) for k in
                       ('max_turns', 'max_calls', 'total_seconds', 'call_timeout', 'read_lines', 'batch_lines')}}


def _history_names(store, run_id):
    names = ['codex-turns/' + n for n in store.names(run_id, 'codex-turns')]
    for role in ('auditor', 'defensor', 'juiz'):
        for group in ('attempts', 'phases'):
            names += [f'roles/{role}/{group}/' + n for n in store.names(run_id, f'roles/{role}/{group}')]
    return names


def _check_started_assignments(store, manifest, original, replacement):
    for role in ('auditor', 'defensor'):
        for group in ('attempts', 'phases'):
            for name in store.names(manifest.run_id, f'roles/{role}/{group}'):
                match = re.match(r'^initial-(\d{4})(?:-|$)', name)
                if match:
                    index = int(match[1])
                    if index >= len(original) or index >= len(replacement) or original[index] != replacement[index]:
                        raise PolicyError('distribuição altera atribuição de fase já iniciada: ' + role + '/' + name)


def build_distribution(store, manifest, config, reviewer):
    if not reviewer.strip():
        raise PolicyError('revisor explícito obrigatório')
    if store.exists(manifest.run_id, RECORD):
        raise PolicyError('distribuição já registrada; não substituir histórico')
    if store.exists(manifest.run_id, 'barrier') or any(store.exists(manifest.run_id, f'roles/{r}/initial') for r in ('auditor', 'defensor')):
        raise PolicyError('investigação inicial já congelada; redistribuição recusada')
    original = _original(manifest, config)
    baseline_ids = store.get(manifest.run_id, 'baseline')['ids'] if store.exists(manifest.run_id, 'baseline') else []
    reserve = sum(RESERVES.values()) + len(baseline_ids)
    capacity = config.limits.max_turns - reserve
    if capacity < 1:
        raise PolicyError('teto não comporta leitura e reservas explícitas')
    tools = SourceTools(store, manifest, config, None, ToolContext(manifest.run_id, 'auditor', 'initial-0000', 'distribution-planning'))
    replacement, parents, costs = [], [], []
    for index, batch in enumerate(original):
        plan = initial_read_plan(tools, batch, [], reuse_reads=False)
        if plan['unreadable_lines']:
            raise PolicyError('linha não materializável impede distribuição de cobertura completa')
        chunks = plan['source_read_calls']
        if len(chunks) > capacity:
            count = (len(chunks) + capacity - 1) // capacity
            width = (len(chunks) + count - 1) // count
            parts = [chunks[n:n + width] for n in range(0, len(chunks), width)]
        else:
            parts = [chunks]
        for part in parts:
            replacement.append(_merge(part) if len(parts) > 1 else batch)
            parents.append(index)
            costs.append({'source_calls': part, 'minimum_source_calls': len(part),
                          'reserved_tool_calls': reserve, 'required_tool_capacity': len(part) + reserve})
    _check_started_assignments(store, manifest, original, replacement)
    ledger = store.get(manifest.run_id, 'ledger')['calls']
    if any(c['status'] == 'in_flight' for c in ledger):
        raise PolicyError('chamada ativa impede congelamento de distribuição')
    mapping = {f'initial-{n:04d}': [f'initial-{i:04d}' for i, parent in enumerate(parents) if parent == n]
               for n in range(len(original))}
    record = {'version': VERSION, **_bindings(manifest, config), 'reviewer': reviewer, 'created_at': now(),
              'original_batches': original, 'original_hash': object_hash(original),
              'batches': replacement, 'parents': parents, 'mapping': mapping, 'costs': costs,
              'reserves': RESERVES, 'baseline_ids': baseline_ids,
              'inspection_delivery': 'Análises/inspeções no contrato final não consomem chamada de ferramenta; source_followup reserva contexto. Reservas não obrigam testes ou achados e não ampliam as 12 reproduções globais.',
              'protected_records': {n: object_hash(store.get(manifest.run_id, n)) for n in _history_names(store, manifest.run_id)},
              'past_calls': [object_hash(c) for c in ledger],
              'elapsed_floor': store.get(manifest.run_id, 'state').get('elapsed_seconds', 0)}
    record['id'] = object_hash(record)
    validate_distribution(store, manifest, config, record)
    return record


def validate_distribution(store, manifest, config, record):
    if record.get('version') != VERSION or record.get('id') != object_hash({k: v for k, v in record.items() if k != 'id'}):
        raise PolicyError('versão/hash de distribuição inválido')
    if any(record.get(k) != v for k, v in _bindings(manifest, config).items()):
        raise PolicyError('distribuição de outro run/fonte/objetivo/configuração')
    original, replacement = record['original_batches'], record['batches']
    if original != _original(manifest, config) or record['original_hash'] != object_hash(original):
        raise PolicyError('mapa original divergente')
    parents = record['parents']
    if (len(parents) != len(replacement) or not parents or any(type(p) is not int for p in parents)
        or sorted(set(parents)) != list(range(len(original))) or parents != sorted(parents)):
        raise PolicyError('identificação/correspondência de lotes inválida')
    for n, batch in enumerate(original):
        children = [r for i, child in enumerate(replacement) if parents[i] == n for r in child]
        if _coverage(children) != _coverage(batch):
            raise PolicyError('escopo perdido/adicionado na distribuição')
    expected_mapping = {f'initial-{n:04d}': [f'initial-{i:04d}' for i, p in enumerate(parents) if p == n] for n in range(len(original))}
    if record['mapping'] != expected_mapping or record['reserves'] != RESERVES:
        raise PolicyError('mapa/reservas de distribuição divergentes')
    baselines = store.get(manifest.run_id, 'baseline')['ids'] if store.exists(manifest.run_id, 'baseline') else []
    if record['baseline_ids'] != baselines or len(record['costs']) != len(replacement):
        raise PolicyError('evidências/custos de distribuição divergentes')
    reserve = sum(RESERVES.values()) + len(baselines)
    for batch, cost in zip(replacement, record['costs'], strict=True):
        if (_coverage(cost['source_calls']) != _coverage(batch)
            or cost['minimum_source_calls'] != len(cost['source_calls'])
            or cost['reserved_tool_calls'] != reserve
            or cost['required_tool_capacity'] != len(cost['source_calls']) + reserve
            or cost['required_tool_capacity'] > config.limits.max_turns):
            raise PolicyError('lote não reserva capacidade de investigação/evidência/testes')
        if sum(r['end'] - r['start'] + 1 for r in batch) > config.limits.batch_lines:
            raise PolicyError('distribuição excede limite de linhas do lote')
    for name, expected in record['protected_records'].items():
        if not store.exists(manifest.run_id, name) or object_hash(store.get(manifest.run_id, name)) != expected:
            raise PolicyError('histórico protegido da distribuição alterado')
    calls = store.get(manifest.run_id, 'ledger')['calls']
    if [object_hash(c) for c in calls[:len(record['past_calls'])]] != record['past_calls']:
        raise PolicyError('chamadas anteriores alteradas/removidas')
    if store.get(manifest.run_id, 'state').get('elapsed_seconds', 0) < record['elapsed_floor']:
        raise PolicyError('tempo acumulado anterior reduzido')
    _check_started_assignments_at_registration(record)
    return record


def _check_started_assignments_at_registration(record):
    # Only pre-registration records constrain renumbering. Future phases use the
    # versioned assignments, whose own binding is checked by investigation.py.
    for name in record['protected_records']:
        match = re.match(r'roles/(?:auditor|defensor)/(?:attempts|phases)/initial-(\d{4})(?:-|$)', name)
        if match:
            n = int(match[1])
            if n >= len(record['batches']) or record['original_batches'][n] != record['batches'][n]:
                raise PolicyError('atribuição histórica modificada')


def distribution(store, manifest, config):
    return validate_distribution(store, manifest, config, store.get(manifest.run_id, RECORD)) if store.exists(manifest.run_id, RECORD) else None


def effective_batches(store, manifest, config):
    current = distribution(store, manifest, config)
    return current['batches'] if current else _original(manifest, config)


def assignment_for_phase(store, manifest, config, phase):
    suffix = phase.removeprefix('initial-')
    if not suffix.isascii() or not suffix.isdigit():
        raise PolicyError('lote inicial inexistente')
    index = int(suffix)
    batches = effective_batches(store, manifest, config)
    if phase != f'initial-{index:04d}' or index >= len(batches):
        raise PolicyError('lote inicial inexistente')
    return batches[index]


def register_distribution(store, manifest, config, record):
    with store.lock(manifest.run_id):
        validate_distribution(store, manifest, config, record)
        _check_started_assignments(store, manifest, record['original_batches'], record['batches'])
        store.put(manifest.run_id, RECORD, record, immutable=True)


def tool_reserves(store, manifest, config):
    current = distribution(store, manifest, config)
    return dict(current['reserves']) if current else {}
