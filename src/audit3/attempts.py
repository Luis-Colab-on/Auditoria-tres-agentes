"""Durable logical input and confirmed response, independent of aggregate indexes."""
from .schemas import RunManifest
from .security import PolicyError, object_hash, now

INPUT_VERSION = 'attempt-input-1'
RESULT_VERSION = 'confirmed-turn-result-1'


def scope(store, manifest, role, phase, assignment=None):
    from .batch_distribution import distribution
    from .config import Config
    current = distribution(store, manifest, Config.model_validate(store.get(manifest.run_id, 'config')))
    return {'run_id': manifest.run_id, 'role': role, 'phase': phase,
            'manifest_hash': object_hash(store.get(manifest.run_id, 'manifest')),
            'source_id': manifest.source_id, 'config_hash': manifest.config_hash,
            'profile_hash': manifest.profile_hash, 'assignment_hash': object_hash(assignment),
            'distribution_id': current['id'] if current else None,
            'barrier_hash': object_hash(store.get(manifest.run_id, 'barrier'))
                if not (phase.startswith('initial-') or phase == 'blind') and store.exists(manifest.run_id, 'barrier') else None}


def freeze_input(store, manifest, role, phase, invocation, payload, assignment=None):
    name = 'turn-inputs/' + invocation
    record = {'version': INPUT_VERSION, 'invocation_id': invocation,
              'scope': scope(store, manifest, role, phase, assignment),
              'input_hash': object_hash(payload), 'payload': payload}
    if store.exists(manifest.run_id, name):
        if store.get(manifest.run_id, name) != record:
            raise PolicyError('Entrada original da tentativa diverge; não substituir contexto')
    else:
        store.put(manifest.run_id, name, record, immutable=True)
    return record


def original_input(store, manifest, role, phase, invocation, assignment=None):
    record = store.get(manifest.run_id, 'turn-inputs/' + invocation)
    if assignment is None:
        assignment = record.get('payload', {}).get('assignment')
    if (record.get('version') != INPUT_VERSION or record.get('invocation_id') != invocation
        or record.get('input_hash') != object_hash(record.get('payload'))
        or record.get('scope') != scope(store, manifest, role, phase, assignment)):
        raise PolicyError('Entrada original não corresponde à identidade/fonte/fase atual')
    return record['payload']


def confirmed(store, run_id, invocation, role=None, phase=None, input_hash=None):
    name = 'confirmed-results/' + invocation
    if not store.exists(run_id, name):
        return None
    record = store.get(run_id, name)
    if (record.get('version') != RESULT_VERSION or record.get('invocation_id') != invocation
        or record.get('status') != 'completed' or not isinstance(record.get('output'), str)
        or record.get('output_hash') != object_hash(record['output'])
        or (role is not None and record.get('role') != role)
        or (phase is not None and record.get('phase') != phase)
        or (input_hash is not None and record.get('input_hash') != input_hash)):
        raise PolicyError('Resposta confirmada com integridade/identidade divergente')
    manifest = RunManifest.model_validate(store.get(run_id, 'manifest'))
    if (record.get('source_id') != manifest.source_id or record.get('config_hash') != manifest.config_hash
        or record.get('profile_hash') != manifest.profile_hash):
        raise PolicyError('Resposta confirmada de outro contexto de auditoria')
    cp = store.get(run_id, 'codex-turns/' + invocation)
    for key in ('call_id', 'role', 'phase', 'thread_id', 'turn_id', 'input_hash', 'wire_input_hash'):
        if cp.get(key) != record.get(key):
            raise PolicyError('Resposta confirmada diverge do checkpoint')
    wire_name = 'dispatch-inputs/' + invocation
    if store.exists(run_id, wire_name):
        import json
        wire = store.get(run_id, wire_name)
        if (wire['logical_input_hash'] != record['input_hash'] or wire['wire_input_hash'] != record['wire_input_hash']
            or object_hash(json.loads(wire['params']['input'][0]['text'])) != record['wire_input_hash']):
            raise PolicyError('Entrada efetiva diverge da resposta confirmada')
    session = store.get(run_id, f"roles/{record['role']}/codex-session")
    binding = store.get(run_id, 'runtime-binding')
    if (session.get('thread_id') != record['thread_id'] or session.get('snapshot') != manifest.source_id
        or session.get('role') != record['role'] or session.get('run_id') != run_id
        or any(session.get(k) != binding.get(k) for k in ('backend','client_version','model','effort','account_fingerprint'))):
        raise PolicyError('Resposta confirmada de outra sessão/fonte')
    return record


def save_confirmation(store, manifest, invocation, record):
    saved = {**record, 'version': RESULT_VERSION, 'source_id': manifest.source_id,
             'config_hash': manifest.config_hash, 'profile_hash': manifest.profile_hash,
             'output_hash': object_hash(record['output'])}
    store.put(manifest.run_id, 'confirmed-results/' + invocation, saved, immutable=True)
    return saved
