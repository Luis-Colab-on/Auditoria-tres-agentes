"""One append-only authorization after the existing single exceptional slot."""
import math
from pathlib import Path
from .agents import RuntimePaused
from .security import digest, object_hash
from .batch_distribution import distribution, assignment_for_phase

VERSION = 'chained-extra-attempt-1'
CONTROLLER_VERSION = 'controller-recovery-version-1'


def package_hashes():
    root = Path(__file__).resolve().parent
    return {p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in sorted(root.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def authorization_name(role, phase):
    return f'roles/{role}/attempts/{phase}-extra-authorization-v2'


def chained_attempt_count(store, manifest, config, role, phase, attempt_count, parent_name):
    name = authorization_name(role, phase)
    if not store.exists(manifest.run_id, name):
        return attempt_count
    def require(condition):
        if not condition:
            raise RuntimePaused('Autorização encadeada inválida; nenhuma tentativa adicional enviada')
    auth = store.get(manifest.run_id, name)
    base = config.limits.invalid_output_retries + 1
    require(attempt_count == base + 1 and store.exists(manifest.run_id, parent_name))
    parent = store.get(manifest.run_id, parent_name)
    require(parent.get('source') == 'explicit_operator_authorization'
        and parent.get('run_id') == manifest.run_id and parent.get('role') == role and parent.get('phase') == phase
        and parent.get('attempt_slot') == base and parent.get('additional_attempts') == 1
        and parent.get('config_hash') == manifest.config_hash)
    expected = {'version': VERSION, 'source': 'explicit_operator_authorization',
        'run_id': manifest.run_id, 'role': role, 'phase': phase,
        'attempt_slot': attempt_count, 'additional_attempts': 1,
        'source_id': manifest.source_id, 'config_hash': manifest.config_hash,
        'profile_hash': manifest.profile_hash, 'parent_name': parent_name,
        'parent_hash': object_hash(parent)}
    require(all(auth.get(k) == v for k, v in expected.items()))
    require(auth.get('id') == object_hash({k: v for k, v in auth.items() if k != 'id'}))
    active = distribution(store, manifest, config)
    require(active is not None and auth.get('batch_distribution_id') == active['id'])
    require(auth.get('assignment_hash') == object_hash(assignment_for_phase(store, manifest, config, phase)))
    require(store.exists(manifest.run_id, 'runtime-binding') and store.exists(manifest.run_id, f'roles/{role}/codex-session'))
    binding = store.get(manifest.run_id, 'runtime-binding')
    session = store.get(manifest.run_id, f'roles/{role}/codex-session')
    require(auth.get('runtime_binding_hash') == object_hash(binding) and auth.get('role_session_hash') == object_hash(session))
    require(session.get('role') == role and session.get('run_id') == manifest.run_id
        and session.get('snapshot') == manifest.source_id and binding.get('snapshot') == manifest.source_id)
    version_name = auth.get('controller_version_record')
    require(isinstance(version_name, str) and version_name == 'operational/controller-continuation-version-slot3')
    require(store.exists(manifest.run_id, version_name))
    version = store.get(manifest.run_id, version_name)
    require(object_hash(version) == auth.get('controller_version_hash'))
    require(version.get('version') == CONTROLLER_VERSION and version.get('run_id') == manifest.run_id
        and version.get('source_id') == manifest.source_id and version.get('config_hash') == manifest.config_hash
        and version.get('profile_hash') == manifest.profile_hash and version.get('batch_distribution_id') == active['id']
        and version.get('authorized_scope') == {'role': role, 'phase': phase, 'slot': attempt_count, 'count': 1})
    require(version.get('package_hashes') == package_hashes())
    calls = store.get(manifest.run_id, 'ledger')['calls']
    past = auth.get('past_call_hashes')
    require(isinstance(past, list) and len(past) >= attempt_count
        and [object_hash(c) for c in calls[:len(past)]] == past)
    floor = auth.get('elapsed_floor')
    require(type(floor) in (int, float) and math.isfinite(floor) and floor >= 0
        and store.get(manifest.run_id, 'state').get('elapsed_seconds', -1) >= floor)
    require(version.get('original_call_hashes') == past and version.get('original_elapsed_seconds') == floor)
    prior = auth.get('prior_attempts')
    require(isinstance(prior, list) and len(prior) == attempt_count)
    for slot, entry in enumerate(prior):
        attempt_name = f'roles/{role}/attempts/{phase}-{slot}'
        require(store.exists(manifest.run_id, attempt_name))
        attempt = store.get(manifest.run_id, attempt_name)
        invocation = attempt['invocation_id']
        checkpoint_name = 'codex-turns/' + invocation
        marker_name = attempt_name + '-interrupted'
        official_name = f'operational/recovery-official-status/slot3-{slot}'
        require(store.exists(manifest.run_id, checkpoint_name) and store.exists(manifest.run_id, marker_name)
                and store.exists(manifest.run_id, official_name))
        checkpoint = store.get(manifest.run_id, checkpoint_name)
        marker = store.get(manifest.run_id, marker_name)
        official = store.get(manifest.run_id, official_name)
        expected_entry = {'slot': slot, 'invocation_id': invocation, 'attempt_hash': object_hash(attempt),
            'checkpoint_hash': object_hash(checkpoint), 'interruption_hash': object_hash(marker),
            'official_record': official_name, 'official_hash': object_hash(official)}
        require(entry == expected_entry)
        require(checkpoint.get('status') == 'ambiguous' and checkpoint.get('role') == role
            and checkpoint.get('phase') == phase and checkpoint.get('thread_id') == session.get('thread_id')
            and checkpoint.get('dispatch_status') in {'written', 'write_uncertain'})
        require(any(c.get('id') == checkpoint.get('call_id') and c.get('invocation_id') == invocation
                    and c.get('role') == role and c.get('status') == 'error' for c in calls))
        for record in (marker, official):
            require(record.get('source') == 'official_app_server_thread_read' and record.get('status') == 'interrupted'
                and record.get('invocation_id') == invocation and record.get('thread_id') == checkpoint.get('thread_id')
                and record.get('turn_id') == checkpoint.get('turn_id'))
        require(official.get('run_id') == manifest.run_id and official.get('slot') == slot
            and official.get('generation_requests') == 0 and official.get('checkpoint_hash') == object_hash(checkpoint)
            and official.get('runtime_binding_hash') == object_hash(binding))
    # Exactly one further fixed slot. No recursive chain, cap increase, slot
    # refund, reservation deletion, or automatic exception for another phase.
    return attempt_count + 1
