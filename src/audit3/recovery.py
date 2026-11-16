"""Explicit recovery of existing attempts; no generation or slot extensions."""
import re
from .agents import RuntimePaused
from .security import PolicyError, object_hash, now, sensitive
from .attempts import original_input, save_confirmation, confirmed


def locate_attempt(store, manifest, invocation):
    if not re.fullmatch('[a-f0-9]{24}', invocation):
        raise PolicyError('Identificador de tentativa inválido')
    for role in ('auditor', 'defensor', 'juiz'):
        for name in store.names(manifest.run_id, f'roles/{role}/attempts'):
            match = re.fullmatch(r'(.+)-(\d+)', name)
            if match and store.get(manifest.run_id, f'roles/{role}/attempts/' + name).get('invocation_id') == invocation:
                return role, match[1], int(match[2])
    raise PolicyError('Tentativa não encontrada no run')


def validate_decision(store, manifest, invocation):
    decision = store.get(manifest.run_id, 'recovery-decisions/' + invocation)
    cp = store.get(manifest.run_id, 'codex-turns/' + invocation) if store.exists(manifest.run_id, 'codex-turns/' + invocation) else None
    role, phase, slot = locate_attempt(store, manifest, invocation)
    if (decision.get('version') != 'turn-recovery-1' or decision.get('checkpoint_hash') != object_hash(cp)
        or decision.get('source_id') != manifest.source_id or decision.get('config_hash') != manifest.config_hash
        or (decision.get('role'), decision.get('phase'), decision.get('slot')) != (role, phase, slot)):
        raise PolicyError('Decisão de recuperação divergente')
    if decision.get('status') == 'not_sent':
        if not proven_not_sent(store, manifest, invocation, cp):
            raise PolicyError('Ausência de envio não demonstrada')
    elif decision.get('status') == 'interrupted':
        proof = store.get(manifest.run_id, decision['official_record'])
        if (cp is None or object_hash(proof) != decision['official_hash'] or proof.get('status') != 'interrupted'
            or proof.get('thread_id') != cp.get('thread_id') or proof.get('turn_id') != cp.get('turn_id')
            or proof.get('invocation_id') != invocation):
            raise PolicyError('Interrupção oficial não demonstrada')
    else:
        raise PolicyError('Estado desconhecido não libera nova tentativa')
    return decision


def proven_not_sent(store, manifest, invocation, cp):
    role, phase, slot = locate_attempt(store, manifest, invocation)
    if cp and (cp.get('invocation_id') != invocation or cp.get('role') != role or cp.get('phase') != phase):
        return False
    if cp and cp.get('status') == cp.get('dispatch_status') == 'not_sent' and not cp.get('turn_id'):
        return True
    attempt = store.get(manifest.run_id, f'roles/{role}/attempts/{phase}-{slot}')
    if attempt.get('version') != 'phase-attempt-2' or not store.exists(manifest.run_id, 'turn-inputs/' + invocation):
        return False
    if cp and (cp.get('protocol_version') != 'codex-turn-2' or cp.get('status') != 'sending' or cp.get('turn_id')):
        return False
    reservations = [store.get(manifest.run_id, 'accounting/reservations/' + n)
                    for n in store.names(manifest.run_id, 'accounting/reservations')]
    return any(r.get('version') == 'call-reservation-1' and r.get('dispatch_protocol') == 'durable-dispatch-1'
               and r['entry']['invocation_id'] == invocation and r['entry']['role'] == role for r in reservations)


def pending_attempts(store, manifest):
    """Unreconciled dispatches, distinct from a rejected but confirmed response."""
    result = []
    for role in ('auditor', 'defensor', 'juiz'):
        group = f'roles/{role}/attempts'
        for name in store.names(manifest.run_id, group):
            match = re.fullmatch(r'(.+)-(\d+)', name)
            if not match:
                continue
            phase, slot = match[1], int(match[2])
            a = store.get(manifest.run_id, group + '/' + name)
            inv = a['invocation_id']
            if store.exists(manifest.run_id, f'roles/{role}/phases/{phase}') or store.exists(manifest.run_id, group + '/' + name + '-rejected'):
                continue
            if store.exists(manifest.run_id, 'recovery-decisions/' + inv):
                validate_decision(store, manifest, inv)
                continue
            cp = store.get(manifest.run_id, 'codex-turns/' + inv) if store.exists(manifest.run_id, 'codex-turns/' + inv) else None
            if store.exists(manifest.run_id, group + '/' + name + '-interrupted'):
                proof = store.get(manifest.run_id, group + '/' + name + '-interrupted')
                if (cp and proof.get('source') == 'official_app_server_thread_read' and proof.get('status') == 'interrupted'
                    and proof.get('invocation_id') == inv and cp.get('role') == role and cp.get('phase') == phase
                    and proof.get('thread_id') == cp.get('thread_id') and proof.get('turn_id') == cp.get('turn_id')):
                    continue
                raise PolicyError('Interrupção oficial histórica divergente')
            reservations = [store.get(manifest.run_id, 'accounting/reservations/' + n)['entry']
                            for n in store.names(manifest.run_id, 'accounting/reservations')]
            if cp or any(r.get('invocation_id') == inv for r in reservations):
                result.append({'role': role, 'phase': phase, 'slot': slot, 'invocation_id': inv,
                    'status': 'confirmed_local_pending' if confirmed(store, manifest.run_id, inv) else (cp or {}).get('status', 'reserved_not_dispatched'),
                    'proven_not_sent': proven_not_sent(store, manifest, inv, cp)})
    return result


def _turn_page(response):
    if (not isinstance(response, dict) or not isinstance(response.get('data'), list)
        or (response.get('nextCursor') is not None and not isinstance(response['nextCursor'], str))
        or any(not isinstance(t, dict) or not isinstance(t.get('id'), str)
               or t.get('status') not in {'completed','interrupted','failed','inProgress'} for t in response['data'])):
        raise RuntimePaused('Resposta oficial de consulta malformada; ambiguidade preservada')
    return response['data']


async def observe_official(runtime, manifest, invocation):
    """Supported metadata query; no resume, turn/start or billing operations."""
    from .codex_policy import account_identity, check_effective_config
    s, rid = runtime.store, runtime.run_id
    cp = s.get(rid, 'codex-turns/' + invocation)
    if not cp.get('thread_id') or not cp.get('turn_id'):
        raise RuntimePaused('Checkpoint sem identificadores oficiais; ambiguidade preservada')
    await runtime.start()
    check_effective_config((await runtime.rpc.request('config/read', {'includeLayers': False}))['config'], runtime.home)
    identity = account_identity((await runtime.rpc.request('account/read', {'refreshToken': False})).get('account'))
    binding = s.get(rid, 'runtime-binding')
    session = s.get(rid, f"roles/{cp['role']}/codex-session")
    if binding['account_fingerprint'] != identity or session['thread_id'] != cp['thread_id']:
        raise RuntimePaused('Consulta oficial de outra conta/sessão recusada')
    cursor, seen, target = None, set(), None
    for _ in range(10):
        response = await runtime.rpc.request('thread/turns/list', {
            'threadId': cp['thread_id'], 'itemsView': 'notLoaded', 'limit': 1, 'cursor': cursor})
        target = next((t for t in _turn_page(response) if t['id'] == cp['turn_id']), None)
        if target:
            break
        cursor = response.get('nextCursor')
        if cursor is None or cursor in seen:
            break
        seen.add(cursor)
    if target is None:
        raise RuntimePaused('Estado oficial não observável nas páginas limitadas; ambiguidade preservada')
    proof = {'version': 'official-turn-observation-1', 'source': 'official_app_server_thread_turns_list',
             'invocation_id': invocation, 'thread_id': cp['thread_id'], 'turn_id': cp['turn_id'],
             'status': target['status'], 'checkpoint_hash': object_hash(cp), 'observed_at': now(),
             'generation_requests': 0, 'run_id': rid, 'source_id': manifest.source_id,
             'account_fingerprint': identity, 'runtime_binding_hash': object_hash(binding),
             'session_hash': object_hash(session)}
    name = 'recovery-observations/' + object_hash(proof)[:24]
    s.put(rid, name, proof, immutable=True)
    if target['status'] == 'completed' and not confirmed(s, rid, invocation):
        response = await runtime.rpc.request('thread/turns/list', {
            'threadId': cp['thread_id'], 'itemsView': 'full', 'limit': 1, 'cursor': cursor})
        target = next((t for t in _turn_page(response) if t['id'] == cp['turn_id'] and t['status'] == 'completed'), None)
        if target is None:
            raise RuntimePaused('Conclusão oficial mudou durante consulta; ambiguidade preservada')
        allowed = {'userMessage', 'agentMessage', 'reasoning', 'dynamicToolCall', 'functionCallOutput', 'contextCompaction'}
        items = target.get('items')
        if (not isinstance(items, list) or any(not isinstance(item, dict) or item.get('type') not in allowed
            or not isinstance(item.get('id'), str) for item in items)):
            raise RuntimePaused('Turno oficial contém item incompatível; resultado não recuperado')
        from .codex_runtime import tool_specs
        names = {tool['name'] for tool in tool_specs()}
        if any((i['type'] == 'dynamicToolCall' and i.get('tool') not in names)
               or (i['type'] == 'functionCallOutput' and i.get('name') not in names) for i in items):
            raise RuntimePaused('Ferramenta oficial fora do escopo; resultado não recuperado')
        outputs = [item['text'] for item in target.get('items', [])
                   if item.get('type') == 'agentMessage' and item.get('phase') == 'final_answer' and isinstance(item.get('text'), str)]
        if len(outputs) != 1 or sensitive(outputs[0]):
            raise RuntimePaused('Resposta final oficial ausente/ambígua ou sensível; não inferir seu conteúdo')
        # A later consultation must never repair the original response's proof.
        # The controller stop is an upper bound on its original tool activity.
        cutoff = cp.get('stopped_at')
        if cutoff is None and type(target.get('completedAt')) is int:
            from datetime import datetime, timezone
            try:
                cutoff = datetime.fromtimestamp(target['completedAt'], timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                pass
        if cutoff is None:
            raise RuntimePaused('Instante limite das evidências originais desconhecido; resposta não recuperada')
        summary = cp.get('context_compaction') or {}
        if summary.get('started', 0) != summary.get('completed', 0):
            compact = [i for i in target.get('items', []) if i.get('type') == 'contextCompaction']
            if not compact or any(type(i.get('completedAtMs')) is not int for i in compact):
                raise RuntimePaused('Ciclo de compactação não comprovado no histórico oficial')
        save_confirmation(s, manifest, invocation, {
            **cp, 'status': 'completed', 'output': outputs[0], 'usage': None,
            'finished_at': cutoff, 'confirmation_origin': {'record': name, 'sha256': object_hash(proof)}})
    return name, proof


async def recover(workflow, invocation=None, *, check_official=False, allow_next=False):
    from .codex_runtime import CodexRuntime
    from .turn_planning import global_plan
    s, m = workflow.store, workflow.manifest
    with s.lock(m.run_id):
        local = await workflow.reconcile()
        decision = None
        runtime = workflow.runtime
        try:
            if invocation:
                role, phase, slot = locate_attempt(s, m, invocation)
                cp = s.get(m.run_id, 'codex-turns/' + invocation) if s.exists(m.run_id, 'codex-turns/' + invocation) else None
                if s.exists(m.run_id, 'recovery-decisions/' + invocation):
                    decision = validate_decision(s, m, invocation)
                elif (cp is None or cp['status'] != 'completed') and not confirmed(s, m.run_id, invocation):
                    official_name = proof = None
                    if check_official:
                        if cp is None:
                            raise RuntimePaused('Nenhum turno oficial identificado; use recuperação local da reserva')
                        official_name, proof = await observe_official(runtime, m, invocation)
                        if proof['status'] == 'completed':
                            local = await workflow.reconcile()
                    if allow_next and not confirmed(s, m.run_id, invocation):
                        not_sent = proven_not_sent(s, m, invocation, cp)
                        interrupted = proof and proof.get('status') == 'interrupted'
                        if not not_sent and not interrupted:
                            raise RuntimePaused('Envio desconhecido/ativo; não liberar outra tentativa')
                        from .recovery_authorization import attempt_limit
                        limit = attempt_limit(s, m, workflow.config, role, phase)
                        available = [i for i in range(slot + 1, limit)
                                     if not s.exists(m.run_id, f'roles/{role}/attempts/{phase}-{i}')]
                        if not available:
                            raise RuntimePaused('Tentativas existentes esgotadas; recuperação não cria slots')
                        plan = global_plan(s, m, workflow.config)
                        if not plan['calls_available']:
                            raise RuntimePaused('Limite de chamadas esgotado; reservas preservadas')
                        decision = {'version': 'turn-recovery-1', 'source_id': m.source_id, 'config_hash': m.config_hash,
                            'invocation_id': invocation, 'role': role, 'phase': phase, 'slot': slot,
                            'next_existing_slot': available[0], 'checkpoint_hash': object_hash(cp),
                            'status': 'not_sent' if not_sent else 'interrupted', 'recorded_at': now()}
                        if proof:
                            decision.update(official_record=official_name, official_hash=object_hash(proof))
                        s.put(m.run_id, 'recovery-decisions/' + invocation, decision, immutable=True)
                        validate_decision(s, m, invocation)
            return {'run_id': m.run_id, **local, 'decision': decision,
                    'planning': global_plan(s, m, workflow.config), 'new_model_calls': 0}
        finally:
            if isinstance(runtime, CodexRuntime):
                await runtime.close()
