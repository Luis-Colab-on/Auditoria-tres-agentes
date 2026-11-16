from __future__ import annotations
import asyncio
import json
import secrets
import time
from datetime import datetime, timezone
from importlib.resources import files
from pydantic import ValidationError
from .agents import BudgetExceeded, RuntimePaused, PersistencePending, ReservationPending
from .codex_runtime import CodexRuntime
from .codex_policy import financial_policy
from .config import Config, Profile
from .evidence import Store
from .executor import Executor
from .schemas import (Classification, Decision, Judgment, Opinion, Role, RunManifest, TestRequest, Verdict)
from .security import PolicyError, digest, now, object_hash, redact, sensitive
from .snapshot import verify_source
from .tools import SourceTools, ToolContext
from .causality import causal_groups
from .completion import assess_completion, VERSION as ASSESSMENT_VERSION
from .operational import total_seconds
from .investigation import is_blind, validate_initial_output, validate_saved_initial, assess_independent_investigation
from .batch_distribution import effective_batches, distribution, tool_reserves, assignment_for_phase
from .agent_context import agent_manifest
from .phase_validation import PhaseValidator
from .turn_planning import batches
from .attempts import freeze_input, original_input, confirmed


class Workflow:
    def __init__(self, store: Store, run_id: str, runtime=None, executor=None):
        self.store, self.run_id = store, run_id
        self.manifest = RunManifest.model_validate(store.get(run_id, "manifest"))
        if runtime is None and self.manifest.backend != "codex-app-server":
            raise PolicyError("Run histórico: somente leitura/exportação; prepare nova execução Codex, sem continuidade equivalente")
        raw_config = store.get(run_id, "config")
        self.config = Config.model_validate(raw_config)
        self.profile = Profile.model_validate(store.get(run_id, "profile"))
        if object_hash(raw_config) != self.manifest.config_hash or object_hash(self.profile) != self.manifest.profile_hash:
            raise PolicyError("configuração/perfil adulterado")
        for role, expected in self.manifest.prompt_hashes.items():
            if digest(files("audit3").joinpath("prompts", role + ".txt").read_bytes()) != expected:
                raise PolicyError("prompt mudou: nova auditoria necessária")
        self.runtime, self.executor = runtime, executor or Executor(store, self.manifest, self.config, self.profile)
        self.validator = PhaseValidator(store, self.manifest, self.config)
        self.semaphore = asyncio.Semaphore(self.config.limits.concurrency)

    def state(self):
        return self.store.get(self.run_id, "state")

    def update(self, **kwargs):
        state = self.state()
        state.update(kwargs)
        self.store.put(self.run_id, "state", state)

    def opinions(self, role):
        return self.validator.opinions(role)

    def shared(self):
        if not self.store.exists(self.run_id, "barrier"):
            raise PolicyError("barreira não publicada")
        return {r.value: self.opinions(r.value) for r in Role}

    def findings(self):
        return self.validator.findings()

    def validate_output(self, output, tools, final):
        return self.validator.validate_output(output, tools, final)

    def finish_phase(self, role, phase, record):
        """Reconcile derived indexes from an already validated durable phase."""
        role_name = f'roles/{role}/state'
        role_state = {'phase': phase, 'invocation_id': record.get('invocation_id'), 'status': 'completed'}
        if self.store.exists(self.run_id, role_name):
            current = self.store.get(self.run_id, role_name)
            prior_name = f"roles/{role}/phases/{current['phase']}"
            if self.store.exists(self.run_id, prior_name):
                prior = self.store.get(self.run_id, prior_name)
                if prior.get('published_at', '') > record.get('published_at', ''):
                    role_state = {'phase': current['phase'], 'invocation_id': prior.get('invocation_id'), 'status': 'completed'}
        if record.get('invocation_id') and (not self.store.exists(self.run_id, role_name) or self.store.get(self.run_id, role_name) != role_state):
            self.store.put(self.run_id, role_name, role_state)
        state = self.state()
        completed = list(dict.fromkeys([*state['completed'], role + '/' + phase]))
        if completed != state['completed']:
            state['completed'] = completed
            self.store.put(self.run_id, 'state', state)

    def publish_phase(self, role, phase, invocation, result, tools, *, origin='execution'):
        name = f'roles/{role}/phases/{phase}'
        cls = Judgment if phase == 'final' else Opinion
        output = cls.model_validate_json(result) if isinstance(result, str) else cls.model_validate(result)
        confirmation = confirmed(self.store, self.run_id, invocation, role, phase)
        if confirmation:
            if result != confirmation['output']:
                raise PolicyError('Publicação diverge da resposta confirmada original')
            tools.read_before = confirmation['finished_at']
        self.validate_output(output, tools, phase == 'final')
        record = {'version': 'phase-publication-2', 'role': role, 'phase': phase,
            'invocation_id': invocation, 'published_at': now(), 'mode': self.runtime.mode,
            'output': output.model_dump(mode='json'), 'publication_origin': origin}
        if confirmation:
            record['evidence_cutoff'] = confirmation['finished_at']
            record['confirmation_hash'] = object_hash(confirmation)
        if self.store.exists(self.run_id, 'turn-inputs/' + invocation):
            record['input_hash'] = self.store.get(self.run_id, 'turn-inputs/' + invocation)['input_hash']
        current = distribution(self.store, self.manifest, self.config)
        if current:
            record['batch_distribution_id'] = current['id']
        try:
            self.store.put(self.run_id, name, record, immutable=True)
            self.finish_phase(role, phase, record)
        except OSError as exc:
            if confirmation:
                raise PersistencePending(invocation) from exc
            raise
        return record['output']

    async def reconcile(self):
        """Repair local publication/index work only; never dispatch or execute."""
        if self.runtime is None:
            self.runtime = CodexRuntime(self.store, self.run_id, self.config)
        if isinstance(self.runtime, CodexRuntime):
            await self.runtime.budget.reconcile()
            from .recovery import settle_not_sent_decisions
            settled = await settle_not_sent_decisions(self.store, self.manifest, self.runtime.budget)
            if settled:
                self.resolve_local_persistence(settled)
        repaired, pending = [], []
        for role in Role:
            role = role.value
            for phase in self.store.names(self.run_id, f'roles/{role}/phases'):
                record = self.store.get(self.run_id, f'roles/{role}/phases/{phase}')
                self.validator.validate_record(record, role, phase)
                if is_blind(phase):
                    validate_saved_initial(self.store, self.manifest, self.config, role, phase)
                else:
                    tools = SourceTools(self.store, self.manifest, self.config, None,
                        ToolContext(self.run_id, role, phase, record.get('invocation_id', 'historical-phase-validation')),
                        read_before=record['published_at'])
                    self.validate_output((Judgment if phase == 'final' else Opinion).model_validate(record['output']), tools, phase == 'final')
                self.finish_phase(role, phase, record)
            import re
            for name in self.store.names(self.run_id, f'roles/{role}/attempts'):
                match = re.fullmatch(r'(.+)-(\d+)', name)
                if not match:
                    continue
                phase, slot = match[1], int(match[2])
                path = f'roles/{role}/phases/{phase}'
                if self.store.exists(self.run_id, path) or self.store.exists(self.run_id, f'roles/{role}/attempts/{name}-rejected'):
                    continue
                attempt = self.store.get(self.run_id, f'roles/{role}/attempts/{name}')
                invocation = attempt['invocation_id']
                if self.store.exists(self.run_id, 'recovery-decisions/' + invocation):
                    from .recovery import validate_decision
                    validate_decision(self.store, self.manifest, invocation)
                    continue
                checkpoint = 'codex-turns/' + invocation
                if not self.store.exists(self.run_id, checkpoint):
                    continue
                cp = self.store.get(self.run_id, checkpoint)
                result = confirmed(self.store, self.run_id, invocation, role, phase)
                if result is None and cp.get('status') != 'completed':
                    pending.append({'invocation_id': invocation, 'role': role, 'phase': phase, 'status': cp['status']})
                    continue
                if not self.store.exists(self.run_id, 'turn-inputs/' + invocation):
                    pending.append({'invocation_id': invocation, 'status': 'historical_input_unavailable'})
                    continue
                assignment = assignment_for_phase(self.store, self.manifest, self.config, phase) if phase.startswith('initial-') else None
                payload = original_input(self.store, self.manifest, role, phase, invocation, assignment)
                result = result or cp
                if result['input_hash'] != object_hash(payload):
                    raise PolicyError('Entrada original diverge da resposta concluída')
                output = await self.runtime.complete_local(result)
                tools = SourceTools(self.store, self.manifest, self.config, self.executor,
                    ToolContext(self.run_id, role, phase, invocation, slot))
                try:
                    self.publish_phase(role, phase, invocation, output, tools, origin='local_recovery')
                except (ValidationError, PolicyError, json.JSONDecodeError) as exc:
                    if isinstance(exc, RuntimePaused):
                        raise
                    rejection = {'error_type': type(exc).__name__, 'feedback': 'Saída rejeitada: ' + redact(str(exc))[:1500]}
                    self.store.put(self.run_id, f'roles/{role}/attempts/{name}-rejected', rejection, immutable=True)
                    self.store.event_once(self.run_id, 'invalid_output', invocation,
                        {'role': role, 'phase': phase, 'attempt': slot, 'error_type': type(exc).__name__})
                    pending.append({'invocation_id': invocation, 'role': role, 'phase': phase, 'status': 'completed_output_invalid'})
                    continue
                repaired.append(role + '/' + phase)
        if self.store.exists(self.run_id, 'roles/juiz/phases/final') and not self.store.exists(self.run_id, 'judgment'):
            self.store.put(self.run_id, 'judgment', self.store.get(self.run_id, 'roles/juiz/phases/final')['output'], immutable=True)
        from .turn_planning import global_plan
        if (self.store.exists(self.run_id, 'judgment') and not global_plan(self.store, self.manifest, self.config)['pending_phases']
            and self.state().get('phase') != 'done'):
            self.finalize(self.store.get(self.run_id, 'judgment'))
        return {'repaired_phases': repaired, 'pending': pending, 'new_model_calls': 0}

    def resolve_local_persistence(self, settled_not_sent=None):
        state = self.state()
        resolved, confirmation_hashes, recovery_hashes = [], {}, {}
        for block in state.get('operational_blockers', []):
            inv = block.get('invocation_id')
            if not inv:
                continue
            if block.get('kind') == 'reservation_persistence' and inv in (settled_not_sent or {}):
                resolved.append(block)
                recovery_hashes[inv] = settled_not_sent[inv]
            elif settled_not_sent is None and block.get('kind') == 'local_persistence':
                result = confirmed(self.store, self.run_id, inv)
                if result and self.store.exists(self.run_id, f"roles/{result['role']}/phases/{result['phase']}"):
                    resolved.append(block)
                    confirmation_hashes[inv] = object_hash(result)
        if not resolved:
            return
        record = {'version': 'local-persistence-reconciliation-1', 'source_id': self.manifest.source_id,
                  'original_state': state, 'resolved': resolved,
                  'confirmation_hashes': confirmation_hashes}
        if recovery_hashes:
            record['not_sent_settlement_hashes'] = recovery_hashes
        identity = object_hash(record)
        self.store.put(self.run_id, 'reconciliations/' + identity, record, immutable=True)
        remaining = [b for b in state['operational_blockers'] if b not in resolved]
        messages = {b['message'] for b in resolved} - {b['message'] for b in remaining}
        state.update(operational_blockers=remaining,
                     limitations=[t for t in state.get('limitations', []) if t not in messages],
                     reconciliation_records=[*state.get('reconciliation_records', []), identity])
        if not remaining and state['status'] in {'failed', 'blocked'}:
            state['status'] = 'running'  # Local commit completion; no execution is started.
        self.store.put(self.run_id, 'state', state)

    def build_payload(self, role, phase, assignment, current_distribution, feedback=None):
        payload = {"phase": phase, "role": role, "manifest": agent_manifest(
            self.store, self.manifest, self.store.exists(self.run_id, 'barrier')),
            "financial_restriction": financial_policy(),
            "assignment": assignment, "own_observations": self.opinions(role) if self.runtime.mode != "codex-app-server" else [],
            "baseline_receipts": self.store.get(self.run_id, "baseline")["ids"],
            "comparison_ids": self.store.names(self.run_id, "comparisons"),
            "instruction": "Leia os intervalos atribuídos via ferramentas. Declare lacunas. Em debate retorne posições; final exige decisão por achado."}
        if current_distribution:
            payload['batch_distribution_id'] = current_distribution['id']
        if self.runtime.mode == 'codex-app-server' and self.opinions(role):
            from .context_pages import create_reference
            payload['own_observations'] = create_reference(self.store, self.manifest, self.config,
                self.opinions(role), phase=phase, audience=[role], kind='own_history')
        if self.store.exists(self.run_id, "assessment/smoke-contract"):
            from .smoke_causality import check_marker
            marker = check_marker(self.store, self.manifest)
            payload["smoke_evidence_instruction"] = {
                "receipt_id": marker["receipt_id"],
                "instruction": "Consulte os receipts de base pelas ferramentas. Se um achado usar essa evidência, "
                    "cite seu ID e referências que cubram a função examinada inteira. Registre somente o que "
                    "a fonte e as observações sustentam; nenhum achado é obrigatório."}
        if self.store.exists(self.run_id, "barrier"):
            phase_input = f"phase-inputs/{phase}"
            from .context_pages import create_reference
            ref = create_reference(self.store, self.manifest, self.config, {
                'published_opinions': self.store.get(self.run_id, phase_input) if self.store.exists(self.run_id, phase_input) else self.shared(),
                'finding_ids': list(self.findings()), 'receipt_ids': self.store.names(self.run_id, 'receipts')},
                phase=phase, audience=[r.value for r in Role], kind='discussion')
            payload['published_opinions'] = ref
            payload['required_context_pages'] = ref['page_ids']
            if len(ref['page_ids']) > self.config.limits.max_turns:
                raise BudgetExceeded(f"Contexto obrigatório exige {len(ref['page_ids'])} ferramentas; teto {self.config.limits.max_turns}")
        if self.runtime.mode == 'codex-app-server' and phase.startswith('initial-') and isinstance(assignment, list):
            from .turn_planning import initial_read_plan
            planning_tools = SourceTools(self.store, self.manifest, self.config, None,
                ToolContext(self.run_id, role, phase, 'controller-planning'))
            plan = initial_read_plan(planning_tools, assignment, payload['baseline_receipts'],
                                     reserves=tool_reserves(self.store, self.manifest, self.config))
            if not plan['mandatory_reads_fit']:
                raise BudgetExceeded('lote inicial inviável no limite de ferramentas: '
                    f"mínimo {plan['minimum_tool_calls']}, teto {plan['max_tool_calls']}, "
                    f"linhas não materializáveis {len(plan['unreadable_lines'])}; replanejamento necessário, sem nova chamada")
            payload['initial_read_plan'] = plan
        # The effective, selected context is measured by the runtime after
        # paging/catalog selection and factual financial data are added.
        if feedback:
            payload['validation_feedback'] = feedback
        return payload

    async def invoke(self, role: str, phase: str, assignment=None, final=False):
        current_distribution = distribution(self.store, self.manifest, self.config)
        if phase.startswith('initial-'):
            expected_assignment = assignment_for_phase(self.store, self.manifest, self.config, phase)
            if assignment is not None and assignment != expected_assignment:
                raise PolicyError('lote inicial diverge da distribuição efetiva')
            assignment = expected_assignment
        name = f"roles/{role}/phases/{phase}"
        if self.store.exists(self.run_id, name):
            if is_blind(phase):
                validate_saved_initial(self.store, self.manifest, self.config, role, phase, assignment if isinstance(assignment, list) else None)
            record = self.store.get(self.run_id, name)
            self.validator.validate_record(record, role, phase)
            self.finish_phase(role, phase, record)
            return record['output']
        async with self.semaphore:
            if self.store.exists(self.run_id, "cancel"):
                raise asyncio.CancelledError
            self.update(phase=phase)
            payload, feedback = None, None
            from .recovery_authorization import attempt_limit
            attempt_count = attempt_limit(self.store, self.manifest, self.config, role, phase)
            for attempt in range(attempt_count):
                attempt_name = name.replace("/phases/", "/attempts/") + f"-{attempt}"
                if self.store.exists(self.run_id, attempt_name):
                    if self.store.exists(self.run_id, 'recovery-decisions/' + self.store.get(self.run_id, attempt_name)['invocation_id']):
                        from .recovery import validate_decision
                        validate_decision(self.store, self.manifest, self.store.get(self.run_id, attempt_name)['invocation_id'])
                        continue
                    if self.store.exists(self.run_id, attempt_name + '-interrupted'):
                        # Explicit operator recovery after an official terminal-state
                        # check. It consumes an existing slot; never creates retries.
                        recovery = self.store.get(self.run_id, attempt_name + '-interrupted')
                        previous = self.store.get(self.run_id, attempt_name)
                        turn = self.store.get(self.run_id, 'codex-turns/' + previous['invocation_id'])
                        if (recovery.get('source') != 'official_app_server_thread_read' or recovery.get('status') != 'interrupted'
                            or recovery.get('invocation_id') != previous['invocation_id'] or turn.get('status') != 'ambiguous'
                            or recovery.get('thread_id') != turn.get('thread_id') or recovery.get('turn_id') != turn.get('turn_id')
                            or turn.get('role') != role or turn.get('phase') != phase):
                            raise RuntimePaused('Reconciliação de turno interrompido inválida; retomada bloqueada')
                        continue
                    if self.store.exists(self.run_id, attempt_name + "-rejected"):
                        rejected = self.store.get(self.run_id, attempt_name + "-rejected")
                        if rejected.get("feedback"):
                            feedback = rejected["feedback"]
                        continue
                    if self.runtime.mode != "codex-app-server":
                        continue
                    previous_attempt = self.store.get(self.run_id, attempt_name)
                    invocation_id = previous_attempt['invocation_id']
                    if self.store.exists(self.run_id, 'turn-inputs/' + invocation_id):
                        payload = original_input(self.store, self.manifest, role, phase, invocation_id, assignment)
                    else:
                        payload = self.build_payload(role, phase, assignment, current_distribution, feedback)
                    if current_distribution and not self.store.exists(self.run_id, 'codex-turns/' + invocation_id):
                        if any(c.get('invocation_id') == invocation_id for c in self.store.get(self.run_id, 'ledger')['calls']):
                            raise RuntimePaused('Reserva anterior sem checkpoint: revisão explícita necessária, sem nova reserva')
                        if previous_attempt.get('input_hash') != object_hash(payload):
                            # A prepared slot without reservation/dispatch is still
                            # the same slot. Preserve its old input hash and bind
                            # the new controller context in a separate record.
                            self.store.put(self.run_id, attempt_name + '-distribution-continuation', {
                                'source': 'operator_versioned_batch_distribution',
                                'batch_distribution_id': current_distribution['id'],
                                'original_attempt_hash': object_hash(previous_attempt),
                                'original_input_hash': previous_attempt.get('input_hash'),
                                'effective_input_hash': object_hash(payload),
                                'invocation_id': invocation_id,
                                'previous_checkpoint_absent': True, 'previous_reservation_absent': True}, immutable=True)
                else:
                    invocation_id = secrets.token_hex(12)
                    payload = self.build_payload(role, phase, assignment, current_distribution, feedback)
                if self.store.exists(self.run_id, 'turn-inputs/' + invocation_id):
                    payload = original_input(self.store, self.manifest, role, phase, invocation_id, assignment)
                else:
                    checkpoint_name = 'codex-turns/' + invocation_id
                    if self.store.exists(self.run_id, checkpoint_name) and self.store.get(self.run_id, checkpoint_name).get('input_hash') != object_hash(payload):
                        raise RuntimePaused('Entrada histórica original indisponível; não reconstruir com evidências novas')
                    freeze_input(self.store, self.manifest, role, phase, invocation_id, payload, assignment)
                tools = SourceTools(self.store, self.manifest, self.config, self.executor, ToolContext(self.run_id, role, phase, invocation_id, attempt))
                if not self.store.exists(self.run_id, attempt_name):
                    attempt_record = {"version": "phase-attempt-2", "invocation_id": invocation_id, "started_at": now(), "input_hash": object_hash(payload),
                                      'input_record': 'turn-inputs/' + invocation_id}
                    if current_distribution:
                        attempt_record['batch_distribution_id'] = current_distribution['id']
                    self.store.put(self.run_id, attempt_name, attempt_record, immutable=True)
                self.store.put(self.run_id, f"roles/{role}/state", {"phase": phase, "invocation_id": invocation_id, "status": "running"})
                try:
                    result = await self.runtime.invoke(role, phase, payload, tools, final=final)
                    return self.publish_phase(role, phase, invocation_id, result, tools)
                except RuntimePaused:
                    raise
                except (ValidationError, PolicyError, json.JSONDecodeError) as exc:
                    self.store.put(self.run_id, attempt_name + "-rejected", {"error_type": type(exc).__name__, "feedback": "Saída rejeitada: " + redact(str(exc))[:1500]}, immutable=True)
                    self.store.event(self.run_id, "invalid_output", {"role": role, "phase": phase, "error_type": type(exc).__name__, "attempt": attempt})
                    if attempt == attempt_count - 1:
                        raise PolicyError("saída inválida após limite de correções") from exc
                    feedback = "Saída rejeitada: " + redact(str(exc))[:1500]
                    continue
            raise PolicyError("tentativas desta fase esgotadas; nenhuma chamada repetida automaticamente")

    async def independent(self, role: str):
        if role == "juiz":
            await self.invoke(role, "blind", {"scope": "inspeção cega de requisitos, arquitetura, entradas críticas, invariantes; escolha trechos pelo inventário"})
        else:
            for i, batch in enumerate(effective_batches(self.store, self.manifest, self.config)):
                await self.invoke(role, f"initial-{i:04d}", batch)
        self.store.put(self.run_id, f"roles/{role}/initial", {"role": role, "opinions": self.opinions(role)}, immutable=True)

    async def paired(self, phase: str):
        # gather waits for both; the next phase cannot start on one early result.
        self.store.put(self.run_id, f"phase-inputs/{phase}", self.store.get(self.run_id, f"phase-inputs/{phase}") if self.store.exists(self.run_id, f"phase-inputs/{phase}") else self.shared(), immutable=True)
        tasks = [asyncio.create_task(self.invoke(r, phase)) for r in ("auditor", "defensor")]
        try:
            return await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def body(self):
        verify_source(self.store, self.manifest)
        from .turn_planning import ensure_global_capacity
        ensure_global_capacity(self.store, self.manifest, self.config)
        if not self.store.exists(self.run_id, "baseline"):
            r = await self.executor.execute(TestRequest(kind="baseline", purpose="testes de base factuais do snapshot"), "baseline", "baseline")
            self.store.put(self.run_id, "baseline", {"ids": [r.id]}, immutable=True)
        if self.runtime is None:
            self.runtime = CodexRuntime(self.store, self.run_id, self.config)
        if isinstance(self.runtime, CodexRuntime):
            self.runtime.global_deadline = self._global_deadline
        if self.runtime.mode == 'codex-app-server' and not self.store.exists(self.run_id, 'barrier'):
            from .turn_planning import source_plans
            for entry in source_plans(self.store, self.manifest, self.config):
                if not entry['plan']['mandatory_reads_fit']:
                    raise BudgetExceeded(f"lote inicial inviável {entry['role']}/{entry['phase']}: "
                        f"mínimo {entry['plan']['minimum_tool_calls']} leituras, teto {self.config.limits.max_turns}; "
                        'replanejamento necessário antes de qualquer nova chamada')
        # A cached response/phase is local recovery, not a new dispatch. The
        # Codex runtime runs the mandatory preflight only for new generation.
        if not isinstance(self.runtime, CodexRuntime) and hasattr(self.runtime, 'preflight'):
            await self.runtime.preflight()
        self.update(runtime_mode=self.runtime.mode)
        if not self.store.exists(self.run_id, "barrier"):
            # An explicitly authorized recovery must finish before other initial
            # roles start. Failure spends no additional role's turn.
            for role in Role:
                if self.store.exists(self.run_id, f'roles/{role.value}/attempts/initial-0000-extra-authorization'):
                    await self.independent(role.value)
            tasks = [asyncio.create_task(self.independent(r.value)) for r in Role]
            try:
                await asyncio.gather(*tasks)
            except BaseException:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            investigation = assess_independent_investigation(self.store, self.manifest)
            if not investigation["valid"]:
                raise PolicyError("; ".join(investigation["gaps"]))
            barrier = {"published_at": now(), "initial_hashes": {r.value: object_hash(self.store.get(self.run_id, f"roles/{r.value}/initial")) for r in Role}}
            current_distribution = distribution(self.store, self.manifest, self.config)
            if current_distribution:
                barrier['batch_distribution_id'] = current_distribution['id']
            self.store.put(self.run_id, "barrier", barrier, immutable=True)
            self.store.event(self.run_id, "barrier_published", barrier)
        investigation = assess_independent_investigation(self.store, self.manifest)
        if not investigation["valid"]:
            raise PolicyError("; ".join(investigation["gaps"]))
        await self.paired("contest")
        await self.paired("reply")
        if not self.store.exists(self.run_id, "review-start"):
            self.store.put(self.run_id, "review-start", {"finding_ids": list(self.findings()), "receipt_ids": self.store.names(self.run_id, "receipts")}, immutable=True)
        before_findings = set(self.store.get(self.run_id, "review-start")["finding_ids"])
        before_receipts = set(self.store.get(self.run_id, "review-start")["receipt_ids"])
        review = await self.invoke("juiz", "review")
        if not self.store.exists(self.run_id, "material-review"):
            # Persist the gate so resume makes the same decision.
            new_ids = set(self.findings()) - before_findings
            new_receipts = set(self.store.names(self.run_id, "receipts")) - before_receipts
            self.store.put(self.run_id, "material-review", {"additional_round": bool(new_ids or new_receipts), "new_finding_ids": sorted(new_ids), "new_receipt_ids": sorted(new_receipts)}, immutable=True)
        if self.store.get(self.run_id, "material-review")["additional_round"]:
            await self.paired("extra-contest")
            await self.paired("extra-reply")
        result = await self.invoke("juiz", "final", final=True)
        self.finalize(result)

    def finalize(self, result):
        self.store.put(self.run_id, "judgment", result, immutable=True)
        verify_source(self.store, self.manifest)
        self.resolve_local_persistence()
        from .report import build_report
        report = build_report(self.store, self.run_id)
        review_name = 'assessment/completion-review'
        review = self.store.get(self.run_id, review_name) if self.store.exists(self.run_id, review_name) else None
        completion = assess_completion(report, review)
        self.store.put(self.run_id, 'assessment/completion', completion)
        technical = "decisions_recorded"
        if not result["verdicts"] or all(v["decision"] in {"manter", "descartar", "documentar/aceitar por ora"} for v in result["verdicts"]):
            technical = "Nenhuma alteração necessária no escopo verificado"
        if completion['blockers']:
            technical += "; lacunas bloqueantes/limitações não esclarecidas"
        if result["new_findings"]:
            technical = "inconclusivo: achado novo pendente de contraditório"
        if self.runtime.mode != "codex-app-server":
            technical = "MOCK: teste de infraestrutura; não é auditoria real"
        self.update(status=completion['status'], technical_result=technical, phase='done',
            limitations=[item['text'] for item in completion['limitations']],
            completion_blockers=completion['blockers'], assessment_version=completion['version'])

    async def run(self, resume=False):
        with self.store.lock(self.run_id):
            state = self.state()
            if state["phase"] == "done":
                investigation = assess_independent_investigation(self.store, self.manifest)
                if not investigation["valid"]:
                    raise PolicyError("Run encerrado com impedimento estrutural de investigação cega: "
                        + "; ".join(investigation["gaps"]))
                saved = {r.value + '/' + p for r in Role for p in self.store.names(self.run_id, f'roles/{r.value}/phases')}
                if set(state['completed']) != saved:
                    await self.reconcile()
                    state = self.state()
                return state
            await self.reconcile()
            state = self.state()
            if state.get('phase') == 'done':
                return state
            from .recovery import pending_attempts
            unresolved = pending_attempts(self.store, self.manifest)
            if unresolved:
                self.update(status='blocked', recovery_pending=unresolved)
                return self.state()
            self.store.put(self.run_id, 'financial-policy', {'permanent': True, 'rule': financial_policy()}, immutable=True)
            total_limit = total_seconds(self.store, self.run_id, self.config)
            if self.store.exists(self.run_id, "cancel"):
                if not resume:
                    self.update(status="cancelled")
                    return self.state()
                self.store.event(self.run_id, "cancel_cleared_for_resume", {})
                self.store.path(self.run_id, "cancel.json").unlink()
            if state.get("active_since"):
                wall = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(state["active_since"])).total_seconds())
                state["elapsed_seconds"] += wall
                recovery = {'version': 'elapsed-recovery-1', 'active_since': state['active_since'],
                    'observed_at': now(), 'charged_seconds': wall,
                    'basis': 'conservative_wall_elapsed_including_unknown_downtime; not measured agent duration'}
                self.store.put(self.run_id, 'clock-recoveries/' + object_hash(recovery), recovery, immutable=True)
            self.update(status="running", elapsed_seconds=state['elapsed_seconds'], active_since=now())
            start = time.monotonic()
            remaining = total_limit - state.get("elapsed_seconds", 0)
            self._global_deadline = start + max(0, remaining)
            async def monitor():
                while True:
                    await asyncio.sleep(0.2)
                    if self.store.exists(self.run_id, "cancel"):
                        return
            body = asyncio.create_task(self.body())
            cancel = asyncio.create_task(monitor())
            try:
                done, _ = await asyncio.wait({body, cancel}, timeout=max(0, remaining), return_when=asyncio.FIRST_COMPLETED)
                if cancel in done or not done:
                    body.cancel()
                    await asyncio.gather(body, return_exceptions=True)
                    self.update(status="cancelled" if cancel in done else "partial", technical_result="inconclusivo", limitations=["cancelamento solicitado" if cancel in done else "limite de tempo total"])
                else:
                    await body
            except RuntimePaused as exc:
                kind = ('local_persistence' if isinstance(exc, PersistencePending) else
                        'reservation_persistence' if isinstance(exc, ReservationPending) else 'runtime_precondition')
                blocker = {'kind': kind,
                           'invocation_id': getattr(exc, 'invocation_id', None), 'message': str(exc)}
                self.update(status="blocked", technical_result="inconclusivo", limitations=[str(exc)], operational_blockers=[blocker])
            except BudgetExceeded as exc:
                self.update(status="partial", technical_result="inconclusivo", limitations=[str(exc)])
            except asyncio.CancelledError:
                body.cancel()
                await asyncio.gather(body, return_exceptions=True)
                self.update(status="cancelled", technical_result="inconclusivo", limitations=["controlador interrompido"])
            except Exception as exc:
                message = redact(str(exc))[:2000] if isinstance(exc, PolicyError) else "Falha do runtime: " + type(exc).__name__
                self.update(status="partial" if isinstance(exc, (PolicyError, TimeoutError)) else "failed", technical_result="inconclusivo", limitations=[message],
                    operational_blockers=[{'kind': 'unresolved_controller_error', 'message': message}])
            finally:
                cancel.cancel()
                await asyncio.gather(cancel, return_exceptions=True)
                self.update(elapsed_seconds=state.get("elapsed_seconds", 0) + time.monotonic() - start, active_since=None)
                for role in Role:
                    name = f"roles/{role.value}/state"
                    if self.store.exists(self.run_id, name):
                        role_state = self.store.get(self.run_id, name)
                        if role_state["status"] == "running":
                            self.store.put(self.run_id, name, {**role_state, "status": "interrupted", "stopped_at": now()})
                if self.runtime and hasattr(self.runtime, "close"):
                    await self.runtime.close()
                from .report import write_report
                write_report(self.store, self.run_id)
            return self.state()
