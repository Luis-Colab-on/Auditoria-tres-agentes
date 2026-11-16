"""Shared deterministic phase validation; no runtime/executor construction."""
import json
from .schemas import Classification, Role
from .security import PolicyError, sensitive
from .tools import SourceTools
from .investigation import validate_initial_output
from .causality import causal_groups


class PhaseValidator:
    def __init__(self, store, manifest, config, *, read_only=False):
        self.store, self.manifest, self.config = store, manifest, config
        self.run_id = manifest.run_id
        self.read_only = read_only

    def validate_record(self, record, role, phase):
        if record.get('role') != role or record.get('phase') != phase:
            raise PolicyError('Identidade da fase persistida divergente')
        if record.get('version') != 'phase-publication-2' or not record.get('confirmation_hash'):
            return  # Original formats remain readable, without fabricated proof.
        from .attempts import confirmed, original_input
        from .security import object_hash
        from .schemas import Judgment, Opinion
        inv = record['invocation_id']
        result = confirmed(self.store, self.run_id, inv, role, phase, record['input_hash'])
        payload = original_input(self.store, self.manifest, role, phase, inv)
        if (result is None or object_hash(result) != record['confirmation_hash']
            or record.get('evidence_cutoff') != result['finished_at']
            or object_hash(payload) != result['input_hash']
            or (Judgment if phase == 'final' else Opinion).model_validate_json(result['output']).model_dump(mode='json') != record['output']):
            raise PolicyError('Publicação não corresponde à confirmação original')

    def opinions(self, role: str):
        return [self.store.get(self.run_id, f"roles/{role}/phases/{name}")["output"] for name in self.store.names(self.run_id, f"roles/{role}/phases")]

    def findings(self):
        found = {}
        for role in Role:
            for opinion in self.opinions(role.value):
                for finding in opinion.get("findings", []):
                    if finding["id"] in found and found[finding["id"]]["mechanism"] != finding["mechanism"]:
                        raise PolicyError("ID reaproveitado para mecanismo diferente")
                    # Keep the initial allegation; revisions are preserved in positions.
                    found.setdefault(finding["id"], finding)
        return found

    def validate_output(self, output, tools: SourceTools, final: bool):
        tools.require_phase_context()
        if sensitive(json.dumps(output.model_dump(mode="json"), ensure_ascii=False)):
            raise PolicyError("saída contém possível segredo/PII")
        if not final:
            for inspection in output.inspections:
                tools.validate_inspection(inspection)
            for finding in output.findings:
                if not finding.id.startswith(tools.context.role + "-"):
                    raise PolicyError("ID deve pertencer ao papel")
                tools.validate_finding(finding)
                if not (tools.context.phase.startswith("initial") or tools.context.phase in {"blind", "review"}) and finding.id not in self.findings():
                    raise PolicyError("novo achado tardio sem contraditório: registre limitação para nova auditoria")
            # Resolve references after validating the response's own findings.
            # Blind phases can use this role's history, never another role's
            # unpublished findings merely because it happened to finish first.
            blind = tools.context.phase.startswith("initial") or tools.context.phase == "blind"
            known = ({finding["id"] for opinion in self.opinions(tools.context.role)
                for finding in opinion.get("findings", [])} if blind else set(self.findings()))
            known.update(finding.id for finding in output.findings)
            for position in output.positions:
                if not position.argument.strip():
                    raise PolicyError('Posição sem argumento técnico')
                if position.finding_id not in known:
                    raise PolicyError("posição sobre achado inexistente")
                for eid in position.evidence_ids:
                    tools.read_evidence(eid, record_access=False)
            validate_initial_output(output, tools)
            return
        known = self.findings()
        modern = self.store.exists(self.run_id, 'planning/initial') or bool(self.store.names(self.run_id, 'turn-inputs'))
        if modern:
            for fid in known:
                owner = next((r.value for r in Role if any(f['id'] == fid for o in self.opinions(r.value) for f in o.get('findings', []))), None)
                if owner in {'auditor', 'defensor'}:
                    opponent = 'defensor' if owner == 'auditor' else 'auditor'
                    required = [(opponent, 'contest'), (owner, 'reply')]
                else:
                    review = self.store.exists(self.run_id, 'roles/juiz/phases/review') and any(
                        f['id'] == fid for f in self.store.get(self.run_id, 'roles/juiz/phases/review')['output'].get('findings', []))
                    blind = self.store.exists(self.run_id, 'roles/juiz/phases/blind') and any(
                        f['id'] == fid for f in self.store.get(self.run_id, 'roles/juiz/phases/blind')['output'].get('findings', []))
                    new_in_review = review and not blind
                    if new_in_review:
                        material = self.store.get(self.run_id, 'material-review') if self.store.exists(self.run_id, 'material-review') else {}
                        if material.get('additional_round') is not True or fid not in material.get('new_finding_ids', []):
                            raise PolicyError(f'Achado novo {fid} sem registro material da rodada adicional')
                    required = [(r, p) for r in ('auditor', 'defensor')
                                for p in (('extra-contest', 'extra-reply') if new_in_review else ('contest', 'reply'))]
                for r, p in required:
                    path = f'roles/{r}/phases/{p}'
                    if not self.store.exists(self.run_id, path) or not any(
                        x['finding_id'] == fid and x.get('argument', '').strip()
                        for x in self.store.get(self.run_id, path)['output'].get('positions', [])):
                        raise PolicyError(f'Achado {fid} sem contraditório obrigatório em {r}/{p}')
        if self.store.exists(self.run_id, "baseline"):
            for eid in self.store.get(self.run_id, "baseline")["ids"]:
                receipt = tools.read_evidence(eid, record_access=False)["receipt"]
                if receipt["status"] in {"passed", "failed"}:
                    tools.require_evidence_consulted(eid)
                    if not output.baseline_assessment or not output.baseline_assessment.strip():
                        raise PolicyError("Juiz precisa avaliar testes de base e suas expectativas, inclusive divergências")
        if {v.finding_id for v in output.verdicts} != set(known) or len(output.verdicts) != len(known):
            raise PolicyError("cada achado exige exatamente uma decisão")
        for verdict in output.verdicts:
            finding = known[verdict.finding_id]
            if modern:
                if verdict.delivery is None:
                    raise PolicyError('Veredito exige prioridade fundamentada, preservação e teste de regressão')
                if verdict.decision.value in {'corrigir agora', 'programar correção'} and not verdict.delivery.proposed_adjustment:
                    raise PolicyError('Correção proposta ausente da entrega técnica')
                if verdict.classification == Classification.HYPOTHESIS and not verdict.delivery.pending_verification:
                    raise PolicyError('Hipótese exige indicar a verificação pendente')
            # Judge has to consult source directly, including initially raised findings.
            from .schemas import SourceRef
            for ref in finding["refs"]:
                tools.validate_ref(SourceRef.model_validate(ref))
            for eid in verdict.evidence_ids:
                tools.read_evidence(eid, record_access=False)
                tools.require_evidence_consulted(eid)
            if verdict.classification == Classification.PROVEN:
                if verdict.proof_method == "executed":
                    if not verdict.evidence_ids:
                        raise PolicyError("falha executada sem receipt")
                    for eid in verdict.evidence_ids:
                        r = tools.read_evidence(eid, record_access=False)["receipt"]
                        if r["execution"] not in {"docker", "compose"} or r["status"] not in {"passed", "failed"}:
                            raise PolicyError("receipt não prova execução")
                if verdict.proof_method == "static" and not finding.get("static_demonstration"):
                    raise PolicyError("falta demonstração estática verificável")
        for finding in output.new_findings:
            tools.validate_finding(finding)
        certificate_name = 'assessment/causal-certificates'
        prepare_certificates = (self.store.exists(self.run_id, 'assessment/smoke-contract')
            and tools.context.invocation_id != 'report-validation' and not self.read_only)
        if prepare_certificates:
            from .smoke_causality import certificates_for_smoke
            candidates = [known[v.finding_id] for v in output.verdicts if v.classification == Classification.PROVEN]
            certificates = certificates_for_smoke(self.store, self.manifest, candidates, tools)
        else:
            certificates = self.store.get(self.run_id, certificate_name) if self.store.exists(self.run_id, certificate_name) else []
        causal_groups(list(known.values()), [v.model_dump(mode='json') for v in output.verdicts],
            tools, tools.source_bytes_for_validation, certificates)
        if prepare_certificates:
            self.store.put(self.run_id, certificate_name, certificates, immutable=True)
