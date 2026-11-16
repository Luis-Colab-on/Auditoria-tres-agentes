"""Codex is the sole generation backend; historical API helpers cannot generate."""
from __future__ import annotations
import asyncio
import secrets
from .security import PolicyError, now


class BudgetExceeded(RuntimeError):
    pass


class RuntimePaused(PolicyError):
    """Precondition failed; never treat as invalid model output or retry it."""


class AmbiguousTurn(RuntimePaused):
    pass


class PersistencePending(RuntimePaused):
    def __init__(self, invocation_id):
        self.invocation_id = invocation_id
        super().__init__('Persistência local pendente de resposta confirmada; execute recover sem nova inferência')


def retryable_api_error(error):
    """Historical offline compatibility only. There is no API retry path."""
    body = getattr(error, "body", None)
    details = body.get("error", body) if isinstance(body, dict) else {}
    details = details if isinstance(details, dict) else {}
    codes = {str(getattr(error, "code", "")), str(details.get("code", "")), str(details.get("type", ""))}
    return not any(any(word in code.lower() for word in ("quota", "billing", "credit", "spend", "budget", "usage_limit")) for code in codes)


class Budget:
    """Finite operational limits, NOT an atomic financial guard."""
    def __init__(self, store, run_id, config):
        self.store, self.run_id, self.config = store, run_id, config
        self.lock = asyncio.Lock()

    def _reconcile(self):
        ledger = self.store.get(self.run_id, 'ledger')
        for name in sorted(self.store.names(self.run_id, 'accounting/reservations'),
                           key=lambda n: self.store.get(self.run_id, 'accounting/reservations/' + n)['index']):
            reservation = self.store.get(self.run_id, 'accounting/reservations/' + name)
            index, entry = reservation['index'], reservation['entry']
            if index == len(ledger['calls']):
                ledger['calls'].append(dict(entry))
            elif not 0 <= index < len(ledger['calls']) or any(
                    ledger['calls'][index].get(k) != entry[k] for k in ('id', 'role', 'invocation_id', 'started_at')):
                raise PolicyError('Histórico de reservas divergente; não reordenar chamadas')
        for entry in ledger['calls']:
            name = 'accounting/settlements/' + entry['id']
            if self.store.exists(self.run_id, name):
                saved = self.store.get(self.run_id, name)
                if saved['call_id'] != entry['id'] or saved['invocation_id'] != entry['invocation_id']:
                    raise PolicyError('Liquidação local de outra chamada')
                entry.update(saved['fields'])
        return ledger

    def _save(self, ledger):
        ledger['known_cost_usd'] = None
        ledger['unknown_cost_calls'] = len(ledger['calls'])
        ledger['tokens'] = (None if not ledger['calls'] or any(c.get('input_tokens') is None or c.get('output_tokens') is None for c in ledger['calls'])
                            else sum(c['input_tokens'] + c['output_tokens'] for c in ledger['calls']))
        if ledger != self.store.get(self.run_id, 'ledger'):
            self.store.put(self.run_id, 'ledger', ledger)

    async def reconcile(self):
        async with self.lock:
            ledger = self._reconcile()
            self._save(ledger)
            return ledger

    async def reserve(self, role, invocation_id):
        async with self.lock:
            ledger = self._reconcile()
            self._save(ledger)
            if any(c.get('invocation_id') == invocation_id for c in ledger['calls']):
                raise RuntimePaused('Tentativa já reservada; reconciliar sem duplicar chamada')
            if len(ledger["calls"]) >= self.config.limits.max_calls:
                raise BudgetExceeded("limite operacional de turnos atingido")
            if self.store.exists(self.run_id, "cancel"):
                raise asyncio.CancelledError
            cid = secrets.token_hex(12)
            entry = {"id": cid, "role": role, "invocation_id": invocation_id,
                "started_at": now(), "status": "in_flight", "cost_usd": None,
                "input_tokens": None, "output_tokens": None}
            self.store.put(self.run_id, 'accounting/reservations/' + cid,
                           {'version': 'call-reservation-1', 'dispatch_protocol': 'durable-dispatch-1',
                            'index': len(ledger['calls']), 'entry': entry}, immutable=True)
            ledger['calls'].append(entry)
            self._save(ledger)
            return cid

    async def finish(self, cid, usage=None, error=None, dispatch_status=None):
        async with self.lock:
            ledger = self._reconcile()
            entry = next(c for c in ledger["calls"] if c["id"] == cid)
            name = 'accounting/settlements/' + cid
            if self.store.exists(self.run_id, name):
                saved = self.store.get(self.run_id, name)
                if saved['fields']['error'] != error:
                    raise PolicyError('Resultado contábil já confirmado; não reclassificar')
                self._save(ledger)
                return
            fields = dict(finished_at=now(), status="error" if error else "completed", error=error)
            if dispatch_status is not None:
                fields['dispatch_status'] = dispatch_status
                if dispatch_status == 'not_sent':
                    fields['status'] = 'not_sent'
            if usage is not None:
                fields["input_tokens"] = getattr(usage, "input_tokens", None)
                fields["output_tokens"] = getattr(usage, "output_tokens", None)
                if getattr(usage, "official_sample", None):
                    fields["official_token_sample"] = usage.official_sample
            self.store.put(self.run_id, name, {'call_id': cid, 'invocation_id': entry['invocation_id'], 'fields': fields}, immutable=True)
            entry.update(fields)
            self._save(ledger)


class SDKRuntime:
    """Tombstone: older callers fail before importing any paid SDK."""
    def __init__(self, *args, **kwargs):
        raise PolicyError("Backend Agents SDK/API removido. Prepare nova execução Codex/ChatGPT; sem fallback pago.")
