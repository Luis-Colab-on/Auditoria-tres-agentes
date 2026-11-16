"""Pinned 0.167.0 context-compaction lifecycle, without tool authority or content."""
from .runtime_diagnostics import rejection
from .security import object_hash

VERSION = 'context-compaction-lifecycle-1'


def _milliseconds(value, *, nullable=False):
    return (nullable and value is None) or (type(value) is int and -(2**63) <= value < 2**63)


class CompactionLifecycle:
    def __init__(self, store, context, thread_id, turn_id, tool_limit, *, elapsed=None):
        self.store, self.context = store, context
        self.thread_id, self.turn_id, self.tool_limit = thread_id, turn_id, tool_limit
        self.active, self.completed, self.other_items = set(), set(), set()
        self.elapsed = elapsed

    def reject(self, message, reason, msg, steps):
        return rejection(message, reason, msg, self.context,
                         self.thread_id, self.turn_id, steps, self.tool_limit)

    def observe(self, msg, steps):
        method, params = msg.get('method'), msg.get('params')
        stamp = 'startedAtMs' if method == 'item/started' else 'completedAtMs'
        item = params.get('item') if isinstance(params, dict) else None
        if (method not in {'item/started', 'item/completed'} or 'id' in msg
            or not isinstance(params, dict) or set(params) != {'item', 'threadId', 'turnId', stamp}
            or params['threadId'] != self.thread_id or params['turnId'] != self.turn_id
            or not _milliseconds(params[stamp]) or not isinstance(item, dict)
            or not {'id', 'type'} <= set(item)
            or set(item) - {'id', 'type', 'startedAtMs', 'completedAtMs'}
            or item.get('type') != 'contextCompaction' or not isinstance(item.get('id'), str) or not item['id']
            or any(not _milliseconds(item[k], nullable=True) for k in ('startedAtMs', 'completedAtMs') if k in item)):
            raise self.reject('Evento de compactação malformado; contrato 0.167.0 obrigatório',
                              'context_compaction_structure', msg, steps)
        ident = item['id']
        if method == 'item/started':
            if ident in self.active or ident in self.completed or ident in self.other_items:
                raise self.reject('ID de compactação reutilizado', 'context_compaction_item', msg, steps)
            self.active.add(ident)
        else:
            if ident not in self.active:
                raise self.reject('Conclusão de compactação sem início correspondente', 'context_compaction_item', msg, steps)
            self.active.remove(ident)
            self.completed.add(ident)
        # Server timestamps validate wire shape only. They never adjust the
        # monotonic deadline or the factual financial confirmation's clock.
        timing = {'elapsed_monotonic_seconds': self.elapsed()} if self.elapsed else {}
        self.store.event(self.context.run_id, 'context_compaction', {
            'version': VERSION, 'method': method, 'item_type': 'contextCompaction',
            'item_id_sha256': object_hash(ident), 'role': self.context.role, 'phase': self.context.phase,
            'attempt': self.context.attempt, 'invocation_id': self.context.invocation_id,
            'thread_id': self.thread_id, 'turn_id': self.turn_id, **timing})

    def observe_other(self, msg, steps):
        item = msg.get('params', {}).get('item', {})
        ident = item.get('id')
        if not isinstance(ident, str):
            return
        if ident in self.active or ident in self.completed:
            raise self.reject('Item de compactação mudou de tipo', 'context_compaction_item', msg, steps)
        self.other_items.add(ident)

    def require_complete(self, msg, steps):
        if self.active:
            raise self.reject('Turno terminou com compactação sem conclusão correspondente',
                              'context_compaction_incomplete', msg, steps)

    def summary(self):
        return {'version': VERSION, 'started': len(self.active) + len(self.completed),
                'completed': len(self.completed), 'active_item_ids_sha256': sorted(object_hash(i) for i in self.active),
                'completed_item_ids_sha256': sorted(object_hash(i) for i in self.completed)}
