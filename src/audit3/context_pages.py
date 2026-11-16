"""Immutable, verifiable pages of existing arguments/evidence, never summaries."""
import json
from .security import PolicyError, canonical, digest, object_hash

VERSION = 'context-pages-1'


def page_text_budget(maximum):
    budget = maximum - 2048
    if budget < 256:
        raise PolicyError(f'max_output_bytes={maximum}: orçamento de saída insuficiente para página verificável; mínimo operacional 2304 bytes')
    return budget


def create_reference(store, manifest, config, value, *, phase, audience, kind, receipt_id=None):
    page_budget = page_text_budget(config.limits.max_output_bytes)
    text = canonical(value).decode('utf-8')
    metadata = {'version': VERSION, 'run_id': manifest.run_id, 'source_id': manifest.source_id,
                'manifest_hash': object_hash(store.get(manifest.run_id, 'manifest')),
                'phase': phase, 'audience': sorted(audience), 'kind': kind, 'receipt_id': receipt_id,
                'barrier_hash': object_hash(store.get(manifest.run_id, 'barrier'))
                    if store.exists(manifest.run_id, 'barrier') else None,
                'content_sha256': digest(text.encode()), 'content_utf8_bytes': len(text.encode())}
    document_id = object_hash(metadata)
    parts, cursor = [], 0
    while cursor < len(text):
        lo, hi = 1, min(page_budget, len(text) - cursor)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps(text[cursor:cursor + mid], ensure_ascii=False).encode()) <= page_budget:
                lo = mid
            else:
                hi = mid - 1
        parts.append(text[cursor:cursor + lo]); cursor += lo
    pages = [object_hash({'document_id': document_id, 'index': i})[:24] for i in range(len(parts))]
    document = {**metadata, 'page_ids': pages}
    store.put(manifest.run_id, 'context-documents/' + document_id, document, immutable=True)
    for i, part in enumerate(parts):
        store.put(manifest.run_id, 'context-pages/' + pages[i], {
            'document_id': document_id, 'index': i, 'text': part, 'text_sha256': digest(part.encode()),
            'next_page': pages[i + 1] if i + 1 < len(pages) else None}, immutable=True)
    return {'version': VERSION, 'document_id': document_id, 'content_sha256': metadata['content_sha256'],
            'utf8_bytes': metadata['content_utf8_bytes'], 'page_ids': pages,
            'tool': 'read_evidence', 'instruction': 'Consulte as páginas pelo ID; elas contêm o JSON integral, '
                'sem resumo. Reuna os fragmentos na ordem e confira o hash. Contexto não é leitura de fonte nem receipt de execução.'}


def read_page(tools, page_id):
    s, m, c = tools.store, tools.manifest, tools.context
    page = s.get(c.run_id, 'context-pages/' + page_id)
    document = s.get(c.run_id, 'context-documents/' + page['document_id'])
    metadata = {k: v for k, v in document.items() if k != 'page_ids'}
    ids = document.get('page_ids', [])
    index = page.get('index')
    if (type(index) is not int or not 0 <= index < len(ids)
        or any(pid != object_hash({'document_id': page['document_id'], 'index': i})[:24] for i, pid in enumerate(ids))
        or page.get('next_page') != (ids[index + 1] if index + 1 < len(ids) else None)
        or object_hash(metadata) != page['document_id'] or document.get('version') != VERSION
        or document.get('run_id') != c.run_id or document.get('source_id') != m.source_id
        or document.get('manifest_hash') != object_hash(s.get(c.run_id, 'manifest'))
        or c.role not in document.get('audience', []) or document.get('phase') != c.phase
        or document['page_ids'][page['index']] != page_id
        or page['text_sha256'] != digest(page['text'].encode())):
        raise PolicyError('Página de outro contexto/papel/fase ou adulterada')
    if document['kind'] == 'discussion':
        if not tools.published() or document['barrier_hash'] != object_hash(s.get(c.run_id, 'barrier')):
            raise PolicyError('Discussão privada antes da barreira')
    if document['receipt_id']:
        # Controller-only lookup still enforces owner/source/visibility, and
        # never records consultation of the not-yet-delivered complete receipt.
        tools.read_evidence(document['receipt_id'], record_access=False)
    tools.log('read_context', {'page_id': page_id, 'document_id': page['document_id'], 'kind': document['kind']})
    if document['receipt_id'] and pages_consulted(tools, document['page_ids']):
        tools.log('read_evidence', {'id': document['receipt_id'], 'complete_document_sha256': document['content_sha256']})
    return {'context_page': {**page, 'id': page_id, 'page_count': len(document['page_ids'])},
            'content_sha256': document['content_sha256']}


def pages_consulted(tools, ids):
    seen = set()
    for name in tools.store.names(tools.context.run_id, 'events'):
        event = tools.store.get(tools.context.run_id, 'events/' + name)
        d = event['data']
        if (event['kind'] == 'tool' and d.get('tool') == 'read_context'
            and d.get('run_id') == tools.context.run_id
            and d.get('role') == tools.context.role and d.get('phase') == tools.context.phase
            and d.get('source_id') == tools.manifest.source_id
            and (not tools.read_before or event['at'] <= tools.read_before)):
            seen.add(d['page_id'])
    return set(ids) <= seen
