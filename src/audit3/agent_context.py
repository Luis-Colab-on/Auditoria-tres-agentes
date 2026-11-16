"""Versioned agent views. The authenticated full manifest remains authoritative."""
from collections import Counter
from .schemas import RunManifest
from .security import PolicyError, object_hash

VERSION = 'agent-manifest-1'


def visible_inventory(manifest, published):
    return [f.model_dump(mode='json') for f in manifest.files
            if f.category != 'prior_report' or published]


def inventory_reference(store, manifest, published):
    raw = store.get(manifest.run_id, 'manifest')
    if RunManifest.model_validate(raw) != manifest:
        raise PolicyError('manifesto da representação diverge do registro autenticado')
    records = visible_inventory(manifest, published)
    return {'manifest_sha256': object_hash(raw), 'inventory_sha256': object_hash(records),
            'visible_count': len(records), 'published': published}


def agent_manifest(store, manifest, published):
    """Keep the objective/constraints verbatim; omit repetitive per-file metadata.

    Every readable file remains discoverable, including files outside the batch.
    Full file metadata (also excluded/runtime records) stays available through the
    existing list_source(offset, limit) contract. Neither view grants source access.
    """
    ref = inventory_reference(store, manifest, published)
    records = visible_inventory(manifest, published)
    readable = [f for f in records if f['category'] != 'excluded']
    catalog = [{k: f[k] for k in ('path', 'sha256', 'lines', 'category')} for f in readable]
    view = {k: v for k, v in manifest.model_dump(mode='json').items() if k != 'files'}
    view.update(representation=VERSION, manifest_ref={'record': 'manifest', 'sha256': ref['manifest_sha256']},
                files=catalog, inventory={**ref, 'categories': dict(Counter(f['category'] for f in records)),
                    'readable_count': len(readable), 'runtime_only_count': sum(f.get('runtime_only', False) for f in records),
                    'lookup': {'tool': 'list_source', 'offset': 0, 'limit': 200},
                    'instruction': 'Catálogo não é leitura nem inspeção. list_source(offset, limit) devolve '
                        'metadados integrais paginados com hashes; read_source e search_source continuam '
                        'disponíveis para toda fonte autorizada, inclusive dependências fora do lote. '
                        'Arquivos excluídos/runtime não ganham permissão de leitura por constar no inventário. '
                        'Referências não substituem os trechos de código/evidências necessários à análise; '
                        'consulte novamente quando a informação não estiver preservada no contexto. '
                        'estimated_input_tokens/estimated_calls são estimativas históricas de preparação, '
                        'não medidas deste turno.'})
    view['catalog_id'] = object_hash({'version': VERSION, **ref, 'files': catalog})
    return view


def prepare_turn_context(store, manifest, payload, role, thread_id, published, *, omit_catalog=False):
    """Suppress a repeated catalog only after a same-session completed delivery.

    Ambiguous/written/not_sent turns never prove delivery. No history is replaced,
    no new session is created, and a missing catalog can always be consulted via
    list_source. Cached outputs are recovered before this function is used.
    """
    view = payload.get('manifest')
    if not isinstance(view, dict) or 'representation' not in view:
        return dict(payload), None  # Historical/direct runtime inputs remain readable.
    expected = agent_manifest(store, manifest, published)
    if view != expected:
        raise PolicyError('representação de manifesto inválida/desatualizada')
    prior_id = None
    for name in store.names(manifest.run_id, 'codex-turns'):
        prior = store.get(manifest.run_id, 'codex-turns/' + name)
        context = prior.get('agent_context') or {}
        if (prior.get('status') == 'completed' and prior.get('role') == role
            and prior.get('thread_id') == thread_id and prior.get('invocation_id') == name
            and context.get('version') == VERSION and context.get('catalog_id') == view['catalog_id']
            and context.get('manifest_sha256') == view['manifest_ref']['sha256']
            and context.get('inventory_sha256') == view['inventory']['inventory_sha256']
            and context.get('catalog_included') is True):
            prior_id = name
            break
    sent_view = dict(view)
    if prior_id or omit_catalog:
        sent_view.pop('files')
    included = prior_id is None and not omit_catalog
    sent_view['catalog_delivery'] = {'included': included, 'previous_completed_invocation_id': prior_id,
        'mode': 'inline' if included else ('previous_delivery' if prior_id else 'paged_first_delivery'),
        'instruction': 'Se o catálogo não estiver no contexto atual, consulte list_source; '
                       'o controlador não apaga o histórico nem presume que a compactação preservou informação.'}
    metadata = {'version': VERSION, 'catalog_id': view['catalog_id'],
                'manifest_sha256': view['manifest_ref']['sha256'],
                'inventory_sha256': view['inventory']['inventory_sha256'],
                'catalog_included': included, 'catalog_origin_invocation_id': prior_id}
    return {**payload, 'manifest': sent_view}, metadata
