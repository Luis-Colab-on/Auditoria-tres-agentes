"""Operator review of scanner matches, bound to the entire acquired inventory.

The scanner still runs. This accepts neither a blanket allowlist nor secrets.
Code contacts/examples and expression false positives require an accountable
reviewer, exact spans and current context. Their semantic interpretation is the
reviewer's responsibility; factual bindings and forbidden types are checked here.
"""
from .security import PATTERNS, PolicyError, digest, object_hash

VERSION = 'source-acquisition-review-1'
KINDS = {4: {'public_code_contact', 'synthetic_example', 'dependency_author_metadata'},
         5: {'input_format_example'}, 6: {'code_expression'}}


def inventory_hash(entries):
    return object_hash(sorted([{'path': name, 'sha256': digest(data)}
                               for name, data, _ in entries], key=lambda f: f['path']))


def scanner_matches(text):
    result = []
    for index, pattern in enumerate(PATTERNS):
        for match in pattern.finditer(text):
            start = text.rfind('\n', 0, match.start()) + 1
            end = text.find('\n', match.end())
            line = text[start:end if end >= 0 else len(text)]
            result.append({'pattern': index, 'start': match.start(), 'end': match.end(),
                           'sha256': digest(match.group().encode()),
                           'context_sha256': digest(line.encode())})
    return result


def validate_review(review, entries, objective):
    if not review:
        return set()
    if (not isinstance(review, dict) or set(review) != {'version', 'reviewer', 'objective',
            'inventory_hash', 'semantic_responsibility', 'files'}
        or review.get('version') != VERSION or review.get('objective') != objective
        or review.get('inventory_hash') != inventory_hash(entries)
        or review.get('semantic_responsibility') != 'reviewer'
        or not isinstance(review.get('reviewer'), str) or not review['reviewer'].strip()
        or not isinstance(review.get('files'), dict)):
        raise PolicyError('Revisão de aquisição sem revisor/objetivo/inventário atual')
    index = {name: data for name, data, _ in entries}
    for name, decision in review['files'].items():
        if name not in index or not isinstance(decision, dict):
            raise PolicyError('Revisão de arquivo inexistente/inválida')
        data = index[name]
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            raise PolicyError('Revisão textual não aceita binário') from None
        if (set(decision) != {'sha256', 'justification', 'matches'}
            or decision['sha256'] != digest(data) or not isinstance(decision['justification'], str)
            or not decision['justification'].strip() or not isinstance(decision['matches'], list)):
            raise PolicyError('Decisão não corresponde aos bytes/justificativa do arquivo')
        observed = scanner_matches(text)
        facts = [{k: match.get(k) for k in ('pattern', 'start', 'end', 'sha256', 'context_sha256')}
                 for match in decision['matches'] if isinstance(match, dict)]
        if not observed or facts != observed:
            raise PolicyError('Revisão não examina todos os sinais atuais do scanner')
        for match in decision['matches']:
            if (set(match) != {'pattern', 'start', 'end', 'sha256', 'context_sha256', 'kind', 'justification'}
                or match.get('kind') not in KINDS.get(match['pattern'], set())
                or not isinstance(match.get('justification'), str) or not match['justification'].strip()):
                raise PolicyError('Sinal sem interpretação suportada; credenciais/chaves não são dispensáveis')
            # CPF format examples must be literal placeholders, not stored values.
            line_start = text.rfind('\n', 0, match['start']) + 1
            line_end = text.find('\n', match['end'])
            line = text[line_start:line_end if line_end >= 0 else len(text)]
            if match['pattern'] == 5 and 'placeholder' not in line:
                raise PolicyError('Dado pessoal não demonstrado como exemplo de formato')
            if match['pattern'] == 6:
                raw = text[match['start']:match['end']]
                value = PATTERNS[6].search(raw).group(1)
                # The supported current false positives are function calls or
                # variable/property expressions, never a literal password/token.
                if '(' not in value and not value.startswith('$'):
                    raise PolicyError('Atribuição literal sensível permanece bloqueada')
    return set(review['files'])
