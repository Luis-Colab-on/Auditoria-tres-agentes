"""Local input policy regressions; no audited program, model or Docker executes."""
import copy
import json
import os
from pathlib import Path
import pytest
from audit3.acquisition_review import VERSION, inventory_hash, scanner_matches
from audit3.config import Config, Profile
from audit3.evidence import Store
from audit3.schemas import FileRecord
from audit3.security import PolicyError, digest, object_hash
from audit3.snapshot import directory_entries, prepare, verify_source
from audit3.tools import SourceTools, ToolContext
from audit3.workflow import batches


OBJECTIVE = 'Inspect this synthetic snapshot; dependencies must execute but are outside source analysis.'


def reviewed(entries):
    result = {'version': VERSION, 'reviewer': 'MOCK operator review; not an audit',
        'objective': OBJECTIVE, 'inventory_hash': inventory_hash(entries),
        'semantic_responsibility': 'reviewer', 'files': {}}
    for name, data, _ in entries:
        signals = scanner_matches(data.decode())
        if not signals:
            continue
        for signal in signals:
            signal.update(kind={4: 'synthetic_example', 5: 'input_format_example', 6: 'code_expression'}.get(signal['pattern'], 'synthetic_example'),
                justification='MOCK: reviewed the original literal/expression and its context for this exact fixture.')
        result['files'][name] = {'sha256': digest(data), 'matches': signals,
            'justification': 'MOCK fixture contact example, not a live account credential; no bytes changed.'}
    return result


def source(tmp_path, files):
    root = tmp_path / 'input'
    root.mkdir()
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
    return root


def setup(tmp_path, files, config=None, review=False):
    root = source(tmp_path, files)
    config = config or Config()
    entries = directory_entries(root, config)
    approval = reviewed(entries) if review else None
    store = Store(tmp_path / 'store')
    manifest = prepare(store, str(root), None, Profile(name='synthetic'), config,
        OBJECTIVE, directory=True, source_review=approval)
    return root, store, manifest, approval


def test_directory_freezes_current_bytes_without_git_execution(tmp_path, monkeypatch):
    root = source(tmp_path, {'app.php': '<?php return 2;', '.git/config': 'untrusted local filter config'})
    monkeypatch.setattr('audit3.snapshot.git', lambda *a: pytest.fail('No Git worktree command authorized'))
    store = Store(tmp_path / 'store')
    m = prepare(store, str(root), None, Profile(name='synthetic'), Config(), directory=True)
    assert m.source_kind == 'directory' and m.commit is None
    assert store.path(m.run_id, 'source/app.php').read_text() == '<?php return 2;'
    assert len(m.files) == 1 and (root / '.git/config').read_text() == 'untrusted local filter config'
    verify_source(store, m)


@pytest.mark.parametrize('which', ['root', 'directory', 'file'])
def test_directory_rejects_links(tmp_path, which):
    root = source(tmp_path, {'file.php': '<?php return 1;'})
    if which == 'root':
        alias = tmp_path / 'alias'; alias.symlink_to(root); root = alias
    elif which == 'directory':
        (root / 'escape').symlink_to(tmp_path)
    else:
        (root / 'file.php').unlink(); (root / 'file.php').symlink_to('/etc/passwd')
    with pytest.raises(PolicyError): directory_entries(root, Config())


@pytest.mark.parametrize('limits', [{'max_file_bytes': 3}, {'max_total_bytes': 3}, {'max_files': 1}])
def test_directory_limits_still_apply_before_materialization(tmp_path, limits):
    root = source(tmp_path, {'one.php': '1234', 'two.php': '5678'})
    with pytest.raises(PolicyError, match='limites'):
        directory_entries(root, Config(**limits))


def test_directory_rejects_fifo_without_waiting_for_a_writer(tmp_path):
    root = source(tmp_path, {})
    os.mkfifo(root / 'fifo')
    with pytest.raises(PolicyError, match='regulares'):
        directory_entries(root, Config())


def test_scanner_remains_active_without_explicit_review(tmp_path):
    _, store, m, _ = setup(tmp_path, {'contact.php': "<?php $contact = 'operator@example.invalid';"})
    assert m.files[0].category == 'excluded'
    assert not store.path(m.run_id, 'source/contact.php').exists()


def test_current_explicit_review_preserves_bytes_and_authenticated_provenance(tmp_path):
    data = "<?php $contact = 'operator@example.invalid';"
    _, store, m, approval = setup(tmp_path, {'contact.php': data}, review=True)
    assert m.files[0].category == 'source' and store.path(m.run_id, 'source/contact.php').read_text() == data
    assert m.acquisition_review_hash == object_hash(approval)
    assert store.get(m.run_id, 'acquisition/source-review') == approval
    tools = SourceTools(store, m, Config(), None, ToolContext(m.run_id, 'auditor', 'initial-0000', 'unit'))
    assert tools.read_source('contact.php')['lines'][0]['text'] == data
    verify_source(store, m)
    store.put(m.run_id, 'acquisition/source-review', {**approval, 'reviewer': 'changed'})
    with pytest.raises(PolicyError, match='Revisão'): verify_source(store, m)


@pytest.mark.parametrize('change', ['reviewer', 'objective', 'inventory', 'file', 'span', 'context', 'omitted_match', 'kind', 'reason'])
def test_review_must_bind_every_signal_and_current_context(tmp_path, change):
    root = source(tmp_path, {'contact.php': "<?php $a='a@example.invalid'; $b='b@example.invalid';"})
    entries = directory_entries(root, Config()); approval = reviewed(entries)
    decision = approval['files']['contact.php']
    if change == 'reviewer': approval['reviewer'] = ''
    if change == 'objective': approval['objective'] = 'another goal'
    if change == 'inventory': approval['inventory_hash'] = 'wrong'
    if change == 'file': decision['sha256'] = 'wrong'
    if change == 'span': decision['matches'][0]['end'] -= 1
    if change == 'context': decision['matches'][0]['context_sha256'] = 'wrong'
    if change == 'omitted_match': decision['matches'].pop()
    if change == 'kind': decision['matches'][0]['kind'] = 'approve_anything'
    if change == 'reason': decision['matches'][0]['justification'] = ''
    with pytest.raises(PolicyError):
        prepare(Store(tmp_path / 'store'), str(root), None, Profile(name='synthetic'), Config(), OBJECTIVE,
                directory=True, source_review=approval)


@pytest.mark.parametrize('data', ["<?php $api_key='sk-abcdefghijklmnopqrstuvwxyz';", "<?php $password='actual-secret-literal';", "<?php $cpf='123.456.789-01';"])
def test_label_cannot_discharge_credentials_or_personal_values(tmp_path, data):
    root = source(tmp_path, {'data.php': data}); entries = directory_entries(root, Config())
    with pytest.raises(PolicyError):
        prepare(Store(tmp_path / 'store'), str(root), None, Profile(name='synthetic'), Config(), OBJECTIVE,
                directory=True, source_review=reviewed(entries))


@pytest.mark.parametrize('text', ["const password = document.querySelector('input');", "<?php $initial_password = $data['user_pass'];", "<input placeholder='123.456.789-01'>"])
def test_code_expressions_and_format_examples_are_reviewable(tmp_path, text):
    _, store, m, _ = setup(tmp_path, {'code.php': text}, review=True)
    assert m.files[0].category == 'source'
    verify_source(store, m)


def test_runtime_dependencies_exist_are_unreadable_to_models_and_hash_checked(tmp_path):
    cfg = Config(runtime_include=['vendor/**', 'assets/picture.bin'])
    _, store, m, _ = setup(tmp_path, {'app.php': '<?php require __DIR__."/vendor/autoload.php";',
        'vendor/autoload.php': '<?php /* synthetic dependency */', 'assets/picture.bin': b'\0binary'}, cfg)
    dep = next(f for f in m.files if f.path == 'vendor/autoload.php')
    assert dep.runtime_only and dep.category == 'excluded'
    assert store.path(m.run_id, 'source/vendor/autoload.php').exists()
    assert all(ref['path'] == 'app.php' for batch in batches(m, 600) for ref in batch)
    tools = SourceTools(store, m, cfg, None, ToolContext(m.run_id, 'auditor', 'initial-0000', 'unit'))
    with pytest.raises(PolicyError): tools.read_source(dep.path)
    with pytest.raises(PolicyError): tools.source_bytes_for_validation(dep.path)
    assert tools.search_source('synthetic dependency')['matches'] == []
    verify_source(store, m)
    path = store.path(m.run_id, 'source/vendor/autoload.php'); path.chmod(0o644); path.write_text('altered')
    with pytest.raises(PolicyError): verify_source(store, m)


def test_dependency_build_distribution_is_preserved_without_unrelated_metadata(tmp_path):
    _, store, m, _ = setup(tmp_path, {'app.php': '<?php return 1;',
        'assets/vendor/pdfjs/legacy/build/pdf.min.mjs': '/* synthetic distribution */'},
        Config(runtime_include=['assets/vendor/**']))
    dependency = next(f for f in m.files if f.runtime_only)
    assert dependency.path.endswith('/build/pdf.min.mjs')
    assert store.path(m.run_id, 'source/' + dependency.path).exists()
    verify_source(store, m)


@pytest.mark.parametrize('name,data', [('app.php','<?php return 1;'), ('vendor/.env','PASSWORD=x'),
    ('vendor/auth.json','{}'), ('vendor/private.key','key'), ('vendor/token.php','sk-abcdefghijklmnopqrstuvwxyz')])
def test_runtime_is_not_a_way_to_hide_owned_code_or_credentials(tmp_path, name, data):
    root = source(tmp_path, {name: data})
    with pytest.raises(PolicyError):
        prepare(Store(tmp_path / 'store'), str(root), None, Profile(name='synthetic'), Config(runtime_include=['**']), directory=True)


def test_unset_fields_preserve_legacy_serialization():
    assert 'runtime_include' not in Config().model_dump()
    record = FileRecord(path='app.php', sha256='a'*64, size=1, lines=1, category='source')
    assert 'runtime_only' not in record.model_dump()


def test_cli_directory_review_uses_only_explicit_operator_file(tmp_path, capsys):
    from audit3.cli import main
    root = source(tmp_path, {'app.php': "<?php $contact='a@example.invalid';"})
    review = reviewed(directory_entries(root, Config()))
    path = tmp_path / 'operator-review.json'; path.write_text(json.dumps(review))
    requirements = tmp_path / 'objective.txt'; requirements.write_text(OBJECTIVE)
    assert main(['--store', str(tmp_path / 'store'), 'prepare', '--directory', '--repo', str(root),
        '--source-review', str(path), '--requirements', str(requirements)]) == 0
    output = json.loads(capsys.readouterr().out)
    store = Store(tmp_path / 'store'); manifest = store.get(output['prepared'], 'manifest')
    assert manifest['source_kind'] == 'directory'
    assert manifest['acquisition_review_hash'] == object_hash(review)
    assert store.path(output['prepared'], 'source/app.php').read_text() == (root / 'app.php').read_text()


def test_runtime_dependencies_do_not_fill_blind_coverage_or_discharge_unexecuted_tests(make_run, monkeypatch):
    import asyncio
    from audit3.workflow import Workflow
    from audit3.report import build_report
    from helpers import MockRuntime
    monkeypatch.setattr('audit3.executor.shutil.which', lambda _: None)
    store, manifest = make_run({'app.php': '<?php return 1;', 'vendor/lib.php': '<?php return 2;'},
        config=Config(runtime_include=['vendor/**']))
    state = asyncio.run(Workflow(store, manifest.run_id, runtime=MockRuntime()).run())
    report = build_report(store, manifest.run_id)
    assert state['status'] == 'partial'
    assert report['coverage']['excluded'] == []
    assert report['coverage']['runtime_dependencies'][0]['path'] == 'vendor/lib.php'
    assert report['coverage']['independent_investigation']['valid'] is True
    assert report['coverage']['gaps']  # no Docker execution remains blocking
    assert 'vendor/lib.php' not in report['coverage']['roles']['auditor']
