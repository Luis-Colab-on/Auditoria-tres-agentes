from __future__ import annotations
import fnmatch
import math
import os
import re
import secrets
import stat
import subprocess
import tempfile
import zipfile
from contextlib import ExitStack
from pathlib import Path
from importlib.resources import files
from .config import Config, Profile
from .evidence import Store
from .schemas import FileRecord, RunManifest, Role
from .security import PATTERNS, PolicyError, atomic_write, contained, digest, now, object_hash, redact, safe_relative, sensitive

DEPENDENCIES = {"vendor", "node_modules", ".venv", "venv"}
GENERATED = {".git", "__pycache__", ".pytest_cache", "dist", "build", "coverage", ".audit3"}
SECRET_NAMES = {".env", "wp-config.php", "id_rsa", "id_ed25519", "credentials", "auth.json"}


def git(repo: Path, *args: str) -> bytes:
    # No global config, hooks, fsmonitor, SSH agent or credential helper. Local
    # config is still present: callers must use object plumbing, never worktree
    # operations (even `status` can execute locally configured clean filters).
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "credential.helper=", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "-c", "http.followRedirects=false", "-C", str(repo), *args], env=env, capture_output=True, timeout=120)
    if result.returncode:
        raise PolicyError("Git falhou: " + redact(result.stderr.decode(errors="replace"))[:1000])
    return result.stdout


def github_source(url: str, ref: str, config: Config, destination: Path):
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url) or url not in config.github_allowlist:
        raise PolicyError("URL GitHub não permitida explicitamente")
    if not ref or ref.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_./-]+", ref):
        raise PolicyError("ref inválida")
    git(destination, "init", "--bare")
    git(destination, "fetch", "--no-tags", "--depth=1", url, ref)
    return git(destination, "rev-parse", "--verify", "FETCH_HEAD^{commit}").decode().strip()


def git_entries(repo: Path, ref: str, config: Config):
    if not ref or ref.startswith("-") or any(c in ref for c in ("\x00", "\n")):
        raise PolicyError("commit/ref explícito obrigatório")
    sha = git(repo, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40,64}", sha):
        raise PolicyError("SHA não resolvido")
    raw = git(repo, "ls-tree", "-rlz", "--full-tree", sha)
    entries = []
    submodules = []
    total = 0
    for item in raw.split(b"\x00"):
        if not item:
            continue
        meta, path = item.split(b"\t", 1)
        mode, kind, oid, size = meta.split()
        name = safe_relative(path.decode("utf-8"))
        if len(entries) >= config.max_files:
            raise PolicyError("inventário excede limites")
        if kind == b"commit":
            submodules.append(name + "@" + oid.decode())
            entries.append((name, b"", "submodule_not_materialized"))
        else:
            # Check every blob, including excluded links, before materializing it.
            if int(size) > config.max_file_bytes:
                raise PolicyError("arquivo excede limite; ajuste escopo explicitamente")
            total += int(size)
            if total > config.max_total_bytes:
                raise PolicyError("inventário excede limites")
            data = git(repo, "cat-file", "blob", oid.decode())
            if len(data) != int(size):
                raise PolicyError("tamanho do blob inconsistente")
            entries.append((name, data, "symlink_excluded" if mode == b"120000" else None))
    try:
        origin = git(repo, "config", "--local", "--get", "remote.origin.url").decode().strip()
        # Origins can embed tokens, usernames, or local private paths.
        origin = origin if re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", origin) else "origin_omitted"
    except PolicyError:
        origin = None
    bare = git(repo, "rev-parse", "--is-bare-repository").decode().strip() == "true"
    # Inspect only the explicit commit. Worktree/index inspection can run code
    # from received local configuration; untouched is not evidence of clean.
    state = "bare" if bare else "worktree_not_inspected_commit_only"
    return entries, sha, origin, state, submodules


def zip_entries(path: Path, config: Config):
    entries = []
    seen = set()
    total = 0
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) > config.max_files:
            raise PolicyError("ZIP excede quantidade de entradas")
        for info in archive.infolist():
            name = safe_relative(info.filename.rstrip("/"))
            if name.casefold() in seen:
                raise PolicyError("ZIP com caminhos duplicados ou colisão de caixa")
            seen.add(name.casefold())
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                raise PolicyError("ZIP com links/arquivo especial")
            if info.flag_bits & 1:
                raise PolicyError("ZIP criptografado não suportado")
            if info.is_dir():
                continue
            total += info.file_size
            if info.file_size > config.max_file_bytes or total > config.max_total_bytes or info.file_size > max(1, info.compress_size) * 200:
                raise PolicyError("limite de extração ZIP")
            with archive.open(info) as stream:
                data = stream.read(config.max_file_bytes + 1)
            if len(data) != info.file_size:
                raise PolicyError("tamanho ZIP inconsistente")
            entries.append((name, data, None))
    return entries


def classify(name: str, data: bytes, config: Config, reason: str | None, *, reviewed=False):
    parts = Path(name).parts
    lower = name.lower()
    if reason:
        return "excluded", reason
    if any(x in DEPENDENCIES for x in parts):
        return "excluded", "dependency: auditar separadamente; não enviado à API"
    if any(x in GENERATED for x in parts) or lower.endswith((".min.js", ".map", ".pyc")):
        return "excluded", "generated_or_metadata"
    if Path(name).name.lower() in SECRET_NAMES or lower.endswith((".pem", ".key", ".sql.gz", ".sqlite", ".db")) or Path(name).name.startswith(".env."):
        return "excluded", "sensitive_filename"
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in config.exclude):
        return "excluded", "operator_exclusion"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "excluded", "binary_or_non_utf8"
    if "\x00" in text:
        return "excluded", "binary"
    if sensitive(name) or (sensitive(text) and not reviewed):
        return "excluded", "possible_secret_or_personal_data"
    if text.startswith("version https://git-lfs.github.com/spec/v1"):
        return "excluded", "lfs_pointer_not_materialized"
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in config.prior_reports):
        return "prior_report", "withheld_until_barrier"
    if any("test" in x.lower() for x in parts):
        return "test", None
    if "migrat" in lower or lower.endswith(".sql"):
        return "migration", None
    if lower.endswith((".md", ".rst", ".txt")):
        return "spec", None
    if lower.endswith((".json", ".toml", ".ini", ".yaml", ".yml", ".xml", ".lock")):
        return "config", None
    return "source", None


def directory_entries(root: Path, config: Config):
    """Explicit worktree-byte acquisition: no Git commands, filters or execution."""
    if root.is_symlink() or not root.is_dir():
        raise PolicyError('Diretório de aquisição inválido')
    entries, total = [], 0
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        names.sort()
        for name in [*dirs, *names]:
            if (Path(base) / name).is_symlink():
                raise PolicyError('Aquisição de diretório não segue links')
        dirs[:] = [d for d in dirs if d != '.git']
        for name in names:
            path = Path(base) / name
            relative = safe_relative(path.relative_to(root).as_posix())
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise PolicyError('Aquisição de diretório exige arquivos regulares')
            total += before.st_size
            if (len(entries) >= config.max_files or before.st_size > config.max_file_bytes
                or total > config.max_total_bytes):
                raise PolicyError('inventário excede limites')
            # Anchor every component at an opened directory. A received tree
            # cannot exchange a parent for a link and expose a host file.
            with ExitStack() as handles:
                parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                handles.callback(os.close, parent_fd)
                for part in Path(relative).parts[:-1]:
                    parent_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    handles.callback(os.close, parent_fd)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                stream = handles.enter_context(os.fdopen(fd, 'rb'))
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise PolicyError('Fonte não regular durante aquisição')
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                    raise PolicyError('Fonte mudou antes da leitura')
                data = stream.read(config.max_file_bytes + 1)
                after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(opened) or identity(opened) != identity(after) or len(data) != before.st_size:
                raise PolicyError('Fonte mudou durante aquisição')
            entries.append((relative, data, None))
    return entries


def prepare(store: Store, repo: str, ref: str | None, profile: Profile, config: Config, requirements: str = "", *, directory=False, source_review=None) -> RunManifest:
    if sensitive(requirements):
        raise PolicyError("requisitos contêm possível dado sensível")
    run_id = secrets.token_hex(12)
    kind = "git"
    sha = origin = None
    submodules = []
    if directory:
        if ref:
            raise PolicyError('Diretório congela bytes atuais, não aceita --ref')
        entries = directory_entries(Path(repo).absolute(), config)
        kind, state = 'directory', 'current_directory_bytes_frozen'
    elif repo.startswith("https://"):
        if not ref:
            raise PolicyError("GitHub exige ref explícita")
        with tempfile.TemporaryDirectory(prefix="audit3-acquire-") as directory:
            resolved = github_source(repo, ref, config, Path(directory))
            entries, sha, _, state, submodules = git_entries(Path(directory), resolved, config)
        kind, origin = "github", repo
    elif Path(repo).is_file():
        if ref:
            raise PolicyError("ZIP não tem commit: não forneça --ref")
        kind, state = "zip", "no_git_history"
        entries = zip_entries(Path(repo), config)
    else:
        if not ref:
            raise PolicyError("Git exige --ref explícito; modificações locais são preservadas")
        entries, sha, origin, state, submodules = git_entries(Path(repo).resolve(), ref, config)
    from .acquisition_review import validate_review
    reviewed = validate_review(source_review, entries, requirements)
    review_hash = object_hash(source_review) if source_review else None
    records = []
    materializations = []
    seen = set()
    for name, data, reason in entries:
        if name.casefold() in seen:
            raise PolicyError("colisão de caminhos")
        seen.add(name.casefold())
        category, why = classify(name, data, config, reason, reviewed=name in reviewed)
        runtime_only = any(fnmatch.fnmatchcase(name, pattern) for pattern in config.runtime_include)
        if runtime_only:
            if (category != 'excluded' or not (why.startswith('dependency:') or why in {'binary', 'binary_or_non_utf8', 'generated_or_metadata'})
                or any(p in {'.git', '.audit3', '.codex', '.agents', '.aws', '.ssh', '__pycache__', '.pytest_cache'} for p in Path(name).parts)
                or Path(name).name.lower() in SECRET_NAMES or name.lower().endswith(('.pem', '.key', '.db', '.sqlite'))
                or Path(name).name.startswith('.env.')):
                raise PolicyError('Arquivo não elegível para dependência somente de execução: ' + name)
            if sensitive(name) or any(p.search(data.decode('utf-8', errors='replace')) for p in PATTERNS[:4]):
                raise PolicyError('Credencial/chave não pode entrar como dependência de execução')
        # Sensitive filenames are represented by opaque identifiers too.
        public_name = "omitted/" + digest(name.encode()) if sensitive(name) else name
        lines = len(data.decode("utf-8", errors="replace").splitlines())
        records.append(FileRecord(path=public_name, sha256=digest(data), size=len(data), lines=lines, category=category, reason=why, runtime_only=runtime_only))
        if category != "excluded" or runtime_only:
            location = "prior" if category == "prior_report" else "source"
            materializations.append((location, name, data))
    # Validate the entire acquisition before writing a partial source tree.
    for location, name, data in materializations:
        target = contained(store.path(run_id, location), name)
        atomic_write(target, data, mode=0o444)
    records.sort(key=lambda x: x.path)
    identity = {"commit": sha, "files": [f.model_dump() for f in records]}
    if review_hash:
        identity['acquisition_review_hash'] = review_hash
    source_id = object_hash(identity)
    owned = [f for f in records if f.category not in {"excluded", "prior_report"}]
    manifest = RunManifest(backend=config.backend, client_version="0.167.0", models={r.value: m for r,m in config.models.items()}, run_id=run_id, created_at=now(), source_kind=kind, source_id=source_id, commit=sha, origin=origin,
        tree_state=state, submodules=submodules, files=records, lfs=[f.path for f in records if f.reason == "lfs_pointer_not_materialized"],
        config_hash=object_hash(config), profile_hash=object_hash(profile), requirements=requirements, acquisition_review_hash=review_hash,
        prompt_hashes={name: digest(files("audit3").joinpath("prompts", name + ".txt").read_bytes()) for name in [*(r.value for r in Role), "common"]},
        estimated_input_tokens=None,
        estimated_calls=0,
        limitations=["Scanner de segredos/PII é heurístico: revisar inventário antes do run; omissões reduzem cobertura.", "Nenhuma ocorrência em produção fornecida."])
    from .completion import protocol_phases
    manifest.estimated_calls = len(protocol_phases(manifest, config))
    if source_review:
        store.put(run_id, 'acquisition/source-review', source_review, immutable=True)
    store.put(run_id, "manifest", manifest, immutable=True)
    store.put(run_id, "config", config, immutable=True)
    store.put(run_id, "profile", profile, immutable=True)
    store.put(run_id, "state", {"status": "prepared", "technical_result": "not_evaluated", "phase": "prepared", "completed": [], "limitations": [], "elapsed_seconds": 0.0})
    store.put(run_id, "ledger", {"calls": [], "tokens": None, "known_cost_usd": None, "unknown_cost_calls": 0})
    from .turn_planning import global_plan
    store.put(run_id, 'planning/initial', global_plan(store, manifest, config, check_tools=True), immutable=True)
    for location in ("source", "prior"):
        root = store.path(run_id, location)
        root.mkdir(exist_ok=True, parents=True)
        for p in sorted(root.rglob("*"), reverse=True):
            if p.is_dir():
                p.chmod(0o555)
        root.chmod(0o555)
    store.event(run_id, "prepared", {"source_id": source_id, "prior_reports_withheld": True})
    return manifest


def verify_source(store: Store, manifest: RunManifest):
    if manifest.acquisition_review_hash:
        if object_hash(store.get(manifest.run_id, 'acquisition/source-review')) != manifest.acquisition_review_hash:
            raise PolicyError('Revisão de aquisição adulterada')
    expected = {f.path for f in manifest.files if f.category not in {"excluded", "prior_report"} or f.runtime_only}
    actual = {p.relative_to(store.path(manifest.run_id, "source")).as_posix() for p in store.path(manifest.run_id, "source").rglob("*") if p.is_file() or p.is_symlink()}
    if expected != actual:
        raise PolicyError("inventário da fonte adulterado")
    for f in manifest.files:
        if f.category == "excluded" and not f.runtime_only:
            continue
        root = store.path(manifest.run_id, "prior" if f.category == "prior_report" else "source")
        if digest(contained(root, f.path).read_bytes()) != f.sha256:
            raise PolicyError("hash da fonte adulterado")
