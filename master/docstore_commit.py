#!/usr/bin/env python3
"""Commit documentation worker: immutable Git evidence, guarded SQLite CAS, no Git writes."""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
import docstore as ds

ROOT = ds.ROOT
STATE = ROOT / 'docs' / '.docstore-commit'
CONFIG = ROOT / 'docs' / 'docstore-commit-config.json'
BEGIN = '<!-- docstore-commit-topics:begin -->'
END = '<!-- docstore-commit-topics:end -->'
STARTUP_BEGIN = '<!-- docstore-startup:begin -->'
STARTUP_END = '<!-- docstore-startup:end -->'
HEX = re.compile(r'[0-9a-f]{40}|[0-9a-f]{64}')
MAX_SOURCES = 24
MAX_DOCUMENTS = 32
MAX_TEXT = 16000
STARTUP_INSTRUCTION = 'Before any new repository work, run `python master/docstore_commit.py startup --json` and finish pending closing documentation. If it exits nonzero, pause new work. If Codex usage is unavailable, preserve the deferred queue and retry at the next startup; never treat a failed/deferred receipt as complete. This gate does not apply recursively to the startup/commit documentation worker or its bounded internal JSON-only AI review: the parent worker already owns closing work, and that internal review must not invoke startup, worker, or tools.'


def git(*args: str) -> bytes:
    # Git hook context variables may point at the caller index/worktree. Reads
    # explicitly bind this checkout and never inherit object replacement refs.
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith('GIT_'):
            env.pop(name, None)
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    result = subprocess.run(['git', '-C', str(ROOT), *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ds.StoreError('Git evidence command failed; output withheld')
    return result.stdout


def config() -> dict:
    if not CONFIG.exists():
        raise ds.StoreError('commit configuration missing; run repository installer')
    value = json.loads(ds.checked_path(CONFIG).read_bytes())
    if not isinstance(value, dict) or value.get('provider') != 'codex' or value.get('enabled') is not True:
        raise ds.StoreError('Codex commit documentation configuration is not enabled')
    return value


def atomic(path: Path, data: bytes, previous: bytes | None = None) -> None:
    target = ds.checked_path(path, mutation=True)
    ds.checked_path(target.parent, mutation=True).mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=target.name + '.pending-', dir=target.parent)
    pending = Path(name)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        if previous is not None and (not target.exists() or target.read_bytes() != previous):
            raise ds.StoreError('file changed concurrently; no index/config overwrite applied')
        ds.checked_path(target, mutation=True)
        os.replace(pending, target)
    finally:
        pending.unlink(missing_ok=True)


def save(path: Path, value: object) -> None:
    atomic(path, ds.canonical(value) + b'\n')


def commit_id(value: str) -> str:
    if not HEX.fullmatch(value):
        raise ds.StoreError('full immutable commit hash required')
    actual = git('rev-parse', '--verify', value + '^{commit}').decode('ascii').strip()
    if actual != value:
        raise ds.StoreError('commit identity mismatch')
    return actual


def state_path() -> Path:
    path = ds.checked_path(STATE, mutation=True)
    path.mkdir(parents=True, exist_ok=True)
    for name in ('queue', 'runs', 'receipts'):
        ds.checked_path(path / name, mutation=True).mkdir(exist_ok=True)
    return path


def enqueue(commit: str) -> Path:
    commit = commit_id(commit)
    base = state_path()
    path = base / 'queue' / (commit + '.json')
    if not path.exists():
        # No mutable caller bytes, messages, author identities or source bodies.
        payload = ds.canonical({'format': 1, 'commit': commit}) + b'\n'
        try:
            with path.open('xb') as out:
                out.write(payload); out.flush(); os.fsync(out.fileno())
        except FileExistsError:
            pass
    return path


def owned_stores(cfg: dict) -> dict[str, Path]:
    stores = {}
    candidates = []
    agent = ds.checked_path('AGENTS.md')
    if agent.is_file():
        text = agent.read_text(encoding='utf-8-sig')
        candidates.extend(re.findall(r'(?<![\w/])(?:docs|master)/[A-Za-z0-9_./-]+\.sqlite', text))
    if ds.DEFAULT_DB.exists():
        candidates.append('docs/knowledge.sqlite')
    topics = ds.checked_path('docs/topics')
    if topics.is_dir():
        candidates.extend(p.relative_to(ROOT).as_posix() for p in topics.glob('*.sqlite'))
    for value in cfg.get('stores', []):
        candidates.append(value)
    for value in sorted(set(candidates)):
        path = ds.checked_path(value)
        if path.suffix != '.sqlite':
            continue
        owned_authority = value == 'docs/knowledge.sqlite' or value.startswith('docs/topics/') or value in cfg.get('stores', [])
        if not path.is_file():
            export, checksum = ds.exports(path)
            if owned_authority or export.exists() or checksum.exists():
                raise ds.StoreError('indexed SQLite authority missing; restore its owned versioned export before enabling commit documentation')
            continue
        # Runtime SQLite schemas may coincidentally use user_version=1. Recognize
        # our explicit tables first, then fail closed on publication problems.
        with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as probe:
            names = {row[0] for row in probe.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'store_meta', 'documents', 'revisions', 'documents_fts'}.issubset(names):
            if owned_authority:
                raise ds.StoreError('indexed owned SQLite authority has unsupported schema; reconcile ownership before enabling commit documentation')
            continue
        with contextlib.closing(ds.connect(path)) as con:
            ds.check_publication(con, path)
        stores[value] = path
    return stores


def documents(stores: dict[str, Path]) -> list[dict]:
    result = []
    for store, path in stores.items():
        with contextlib.closing(ds.connect(path)) as con:
            for row in con.execute('SELECT * FROM documents ORDER BY path'):
                ds.validated_body(row)
                result.append({**dict(row), 'store': store})
    return result


def topic(path: str, owners: dict[str, dict], cfg: dict) -> tuple[str, str]:
    if path in owners:
        store = owners[path]['store']
        return ('owned-' + ds.sha(store.encode())[:12], store)
    routes = cfg.get('routes', {})
    if not isinstance(routes, dict):
        raise ds.StoreError('routes must be a prefix-to-topic mapping')
    for prefix in sorted(routes, key=len, reverse=True):
        if path == prefix or path.startswith(prefix.rstrip('/') + '/'):
            label = routes[prefix]
            if not isinstance(label, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', label):
                raise ds.StoreError('invalid topic route')
            return label, 'docs/topics/' + label + '.sqlite'
    directory = path.partition('/')[0] if '/' in path else 'project'
    label = re.sub('[^a-z0-9]+', '-', directory.casefold()).strip('-')[:40] or 'project'
    label += '-' + ds.sha(directory.encode())[:8]
    return label, 'docs/topics/' + label + '.sqlite'


def unsafe_source(path: str) -> bool:
    parts = Path(path).parts
    return (any(part.casefold() in {'.git', '.ssh', '.aws', 'credentials', 'secrets', 'node_modules', 'agent-policies'} or part.casefold().startswith('.env') for part in parts)
            or Path(path).name.casefold() in {'agents.md', 'ai_context.md', 'docstore-commit-config.json'}
            or '.docstore-commit' in parts
            or bool(re.search(r'(?i)(?:credential|private[-_]?key|cookie[-_]?jar|\.pem$|\.key$|\.pfx$|\.sqlite$|export-history|export\.(?:jsonl|json))', path)))


def evidence(commit: str, cfg: dict, rows: list[dict]) -> dict:
    parents = git('rev-list', '--parents', '-n', '1', commit).decode('ascii').split()[1:]
    raw = git('diff-tree', '--root', '--no-commit-id', '--no-renames', '-r', '--raw', '--no-abbrev', '-z', *([parents[0], commit] if parents else [commit]))
    tokens = raw.split(b'\0')
    changes = []; sources = []; exclusions = []; topics = {}
    agent_text = ds.checked_path('AGENTS.md').read_text(encoding='utf-8-sig') if ds.checked_path('AGENTS.md').is_file() else ''
    excluded_paths = set(re.findall(r'(?m)^- \x60([^\x60]+)\x60 — (?:credential indicator|runtime-owned|code-template)', agent_text))
    owners = {}
    for row in rows:
        if row['path'] in owners:
            raise ds.StoreError('ambiguous authoritative document path ownership')
        owners[row['path']] = row
    for index in range(0, len(tokens)-1, 2):
        header, name = tokens[index:index+2]
        if not header:
            continue
        fields = header.decode('ascii').split()
        path = name.decode('utf-8', errors='strict')
        ds.secret_guard(path, 'committed path')
        identity = Path(path)
        if identity.is_absolute() or '..' in identity.parts or '\\' in path or identity.as_posix() != path:
            raise ds.StoreError('noncanonical committed path')
        label, store = topic(path, owners, cfg)
        topics[label] = store
        entry = {'path': path, 'status': fields[4], 'old_blob': fields[2], 'new_blob': fields[3], 'topic': label}
        changes.append(entry)
        if fields[1] in {'160000', '120000'}:
            exclusions.append({'path': path, 'category': 'gitlink-or-symlink-reference'}); continue
        if path in excluded_paths or unsafe_source(path) or path == 'AGENTS.md' or path.startswith(('master/docstore', 'scripts/Install-DocstoreCommit', 'scripts/Run-DocstoreCommit')):
            exclusions.append({'path': path, 'category': 'protected-or-sensitive-identity'}); continue
        if fields[4] == 'D' or len(sources) >= MAX_SOURCES:
            exclusions.append({'path': path, 'category': 'deleted-or-packet-source-bound'}); continue
        size = int(git('cat-file', '-s', fields[3]).decode('ascii'))
        if size > 1024 * 1024:
            exclusions.append({'path': path, 'category': 'binary-or-size-bound'}); continue
        blob = git('cat-file', 'blob', fields[3])
        if b'\0' in blob:
            exclusions.append({'path': path, 'category': 'binary-or-size-bound'}); continue
        try:
            text = ds.text_bytes(blob, 'committed source')
        except ds.StoreError:
            exclusions.append({'path': path, 'category': 'credential-or-encoding-guard'}); continue
        sources.append({'id': 'blob-' + fields[3], 'path': path, 'blob': fields[3], 'sha256': ds.sha(blob), 'text': text[:MAX_TEXT], 'truncated': len(text) > MAX_TEXT})
    selected = [row for row in rows if row['path'] in {c['path'] for c in changes}]
    changed_paths = [change['path'] for change in changes]
    def relevance(row: dict) -> int:
        candidate = set(re.findall(r'[a-z0-9]+', row['path'].casefold()))
        return max((len(candidate & set(re.findall(r'[a-z0-9]+', path.casefold()))) for path in changed_paths), default=0)
    candidates = [row for row in rows if row not in selected and row['type'] in {'contract', 'decision', 'spec'} and relevance(row) > 0]
    selected.extend(sorted(candidates, key=lambda row: (-relevance(row), row['path'])))
    offered = []
    for row in selected[:MAX_DOCUMENTS]:
        if len(row['body']) > MAX_TEXT:
            exclusions.append({'path': row['path'], 'category': 'canonical-document-size-bound'}); continue
        label, store = topic(row['path'], owners, cfg)
        topics[label] = store
        offered.append({key: row[key] for key in ('id', 'store', 'slug', 'path', 'revision', 'sha256', 'type', 'status', 'body')} | {'topic': label})
    current_head = git('rev-parse', 'HEAD').decode('ascii').strip()
    source_hashes = {source['path']: source['sha256'] for source in sources}
    protected = [owners[change['path']]['id'] for change in changes if change['path'] in owners and source_hashes.get(change['path']) != owners[change['path']]['sha256']]
    return {'current_head': current_head, 'existing_updates_allowed': current_head == commit, 'protected_document_ids': protected, 'format': 1, 'commit': commit, 'parents': parents, 'comparison': 'first-parent' if parents else 'empty-tree-root', 'changes': changes, 'sources': sources, 'documents': offered, 'topics': [{'id': key, 'store': value} for key, value in sorted(topics.items())], 'exclusions': exclusions, 'update_constraints': {'new_path': 'docs/commit-docs/<topic>/<basename>.md', 'new_slug': 'lowercase ASCII letters, digits and hyphens, maximum 160 characters', 'new_types': ['decision', 'work-log', 'contract', 'spec'], 'new_non_decision_status': ['proposed', 'source-only'], 'new_decision_status': 'proposed', 'existing_decisions': 'never rewrite; create a linked proposed decision', 'existing_other_documents': 'preserve type and status; use offered exact revision and identity'}}


def reconcile(packet: dict, rows: list[dict]) -> list[dict]:
    owners = {row['path']: row for row in rows}
    unresolved = []
    is_current = packet['commit'] == git('rev-parse', 'HEAD').decode('ascii').strip()
    available_sources = {source['path'] for source in packet['sources'] if not source['truncated']}
    for change in packet['changes']:
        row = owners.get(change['path'])
        if row is None:
            continue  # New source Markdown is not automatically new authority.
        if not is_current:
            unresolved.append({'topic': change['topic'], 'reason': 'Historical commit: current canonical document authority preserved; review as a linked proposal.', 'evidence_ids': []}); continue
        if change['status'] == 'D':
            unresolved.append({'topic': change['topic'], 'reason': 'Owned source deleted; canonical history retained.', 'evidence_ids': []}); continue
        if change['path'] not in available_sources:
            unresolved.append({'topic': change['topic'], 'reason': 'Committed owned document omitted by evidence guard/bound; canonical authority preserved.', 'evidence_ids': []}); continue
        if int(git('cat-file', '-s', change['new_blob']).decode('ascii')) > ds.MAX_BYTES:
            unresolved.append({'topic': change['topic'], 'reason': 'Owned document size bound; canonical authority preserved.', 'evidence_ids': []}); continue
        new = git('cat-file', 'blob', change['new_blob'])
        ds.text_bytes(new, 'committed owned document')
        if ds.sha(new) == row['sha256']:
            continue
        old_size = int(git('cat-file', '-s', change['old_blob']).decode('ascii')) if set(change['old_blob']) != {'0'} else 0
        old = git('cat-file', 'blob', change['old_blob']) if old_size and old_size <= ds.MAX_BYTES else None
        if old is None or ds.sha(old) != row['sha256']:
            unresolved.append({'topic': change['topic'], 'reason': 'Canonical SQLite and committed source differ; authority preserved pending review.', 'evidence_ids': []}); continue
        if operation_active():
            raise ds.StoreError('Git operation began during document reconciliation; queued commit retained')
        if packet['commit'] != git('rev-parse', 'HEAD').decode('ascii').strip():
            unresolved.append({'topic': change['topic'], 'reason': 'HEAD advanced during reconciliation; canonical document authority preserved.', 'evidence_ids': []}); continue
        ds.write_document(ds.checked_path(row['store']), row['slug'], row['path'], new, row['revision'], 'git-committed-document:' + packet['commit'])
    return unresolved


def validate_plan(plan: dict, packet: dict) -> list[tuple[dict, bytes]]:
    if not isinstance(plan, dict) or set(plan) != {'summary', 'updates', 'unresolved'}:
        raise ds.StoreError('AI plan schema rejected')
    if not isinstance(plan['summary'], str) or not isinstance(plan['updates'], list) or not isinstance(plan['unresolved'], list) or len(plan['updates']) > 32:
        raise ds.StoreError('AI plan bounds rejected')
    ds.secret_guard(json.dumps(plan, ensure_ascii=False), 'AI plan')
    evidence_ids = {row['id'] for row in packet['sources']} | {row['id'] for row in packet['documents']}
    topics = {row['id']: row['store'] for row in packet['topics']}
    offered = {(row['topic'], row['slug'], row['path']): row for row in packet['documents']}
    changes_topics = {row['topic'] for row in packet['changes']}
    prepared = []; identities = set()
    for update in plan['updates']:
        if not isinstance(update, dict) or set(update) != {'topic', 'slug', 'path', 'expected_revision', 'body', 'evidence_ids'}:
            raise ds.StoreError('AI update schema rejected')
        if not all(isinstance(update[key], str) for key in ('topic', 'slug', 'path', 'body')) or type(update['expected_revision']) is not int:
            raise ds.StoreError('AI update field types rejected')
        if update['topic'] not in topics or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,159}', update['slug']):
            raise ds.StoreError('AI update topic/slug rejected')
        ids = update['evidence_ids']
        if not isinstance(ids, list) or not ids or any(not isinstance(item, str) or item not in evidence_ids for item in ids) or not any(item in {source['id'] for source in packet['sources']} for item in ids):
            raise ds.StoreError('AI update evidence rejected')
        key = (update['topic'], update['slug'], update['path'])
        if key in identities:
            raise ds.StoreError('duplicate AI update identity')
        identities.add(key)
        old = offered.get(key)
        body = update['body']; fields = ds.metadata(body, update['path'])
        if old:
            if old['id'] in packet.get('protected_document_ids', []):
                raise ds.StoreError('AI cannot overwrite canonical/source-conflicted authority; create a linked proposal')
            if update['expected_revision'] != old['revision']:
                raise ds.StoreError('AI offered revision mismatch')
            if old['type'] == 'decision':
                raise ds.StoreError('AI cannot rewrite existing decision history; create a linked proposed decision')
            if fields['type'] != old['type'] or fields['status'] != old['status']:
                raise ds.StoreError('AI cannot change authoritative document type/status')
        else:
            prefix = 'docs/commit-docs/' + update['topic'] + '/'
            if update['expected_revision'] != 0 or not update['path'].startswith(prefix) or not re.fullmatch(r'[a-z0-9-]+\.md', update['path'][len(prefix):]) or update['topic'] not in changes_topics:
                raise ds.StoreError('AI new document identity rejected')
            if fields['type'] not in {'decision', 'work-log', 'contract', 'spec'}:
                raise ds.StoreError('AI new document type rejected')
            if fields['type'] == 'decision' and (fields['status'] != 'proposed' or ds.decision_fields(body, 'proposed')['missing_fields']):
                raise ds.StoreError('AI decision must be a complete source-backed proposal')
            if fields['type'] != 'decision' and fields['status'] not in {'proposed', 'source-only'}:
                raise ds.StoreError('AI new document requires proposed/source-only status')
        data = body.encode('utf-8')
        ds.text_bytes(data, 'AI document')
        if len(data) > 128 * 1024:
            raise ds.StoreError('AI document size rejected')
        prepared.append((update, data))
    for item in plan['unresolved']:
        if not isinstance(item, dict) or set(item) != {'topic', 'reason', 'evidence_ids'} or item['topic'] not in topics or not isinstance(item['reason'], str) or not isinstance(item['evidence_ids'], list) or any(value not in evidence_ids for value in item['evidence_ids']):
            raise ds.StoreError('AI unresolved schema/evidence rejected')
    return prepared


def index_stores(stores: dict[str, str]) -> None:
    path = ds.checked_path('AGENTS.md', mutation=True)
    old = path.read_bytes() if path.exists() else b''
    text = old.decode('utf-8-sig')
    if text.count(STARTUP_BEGIN) != text.count(STARTUP_END) or text.count(STARTUP_BEGIN) > 1:
        raise ds.StoreError('ambiguous managed AGENTS startup index')
    startup_block = STARTUP_BEGIN + '\n' + STARTUP_INSTRUCTION + '\n' + STARTUP_END
    if STARTUP_BEGIN in text:
        start = text.index(STARTUP_BEGIN); finish = text.index(STARTUP_END, start) + len(STARTUP_END)
        text = text[:start] + text[finish:]
        text = text.lstrip('\r\n')
    text = startup_block + '\n\n' + text
    if text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1:
        raise ds.StoreError('ambiguous managed AGENTS topic index')
    # Include previous known topic stores, not just the latest commit's topics.
    known = {value for value in re.findall(r'docs/topics/[a-z0-9-]+\.sqlite', text)} | set(stores.values())
    if any(ds.checked_path(value).is_file() for value in known):
        text = text.replace('| No owned SQLite store discovered | Use this index and the small owned Markdown corpus; do not invent a database or retrieval command. |', '| Owned commit topic stores | See the managed Commit documentation stores index below for exact authorities and retrieval. |')
        text = text.replace('No substantive owned documentation corpus justified a new authority database in this audit.', 'The initial audit retained a small Markdown corpus; subsequent actual commits now have authoritative topic documentation in the stores indexed below.')
    lines = [BEGIN, '## Commit documentation stores', '', 'After every local commit, the installed hook queues Codex review of bounded committed evidence. Hook-generated edits remain uncommitted. Existing decisions are preserved; new AI decisions are proposals. Inspect failures with `python master/docstore_commit.py status --json`; replay with `python master/docstore_commit.py replay --commit <full-hash> --foreground`.', '', '| Owned authority | Versioned export / checksum | History | Retrieval |', '|---|---|---|---|']
    for value in sorted(known):
        db = ds.checked_path(value)
        if not db.is_file():
            continue
        with contextlib.closing(ds.connect(db)) as con:
            ds.check_publication(con, db)
        export, checksum = ds.exports(db)
        history = db.parent / (db.stem + '-export-history')
        lines.append(f'| `{value}` | `{export.relative_to(ROOT).as_posix()}` / `{checksum.relative_to(ROOT).as_posix()}` | `{history.relative_to(ROOT).as_posix()}/` | `python master/docstore.py --db {value} search <words> --limit 5 --json` |')
    lines.extend(['', 'Recovery before installation: indexed missing SQLite authority with an existing versioned export pair blocks installation. First run `python master/docstore.py recover --target <separate-absent-owned.sqlite> --export <owned-store-export.jsonl> --checksum <owned-store-export.sha256.json>`, then `python master/docstore.py --db <recovered-owned.sqlite> integrity` and verify its export bytes equal the original versioned export. Use `python master/docstore.py --db <recovered-owned.sqlite> backup --target <absent-original-authority.sqlite>` to restore the original indexed database through SQLite API backup; original exports and complete history stay intact. Never overwrite an existing authority or recover directly into a family whose export pair already exists. Reconcile authority explicitly and rerun installation after verification.', '', 'Repository-owned installer (run from PowerShell 7 / `pwsh`): `& \'./scripts/Install-DocstoreCommitHook.ps1\' -PythonPath \'<absolute installed python.exe>\' -CodexPath \'<absolute installed native codex.exe>\'`. Resolve executable paths for this machine; new clones/worktrees require this local installer and existing signed-in Codex authentication. Topic routing/config: `docs/docstore-commit-config.json` (machine paths are local, ignored). Runtime queues/status: `docs/.docstore-commit/` (ignored). SQLite is authoritative; preserve checksummed current exports and complete export history in Git. Runtime/legacy/external databases are never adopted by this hook.', END])
    lines.insert(3, STARTUP_INSTRUCTION)
    block = '\n'.join(lines)
    if BEGIN in text:
        start = text.index(BEGIN); finish = text.index(END, start) + len(END)
        desired = text[:start] + block + text[finish:]
    else:
        desired = text.rstrip('\r\n') + '\n\n' + block + '\n'
    data = desired.encode('utf-8')
    if data != old:
        atomic(path, data, old if path.exists() else None)
    for name, additions in (('.gitignore', ['/docs/.docstore-commit/', '/docs/docstore-commit-config.json', '/docs/topics/*.sqlite', '/docs/topics/*.sqlite.writer-lock/']), ('.gitattributes', ['/docs/topics/*-export.jsonl -text', '/docs/topics/*-export.sha256.json -text', '/docs/topics/*-export-history/* -text'])):
        target = ds.checked_path(name, mutation=True)
        original = target.read_bytes() if target.exists() else b''
        content = original.decode('utf-8-sig')
        missing = [line for line in additions if line not in content.splitlines()]
        if missing:
            atomic(target, original.rstrip(b'\r\n') + b'\n' + '\n'.join(missing).encode() + b'\n', original if target.exists() else None)


def fact_body(packet: dict, label: str) -> bytes:
    commit = packet['commit']
    entries = [change for change in packet['changes'] if change['topic'] == label]
    body = '---\ntype: work-log\nstatus: source-only\n---\n# Commit ' + commit + '\n\nImmutable commit: `' + commit + '`\nComparison: ' + packet['comparison'] + '\nParents: ' + (', '.join(packet['parents']) or 'none') + '\n\nThis records Git object facts, not runtime verification or approved architectural rationale. Semantic review is tracked separately in the worker receipt.\n\n' + '\n'.join('- `' + item['path'] + '` status ' + item['status'] + '; old blob ' + item['old_blob'] + '; new blob ' + item['new_blob'] for item in entries) + '\n'
    return body.encode()

def record_facts(packet: dict) -> dict[str, str]:
    commit = packet['commit']
    topics = {item['id']: item['store'] for item in packet['topics']}
    changed_topics = {change['topic'] for change in packet['changes']}
    for label in sorted(changed_topics):
        entries = [change for change in packet['changes'] if change['topic'] == label]
        data = fact_body(packet, label)
        ds.write_document(ds.checked_path(topics[label]), 'commit-' + commit, 'docs/commit-records/' + label + '/' + commit + '.md', data, 0, 'git-commit-facts:' + commit)
    index_stores(topics)
    return topics


def complete_receipt(commit: str, cfg: dict) -> bool:
    """Completion requires retained guarded evidence and published factual stores.

    Old receipts alone are insufficient after missing/corrupt authority or index
    data. This checks source completion, never runtime or business acceptance.
    """
    base = state_path(); receipt = base / 'receipts' / (commit + '.json')
    if not receipt.is_file():
        return False
    value = json.loads(ds.checked_path(receipt).read_bytes())
    if not isinstance(value, dict) or value.get('format') != 1 or value.get('commit') != commit:
        raise ds.StoreError('documentation receipt identity rejected')
    if value.get('state') != 'complete':
        return False
    if value.get('ai_invoked') is not True or value.get('verification') != 'source-only':
        return False
    applied = value.get('applied_revisions')
    if not isinstance(applied, list) or value.get('updates') != len(applied):
        return False  # Older receipts conservatively replay retained plans.
    run = base / 'runs' / commit
    if not (run / 'offered-packet.json').is_file() or not (run / 'validated-plan.json').is_file():
        return False
    packet = json.loads(ds.checked_path(run / 'offered-packet.json').read_bytes())
    plan = json.loads(ds.checked_path(run / 'validated-plan.json').read_bytes())
    if packet.get('commit') != commit:
        raise ds.StoreError('documentation evidence identity rejected')
    validate_plan(plan, packet)
    stores = owned_stores(cfg)
    labels = {change['topic'] for change in packet['changes']}
    topic_stores = {item['id']: item['store'] for item in packet['topics']}
    agent = ds.checked_path('AGENTS.md').read_text(encoding='utf-8-sig')
    if agent.count(BEGIN) != 1 or agent.count(END) != 1:
        return False
    for label in labels:
        store = topic_stores[label]
        if store not in stores or store not in agent:
            return False
        with contextlib.closing(ds.connect(stores[store])) as con:
            ds.check_publication(con, stores[store])
            row = con.execute('SELECT r.* FROM revisions r JOIN documents d ON d.id=r.document_id WHERE d.slug=? AND d.path=? AND r.sha256=?', ('commit-' + commit, 'docs/commit-records/' + label + '/' + commit + '.md', ds.sha(fact_body(packet, label)))).fetchone()
            if row is None:
                return False
            ds.validated_body(row)
    for item in applied:
        if not isinstance(item, dict) or set(item) != {'store', 'slug', 'path', 'sha256', 'revision', 'document_id'}:
            raise ds.StoreError('semantic completion receipt rejected')
        store = item['store']
        if store not in stores or store not in agent:
            return False
        with contextlib.closing(ds.connect(stores[store])) as con:
            row = con.execute('SELECT r.* FROM revisions r JOIN documents d ON d.id=r.document_id WHERE d.slug=? AND d.path=? AND r.document_id=? AND r.revision=? AND r.sha256=?', (item['slug'], item['path'], item['document_id'], item['revision'], item['sha256'])).fetchone()
            if row is None:
                return False
            ds.validated_body(row)
    return True


def startup() -> int:
    """Finish closing documentation once before allowing new repository work.

    A concurrent/stale lock blocks rather than implying success. Quota deferral
    retains queue and receipts; this foreground invocation never loops retries.
    """
    cfg = config(); base = state_path()
    for name in ('python_path', 'codex_path'):
        value = cfg.get(name)
        if not isinstance(value, str) or not Path(value).is_absolute() or not Path(value).is_file():
            raise ds.StoreError('startup configured executable path unavailable')
    owned_stores(cfg)
    head = commit_id(git('rev-parse', 'HEAD').decode('ascii').strip())
    if operation_active():
        enqueue(head)
        print(json.dumps({'ready': False, 'state': 'blocked-git-operation', 'head': head}))
        return 2
    if (base / 'worker-lock').exists():
        print(json.dumps({'ready': False, 'state': 'blocked-worker-lock', 'head': head}))
        return 2
    # A interrupted worker may leave a failure receipt after a queue was lost.
    # Recover only validated immutable identities, never caller source bytes.
    for path in sorted((base / 'receipts').glob('*.json')):
        identity = commit_id(path.stem)
        value = json.loads(ds.checked_path(path).read_bytes())
        if not isinstance(value, dict) or value.get('format') != 1 or value.get('commit') != identity or value.get('state') not in {'complete', 'running', 'failed', 'deferred'}:
            raise ds.StoreError('documentation receipt identity or state rejected')
        if not complete_receipt(identity, cfg):
            enqueue(identity)
    for path in sorted((base / 'queue').glob('*.json')):
        value = json.loads(ds.checked_path(path).read_bytes())
        if not isinstance(value, dict) or value.get('format') != 1 or commit_id(path.stem) != value.get('commit'):
            raise ds.StoreError('documentation queue identity rejected')
    stores = owned_stores(cfg)
    if operation_active():
        print(json.dumps({'ready': False, 'state': 'blocked-git-operation', 'head': head}))
        return 2
    index_stores({name: name for name in stores})
    if not complete_receipt(head, cfg):
        enqueue(head)
    result = worker() if any((base / 'queue').glob('*.json')) else 0
    # Git may advance while Codex is busy. Do not declare the new HEAD clean or
    # launch a second foreground attempt during this same startup.
    current = commit_id(git('rev-parse', 'HEAD').decode('ascii').strip())
    if current != head and not complete_receipt(current, cfg):
        enqueue(current)
    lock = (base / 'worker-lock').exists()
    pending = len(list((base / 'queue').glob('*.json')))
    completed = complete_receipt(current, cfg)
    for db in owned_stores(cfg).values():
        with contextlib.closing(ds.connect(db)) as con:
            ds.check_publication(con, db)
            if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or con.execute('PRAGMA foreign_key_check').fetchone():
                raise ds.StoreError('startup store integrity failed')
    ready = result == 0 and not lock and not pending and completed and not operation_active()
    status_file = base / 'worker-status.json'
    status = json.loads(ds.checked_path(status_file).read_bytes()).get('state') if status_file.exists() else 'idle'
    # Point-in-time context gate: narrow the final observation gap without
    # claiming an OS-atomic barrier against concurrent Git or another worker.
    latest = commit_id(git('rev-parse', 'HEAD').decode('ascii').strip())
    if latest != current:
        enqueue(latest); ready = False; completed = False; current = latest
    lock = (base / 'worker-lock').exists()
    pending = len(list((base / 'queue').glob('*.json')))
    ready = ready and not lock and not pending
    print(json.dumps({'ready': ready, 'state': 'ready' if ready else ('blocked-worker-lock' if lock else status), 'head': current, 'current_head_complete': completed, 'queued': pending, 'worker_lock': lock}))
    return 0 if ready else 1


def process_commit(commit: str, cfg: dict) -> None:
    base = state_path(); run = base / 'runs' / commit
    ds.checked_path(run, mutation=True).mkdir(exist_ok=True)
    status_file = base / 'receipts' / (commit + '.json')
    previous = json.loads(status_file.read_bytes()) if status_file.exists() else {}
    if previous.get('state') == 'complete' and complete_receipt(commit, cfg):
        return
    save(status_file, {'format': 1, 'commit': commit, 'state': 'running', 'stage': 'evidence'})
    rows = documents(owned_stores(cfg))
    packet = evidence(commit, cfg, rows)
    deterministic_unresolved = reconcile(packet, rows)
    # Re-read canonical revisions after explicit committed-document CAS updates.
    packet = evidence(commit, cfg, documents(owned_stores(cfg)))
    if operation_active():
        raise ds.StoreError('Git operation began during evidence read; queued commit retained for replay')
    topics = record_facts(packet)
    changed_topics = {change['topic'] for change in packet['changes']}
    plan_file = run / 'validated-plan.json'
    from docstore_commit_ai import generate_plan
    def progress(value: object) -> None:
        save(status_file, {'format': 1, 'commit': commit, 'state': 'running', 'stage': 'ai', 'heartbeat': int(time.time())})
    packet_file = run / 'offered-packet.json'
    if plan_file.exists():
        packet = json.loads(packet_file.read_bytes())
        plan = json.loads(plan_file.read_bytes())
    else:
        save(packet_file, packet)
        progress(None)
        plan = generate_plan(packet, run, cfg, progress)
        validate_plan(plan, packet)
        save(plan_file, plan)
    topics = {item['id']: item['store'] for item in packet['topics']}
    updates = validate_plan(plan, packet)
    applied = 0; applied_revisions = []; temporal_unresolved = []
    existing_targets = {(row['topic'], row['slug'], row['path']) for row in packet['documents']}
    for update, data in updates:
        if operation_active():
            raise ds.StoreError('Git operation began during AI review; guarded plan retained for replay')
        if (update['topic'], update['slug'], update['path']) in existing_targets and packet['commit'] != git('rev-parse', 'HEAD').decode('ascii').strip():
            temporal_unresolved.append({'topic': update['topic'], 'reason': 'Historical commit or advanced HEAD: AI update of existing canonical document skipped; guarded draft retained for review.', 'evidence_ids': update['evidence_ids']}); continue
        ds.write_document(ds.checked_path(topics[update['topic']]), update['slug'], update['path'], data, update['expected_revision'], 'codex-commit-review:' + commit)
        with contextlib.closing(ds.connect(ds.checked_path(topics[update['topic']]))) as con:
            row = con.execute('SELECT id,revision,sha256 FROM documents WHERE slug=? AND path=?', (update['slug'], update['path'])).fetchone()
            if row is None or row['sha256'] != ds.sha(data):
                raise ds.StoreError('semantic update publication identity rejected')
            applied_revisions.append({'store': topics[update['topic']], 'slug': update['slug'], 'path': update['path'], 'document_id': row['id'], 'revision': row['revision'], 'sha256': row['sha256']})
        applied += 1
    index_stores(topics)
    for store in set(topics.values()):
        db = ds.checked_path(store)
        if db.exists():
            with contextlib.closing(ds.connect(db)) as con:
                ds.check_publication(con, db)
                if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or con.execute('PRAGMA foreign_key_check').fetchone():
                    raise ds.StoreError('post-commit store integrity failed')
    unresolved = deterministic_unresolved + plan['unresolved'] + temporal_unresolved
    save(status_file, {'format': 1, 'commit': commit, 'state': 'complete', 'ai_invoked': True, 'updates': applied, 'applied_revisions': applied_revisions, 'topics': len(changed_topics), 'unresolved': unresolved, 'evidence_omissions': len(packet['exclusions']), 'verification': 'source-only'})


def operation_active() -> bool:
    """Queue commits during sequenced Git operations; publish after Git finishes."""
    for name in ('rebase-merge', 'rebase-apply', 'sequencer', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD'):
        value = git('rev-parse', '--git-path', name).decode('utf-8').strip()
        path = Path(value)
        if not path.is_absolute():
            path = ROOT / path
        if path.exists():
            return True
    return False


def safe_error(error: Exception) -> str:
    if isinstance(error, ds.StoreError):
        return str(error)
    category = getattr(error, 'category', None)
    allowed = {'provider-model-unsupported', 'provider-deadline', 'provider-credential-rejected', 'provider-tool-use-rejected', 'provider-failed', 'provider-usage-deferred'}
    return category if category in allowed else type(error).__name__

def worker() -> int:
    base = state_path(); lock = base / 'worker-lock'
    try:
        lock.mkdir()
    except FileExistsError:
        return 2  # Existing/stale locks block foreground gates; never auto-break.
    save(lock / 'owner.json', {'pid': os.getpid(), 'started': int(time.time())})
    save(base / 'worker-status.json', {'state': 'running'})
    result = 0; seen = set(); usage_deferred = False
    try:
        cfg = config()
        while True:
            wait_started = time.monotonic()
            while operation_active():
                save(base / 'worker-status.json', {'state': 'deferred-git-operation', 'elapsed_seconds': int(time.monotonic() - wait_started)})
                if time.monotonic() - wait_started >= 600:
                    return 1
                time.sleep(1)
            pending = [path for path in (base / 'queue').glob('*.json') if path.name not in seen]
            if not pending:
                break
            for path in sorted(pending, key=lambda item: item.stat().st_mtime_ns):
                if operation_active():
                    break
                seen.add(path.name)
                commit = commit_id(json.loads(path.read_bytes())['commit'])
                try:
                    process_commit(commit, cfg)
                    path.unlink()
                except Exception as error:
                    category = safe_error(error)
                    usage_deferred = category == 'provider-usage-deferred'
                    save(base / 'receipts' / (commit + '.json'), {'format': 1, 'commit': commit, 'state': 'deferred' if usage_deferred else 'failed', 'error': category, 'retry': 'python master/docstore_commit.py startup --json'})
                    result = 1
                    if usage_deferred:
                        return result
        return result
    finally:
        (lock / 'owner.json').unlink(missing_ok=True)
        lock.rmdir()
        if usage_deferred or not operation_active():
            save(base / 'worker-status.json', {'state': 'deferred-usage' if usage_deferred else ('failed' if result else 'idle'), 'queued': len(list((base / 'queue').glob('*.json')))})
        # An enqueuer that saw the lock immediately before release cannot strand
        # its item. Failed items already attempted here do not start retry loops.
        if not usage_deferred and not operation_active() and any(path.name not in seen for path in (base / 'queue').glob('*.json')):
            launch()

def launch() -> None:
    cfg = config(); base = state_path()
    if (base / 'worker-lock').exists():
        return
    status_file = base / 'worker-status.json'
    if status_file.exists() and json.loads(ds.checked_path(status_file).read_bytes()).get('state') == 'deferred-usage':
        return  # Preserve closing work until an explicit startup/replay retries.
    python = cfg.get('python_path') or sys.executable
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith('GIT_'):
            env.pop(name, None)
    kwargs = {'env': env, 'cwd': str(ROOT), 'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL, 'close_fds': True}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True
    subprocess.Popen([python, str(Path(__file__).resolve()), 'worker'], **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    event = subs.add_parser('post-commit'); event.add_argument('--event', choices=('post-commit', 'post-merge', 'post-rewrite', 'post-applypatch'), default='post-commit')
    subs.add_parser('worker'); subs.add_parser('index'); subs.add_parser('install-index')
    status = subs.add_parser('status'); status.add_argument('--json', action='store_true')
    gate = subs.add_parser('startup'); gate.add_argument('--json', action='store_true')
    replay = subs.add_parser('replay'); replay.add_argument('--commit', required=True); replay.add_argument('--foreground', action='store_true')
    args = parser.parse_args()
    try:
        if Path(git('rev-parse', '--show-toplevel').decode().strip()).resolve() != ROOT.resolve():
            raise ds.StoreError('repository helper root differs from Git root')
        if args.command in {'index', 'install-index'}:
            index_config = json.loads(ds.checked_path(CONFIG).read_bytes()) if CONFIG.exists() else {}
            if not isinstance(index_config, dict):
                raise ds.StoreError('index configuration requires a JSON object')
            index_stores({name: name for name in owned_stores(index_config)})
            print('Repository commit documentation index verified.')
            return 0
        if args.command == 'status':
            base = state_path()
            receipts = [json.loads(path.read_bytes()) for path in sorted((base / 'receipts').glob('*.json'))]
            worker_info = json.loads((base / 'worker-status.json').read_bytes()) if (base / 'worker-status.json').exists() else {'state': 'not-started'}
            worker_info = {key: value for key, value in worker_info.items() if key in {'state', 'elapsed_seconds', 'queued'}}
            print(json.dumps({'worker_status': worker_info, 'queued': len(list((base / 'queue').glob('*.json'))), 'worker_lock': (base / 'worker-lock').exists(), 'receipts': receipts}, ensure_ascii=False))
            return 0
        if args.command == 'worker':
            return worker()
        if args.command == 'startup':
            return startup()
        cfg = config()
        value = args.commit if args.command == 'replay' else git('rev-parse', 'HEAD').decode().strip()
        commits = [value]
        if args.command == 'post-commit' and args.event == 'post-rewrite':
            raw = sys.stdin.buffer.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ds.StoreError('post-rewrite event exceeds bound')
            commits = []
            for line in raw.decode('ascii').splitlines():
                if not line.strip():
                    continue
                pair = line.split()
                if len(pair) != 2 or any(not HEX.fullmatch(item) for item in pair):
                    raise ds.StoreError('post-rewrite event identity rejected')
                commits.append(pair[1])
            commits = list(dict.fromkeys(commits or [value]))
        if args.command == 'post-commit' and args.event == 'post-merge':
            try:
                old_head = git('rev-parse', '--verify', 'ORIG_HEAD^{commit}').decode('ascii').strip()
                commits = git('rev-list', '--reverse', value, '^' + commit_id(old_head)).decode('ascii').split() or [value]
            except ds.StoreError:
                commits = [value]
        for value in commits:
            enqueue(value)
        if args.command == 'replay' and args.foreground:
            return worker()
        launch()
        print('Commit documentation queued. Inspect python master/docstore_commit.py status --json for completion or retryable failure.')
        return 0
    except Exception as error:
        category = safe_error(error)
        if args.command == 'startup':
            print(json.dumps({'ready': False, 'state': 'startup-verification-failed', 'error': category if category.startswith('provider-') else type(error).__name__}))
            return 1
        print('Git commit succeeded; documentation synchronization failed: ' + category + '. Inspect python master/docstore_commit.py status --json.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
