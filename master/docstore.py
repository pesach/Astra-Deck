#!/usr/bin/env python3
"""Repository-owned SQLite document authority; Python stdlib only.

init/import consumes an explicit owned Markdown manifest once. put requires the
expected document revision; 0 creates a new owned document only. New decisions
require source-backed status/context/decision/consequences. Legacy incomplete
imports retain their bytes and remain auditable; this tool cannot grant approval.
SQLite commits precede recovery export publication: DB and two files are not an
atomic filesystem unit. An interrupted publication blocks edits until explicit
export repairs only known DB-current/previous states. Dirty exports fail closed.
Never auto-break a leftover writer lock. Read commands do not create a store.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / 'docs' / 'knowledge.sqlite'
VERSION = 1
MAX_BYTES = 16 * 1024 * 1024
MAX_LIMIT = 100
LIFECYCLES = ('proposed', 'accepted', 'superseded', 'rejected', 'deferred')
SECRET_PATTERNS = {
    'private-key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'github-token': r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{25,}\b|\bgithub_pat_[A-Za-z0-9_]{35,}\b',
    'openai-key': r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b',
    'aws-access-key': r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'jwt-literal': r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b',
    'credential-url': r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:<>]+:[^\s/@<>]{5,}@',
}
SCHEMA = '''
CREATE TABLE store_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE documents(
 id TEXT PRIMARY KEY,slug TEXT NOT NULL UNIQUE,path TEXT NOT NULL UNIQUE,
 revision INTEGER NOT NULL CHECK(revision>0),type TEXT NOT NULL,status TEXT NOT NULL,
 title TEXT NOT NULL,body TEXT NOT NULL,bytes BLOB NOT NULL,
 sha256 TEXT NOT NULL,text_sha256 TEXT NOT NULL,
 FOREIGN KEY(id,revision) REFERENCES revisions(document_id,revision)
 DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE revisions(
 document_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),
 type TEXT NOT NULL,status TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,
 bytes BLOB NOT NULL,sha256 TEXT NOT NULL,text_sha256 TEXT NOT NULL,
 provenance TEXT NOT NULL,PRIMARY KEY(document_id,revision),
 FOREIGN KEY(document_id) REFERENCES documents(id) DEFERRABLE INITIALLY DEFERRED);
CREATE VIRTUAL TABLE documents_fts USING fts5(title,body,path,
 content='documents',content_rowid='rowid',tokenize='unicode61');
CREATE TRIGGER documents_ai AFTER INSERT ON documents BEGIN
 INSERT INTO documents_fts(rowid,title,body,path) VALUES(new.rowid,new.title,new.body,new.path); END;
CREATE TRIGGER documents_ad AFTER DELETE ON documents BEGIN
 INSERT INTO documents_fts(documents_fts,rowid,title,body,path)
 VALUES('delete',old.rowid,old.title,old.body,old.path); END;
CREATE TRIGGER documents_au AFTER UPDATE ON documents BEGIN
 INSERT INTO documents_fts(documents_fts,rowid,title,body,path)
 VALUES('delete',old.rowid,old.title,old.body,old.path);
 INSERT INTO documents_fts(rowid,title,body,path) VALUES(new.rowid,new.title,new.body,new.path); END;
PRAGMA user_version=1;
'''


class StoreError(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


# This is a conservative heuristic, not proof that text contains no secrets.
# Surrounding example/test prose never exempts a literal credential. Keep values
# entirely in memory and expose only a category; references must match in full.
CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?<![\w.-])(?P<key>["']?[A-Za-z_][A-Za-z0-9_.-]{0,127}["']?)"""
    r"""(?:\*\*)?[ \t]*(?P<operator>:=|=(?!=)|:(?!=))[ \t]*(?:\*\*)?[ \t]*(?P<value>"""
    r"""<[^<>\r\n]+>|\$\([^\r\n()]*\)|\$\{\{[^\r\n}]*\}\}|(?:os\.getenv|os\.environ\.get|Deno\.env\.get)\([^()\r\n]*\)|"""
    r""""(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|\x60[^\x60\r\n]*\x60|["'][^\r\n]*|[^\s,;#\x60"'<>]+)""")
CREDENTIAL_LABEL = re.compile(
    r"""(?i)\b(?:password|passwd|secret|token|api[ _-]?key)"""
    r"""(?:[ \t]*\([^)\r\n]{0,40}\))?[ \t]*(?::|=|\bis\b)[ \t]*(?:\*\*)?[ \t]*"""
    r"""(?P<value>\x60[^\x60\r\n]*\x60|"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*')""")
OPERATOR_PASSWORD_LABEL = re.compile(
    r'(?i)\b(?:storefront|reviewer)(?:[ \t]+(?:account|login|access|store)){0,3}[ \t]+password[ \t]*:[ \t]*'
    r"""(?P<value>\x60[^\x60\r\n]*\x60|"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;#\x60"'<>]+)""")
BEARER_LITERAL = re.compile(
    r"""(?i)\b(?:proxy-)?authorization[ \t]*:[ \t]*(?:Bearer|Basic)[ \t]+"""
    r"""(<[^<>\r\n]+>|\$\{\{[^\r\n}]*\}\}|\x60[^\x60\r\n]*\x60|"(?:\\.|[^"\\\r\n])*"|"""
    r"""'(?:\\.|[^'\\\r\n])*'|[^\s"'\x60]+)""")
USERINFO_LITERAL = re.compile(
    r"""[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:<>]+:([^\s/@<>]+)@""")
SENSITIVE_NAME = re.compile(
    r'(?i)(?:password|passwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key|'
    r'auth[_-]?key|private[_-]?key|pwd|connection[_-]?string|authorization)(?:$|[_-])|(?:^|[_-])pass(?:$|[_-])')
REFERENCE_VALUE = re.compile(
    r'(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|'
    r'\$env:[A-Za-z_][A-Za-z0-9_]*|'
    r'(?:process\.env|os\.environ|settings|config|self)\.[A-Za-z_][A-Za-z0-9_]*|'
    r"""(?:os\.getenv|os\.environ\.get|Deno\.env\.get)\(["'][A-Za-z_][A-Za-z0-9_]*["']\)|"""
    r"""(?:process\.env|os\.environ)\[["'][A-Za-z_][A-Za-z0-9_]*["']\]|"""
    r'\$\{\{[ \t]*secrets\.[A-Za-z_][A-Za-z0-9_]*[ \t]*\}\})')
CODE_CONTEXT = re.compile(
    r'(?ims)^[ \t]*(?P<fence>\x60{3,}|~{3,})[ \t]*(?P<language>typescript|ts|javascript|js|python|py|json|jsonc)[ \t]*\r?\n'
    r'(?P<body>.*?)^[ \t]*(?P=fence)[ \t]*$')
SHELL_CONTEXT = re.compile(
    r'(?ims)^[ \t]*(?P<fence>\x60{3,}|~{3,})[ \t]*(?:bash|sh|shell|powershell|ps1)[ \t]*\r?\n'
    r'(?P<body>.*?)^[ \t]*(?P=fence)[ \t]*$')
CONFIG_CONTEXT = re.compile(
    r'(?ims)^[ \t]*(?P<fence>\x60{3,}|~{3,})[ \t]*(?:bash|sh|shell|powershell|ps1|env|dotenv|yaml|yml|toml|ini|properties|conf|config|http)[ \t]*\r?\n'
    r'(?P<body>.*?)^[ \t]*(?P=fence)[ \t]*$')
PLACEHOLDER_VALUE = re.compile(
    r'(?i)(?:<(?:YOUR[ _-])?(?:PASSWORD|PASSWD|TOKEN|AUTH[ _-]?TOKEN|JWT|SECRET|API[ _-]?KEY|KEY|VALUE)'
    r'(?:[ _-](?:HERE|VALUE))?>|'
    r'(?:YOUR|REPLACE|INSERT|EXAMPLE|PLACEHOLDER|REDACTED|WITHHELD|MASKED|CHANGEME)'
    r'(?:[_ -][A-Za-z_ -]+)?)')


def credential_reference(value: str, *, code_context: bool = False, typescript_context: bool = False) -> bool:
    """Only empty values, explicit whole references and marked placeholders pass."""
    value = value.strip()

    quoted = len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'\x60"
    string_literal = quoted
    # A TypeScript non-null assertion changes a code reference, not its value.
    if typescript_context and not string_literal and value.endswith('!'):
        value = value[:-1]
    if quoted:
        value = value[1:-1]
    # Only an unquoted expression in proven code context is exempt, not a default.
    if code_context and not string_literal and re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*', value):
        return True
    header = re.fullmatch(r'(?i)(?:Bearer|Basic)[ \t]+(.+)', value)
    if header:
        return credential_reference(header.group(1), code_context=code_context, typescript_context=typescript_context)
    if (not value or REFERENCE_VALUE.fullmatch(value) or PLACEHOLDER_VALUE.fullmatch(value)
            or re.fullmatch(r'<[A-Za-z_][A-Za-z0-9_ -]*>', value)
            or re.fullmatch(r'[-_*.]{3,}', value)
            or re.fullmatch(r'(?:xox[baprs]-|[sp]k_(?:test|live)_|whsec_)\.{3,}', value)):
        return True
    if re.fullmatch(r'\{(?=[^{}]*token)[A-Za-z_][A-Za-z0-9_.-]*\}', value, re.I):
        return True
    if code_context and re.fullmatch(r'\$\{[A-Za-z_][A-Za-z0-9_.]*(?:\(\))?\}', value):
        return True
    # Code expressions/types may pass in explicit code/schema context, not env
    # assignments or authorization values. Quoted defaults are still literals.
    if code_context and not string_literal:
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*\((?:[A-Za-z_][A-Za-z0-9_.]*)?\)(?:\.[A-Za-z_][A-Za-z0-9_]*\(\))*', value):
            return True
        if not quoted and value in {'None', 'null', 'undefined', 'str', 'string', 'bytes', 'bool', 'boolean', 'int', 'number', 'object', 'dict', 'list', 'Any', 'true', 'false'}:
            return True
    return False


def generic_credential_guard(text: str, category: str) -> None:
    """Reject literal credential evidence; bare prose/code identifiers are audit-only."""
    code_spans = [(m.start('body'), m.end('body'), m.group('language').casefold()) for m in CODE_CONTEXT.finditer(text)]
    config_spans = [(m.start('body'), m.end('body')) for m in CONFIG_CONTEXT.finditer(text)]
    shell_spans = [(m.start('body'), m.end('body')) for m in SHELL_CONTEXT.finditer(text)]
    for match in CREDENTIAL_ASSIGNMENT.finditer(text):
        key = match.group('key').strip("\"'")
        if not SENSITIVE_NAME.search(key):
            continue
        # These identifier suffixes denote settings/reference names, not key bytes.
        if re.search(r'(?i)(?:[_-](?:file|path|name|env|env_var|variable|enabled|ttl|expiry|expires|length|limit|count|type|id|endpoint|minutes|seconds|hours|days|duration))$', key):
            continue
        value = match.group('value')
        if key in {'pass_fds', 'ONE_TIME_PASSWORD_TEMPLATE', 'FORGOT_PASSWORD_TEMPLATE'} or key.casefold().endswith('.dart'):
            continue  # Process descriptor, source-template metadata or file reference.
        if key == 'user_authorization' and value.strip("\"'\x60") == 'high':
            continue  # Source-backed policy enum, not an authorization credential.
        if key.casefold().endswith('authorization') and value.casefold() in {'bearer', 'basic'}:
            continue  # The complete header value is checked separately below.
        prefix = text[text.rfind('\n', 0, match.start()) + 1:match.start()]
        code_context = any(start <= match.start() < end for start, end, language in code_spans) or bool(re.search(r'\b(?:const|let|var)[ \t]+$', prefix))
        if prefix.endswith('$' + '{') and match.group('operator') == ':' and value == '-}':
            continue  # A whole environment expansion has an empty default.
        if key == 'PWD' and prefix.endswith('$') and match.group('operator') == ':' and value.startswith('/'):
            continue  # Docker working-directory bind mount, not password data.
        # An explicit env-getter default is separate literal evidence even when
        # the surrounding RHS is executable code; never mistake it for a name.
        safe_getter_default = False
        env_default = re.fullmatch(
            r"""(?:os\.getenv|os\.environ\.get|Deno\.env\.get)\(["'][A-Za-z_][A-Za-z0-9_]*["'][ \t]*,[ \t]*(.+)\)""",
            value)
        if env_default:
            default = env_default.group(1).strip()
            if credential_reference(default, code_context=True):
                safe_getter_default = True
                value = default  # Still inspect the outer RHS fallback below.
            elif default[:1] in {'"', "'", '\x60'} or re.fullmatch(r'[+-]?\d+(?:\.\d+)?', default):
                raise StoreError(f'secret indicator (credential-default-literal) in {category}; content withheld')
        # Bare prose identifiers and code/type expressions are audit candidates,
        # not evidence of a credential literal. Shell/config values are data.
        quoted_literal = bool(value) and value[0] in "\"'\x60"
        numeric_literal = bool(re.fullmatch(r'[+-]?\d+(?:\.\d+)?', value))
        config_context = any(start <= match.start() < end for start, end in config_spans)
        env_assignment = key.isupper() and match.group('operator') == '=' and bool(re.fullmatch(r'[ \t]*(?:export[ \t]+)?', prefix))
        # Only this complete proven generator expression is a reference. Single
        # quotes preserve literal text; arbitrary substitutions are not trusted.
        shell_context = any(start <= match.start() < end for start, end in shell_spans)
        generated = value[1:-1] if value.startswith('"') and value.endswith('"') else value
        if shell_context and re.fullmatch(r'\$\(openssl[ \t]+rand[ \t]+-hex[ \t]+[1-9][0-9]*\)', generated):
            continue
        # PASS in ordinary prose is a check outcome, not a password label.
        if key.casefold() == 'pass' and not (config_context or env_assignment):
            continue
        # This source-backed named toggle is boolean metadata, not token bytes.
        if key == 'ASTRA_LEGACY_HEALTH_TOKEN_ECHO' and value in {'0', '1'}:
            continue
        if numeric_literal and not (code_context or config_context or env_assignment):
            if not re.fullmatch(r'(?i)(?:password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|client[_-]?secret|private[_-]?key|db[_-]?password|database[_-]?password|connection[_-]?string)', key):
                continue  # Unqualified prose quantities are audit-only.
        if not (quoted_literal or numeric_literal or config_context or env_assignment or safe_getter_default):
            continue
        typescript_context = any(start <= match.start() < end and language in {'typescript', 'ts'} for start, end, language in code_spans)
        if safe_getter_default or credential_reference(value, code_context=code_context, typescript_context=typescript_context):
            end = text.find('\n', match.end())
            remainder = text[match.end():end if end != -1 else len(text)]
            if not (code_context or config_context or env_assignment or safe_getter_default) or not re.match(r'[ \t]*(?:\|\||\?\?|\bor\b)', remainder):
                continue
        raise StoreError(f'secret indicator (credential-literal) in {category}; content withheld')
    for pattern, name in ((CREDENTIAL_LABEL, 'credential-label'),
                          (OPERATOR_PASSWORD_LABEL, 'operator-password-literal'),
                          (BEARER_LITERAL, 'bearer-literal'),
                          (USERINFO_LITERAL, 'credential-url-literal')):
        for match in pattern.finditer(text):
            value = match.group('value') if pattern in (CREDENTIAL_LABEL, OPERATOR_PASSWORD_LABEL) else match.group(1)
            pattern_context = any(start <= match.start() < end for start, end, language in code_spans)
            if not credential_reference(value, code_context=pattern_context):
                raise StoreError(f'secret indicator ({name}) in {category}; content withheld')

def secret_guard(text: str, category: str) -> None:
    for name, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            raise StoreError(f'secret indicator ({name}) in {category}; content withheld')
    generic_credential_guard(text, category)


def checked_path(value: str | Path, *, owned: bool = True, mutation: bool = False) -> Path:
    """Literal owned paths never traverse reparse points; writes reject hardlinks."""
    path = Path(value)
    if '..' in path.parts:
        raise StoreError('path traversal rejected')
    path = Path(os.path.abspath(path if path.is_absolute() else ROOT / path))
    if owned and not path.is_relative_to(ROOT):
        raise StoreError('path outside repository')
    excluded = {'.git', '.ssh', '.aws', 'credentials', 'secrets', 'node_modules'}
    if any(part.casefold() in excluded or part.casefold().startswith('.env') for part in path.parts):
        raise StoreError('credential or excluded path rejected')
    for ancestor in [path, *path.parents]:
        try:
            stat = ancestor.lstat()
        except FileNotFoundError:
            continue
        if ancestor.is_symlink() or getattr(stat, 'st_file_attributes', 0) & 0x400:
            raise StoreError('symlink or reparse point rejected')
        if ancestor == ROOT:
            break
        if owned and ancestor.is_dir() and (ancestor / '.git').exists():
            raise StoreError('nested Git repository rejected')
    if mutation and path.is_file() and path.stat().st_nlink != 1:
        raise StoreError('hardlinked mutation target rejected')
    return path


def auxiliary(path: Path) -> Path:
    return checked_path(path, owned=False, mutation=True)


def owned_source(value: str) -> Path:
    if not isinstance(value, str) or Path(value).is_absolute() or '\\' in value:
        raise StoreError('source requires owned relative forward-slash path')
    secret_guard(value, 'source identity')
    path = checked_path(value)
    if path.relative_to(ROOT).as_posix() != value or path.suffix.casefold() != '.md' or not path.is_file():
        raise StoreError('source must be canonical existing owned Markdown')
    return path


def read_input(path: Path) -> bytes:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise StoreError('input missing, not regular, or exceeds 16 MiB')
    return path.read_bytes()


def text_bytes(data: bytes, label: str) -> str:
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError:
        raise StoreError(f'invalid UTF-8 in {label}') from None
    secret_guard(text, label)
    return text


def frontmatter(text: str) -> dict[str, str]:
    match = re.match(r'\A---\s*\r?\n(.*?)\r?\n---(?:\r?\n|$)', text, re.S)
    fields = {}
    if match:
        for line in match.group(1).splitlines():
            key, separator, value = line.partition(':')
            if separator and key.strip() in {'type', 'status', 'title', 'slug'}:
                fields[key.strip()] = value.strip().strip('\'"')
    return fields


def classify(path: str) -> str:
    relative = path.casefold()
    name = Path(relative).stem.replace('_', '-')
    parts = Path(relative).parts
    if 'decision' in name or any(part in {'decision', 'decisions', 'adr', 'adrs'} for part in parts):
        return 'decision'
    if 'worklog' in name or 'work-log' in name or 'work-record' in name or 'work-log' in parts:
        return 'work-log'
    if 'plan' in name:
        return 'plan'
    if 'runbook' in name or name in {'deploy', 'operations'}:
        return 'runbook'
    if relative.startswith(('docs/rules/', 'docs/contracts/', 'docs/contract/', 'docs/agent-policies/')):
        return 'contract'
    if 'spec' in name or 'spec' in parts:
        return 'spec'
    return 'note'


def metadata(text: str, path: str, old: dict | None = None) -> dict[str, str]:
    old = old or {}
    fields = frontmatter(text)
    heading = re.search(r'^#\s+([^\r\n]+)', text, re.M)
    return {
        'type': fields.get('type', old.get('type', classify(path))),
        'status': fields.get('status', old.get('status', 'unspecified')),
        'title': fields.get('title', old.get('title', heading.group(1).strip() if heading else Path(path).stem)),
        'slug': fields.get('slug', re.sub(r'[^a-z0-9]+', '-', path.casefold()).strip('-')),
    }


def recognized_status(value: str) -> str:
    normalized = re.sub(r'[*`\[\]]', '', value).strip().casefold()
    return next((status for status in LIFECYCLES if normalized.startswith(status)), 'unspecified')


def decision_fields(text: str, status: str = 'unspecified') -> dict:
    found_status = re.search(r'(?im)^\s*(?:\*\*)?Status(?:\*\*)?\s*:\s*(?:\*\*)?([^\r\n]+)', text)
    marker = found_status.group(1).strip() if found_status else status
    fields = {'status_marker': marker, 'recognized_status': recognized_status(marker)}
    for label in ('context', 'decision', 'consequences'):
        match = re.search(r'(?ims)^#{1,6}\s+' + label + r'\s*\r?\n(.*?)(?=^#{1,6}\s|\Z)', text)
        if not match:
            match = re.search(r'(?im)^\s*\*\*' + label + r'(?:\*\*:|:\*\*)\s*([^\r\n]+)', text)
        fields[label] = match.group(1).strip() if match else ''
    fields['missing_fields'] = [label for label in ('context', 'decision', 'consequences') if not fields[label]]
    if fields['recognized_status'] == 'unspecified':
        fields['missing_fields'].append('recognized status')
    return fields


def exports(db: Path) -> tuple[Path, Path]:
    base = 'knowledge-export' if db == DEFAULT_DB else db.stem + '-export'
    return auxiliary(db.parent / (base + '.jsonl')), auxiliary(db.parent / (base + '.sha256.json'))


@contextlib.contextmanager
def writer_lock(db: Path):
    auxiliary(db.parent).mkdir(parents=True, exist_ok=True)
    lock = auxiliary(db.with_name(db.name + '.writer-lock'))
    try:
        lock.mkdir()
    except FileExistsError:
        raise StoreError('writer lock exists; inspect active/interrupted owner before retrying') from None
    try:
        yield
    finally:
        lock.rmdir()


def connect(db: Path, *, write: bool = False) -> sqlite3.Connection:
    if not db.is_file():
        raise StoreError('store missing; explicit init or recover required')
    if write:
        auxiliary(db)
    con = sqlite3.connect(db.as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    if not write:
        con.execute('PRAGMA query_only=ON')
    if con.execute('PRAGMA user_version').fetchone()[0] != VERSION:
        con.close()
        raise StoreError('unsupported store schema version')
    return con


def state(con: sqlite3.Connection) -> dict[str, str]:
    return dict(con.execute('SELECT key,value FROM store_meta'))


def validate_current(con: sqlite3.Connection) -> None:
    mismatch = con.execute('''SELECT 1 FROM documents d LEFT JOIN revisions r
        ON r.document_id=d.id AND r.revision=d.revision
        WHERE r.document_id IS NULL OR d.bytes!=r.bytes OR d.body!=r.body
        OR d.sha256!=r.sha256 OR d.text_sha256!=r.text_sha256 OR d.type!=r.type
        OR d.status!=r.status OR d.title!=r.title LIMIT 1''').fetchone()
    if mismatch:
        raise StoreError('current document differs from immutable revision')


def validated_body(row) -> str:
    body = text_bytes(row['bytes'], 'stored document')
    if body != row['body'] or sha(row['bytes']) != row['sha256'] or sha(body.encode('utf-8')) != row['text_sha256']:
        raise StoreError('stored bytes/hash/text projection mismatch')
    return body


def payload(con: sqlite3.Connection) -> bytes:
    validate_current(con)
    meta = state(con)
    lines = [canonical({'kind': 'store', 'format': VERSION, 'store_id': meta['store_id'], 'generation': int(meta['generation'])})]
    for row in con.execute('SELECT id,slug,path,revision FROM documents ORDER BY id'):
        record = dict(row)
        for key in ('id', 'slug', 'path'):
            secret_guard(record[key], 'export identity')
        lines.append(canonical({'kind': 'document', **record}))
    for row in con.execute('SELECT * FROM revisions ORDER BY document_id,revision'):
        validated_body(row)
        record = dict(row)
        for key in ('type', 'status', 'title', 'provenance'):
            secret_guard(record[key], 'export metadata')
        record['bytes_b64'] = base64.b64encode(record.pop('bytes')).decode('ascii')
        lines.append(canonical({'kind': 'revision', **record}))
    return b'\n'.join(lines) + b'\n'


def checksum_info(value: object) -> dict:
    keys = {'format', 'sha256', 'bytes', 'store_id', 'generation'}
    if not isinstance(value, dict) or set(value) != keys:
        raise StoreError('invalid recovery checksum fields')
    if type(value['format']) is not int or value['format'] != VERSION:
        raise StoreError('unsupported recovery checksum format')
    if type(value['generation']) is not int or value['generation'] < 1 or type(value['bytes']) is not int or value['bytes'] < 1:
        raise StoreError('invalid recovery checksum numeric metadata')
    if not isinstance(value['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['sha256']):
        raise StoreError('invalid recovery checksum hash')
    if not isinstance(value['store_id'], str) or not value['store_id']:
        raise StoreError('invalid recovery store identity')
    return value


def check_publication(con: sqlite3.Connection, db: Path, *, repair: bool = False) -> None:
    """Validate both snapshot identity and every checksum field, including crash states."""
    output, manifest = exports(db)
    meta = state(con)
    current_data = payload(con)
    current_sha = sha(current_data)
    previous = meta.get('export_sha256', '')
    generation = int(meta['generation'])
    actual_data = output.read_bytes() if output.is_file() else None
    actual_sha = sha(actual_data) if actual_data is not None else None
    info = None
    if manifest.is_file():
        try:
            info = checksum_info(json.loads(manifest.read_bytes()))
        except (ValueError, UnicodeError):
            raise StoreError('invalid recovery checksum JSON') from None
        if info['store_id'] != meta['store_id'] or info['generation'] > generation:
            raise StoreError('recovery checksum store/generation mismatch')
        if info['sha256'] == current_sha:
            expected_generation, expected_bytes = generation, len(current_data)
        elif previous and info['sha256'] == previous:
            expected_generation = int(meta.get('export_generation', '0'))
            expected_bytes = int(meta.get('export_bytes', '0'))
        else:
            raise StoreError('checksum changed outside store; reconcile before writing')
        if info['generation'] != expected_generation or info['bytes'] != expected_bytes:
            raise StoreError('checksum generation/size differs from known snapshot')
    if actual_sha is not None and actual_sha not in (current_sha, previous):
        raise StoreError('recovery export changed outside store')
    if not previous and actual_data is None and info is None:
        if repair:
            return
        raise StoreError('initial recovery export missing; run explicit export')
    if repair:
        return
    if actual_data is None or info is None or info['sha256'] != actual_sha:
        raise StoreError('recovery export incomplete; run explicit export')
    if actual_sha != current_sha:
        raise StoreError('recovery export stale; run explicit export')


def publish(con: sqlite3.Connection, db: Path) -> None:
    """Publish immutable history then each current file using exclusive temporary files."""
    output, manifest = exports(db)
    data = payload(con)
    digest = sha(data)
    meta = state(con)
    generation = int(meta['generation'])
    info = canonical({'format': VERSION, 'sha256': digest, 'bytes': len(data), 'store_id': meta['store_id'], 'generation': generation}) + b'\n'
    history = auxiliary(db.parent / (db.stem + '-export-history'))
    history.mkdir(exist_ok=True)
    for suffix, content in (('.jsonl', data), ('.sha256.json', info)):
        version = auxiliary(history / (str(generation) + '-' + digest + suffix))
        if version.exists():
            if version.read_bytes() != content:
                raise StoreError('immutable export history changed')
        else:
            fd, name = tempfile.mkstemp(prefix=version.name + '.pending-', dir=history)
            pending = Path(name)
            try:
                with os.fdopen(fd, 'wb') as file:
                    file.write(content)
                    file.flush()
                    os.fsync(file.fileno())
                auxiliary(version)
                os.link(pending, version)  # Publish a complete immutable version without overwriting.
            finally:
                pending.unlink(missing_ok=True)
    temporary = []
    try:
        for target, content in ((output, data), (manifest, info)):
            fd, name = tempfile.mkstemp(prefix=target.name + '.pending-', dir=auxiliary(target.parent))
            temporary.append(Path(name))
            with os.fdopen(fd, 'wb') as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
        for temp, target in zip(temporary, (output, manifest)):
            auxiliary(target)
            os.replace(temp, target)
        con.executemany('INSERT OR REPLACE INTO store_meta VALUES(?,?)',
                        [('export_sha256', digest), ('export_generation', str(generation)), ('export_bytes', str(len(data)))])
        con.commit()
    finally:
        for temp in temporary:
            temp.unlink(missing_ok=True)


def add_revision(con, document_id: str, revision: int, data: bytes, fields: dict, provenance: str) -> dict:
    body = text_bytes(data, 'document input')
    values = {'document_id': document_id, 'revision': revision, 'type': fields['type'], 'status': fields['status'],
              'title': fields['title'], 'body': body, 'bytes': data, 'sha256': sha(data),
              'text_sha256': sha(body.encode('utf-8')), 'provenance': provenance}
    for key in ('type', 'status', 'title', 'provenance'):
        secret_guard(values[key], 'revision metadata')
    con.execute('''INSERT INTO revisions VALUES(:document_id,:revision,:type,:status,:title,
        :body,:bytes,:sha256,:text_sha256,:provenance)''', values)
    return values


def add_document(con, path: str, slug: str, data: bytes, fields: dict, provenance: str) -> None:
    document_id = sha(path.encode('utf-8'))
    values = add_revision(con, document_id, 1, data, fields, provenance)
    con.execute('''INSERT INTO documents VALUES(:id,:slug,:path,1,:type,:status,:title,
        :body,:bytes,:sha256,:text_sha256)''', {**values, 'id': document_id, 'path': path, 'slug': slug})


def import_rows(manifest: Path) -> list[dict]:
    try:
        entries = json.loads(read_input(manifest))
    except (ValueError, UnicodeError):
        raise StoreError('invalid import manifest JSON') from None
    entries = entries.get('documents') if isinstance(entries, dict) else entries
    if not isinstance(entries, list) or not entries:
        raise StoreError('manifest requires nonempty documents list')
    result, paths, slugs = [], set(), set()
    for entry in entries:
        relative = entry if isinstance(entry, str) else entry.get('path') if isinstance(entry, dict) else None
        if not isinstance(relative, str):
            raise StoreError('invalid import path')
        source = owned_source(relative)
        data = read_input(source)
        if isinstance(entry, dict) and 'sha256' in entry and entry['sha256'] != sha(data):
            raise StoreError('source hash differs from explicit manifest')
        body = text_bytes(data, 'source document')
        fields = metadata(body, relative)
        if isinstance(entry, dict):
            for key in ('type', 'status', 'title', 'slug'):
                if key in entry:
                    if not isinstance(entry[key], str) or not entry[key].strip():
                        raise StoreError('invalid explicit import metadata')
                    fields[key] = entry[key]
        for value in fields.values():
            secret_guard(value, 'import metadata')
        if relative.casefold() in paths or fields['slug'].casefold() in slugs:
            raise StoreError('duplicate source path or slug')
        paths.add(relative.casefold())
        slugs.add(fields['slug'].casefold())
        provenance = canonical({'source': relative, 'metadata_overrides': entry if isinstance(entry, dict) else {}}).decode('utf-8')
        result.append({'path': relative, 'bytes': data, **fields, 'provenance': provenance})
    return result


def initialize(db: Path, rows: list[dict]) -> None:
    with writer_lock(db):
        if db.exists() or any(path.exists() for path in exports(db)):
            raise StoreError('init refuses existing store or recovery files')
        with db.open('xb'):
            pass
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        try:
            con.execute('PRAGMA foreign_keys=ON')
            con.executescript(SCHEMA)
            con.execute('BEGIN IMMEDIATE')
            con.executemany('INSERT INTO store_meta VALUES(?,?)', [('store_id', str(uuid.uuid4())), ('generation', '1')])
            for row in rows:
                add_document(con, row['path'], row['slug'], row['bytes'], row, row['provenance'])
            con.commit()
            publish(con, db)
        except Exception:
            con.rollback()
            # Committed authority is intentionally retained if export publication failed.
            raise
        finally:
            con.close()


def put(db: Path, slug: str, file: Path, expected: int) -> None:
    """CAS 0 creates from owned source; CAS N edits only the matching existing revision."""
    if expected < 0 or not slug.strip():
        raise StoreError('expected revision must be nonnegative; slug required')
    secret_guard(slug, 'document identity')
    data = read_input(file)
    body = text_bytes(data, 'edit document')
    with writer_lock(db), contextlib.closing(connect(db, write=True)) as con:
        con.execute('BEGIN IMMEDIATE')
        try:
            check_publication(con, db)
            current = con.execute('SELECT * FROM documents WHERE slug=?', (slug,)).fetchone()
            if expected == 0:
                if current is not None:
                    raise StoreError('revision conflict; document already exists')
                source = checked_path(file)
                relative = source.relative_to(ROOT).as_posix()
                owned_source(relative)
                if con.execute('SELECT 1 FROM documents WHERE lower(path)=lower(?) OR lower(slug)=lower(?)', (relative, slug)).fetchone():
                    raise StoreError('new document path/slug already exists')
                fields = metadata(body, relative)
                if fields['type'] == 'decision' and decision_fields(body, fields['status'])['missing_fields']:
                    raise StoreError('new decision requires source-backed status/context/decision/consequences')
                add_document(con, relative, slug, data, fields, 'explicit-new-owned-document:' + relative)
            else:
                if current is None or current['revision'] != expected:
                    raise StoreError('unknown document or revision conflict; no edit applied')
                fields = metadata(body, current['path'], dict(current))
                old_structure = decision_fields(current['body'], current['status'])
                if fields['type'] == 'decision' and not old_structure['missing_fields'] and decision_fields(body, fields['status'])['missing_fields']:
                    raise StoreError('edit would remove required decision structure')
                values = add_revision(con, current['id'], expected + 1, data, fields, 'explicit-edit')
                cursor = con.execute('''UPDATE documents SET revision=:revision,type=:type,status=:status,
                    title=:title,body=:body,bytes=:bytes,sha256=:sha256,text_sha256=:text_sha256
                    WHERE id=:document_id AND revision=:expected''', {**values, 'expected': expected})
                if cursor.rowcount != 1:
                    raise StoreError('revision conflict; no edit applied')
            con.execute("UPDATE store_meta SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
            con.commit()
            publish(con, db)
        except Exception:
            con.rollback()
            raise


def write_document(db: Path, slug: str, path: str, data: bytes, expected: int, provenance: str) -> None:
    """Guarded owned bytes API. Virtual Markdown identities do not create source files.

    Exact desired bytes at the same identity are idempotent, including replay
    after an interrupted publication. Other changes require an exact revision.
    Missing stores can only be initialized by expected=0 with one guarded row.
    """
    db = checked_path(db, mutation=True)
    if db.suffix != '.sqlite' or type(expected) is not int or expected < 0:
        raise StoreError('owned SQLite path and nonnegative revision required')
    if not isinstance(path, str) or '\\' in path or Path(path).is_absolute():
        raise StoreError('owned relative Markdown identity required')
    identity = checked_path(path)
    if identity.relative_to(ROOT).as_posix() != path or identity.suffix.casefold() != '.md':
        raise StoreError('canonical Markdown identity required')
    if not isinstance(slug, str) or not slug.strip() or not isinstance(provenance, str):
        raise StoreError('document slug and provenance required')
    for value in (slug, path, provenance):
        secret_guard(value, 'document identity/provenance')
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise StoreError('document bytes exceed bound')
    body = text_bytes(data, 'document bytes')
    if not db.exists():
        if expected != 0:
            raise StoreError('missing store cannot update an existing revision')
        fields = metadata(body, path)
        if fields['type'] == 'decision' and decision_fields(body, fields['status'])['missing_fields']:
            raise StoreError('new decision requires source-backed status/context/decision/consequences')
        initialize(db, [{'path': path, 'slug': slug, 'bytes': data, **{k: v for k, v in fields.items() if k != 'slug'}, 'provenance': provenance}])
        return
    with writer_lock(db), contextlib.closing(connect(db, write=True)) as con:
        con.execute('BEGIN IMMEDIATE')
        try:
            check_publication(con, db)
            current = con.execute('SELECT * FROM documents WHERE slug=?', (slug,)).fetchone()
            if current is not None and current['path'] == path and current['bytes'] == data:
                con.rollback()
                return
            if current is None:
                if expected != 0:
                    raise StoreError('unknown document or revision conflict')
                if con.execute('SELECT 1 FROM documents WHERE lower(path)=lower(?) OR lower(slug)=lower(?)', (path, slug)).fetchone():
                    raise StoreError('new document identity already exists')
                fields = metadata(body, path)
                if fields['type'] == 'decision' and decision_fields(body, fields['status'])['missing_fields']:
                    raise StoreError('new decision requires source-backed status/context/decision/consequences')
                add_document(con, path, slug, data, fields, provenance)
            else:
                if current['path'] != path or current['revision'] != expected:
                    raise StoreError('document identity or revision conflict')
                fields = metadata(body, path, dict(current))
                old_structure = decision_fields(current['body'], current['status'])
                if fields['type'] == 'decision' and not old_structure['missing_fields'] and decision_fields(body, fields['status'])['missing_fields']:
                    raise StoreError('edit would remove required decision structure')
                values = add_revision(con, current['id'], expected + 1, data, fields, provenance)
                cursor = con.execute('''UPDATE documents SET revision=:revision,type=:type,status=:status,
                    title=:title,body=:body,bytes=:bytes,sha256=:sha256,text_sha256=:text_sha256
                    WHERE id=:document_id AND revision=:expected''', {**values, 'expected': expected})
                if cursor.rowcount != 1:
                    raise StoreError('revision conflict')
            con.execute("UPDATE store_meta SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
            con.commit()
            publish(con, db)
        except Exception:
            con.rollback()
            raise

def validated_export(file: Path, checksum: Path) -> tuple[dict, list[dict], list[dict]]:
    """Validate every record and exact projection before creating any recovery target."""
    data = file.read_bytes()
    try:
        info = checksum_info(json.loads(checksum.read_bytes()))
        records = [json.loads(line) for line in data.splitlines()]
        if data != b'\n'.join(canonical(row) for row in records) + b'\n':
            raise StoreError('recovery JSONL is not canonical')
        header = records[0]
        if set(header) != {'kind', 'format', 'store_id', 'generation'} or header['kind'] != 'store' or type(header['format']) is not int or header['format'] != VERSION:
            raise StoreError('unsupported recovery header/format')
        if not isinstance(header['store_id'], str) or not header['store_id'] or type(header['generation']) is not int or header['generation'] < 1:
            raise StoreError('invalid recovery store metadata')
        if info['sha256'] != sha(data) or info['bytes'] != len(data) or info['store_id'] != header['store_id'] or info['generation'] != header['generation']:
            raise StoreError('recovery checksum metadata mismatch')
        documents = [row for row in records[1:] if row.get('kind') == 'document']
        revisions = [row for row in records[1:] if row.get('kind') == 'revision']
        if not documents or len(documents) + len(revisions) != len(records)-1:
            raise StoreError('invalid recovery record kinds')
        ids, paths, slugs = set(), set(), set()
        for row in documents:
            if set(row) != {'kind', 'id', 'slug', 'path', 'revision'}:
                raise StoreError('unsupported recovery document fields')
            for key in ('id', 'slug', 'path'):
                if not isinstance(row[key], str) or not row[key]:
                    raise StoreError('invalid recovery document identity')
                secret_guard(row[key], 'recovery identity')
            path = Path(row['path'])
            if path.is_absolute() or '..' in path.parts or '\\' in row['path'] or path.as_posix() != row['path']:
                raise StoreError('unsafe recovery source path')
            if type(row['revision']) is not int or row['revision'] < 1 or row['id'] in ids or row['path'].casefold() in paths or row['slug'].casefold() in slugs:
                raise StoreError('duplicate/invalid recovery identity or revision')
            ids.add(row['id']); paths.add(row['path'].casefold()); slugs.add(row['slug'].casefold())
        seen = set()
        for row in revisions:
            if set(row) != {'kind', 'document_id', 'revision', 'type', 'status', 'title', 'body', 'bytes_b64', 'sha256', 'text_sha256', 'provenance'}:
                raise StoreError('unsupported recovery revision fields')
            if not isinstance(row['document_id'], str) or row['document_id'] not in ids or type(row['revision']) is not int or row['revision'] < 1:
                raise StoreError('invalid recovery revision')
            identity = row['document_id'], row['revision']
            if identity in seen:
                raise StoreError('duplicate recovery revision')
            seen.add(identity)
            raw = base64.b64decode(row.pop('bytes_b64'), validate=True)
            if len(raw) > MAX_BYTES:
                raise StoreError('recovery document exceeds size bound')
            body = text_bytes(raw, 'recovery document')
            if row['body'] != body or row['sha256'] != sha(raw) or row['text_sha256'] != sha(body.encode('utf-8')):
                raise StoreError('recovery bytes/hash/projection mismatch')
            for key in ('type', 'status', 'title', 'provenance'):
                if not isinstance(row[key], str):
                    raise StoreError('invalid recovery metadata')
                secret_guard(row[key], 'recovery metadata')
            row['bytes'] = raw
        for row in documents:
            versions = sorted(revision['revision'] for revision in revisions if revision['document_id'] == row['id'])
            if len(versions) != row['revision'] or any(version != index for index, version in enumerate(versions, 1)):
                raise StoreError('recovery history incomplete')
        return header, documents, revisions
    except (ValueError, KeyError, TypeError, IndexError, UnicodeError, AttributeError):
        raise StoreError('invalid recovery structure; content withheld') from None


def recover(target: Path, file: Path, checksum: Path) -> None:
    header, documents, revisions = validated_export(file, checksum)
    with writer_lock(target):
        if target.exists() or any(path.exists() for path in exports(target)):
            raise StoreError('recovery target or recovery files already exist')
        temp = auxiliary(target.with_name(target.name + '.recovering'))
        with temp.open('xb'):
            pass
        con = sqlite3.connect(temp)
        con.row_factory = sqlite3.Row
        try:
            con.execute('PRAGMA foreign_keys=ON')
            con.executescript(SCHEMA)
            con.execute('BEGIN IMMEDIATE')
            con.executemany('INSERT INTO store_meta VALUES(?,?)', [('store_id', header['store_id']), ('generation', str(header['generation']))])
            for row in revisions:
                add_revision(con, row['document_id'], row['revision'], row['bytes'], row, row['provenance'])
            indexed = {(row['document_id'], row['revision']): row for row in revisions}
            for row in documents:
                values = indexed[(row['id'], row['revision'])]
                con.execute('''INSERT INTO documents VALUES(:id,:slug,:path,:revision,:type,:status,
                    :title,:body,:bytes,:sha256,:text_sha256)''', {**values, **row})
            con.commit()
            if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or con.execute('PRAGMA foreign_key_check').fetchone():
                raise StoreError('recovered database integrity failed')
        finally:
            con.close()
        try:
            auxiliary(target)
            os.link(temp, target)  # Atomic no-overwrite publication; unlike replace, refuses a race.
        finally:
            temp.unlink(missing_ok=True)
        with contextlib.closing(connect(target, write=True)) as con:
            publish(con, target)


def bounded(value: str) -> int:
    number = int(value)
    if not 1 <= number <= MAX_LIMIT:
        raise argparse.ArgumentTypeError('limit must be 1..100')
    return number


def output(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--db', default=str(DEFAULT_DB))
    subparsers = cli.add_subparsers(dest='command', required=True)
    for command in ('init', 'import', 'search', 'list', 'adr-audit', 'get', 'put', 'stats', 'reindex', 'export', 'integrity', 'backup', 'recover'):
        sub = subparsers.add_parser(command)
        sub.add_argument('--db', default=argparse.SUPPRESS)
        if command in ('init', 'import'):
            sub.add_argument('--manifest', required=True)
        if command in ('search', 'list', 'adr-audit'):
            if command == 'search':
                sub.add_argument('query')
            sub.add_argument('--limit', type=bounded, default=5 if command == 'search' else 50)
            sub.add_argument('--offset', type=int, default=0)
            sub.add_argument('--type')
            sub.add_argument('--status')
            sub.add_argument('--json', action='store_true')
        if command == 'get':
            selector = sub.add_mutually_exclusive_group(required=True)
            selector.add_argument('--slug')
            selector.add_argument('--path')
            sub.add_argument('--revision', type=int)
            sub.add_argument('--start', type=int, default=1)
            sub.add_argument('--lines', type=bounded)
            sub.add_argument('--raw', action='store_true', help='deliberately output exact original bytes')
        if command == 'put':
            sub.add_argument('--slug', required=True)
            sub.add_argument('--file', required=True)
            sub.add_argument('--expected-revision', type=int, required=True, help='0 creates new owned document; positive matches existing revision')
        if command in ('backup', 'recover'):
            sub.add_argument('--target', required=True)
        if command == 'recover':
            sub.add_argument('--export', required=True)
            sub.add_argument('--checksum', required=True)
    return cli


def main() -> int:
    args = build_parser().parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='strict', newline='')
    try:
        writes = {'init', 'import', 'put', 'export', 'reindex'}
        db = checked_path(args.db, owned=args.command in writes, mutation=args.command in writes)
        if args.command in ('init', 'import'):
            initialize(db, import_rows(checked_path(args.manifest, owned=False)))
        elif args.command == 'put':
            put(db, args.slug, checked_path(args.file, owned=False), args.expected_revision)
        elif args.command == 'recover':
            recover(checked_path(args.target, owned=False, mutation=True), checked_path(args.export, owned=False), checked_path(args.checksum, owned=False))
        elif args.command == 'backup':
            target = checked_path(args.target, owned=False, mutation=True)
            if target.exists():
                raise StoreError('backup target already exists')
            auxiliary(target.parent).mkdir(parents=True, exist_ok=True)
            with target.open('xb'):
                pass
            with contextlib.closing(connect(db)) as source, contextlib.closing(sqlite3.connect(target)) as dest:
                source.backup(dest)
                if dest.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise StoreError('backup integrity failed')
        elif args.command in ('export', 'reindex', 'integrity'):
            with writer_lock(db), contextlib.closing(connect(db, write=True)) as con:
                con.execute('BEGIN IMMEDIATE')
                check_publication(con, db, repair=args.command == 'export')
                if args.command == 'reindex':
                    con.execute("INSERT INTO documents_fts(documents_fts) VALUES('rebuild')")
                if args.command == 'integrity':
                    if con.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or con.execute('PRAGMA foreign_key_check').fetchone():
                        raise StoreError('database integrity failed')
                    con.execute("INSERT INTO documents_fts(documents_fts,rank) VALUES('integrity-check',1)")
                    for row in con.execute('SELECT * FROM revisions'):
                        validated_body(row)
                    validate_current(con)
                con.commit()
                if args.command == 'export':
                    publish(con, db)
        else:
            with contextlib.closing(connect(db)) as con:
                if args.command == 'stats':
                    output({'format': VERSION, 'generation': int(state(con)['generation']), 'documents': con.execute('SELECT count(*) FROM documents').fetchone()[0], 'revisions': con.execute('SELECT count(*) FROM revisions').fetchone()[0]})
                elif args.command == 'get':
                    field, value = ('slug', args.slug) if args.slug else ('path', args.path)
                    row = con.execute(f'SELECT * FROM documents WHERE {field}=?', (value,)).fetchone()
                    if row is None:
                        raise StoreError('unknown document')
                    if args.revision is not None:
                        row = con.execute('SELECT * FROM revisions WHERE document_id=? AND revision=?', (row['id'], args.revision)).fetchone()
                        if row is None:
                            raise StoreError('unknown revision')
                    body = validated_body(row)
                    if args.start < 1:
                        raise StoreError('start must be positive')
                    if args.raw:
                        if args.lines is not None or args.start != 1:
                            raise StoreError('raw retrieval cannot select lines')
                        sys.stdout.buffer.write(row['bytes'])
                    else:
                        if args.lines is not None:
                            body = ''.join(body.splitlines(keepends=True)[args.start-1:args.start-1+args.lines])
                        elif args.start != 1:
                            raise StoreError('start requires bounded lines')
                        print(body, end='')
                else:
                    if args.offset < 0:
                        raise StoreError('offset must be nonnegative')
                    conditions, params = [], []
                    for field in ('type', 'status'):
                        if getattr(args, field):
                            conditions.append(f'd.{field}=?'); params.append(getattr(args, field))
                    fields = 'd.slug,d.type,d.title,d.path,d.status,d.revision,d.sha256'
                    table, order = 'documents d', 'd.path'
                    if args.command == 'search':
                        words = list(dict.fromkeys(re.findall(r'[^\W_]+', args.query, re.UNICODE)))[:32]
                        if not words:
                            raise StoreError('query requires words')
                        conditions.append('documents_fts MATCH ?')
                        params.append(' OR '.join('"' + word + ('"*' if len(word)>2 else '"') for word in words))
                        fields += ",snippet(documents_fts,1,'[',']',' … ',24) snippet,bm25(documents_fts) score"
                        table += ' JOIN documents_fts ON d.rowid=documents_fts.rowid'
                        order = 'score,d.path'
                    if args.command == 'adr-audit':
                        fields += ',d.body'
                    where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
                    rows = [dict(row) for row in con.execute(f'SELECT {fields} FROM {table}{where} ORDER BY {order} LIMIT ? OFFSET ?', [*params, args.limit, args.offset])]
                    for row in rows:
                        for key in ('slug', 'path', 'title', 'snippet', 'body'):
                            if key in row:
                                secret_guard(row[key], 'stored output')
                        if args.command == 'adr-audit':
                            body = row.pop('body')
                            parts = re.split(r'(?m)^(?=#{1,6}\s+.*\bADR[- ]?\d+)', body)
                            markers = []
                            for part in parts:
                                heading = re.match(r'#{1,6}\s+([^\r\n]+)', part)
                                if heading and re.search(r'\bADR[- ]?\d+', heading.group(1)):
                                    fields = decision_fields(part)
                                    for key in ('context', 'decision', 'consequences'):
                                        fields[key] = fields[key][:2000]
                                    markers.append({'heading': heading.group(1), **fields})
                            if not markers and row['type'] == 'decision':
                                fields = decision_fields(body, row['status'])
                                for key in ('context', 'decision', 'consequences'):
                                    fields[key] = fields[key][:2000]
                                markers.append({'heading': row['title'], **fields})
                            row['adr_markers'] = markers
                    output(rows)
            return 0
        output({'operation': args.command, 'result': 'ok'})
        return 0
    except (StoreError, sqlite3.Error, OSError, ValueError, UnicodeError, TypeError) as error:
        # External library exceptions may contain unsafe source values: categories only.
        message = str(error) if isinstance(error, StoreError) else type(error).__name__
        print(f'error: {message}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
