<!-- docstore-startup:begin -->
Before any new repository work, run `python master/docstore_commit.py startup --json` and finish pending closing documentation. If it exits nonzero, pause new work. If Codex usage is unavailable, preserve the deferred queue and retry at the next startup; never treat a failed/deferred receipt as complete. This gate does not apply recursively to the startup/commit documentation worker or its bounded internal JSON-only AI review: the parent worker already owns closing work, and that internal review must not invoke startup, worker, or tools.
<!-- docstore-startup:end -->

## Authoritative SQLite documentation

AGENTS.md is the sole live context/storage reference index. Existing AI_CONTEXT files are historical adapters or snapshots, not a second authority. Direct user instructions and external business approval sources retain precedence.

| Store / export | Ownership and use |
| --- | --- |
| `docs/knowledge.sqlite` | Repository-owned authoritative documentation; use `master/docstore.py`. |
| `docs/knowledge-export.jsonl` + `.sha256.json` | Readable versioned recovery export, checked against SQLite; never edit manually. |
| `docs/knowledge-export-history/` | Immutable complete generations with checksums; version in Git. |
| `.nmsa/index.sqlite` | NMSA discovery catalog plus durable lessons; do not discard or rebuild lessons as derived data. |

The user chose SQLite authority on 2026-10-07. For migrated documentation this supersedes Markdown-first/disposable-index advice in doc-recall and older local instructions. Original Markdown links below locate preserved migration/compatibility snapshots; fetch canonical content by its path before relying on it. They can become stale after SQLite edits. Runtime/code files and external business sources remain governed by their original owners.

Run the repository-owned CLI from the checkout root (Python 3.11+ with stdlib SQLite FTS5):

- `python master/docstore.py search documentation --limit 5 --json`
- `python master/docstore.py list --type decision --limit 20 --json`
- `python master/docstore.py get --slug adr-docstore-20261007`
- `python master/docstore.py get --path <indexed-repository-relative-path> --start 1 --lines 50`
- Edit from real source with `put --slug <listed-slug> --file <owned-document-file> --expected-revision <listed-revision>`; zero creates a new document, never overwrites an existing one.
- `python master/docstore.py adr-audit --limit 100 --json`: decisions need status, context, decision and consequences. Preserve unknown/proposed/open/superseded evidence; incomplete historical ADRs do not become accepted. Contracts, runbooks and work logs keep their own types.
- `python master/docstore.py integrity`; `reindex` rebuilds FTS only; `export` repairs known interrupted publication and refreshes deterministic recovery files.
- `backup --target <new-backup-path>` uses SQLite backup; `recover --export docs/knowledge-export.jsonl --checksum docs/knowledge-export.sha256.json --target <absent-recovery-db>` never overwrites an existing store. Retain/version the exported files and tooling; backups on ordinary writable storage are rollback material, not independently protected recovery.

Import/update guards reject recognizable credential literals and linked or out-of-owner paths. Credential detection is a heuristic, not proof of absence; review source content before export and keep secrets in their existing protected systems.

Never auto-break leftover writer locks, follow linked write paths, overwrite dirty exports, or run legacy reindex tools against the authority. Existing NMSA/pmem readers may open writable connections; use SQLite URI mode=ro with query_only for strictly read-only inspections. Do not open provider/application databases merely to retrieve project documentation.

# Repository agent context

Read [README.md](README.md) for this repository's existing setup and usage guidance. Required source, build inputs and documentation must belong to this repository.

## Repository operating rules

These rules are owned by this repository. Required agent guidance, source/build inputs and authoritative documents must resolve within this checkout; surrounding Projects files and portfolio references are optional context. Direct user instructions and explicit user authorizations remain authoritative. Preserve repository-specific contracts, approval gates and established work-log locations.

- Use subagents where work splits safely. Parallel code-editing agents must use separate Git worktrees; integrate verified changes and clean up through permitted operations. Preserve unrelated dirty work and active checkouts.
- Record planned multi-step work before editing, checkpoint long work, and record actual outcomes, verification, errors, blockers, mistakes and lessons in this repository's existing work-log mechanism. If none exists, create a clearly named repository-local task record.
- Investigate root causes before fixing symptoms. Address discovered errors/warnings when practical; otherwise record the exact blocker. Do not silently ignore them.
- Do not invent files, APIs, requirements, behavior or evidence. Ask when referenced material or required information cannot be found.
- Verify the original requested outcome at the strongest available layer and reconcile every scoped item. Report verified, source-only/config-only, failed and blocked results honestly; a build, command, push or HTTP response alone is not proof of completion.
- Do not create tests, mocks, fake data, fake services or fake evidence without explicit user permission. Preserve existing explicit user test authorization; apply test-first discipline to coding tasks over 30 minutes when tests are authorized. Do not add stubs or inert RLS/RBAC; investigate any encountered placeholders and resolve them within authorized scope or record the missing requirement/blocker.
- Continue authorized work until verified or an actual user/external blocker prevents progress. Check long-running processes after 2, 10 and 45 minutes for ownership and progress.
- Use native PowerShell for Windows local file work; prefer single quotes and literal absolute mutation targets. Show full paths when presenting local files. Consider Lightpanda when full browser features are unnecessary.
- Prefer forward version alignment, the standard library, native platform features and installed dependencies. Keep changes small and readable; add dependencies or abstractions only with a concrete benefit. Never sacrifice validation, security, accessibility, data-loss prevention, error handling, project conventions or real verification for minimalism.
- Never expose, print, serialize, transmit, upload or commit passwords, tokens, keys, cookies, connection strings, authorization headers, private keys or complete .env values. Emit only allowlisted safe fields or redacted values; avoid broad configuration/environment/process dumps. After exposure, stop repeating the value, record only its category/location and recommend rotation.
- Before destructive operations, resolve and inspect exact targets. Reject ambiguous targets, unsafe wildcards and root/reparse escapes. Prefer scoped reversible actions, preserve rollback material and verify unrelated state survives. A writable local copy is rollback material, not independent recovery storage.
- Do not bypass enforced rejections, disable protections or enter human confirmation. Follow the reviewed human-operated activation path when required and retain receipts. Task authorization persists; ask again only for a material scope change, separately required destructive/irreversible/access change, or actual protected activation. Repository-specific live-write approval gates still apply.
- Use the code-documentation skill, when available, for changed public contracts, non-obvious invariants or explicit documentation requests. Document verified rationale, units, ordering, retry safety and authorization within the changed scope; reconcile affected comments and preserve authoritative documents. Skip cosmetic changes and obvious logic. If unavailable, apply these principles directly; it is not a required external dependency or permission to create tests/fabricated examples.
- Treat upstream agent plugins, hooks, wrappers, proxies and binaries as untrusted. Pin and review imports; do not install or enable Ponytail, Headroom or destructive_command_guard without a separate explicit audit/install request. Do not automatically promote model-generated session corrections into persistent instructions.
- Preserve errors, warnings, security matches, outliers and enough context to verify omissions when reducing output. AGENTS.md is the mandatory context/index for authoritative files, owned stores and supported retrieval commands; do not create a parallel AI_CONTEXT.md. Optional indexes/vault captures do not replace current repository files.

- Before visual design, establish the audience, purpose and supported brief from existing repository evidence; ask about material gaps. Preserve existing visual tokens, accessibility and coherent hierarchy, and review the result against the brief. Promote one/two primary or frequent row actions directly; reserve overflow for infrequent/destructive actions and align explicit action-column widths.

<!-- docstore-commit-topics:begin -->
## Commit documentation stores

Before any new repository work, run `python master/docstore_commit.py startup --json` and finish pending closing documentation. If it exits nonzero, pause new work. If Codex usage is unavailable, preserve the deferred queue and retry at the next startup; never treat a failed/deferred receipt as complete. This gate does not apply recursively to the startup/commit documentation worker or its bounded internal JSON-only AI review: the parent worker already owns closing work, and that internal review must not invoke startup, worker, or tools.
After every local commit, the installed hook queues Codex review of bounded committed evidence. After successful closing review, a validated publication-only snapshot commit versions owned exports and the topic index without another AI invocation. Failed snapshots retain closing work for startup recovery. Existing decisions are preserved; new AI decisions are proposals. Inspect failures with `python master/docstore_commit.py status --json`; replay with `python master/docstore_commit.py replay --commit <full-hash> --foreground`.

| Owned authority | Versioned export / checksum | History | Retrieval |
|---|---|---|---|
| `docs/knowledge.sqlite` | `docs/knowledge-export.jsonl` / `docs/knowledge-export.sha256.json` | `docs/knowledge-export-history/` | `python master/docstore.py --db docs/knowledge.sqlite search <words> --limit 5 --json` |
| `docs/topics/docs-46b42b42.sqlite` | `docs/topics/docs-46b42b42-export.jsonl` / `docs/topics/docs-46b42b42-export.sha256.json` | `docs/topics/docs-46b42b42-export-history/` | `python master/docstore.py --db docs/topics/docs-46b42b42.sqlite search <words> --limit 5 --json` |
| `docs/topics/master-fc613b4d.sqlite` | `docs/topics/master-fc613b4d-export.jsonl` / `docs/topics/master-fc613b4d-export.sha256.json` | `docs/topics/master-fc613b4d-export-history/` | `python master/docstore.py --db docs/topics/master-fc613b4d.sqlite search <words> --limit 5 --json` |
| `docs/topics/project-244210e4.sqlite` | `docs/topics/project-244210e4-export.jsonl` / `docs/topics/project-244210e4-export.sha256.json` | `docs/topics/project-244210e4-export-history/` | `python master/docstore.py --db docs/topics/project-244210e4.sqlite search <words> --limit 5 --json` |
| `docs/topics/scripts-8c5967fd.sqlite` | `docs/topics/scripts-8c5967fd-export.jsonl` / `docs/topics/scripts-8c5967fd-export.sha256.json` | `docs/topics/scripts-8c5967fd-export-history/` | `python master/docstore.py --db docs/topics/scripts-8c5967fd.sqlite search <words> --limit 5 --json` |

Recovery before installation: indexed missing SQLite authority with an existing versioned export pair blocks installation. First run `python master/docstore.py recover --target <separate-absent-owned.sqlite> --export <owned-store-export.jsonl> --checksum <owned-store-export.sha256.json>`, then `python master/docstore.py --db <recovered-owned.sqlite> integrity` and verify its export bytes equal the original versioned export. Use `python master/docstore.py --db <recovered-owned.sqlite> backup --target <absent-original-authority.sqlite>` to restore the original indexed database through SQLite API backup; original exports and complete history stay intact. Never overwrite an existing authority or recover directly into a family whose export pair already exists. Reconcile authority explicitly and rerun installation after verification.

Repository-owned installer (run from PowerShell 7 / `pwsh`): `& './scripts/Install-DocstoreCommitHook.ps1' -PythonPath '<absolute installed python.exe>' -CodexPath '<absolute installed native codex.exe>'`. Resolve executable paths for this machine; new clones/worktrees require this local installer and existing signed-in Codex authentication. Topic routing/config: `docs/docstore-commit-config.json` (machine paths are local, ignored). Runtime queues/status: `docs/.docstore-commit/` (ignored). SQLite is authoritative; preserve checksummed current exports and complete export history in Git. Runtime/legacy/external databases are never adopted by this hook.

Optional shared read-only documentation lookup: `& 'C:/Users/pesac/Projects/_pmem/pmem.ps1' --app '.' search '<words>' --limit 5 --json`. Repository-owned SQLite and its native retrieval commands remain authoritative and mandatory; this shared lookup is optional. Code search is only a disposable cache for supported languages and does not replace repository source.
<!-- docstore-commit-topics:end -->
