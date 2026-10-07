---
type: decision
status: accepted
slug: adr-docstore-20261007
title: Authoritative SQLite documentation and recovery
---
# ADR: Authoritative SQLite documentation and recovery

## Status
Accepted by direct user instruction on 2026-10-07. This approves the documentation workflow, not historical product proposals.

## Context
This repository has 27 selected owned Markdown documents. Existing searchable indexes do not provide authoritative revision-controlled document editing and portable recovery. The user requested SQLite authority, versioned exports, ADR decisions, and AGENTS.md as the sole live reference index.

## Decision
Use docs/knowledge.sqlite as the canonical store for the explicitly imported documentation corpus, through the repository-owned master/docstore.py CLI. AGENTS.md remains the editable instruction entry point and storage/reference index. Code, app, provider, and NMSA lesson databases retain their owners and semantics. Original files and proposal statuses are preserved; external business authorities and approval gates are unchanged.

Read canonical knowledge through bounded search/get/list. Write with put and an expected revision; revision zero creates a genuinely new owned record. New decisions require status, context, decision, and consequences. Missing historical rationale stays unknown rather than fabricated. Reindex rebuilds full-text search only.

## Consequences
The SQLite file must be retained or reconstructed from deterministic readable knowledge-export.jsonl and its checksum manifest. Export history preserves generations; SQLite API backups and absent-target recovery provide additional rollback material. A copy on ordinary writable storage is not an independent protected recovery layer.

Original Markdown is retained as migration evidence and compatibility snapshots and can become stale after canonical edits. It must not silently overwrite the database. Version the exports and tooling in repository Git; do not commit live SQLite, lock, or pending files. Interrupted publication requires explicit repair of a known snapshot; no automatic lock deletion or dirty-export overwrite.

## Alternatives
The previous disposable Markdown index was reviewed but superseded by the explicit user choice of SQLite authority. Existing code indexes and durable lesson stores remain separate rather than being relabeled or destructively replaced.
