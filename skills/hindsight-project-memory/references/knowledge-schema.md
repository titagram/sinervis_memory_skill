# Project-memory retained-document schema

Every retained record has one stable `document_id`. Re-running an export updates that ID; it never creates a duplicate document. Source IDs use `kb:<project_slug>:source:<scope>:<relative-path>`. Event IDs use `kb:<project_slug>:event:<scope>:<YYYY-MM-DDTHH-MM>:<stable-heading-slug>`. A corrected event keeps the same timestamp and heading slug, so it replaces the existing ID; an appended heading creates a new ID.

Required tags use non-reserved namespaces only:

```text
user:<active-operator>
project:<project_slug>
kind:source | kind:event | kind:graph_projection | kind:dossier
scope:workspace | scope:webapp | scope:mobile | scope:wiki | scope:runtime
trust:verified | trust:derived | trust:inferred | trust:needs_verification
topic:<controlled-topic>
knowledge:component | knowledge:concept | knowledge:convention | knowledge:decision | knowledge:initiative | knowledge:risk
```

Do not use connector-reserved `source:` or `harness:` namespaces. `knowledge:*` labels are for durable reusable facts; routine events normally remain unlabelled by the remote extraction layer even when the local manifest carries the configured knowledge layer.

Every source, event, graph projection and dossier retain item sets the official top-level request field `observation_scopes` to the string `"shared"`. This project-wide observation setting is separate from the descriptive `scope:*` tag.

The values above are the current project profile vocabulary, not a transport
allowlist: a reviewed project may add non-reserved trust, knowledge, topic or
relation metadata when it preserves the singleton identity/provenance tags.

All metadata values are strings. Each source record supplies `operator`, `project_slug`, `source_path` (or `source_paths`), `source_sha256`, `source_modified_at`, `exported_at`, `export_run_id`, `knowledge_layer`, `verification_status`, and the effective `credential_policy` name. Derived records also supply `generator` and `generator_version`. The active operator is resolved from registry state at build time; each eligible entry contains exactly one matching `user:<active-operator>` tag and identical metadata attribution. Placeholder or stale attribution is rejected at build and again at submission. A redacted export additionally records `exported_sha256`; the source hash remains the hash of the untouched source bytes. Timeless references have no event timestamp. Logbook and decision records use their Europe/Rome-aware ISO event timestamp.

### Multi-source dossier provenance

A graph projection has one canonical `source_path` and its actual-byte
`source_sha256`. A dossier may instead aggregate two or more sources. For that
case it uses string-valued metadata only:

```text
source_paths: JSON array of canonical relative POSIX paths, in evidence order
evidence: JSON array of {"source_path":"...","source_sha256":"..."} objects
source_sha256: SHA-256 of canonical evidence JSON (UTF-8, sorted keys, compact separators)
```

`source_paths` and `evidence` must have the same unique ordered paths. Every
evidence path is checked as a non-symlink regular source strictly below the
registered project root, and every evidence hash is checked against its bytes.
The aggregate hash binds both the order and individual hashes. A multi-source
dossier omits singular `source_path`; a singular graph/dossier omits
`source_paths` and `evidence`. This representation leaves other safe string
metadata, topics, trust labels and knowledge labels extensible.

The four retained-document layers are source, event, graph projection, and dossier, identified by the corresponding `kind:*` tag. Trust is explicit: current recommended meanings are `verified` for direct checked sources, `derived` for deterministic audited projections, `inferred` for conclusions not directly established by an authoritative source, and `needs_verification` for unresolved claims. Current recommended knowledge labels are `component`, `concept`, `convention`, `decision`, `initiative`, and `risk`. These examples are not exhaustive; reviewed projects may use other syntactically safe values, which must still agree exactly with metadata and must never be inferred silently from an event.

## Examples

Example wiki source:

```text
document_id: kb:acme-portal:source:wiki:01-dipendenti/dipendenti.md
tags: user:alice, project:acme-portal, kind:source, scope:wiki, trust:verified, knowledge:concept
metadata: operator="alice", project_slug="acme-portal", source_path="wiki/01-dipendenti/dipendenti.md", source_sha256="<sha256>", knowledge_layer="concept", verification_status="verified"
event_timestamp: unset
observation_scopes: "shared"
```

Neutral project event:

```text
document_id: kb:sample-project:event:project-logbook:2026-09-01T15-50:export-calendario
tags: user:alice, project:sample-project, kind:event, scope:project-logbook, trust:verified, knowledge:initiative
metadata: operator="alice", project_slug="sample-project", source_path="LOGBOOK.md", source_sha256="<event-sha256>", knowledge_layer="initiative", verification_status="verified"
event_timestamp: 2026-09-01T15:50:00+02:00
observation_scopes: "shared"
```

## Credential policy, sensitive-data boundary and refresh

Every project has exactly one effective credential policy:

- `exclude` is the default for absent/unconfigured/new profiles and preserves credential redaction or blocking;
- `allow_project_staging` retains credential-bearing text verbatim only with `reviewed: true` and when the regular in-root source's canonical relative POSIX path is listed exactly in `source_policy.credential_sources`. Every unselected source uses `exclude`. This covers staging passwords, API keys/tokens, certificates and private-key material.

The opt-in changes credential treatment only. It never authorizes automatic crawling, out-of-root paths, symlink escapes, binaries, database dumps, uploads, customer/payroll/medical data, dependency/build caches or global Hindsight configuration. Registry/profile state may store the policy name and selected source paths; manifest metadata stores the effective per-source policy, hashes and provenance. None stores credential values. Audit, command summaries and transport diagnostics remain content-free and sanitize complete certificate/private-key blocks as well as token-shaped echoes. Tags remain identifiers rather than a credential transport.

The local preflight classifies candidates as `include`, `include_redacted`, `exclude`, `blocked_review`, or `derived_after_audit`. Eligible verbatim, safe and redacted text can be retained. A redacted staging copy contains only the exported text under the explicit staging root; an allowed credential-bearing source is read from its hash-bound source path and is not copied into staging. The original source is never modified. Deterministic exclusions and blocked-review candidates are not staged. Derived candidates remain recorded but ineligible until their external audit gate is satisfied.

Incremental refresh compares a run-local candidate with the canonical last-successful manifest. Unchanged documents are skipped for efficiency; changed documents use Hindsight's native same-`document_id` replace/upsert. The candidate becomes the canonical checkpoint only after verified export success, so a dry run or interruption cannot turn unsent content into a later false no-op. Deleted or renamed candidates are reported for explicit removal approval only—an export never clears a bank or deletes a retained record silently.

## Persistent manifest and event handoff

Eligible source and event tags include validated `user:<operator>` and `project:<project_slug>` values, plus any profile-provided validated `topic:<controlled-topic>` values. Reserved `source:` and `harness:` tag namespaces remain forbidden.

The manifest builder requires the active operator explicitly; the CLI obtains it from the selected registry and never falls back to `unknown`. The persistent manifest contains source and event entries only. Audited graph capsules and source-backed dossiers use the separately approved derived-batch channel with `kind:graph_projection` and `kind:dossier`.

The persistent manifest is canonical JSON containing only policy names, safe metadata, hashes, tags, reasons, classifications, and staging locators—never source content or matched credential values. It includes `manifest_sha256`; readers reject malformed or hash-tampered payloads. The builder writes a run-local candidate; promotion to the persistent last-successful path is a separate post-success checkpoint. `exported_at` and `export_run_id` are bound later by Task 7.

Configured event paths require a private staging root. Each parsed heading is staged as one exact, hash-checkable event chunk exposed through `export_path`; the whole logbook is never staged. A correction retains the earlier event ID only if the previous source path and Europe/Rome timestamp identify exactly one event. Unique same-hash source moves are labelled `renamed` with `renamed_from`; ambiguous rename or correction candidates remain fail-closed for explicit review.

Before any staging write, the manifest builder validates all IDs, event identities, collision-proof source-aware export paths, and the final canonical manifest. Redacted text without a staging root is `blocked_review`, not eligible. `validate_manifest_files(manifest, source_root, staging_root)` is the explicit Task 7 handoff check: it rejects escaping/symlink paths, missing or tampered source/staged bytes, and any locator or ID on an ineligible entry.

An appended event uses its timestamp and heading slug for a new ID. If a heading is corrected, the previous ID (including its original slug) is retained only when that source path and timestamp resolve uniquely; the staging locator is therefore stable too.

`topic:*` tags are repeatable controlled tags. The singleton namespaces `user`, `project`, `kind`, `scope`, `trust`, and `knowledge` are each present exactly once and agree with the immutable core metadata: operator, project slug, source path/hash, knowledge layer, verification status, and timestamps. Extra benign string metadata remains permitted.

Exact duplicate tags are rejected. Other non-reserved namespaces may repeat with distinct valid values. Staging and every staged locator are checked for lexical symlink ancestors before validation reads their bytes.

## Graph capsule identity and stale proposals

Each graph subject has one stable base ID `kb:<project_slug>:graph:<projection_slug>:<subject-slug-and-hash>`. The first capsule keeps that base ID whether the subject has one chunk or many; only later chunks use `:part-2`, `:part-3`, and so on. Generation writes a sorted `expected_document_ids` inventory and compares it with the previous inventory to expose sorted `stale_document_ids`. The stale-ID policy is `explicit_deletion_approval_required`; generation never deletes a retained document.

## Knowledge Page operation targets

Profiles that enable Knowledge Pages contain a non-empty ordered list of canonical specs: `name`, `source_query`, and optional `parent_id`, `tags`, `max_tokens`, and `trigger`. An approved ensure target binds those exact specs plus action, bank, registered-profile hash and manifest hash. Existing same-name pages are accepted only after the official page and backing mental-model reads prove the reviewed fields match and the page body is non-empty; drift is reported rather than duplicated. A refresh target additionally binds the exact page and mental-model IDs. Acknowledgement, terminal polling and explicit page-body inspection are separate lifecycle stages, and page content is never copied into audit records.
