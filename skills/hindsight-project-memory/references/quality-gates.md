# Quality gates

Treat load counts as ingestion evidence, not useful-memory evidence.

## Required gates

- **Manifest approval:** canonical root, stable IDs, source/staged hashes, provenance, classifications and exact batch count/bytes are reviewed before mutation. Build a run-local candidate against the canonical last-successful checkpoint and promote it only after verified success. Hindsight's stable-ID upsert provides deduplication; the checkpoint exists for delta efficiency and deletion proposals. Deleted/renamed sources remain proposals until explicitly approved.
- **Credential policy:** missing/`exclude` redacts or blocks as before. `allow_project_staging` requires `reviewed: true` and accepts credential bytes only when the candidate's canonical relative POSIX path is listed exactly in `source_policy.credential_sources`; all unselected candidates use `exclude`. Audit, summaries and diagnostics remain content-free; registry/manifest state stores policy/selector names, hashes and provenance but no credential payload.
- **Graphify:** graph projections are eligible only after the configured project audit is clean and the audited source hash/generator version match. The first subject capsule always keeps its stable base ID; only additional chunks use `:part-2`, `:part-3`, and so on. Compare the generated expected-ID inventory with the prior one and present stale IDs for explicit deletion approval. Graph capabilities remain optional and project-specific.
- **Operations:** `completed`, `failed` and `cancelled` are terminal. `pending`, `processing`, `queued`, timeout and uncertain acknowledgement are not completion. Poll with bounded backoff and reuse the approved operation ID.
- **Partial failure:** retain completed IDs, report failed/uncertain IDs without content, skip consolidation, and retry only the affected idempotent operations after inspection.
- **Consolidate and Knowledge Pages:** an acknowledgement is not success. The approved run binds action/bank/profile/manifest and, for pages, the canonical specs or exact page/mental-model IDs. Existing pages must match their reviewed query/tags/token budget/trigger fields and expose a non-empty inspected body. Record intended, acknowledged and terminal phases, poll each server operation ID with bounded deadlines, never resubmit on ambiguity, and require explicit page-body retrieval plus unsupported-synthesis inspection before readiness.
- **Benchmark:** critical cases are 100%, overall applicable factual coverage is at least 90%, and there are zero fabrication, project-mixing, provenance, temporal, web/mobile or credential-policy violations. An authorized staging value is not a policy violation; echoing it through an audit/summary/diagnostic or retaining it under `exclude` is.
- **Explicit approvals:** full export, deletion and project/bank remapping each require their own exact confirmation.

Diagnose empty Knowledge Pages by checking their metadata and tag scope before recreating anything. Use non-destructive inspection first, and include evidence and remaining gaps in any quality conclusion.
