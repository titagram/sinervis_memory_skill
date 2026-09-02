---
name: hindsight-project-memory
description: Use when a user wants shared Hindsight knowledge for a project, asks an agent to remember or retrieve project information, exports a wiki or logbook, registers a new project bank, refreshes derived graph knowledge, or audits memory provenance and quality.
---

# Hindsight Project Memory

Use shared Hindsight knowledge only within the confirmed project boundary. Keep project knowledge attributable, source-backed, and separate from unrelated products.

## Hard gates

- Resolve the active operator first. If it is absent, ask the user before preparing any mutation.
- Resolve the registered project boundary and bank. Keep an unregistered or uncertain project isolated and route it through onboarding; never mix it into another project's bank.
- Classify every candidate, run its project-policy preflight, and bind provenance before presenting a write. Then show operator, project, bank, action, affected count, and whether credential-bearing records are included; obtain confirmation for that exact summary without displaying their values.
- Every mutation plan must name its content-free lifecycle audit slots: intent before execution, acknowledgement when the server accepts asynchronous work, and completion/terminal after bounded polling. Knowledge Page success additionally requires explicit body retrieval and inspection.

## Packaged helper

Run the project-neutral [CLI entrypoint](scripts/project_memory.py) when its deterministic commands fit the task. Installers and bundlers must retain its complete package: [package marker](scripts/project_memory/__init__.py), [audit](scripts/project_memory/audit.py), [graph capsules](scripts/project_memory/graph_capsules.py), [manifest](scripts/project_memory/manifest.py), [redaction](scripts/project_memory/redaction.py), [registry](scripts/project_memory/registry.py), and [transport](scripts/project_memory/transport.py).

## Route by task

- For retrieval, read [the reading protocol](references/reading-protocol.md) before relying on memory in an answer.
- For retention, export, refresh, replacement, retry, or any other mutation, read [the writing protocol](references/writing-protocol.md) before preparing a write.
- For an unknown workspace or a project not yet registered, read [new-project onboarding](references/new-project-onboarding.md) and fail closed on an uncertain project boundary.
- For registration, bank reuse, or reviewed profile enrichment, read [project registration](references/project-registration.md).
- For document IDs, tags, metadata, operator attribution, shared observation scope, manifests, graph inventories, or Knowledge Page specs, read [the retained-document schema](references/knowledge-schema.md).
- For Graphify-derived material, verification, release readiness, or quality/audit requests, read [the quality gates](references/quality-gates.md).
