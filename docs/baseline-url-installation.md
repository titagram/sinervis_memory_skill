# URL-only installation baseline

These evaluations were run before the repository contained installation or
packaging guidance. The evaluators were not allowed to inspect the existing
local project-memory skill.

## Codex

The evaluator correctly chose read-only GitHub discovery, but required prior
knowledge of Codex's internal installer path and invented a multi-command API
workflow. Its stated uncertainty was: “l'URL non specifica branch,
sottocartella né nome della skill”. It could not derive a single install command
from the repository URL alone.

## Claude Code

The evaluator chose clone, recursive `SKILL.md` discovery, validation, and a
copy to `~/.claude/skills/<nome-skill>/`. It explicitly assumed a personal
installation and would stop for multiple candidates. This is a safe fallback,
but it did not know whether a native URL-based installer was available.

## Hermes Agent

The evaluator correctly refused to execute an uninspected package, but proposed
several speculative commands, including `hermes skills install <local-path>` and
`hermes skills install <github-url>`. Its stated uncertainty included “supporto
a repository privati/path locali” and the actual skill package path. It missed
Hermes's documented GitHub-source form and tap layout.

## Required correction

The repository must make `skills/hindsight-project-memory/SKILL.md` discoverable
and publish exact runtime-native commands. The safe clone-and-copy approach stays
documented as a generic fallback. No custom installer is warranted.

## Forward-test result

After packaging and documentation:

- Codex and Claude converged on the explicit `npx skills add` commands and the
  standard personal directories. Review found and closed ambiguous agent/scope
  selection, unsafe destination merging, authentication variants, temporary
  checkout cleanup, `CODEX_HOME`, and missing post-copy verification.
- Hermes converged on the documented GitHub-source and tap identifiers. Review
  found and closed a potential downloader ambiguity by linking the CLI entrypoint
  and every imported runtime module directly from `SKILL.md`. A live private-repo
  install then exposed credential-shaped test canaries to Hermes' regex scanner;
  `.skillignore` now excludes only `tests/`, while all runtime files remain in
  scope. The resulting community-source verdict is `safe`, and native install
  completed without `--force`.
- The final independent rechecks reported no remaining blocking or important
  installation defects for Codex, Claude, or Hermes.

Live URL tests also confirmed that `npx skills add` cloned the private repository
and installed the complete package for both Codex and Claude Code, while Hermes
installed 24 packaged files and recorded a safe-verdict audit entry.
