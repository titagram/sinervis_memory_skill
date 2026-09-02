# Hindsight Project Memory

Portable Agent Skills package for sharing project knowledge through a
self-hosted Hindsight instance. It keeps each product in its own bank, records
the active operator, preserves source provenance, and supports controlled
retrieval and ingestion from wikis, logbooks, code-derived graphs, and curated
dossiers.

The installable skill is
[`skills/hindsight-project-memory/SKILL.md`](skills/hindsight-project-memory/SKILL.md).
The repository contains no Hindsight endpoint, token, operator profile, project
registration, bank content, or retained credentials.

## If an agent receives only this URL

Give the agent this repository URL:

```text
https://github.com/titagram/sinervis_memory_skill.git
```

On a machine already authorized for the private repository, the agent should:

1. inspect or clone the repository using the existing GitHub authentication;
2. discover `skills/*/SKILL.md` and select `hindsight-project-memory` when it is
   the only matching package;
3. inspect `SKILL.md` and its referenced files before executing bundled scripts;
4. install the complete `skills/hindsight-project-memory/` directory with the
   runtime's native skill installer or standard skill directory;
5. verify that the installed `SKILL.md`, `references/`, and `scripts/` exist.

Do not put a personal access token in the URL. Existing SSH, Git credential
helper, GitHub CLI, or runtime-specific authentication should supply access.

## Codex and compatible skills CLI

```bash
npx skills add https://github.com/titagram/sinervis_memory_skill.git \
  --global --agent codex --skill hindsight-project-memory --copy
```

Omit `--global` only when a project-local installation is intended. The command
keeps confirmation enabled so an existing installation is not replaced without
review. The CLI uses the standard Codex location; with a custom `CODEX_HOME`, or
without Node.js, use the manual authenticated fallback below. Restart an agent
that does not rescan its skills directory live.

## Claude Code

Use the compatible skills CLI with an explicit runtime and personal scope:

```bash
npx skills add https://github.com/titagram/sinervis_memory_skill.git \
  --global --agent claude-code --skill hindsight-project-memory --copy
```

For project-only use, omit `--global`, or copy the complete directory to
`.claude/skills/hindsight-project-memory/` in that project's repository.

## Manual authenticated fallback for Codex or Claude

Use this when Node.js or the skills CLI is unavailable. Select exactly one
`agent_skills_parent`: `${CODEX_HOME:-$HOME/.codex}/skills` for Codex or
`$HOME/.claude/skills` for Claude Code. The final destinations are
`~/.codex/skills/hindsight-project-memory` and
`~/.claude/skills/hindsight-project-memory`, respectively.

```bash
(
set -e
agent_skills_parent="${CODEX_HOME:-$HOME/.codex}/skills" # use "$HOME/.claude/skills" for Claude Code
skill_checkout="$(mktemp -d)" || exit 1
cleanup_skill_checkout() {
  rm -rf -- "$skill_checkout"
}
trap cleanup_skill_checkout EXIT
gh repo clone titagram/sinervis_memory_skill "$skill_checkout/repository" -- --depth 1
mkdir -p "$agent_skills_parent"
skill_destination="$agent_skills_parent/hindsight-project-memory"
if test -e "$skill_destination"; then
  echo "destination already exists: $skill_destination" >&2
  exit 1
fi
cp -R "$skill_checkout/repository/skills/hindsight-project-memory" "$skill_destination"
test -f "$skill_destination/SKILL.md"
test -d "$skill_destination/references"
test -d "$skill_destination/scripts"
)
```

If authentication is available through Git's HTTPS credential helper rather
than GitHub CLI, replace the `gh repo clone` line with:

```bash
git clone --depth 1 https://github.com/titagram/sinervis_memory_skill.git "$skill_checkout/repository"
```

For Git SSH authentication, use instead:

```bash
git clone --depth 1 git@github.com:titagram/sinervis_memory_skill.git "$skill_checkout/repository"
```

## Hermes Agent

Hermes understands this repository as a GitHub skill source or tap because the
package lives below `skills/`:

```bash
GITHUB_TOKEN="$(gh auth token --hostname github.com)" \
  hermes skills inspect titagram/sinervis_memory_skill/skills/hindsight-project-memory
GITHUB_TOKEN="$(gh auth token --hostname github.com)" \
  hermes skills install titagram/sinervis_memory_skill/skills/hindsight-project-memory
```

For team-wide discovery and updates:

```bash
GITHUB_TOKEN="$(gh auth token --hostname github.com)" \
  hermes skills tap add titagram/sinervis_memory_skill
GITHUB_TOKEN="$(gh auth token --hostname github.com)" \
  hermes skills install titagram/sinervis_memory_skill/hindsight-project-memory
```

Hermes uses the GitHub API for private sources, so a computer authenticated only
through Git's credential helper may still need `GITHUB_TOKEN` exported from its
existing credential manager. Never commit that value.

## Generic Agent Skills fallback

An Agent Skills-compatible runtime can install the directory containing
`skills/hindsight-project-memory/SKILL.md` intact. Common personal locations are
`~/.agents/skills/hindsight-project-memory/`,
`~/.claude/skills/hindsight-project-memory/`, and
`~/.hermes/skills/hindsight-project-memory/`.

Do not copy only `SKILL.md`: its relative references and Python helpers are part
of the package.

## First use

The skill resolves the active operator before any memory mutation. If no
operator is registered, it asks for the user's nickname and persists it in local
project-memory state. New products receive a separate proposed Hindsight bank;
additional repositories share a bank only after their relationship to the same
product is explicitly confirmed.

Hindsight connection data remains machine-local. Pass the local configuration
path required by the skill's commands or adapt it to the runtime integration;
never add configuration containing tokens to this repository.

## Validation

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s skills/hindsight-project-memory/tests -v
```

The implementation uses only the Python standard library.
