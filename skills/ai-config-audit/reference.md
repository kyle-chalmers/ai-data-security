# ai-config-audit reference

## What is auditable from disk, and what is not

| Concern | Locally auditable? | Check |
|---|---|---|
| Secret-file deny rules | Yes — `.claude/settings.json` / `.claude/settings.local.json` | AC-01 |
| Over-broad allow rules | Yes — same files | AC-02 |
| Credentials in MCP configs | Yes — config files below | AC-03 |
| Gemini `trust: true` | Yes — `.gemini/settings.json` | AC-04 |
| Plaintext transcripts | Yes — `~/.claude/projects/` | AC-05 |
| Consumer training/retention tier | **No** — account setting at claude.ai | AC-06 (always UNKNOWN) |
| Bash sandbox posture | Yes — `sandbox.enabled` and `sandbox.filesystem.disabled` in `~/.claude/settings.json` (or the project's `settings.local.json`, where the `/sandbox` panel writes it). MEDIUM when isolation is off; INFO when on without `failIfUnavailable` | AC-07 |
| Capability composition | Yes — warehouse-shaped MCP servers × remote MCP / network allow rules. INFO inventory only; not a prompt-injection detector | AC-08 |
| MCP server provenance | Yes — `npx` / `uvx` / `bunx` / `pipx run` / `pnpm dlx` without an exact pin (`pkg@x.y.z` or `pkg==x.y.z`), `@latest`, git/URL sources without a full commit SHA | AC-09 |
| Write-capable warehouse MCP | Yes, from the server's own config — Snowflake `sql_statement_permissions` (YAML named by `--service-config-file`; `Unknown: True` counts as write-capable because it passes unmapped statements), Postgres MCP Pro `--access-mode` (a remote/URL server → **UNKNOWN**, the mode lives server-side), Toolbox `tools.yaml` statements (leading comments stripped; data-modifying CTEs count as writes; a statement the matcher cannot place → **UNKNOWN**); Databricks MCP has no control (INFO). Config not found or unparseable → **UNKNOWN** | AC-10 |
| Local sensitive sinks | Yes — `~/.duckdb/stored_secrets/*`, credential-shaped keys with literal values in `~/.snowflake/connections.toml`, `~/.snowflake/config.toml`, `~/.databrickscfg`, `~/.dbt/profiles.yml`, `~/.aws/credentials`, `~/.pgpass`; shell history files with no `*_history` deny rule | AC-11 |

## MCP config path matrix (scanned by permeval.py)

| Tool | Project scope | User scope |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (`mcpServers` key) |
| Claude Desktop | — | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Gemini CLI | `.gemini/settings.json` | `~/.gemini/settings.json` |
| Codex | — | `~/.codex/config.toml` (`[mcp_servers.*]` tables) + `~/.codex/auth.json` |
| VS Code / Copilot | `.vscode/mcp.json` (`servers` key; `headers` scanned for credential-shaped keys incl. `Authorization`) | — |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` |
| Cline | — | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Roo Code | — | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` |
| Continue | `.continue/mcpServers/*.yaml` / `*.json` (one file per server; `mcpServers` is a list) | `~/.continue/config.yaml`, `~/.continue/mcpServers/*`, legacy `~/.continue/config.json` |
| GitHub Copilot CLI | — | `~/.copilot/mcp-config.json` |
| OpenCode | `opencode.json` (`mcp.servers`, falling back to a flat `mcp` map for older configs; `command` may be a list) | `~/.config/opencode/opencode.json` |

Paths for the v0.5 tools are the locations each tool documented as of 2026-09 (macOS paths for
the VS Code-extension tools). A tool that moves its config produces no finding rather than a
wrong one; add the new path here and to `permeval.py` together.

YAML configs (Continue, Snowflake service config, Toolbox tools) are read by a shared stdlib
YAML-subset reader (`scripts/yaml_subset.py`). Anything it does not support (anchors, aliases,
tags, nested flow collections, multi-document files) makes that file an **UNKNOWN**, never a
guess.

## Why AC-10 reads the server's config, not the warehouse

Warehouse MCP servers run with whatever identity they are given; the warehouse audit
(`db-access-audit`) is the authority on that identity's grants. AC-10 asks the narrower, static
question: does the server's own configuration allow writes at all? Only Postgres MCP Pro has a
named switch (`--access-mode=restricted`). Snowflake-Labs/mcp uses a per-statement-type list in a
YAML passed with `--service-config-file` (no fixed path, so the check follows the argument), and
Toolbox's capability is exactly the SQL in each `tools.yaml` tool. Databricks Labs' server has no
write control, so AC-10 reports INFO and defers to DB-01. A config that cannot be found or parsed
is an AC-10 UNKNOWN: "we could not see the switch" is never "the switch is off".

Codex TOML is parsed with `tomllib` on Python ≥3.11, else a line-based approximation that reads
key names only.

## Retention facts (verified against live Claude Code docs, 2026-07-07)

- **Consumer (Free/Pro/Max)**: the "Help improve Claude" toggle controls training; ON means
  5-year retention, OFF means 30 days. The Aug 2025 rollout presented it pre-set to ON.
  Check: https://claude.ai/settings/data-privacy-controls
- **Commercial (Team/Enterprise/API)**: not trained on by default; 30-day retention; Zero Data
  Retention is a per-organization option for qualified Enterprise accounts only.
- **Transcripts**: Claude Code stores session transcripts in plaintext under `~/.claude/projects/`
  for `cleanupPeriodDays` (default 30).

Re-verify these facts against https://code.claude.com/docs/en/data-usage when they matter — this
table has a compiled-on date, not an expiry warranty.

## Why AC-02 flags env-runners

`Bash(npx *)` reads as "allow npx" but means "allow anything npx can download and execute" — the
wildcard swallows the inner command. Same for uvx, pnpm dlx, docker run/exec, bare shells, etc.
The docs themselves call argument-constraining Bash patterns fragile; prefer exact commands and
PreToolUse hooks for anything broader.

## Deny rules vs. the OS (the AC-01 caveat, and why AC-07 exists)

Per the Claude Code permissions docs (verified 2026-09-11), `Read(...)` deny rules apply to
Claude's built-in file tools, to the Bash file commands Claude Code recognizes (`cat`, `head`,
`tail`, `sed`) and to redirections. They do **not** apply to a command that reads files without
naming them (`grep -r pattern .`) or to scripts that open files themselves. The Bash sandbox
merges the same deny paths into OS-level filesystem rules for every Bash command and its children,
which is why AC-07 reports `sandbox.enabled` as a posture finding. `sandbox.enabled` is a user- or
managed-settings key; a repository's `.claude/settings.json` cannot turn it on.

## Deny-rule spellings (AC-01 matches meaning, not text)

| Spelling | Anchors at | Covers nested copies? |
|---|---|---|
| `Read(.env)` or `Read(**/.env)` | current directory | yes (bare filenames follow gitignore semantics) |
| `Read(./.env)` or `Read(/.env)` | project root (project settings) | no |
| `Read(//**/.env)` | filesystem root | yes, anywhere |

AC-01 accepts any of these for each recommended target (`.env`, `.env.*`, `secrets/**`) and
recommends the bare-name spelling. Before v0.3 the check compared strings and flagged
`Read(.env)` as "missing"; that false positive is regression-locked in `tests/test_matchers.py`.

## Manual procedure — AC-06 (`manual-retention-check`)

1. Open https://claude.ai/settings/data-privacy-controls while logged into the account used by
   the AI tooling.
2. Record the state of "Help improve Claude" and the resulting retention window.
3. For Team/Enterprise: confirm the plan tier and any ZDR agreement in writing with the org admin.
4. Record the outcome next to the audit report; the report itself stays UNKNOWN by design.
