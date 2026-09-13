---
description: Generate the least-privilege recipe for an AI database principal as reviewable SQL text — service identity, key vault, curated masked views, revoke-raw/grant-curated, audit trail, a validation script run as the AI role, and rollback — from a db-access-audit result. Postgres and Snowflake. Never connects, never executes, never writes a file; a human applies it and the audit is re-run.
argument-hint: "--audit <eval.json> [--dialect postgres|snowflake] [--ai-role R] [--ai-user U] [--database D] [--curated-schema S] [--vault-schema S] [--edition enterprise|standard|unknown]"
allowed-tools: "Bash(python3 *), Read, Glob"
---

# safe-db-access (planner)

Approved SPEC amendment (2026-09-11): this skill may *generate* the safe-db-access recipe as text
for a human to review and execute. It MUST NOT write files, execute SQL, or change any connection
or configuration. `scripts/plan.py` renders fixed templates with identifiers the audit captured and
the script validated; you print what it prints. Applying the plan (roadmap v1.0) is not this skill.

## Steps

1. **Get the audit JSON.** The plan is derived from a `db-access-audit` run that used
   `--emit-json <file>` (live or `--recorded`). If the user has none, run
   `/ai-data-security:db-access-audit` first (for Postgres include `columns.sql`, which the pack
   now runs by default, and pass `--columns`); the JSON must carry `plan_inputs` (evaluator tool
   version 4+). Never construct plan inputs by hand.

2. **Collect parameters** from `$ARGUMENTS` (defaults in brackets): `--ai-role` [audit target],
   Snowflake `--ai-user` [audit identity], `--database` [the audit's single database],
   `--curated-schema` [curated/CURATED], `--vault-schema` [vault/VAULT], `--owner-role`
   [curated_owner/SYSADMIN], `--auditor-role` [GOVERNANCE_AUDITOR], `--user-type`
   [SERVICE_AGENT], `--edition` [unknown], `--include-public-revokes` [off: PUBLIC revocations
   are rendered commented out because they affect every role; ask the user before turning it
   on]. The curated and vault schemas must be NEW namespaces (rollback drops them), and the owner
   role must not be the AI role; the script refuses otherwise. Every identifier must match
   `^[A-Za-z_][A-Za-z0-9_]{0,127}$`; the script refuses anything else (exit 2) and renders nothing.
   Do not "fix" a refused value by quoting it: ask the user for a plain identifier.

3. **Render**:
   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/skills/safe-db-access/scripts/plan.py" --audit <eval.json> [params]
   ```
   Show the output **verbatim** in one fenced `sql` block. Do not reorder, trim, or add
   statements. If the header says `INCOMPLETE` or lists `NOT RENDERED` items, say so first and
   explain what to capture or review; the plan must not be executed in that state.

4. **Explain, briefly, in this order**: (a) the plan is text, nothing has changed; (b) who runs
   which section (sections 1–5 a DBA, section 6 the AI role itself); (c) hashed identifiers are
   pseudonymized, not anonymized, and the key stays in the vault schema the AI role cannot read;
   (d) after applying, re-run `db-access-audit` and compare before/after; (e) section 7 restores the
   insecure state and exists for emergencies. Snowflake: masking policies need Enterprise or
   higher; `IS_AGENT_ACTIVATED()` needs the agent-identity user type. Snowflake support is
   fixture-validated only, so section 6 is not optional.

5. **Never**: execute any statement, offer to execute it, write the plan to disk, or paste
   credentials. If asked to "just apply it", decline and point at the SPEC amendment.

If invoked by the `security-audit` orchestrator after a DB audit with findings, run with the
orchestrator's JSON and return the plan fenced after the report.
