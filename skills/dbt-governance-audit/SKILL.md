---
description: Static audit of a dbt project's YAML, with no warehouse connection — which models and columns are tagged as PII, which exposures (dashboards, AI agents, apps) consume them, whether a masking package or masked layer is declared, and which likely-PII columns carry no tag at all. Read-only; cited findings; counts and names only. A missing tag is never proof of no PII.
argument-hint: "[path-to-dbt-project]"
context: fork
allowed-tools: "Bash(python3 *), Read, Glob"
---

# dbt-governance-audit

Audit the governance *declarations* of a dbt project: `meta` PII tags, `tags: [pii]`, exposures,
and `packages.yml`. It runs on the repo alone (no `dbt` binary, no connection), so it multiplies
across every warehouse the project targets. Findings follow
[finding-format.md](${CLAUDE_PLUGIN_ROOT}/reference/finding-format.md); PII column patterns follow
[four-tier-framework.md](${CLAUDE_PLUGIN_ROOT}/reference/four-tier-framework.md).

What it can and cannot prove, said once here and again in every finding: **the YAML declares
intent. It cannot prove the warehouse enforces it, and a column with no tag is not a column with
no PII.** For enforcement, run `db-access-audit` against the target warehouse.

## Steps

1. **Resolve the project**: first positional in `$ARGUMENTS`, default the current directory. The
   script looks for `dbt_project.yml` there (or one level down) and reads `model-paths`.

2. **Compute verdicts**:
   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/skills/dbt-governance-audit/scripts/dbt_audit.py" --target <project>
   ```
   Checks: **DBT-01** a PII-tagged model is consumed by an exposure and no masking package or
   masked model is declared (MEDIUM); **DBT-02** columns whose names match the framework's PII
   patterns but carry no PII tag (MEDIUM, counts and column names); **DBT-03** a YAML file that
   could not be parsed (UNKNOWN, fail-closed); **DBT-04** INFO on masking packages present in
   `packages.yml`. The parser is a stdlib YAML subset; a file it cannot read is DBT-03, never a
   silent skip.

3. **Render** per finding-format.md. Two emphases: name the exposures of type `application` or
   `analysis` that consume tagged models (that is where an agent reads them), and repeat that
   tags are declarations. Suggest `db-access-audit` for the enforcement half.

If invoked by the `security-audit` orchestrator, return the raw JSON fenced after the report.
