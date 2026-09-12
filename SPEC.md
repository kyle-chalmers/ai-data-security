# AI Data Security — v1 Specification

> Approved scope for v1. Changes to this document require explicit maintainer approval.
> The build harness in `dev/` tracks progress against this spec; `dev/feature_list.json` is the
> immutable checklist derived from it.

## Mission

AI Data Security is an open-source Claude Code plugin that helps **data professionals** achieve safe
interactions between AI and their data, on both sides:

- **AI side** — sensitive-data leakage, secrets readable by agents, excessive agency / unsafe tool
  permissions, MCP configuration risk, retention/training exposure.
- **Data side** — PII discovery and classification, least-privilege AI access to databases,
  masked/governed views, audit logging.

v1 is **audit-only and read-only**: every skill scans and reports; nothing mutates a system.
Every finding cites a recognized standard. IMPLEMENT flows (human-gated fixes) are v2.

## v1 skills

| Skill | What it audits | Runs |
|---|---|---|
| `secrets-scanner` | Secrets on disk and in git history (gitleaks), plus the exposure matrix gitleaks lacks: on-disk × in-history × agent-readable × pushed-to-remote | forked |
| `ai-config-audit` | AI tool configuration: permission deny/allow rules, MCP configs across tools, plaintext transcript exposure, retention/training tier guidance | forked |
| `data-classification` | Files/datasets against the 4-tier sensitivity framework (Public / Internal / Confidential / Restricted) | forked |
| `db-access-audit` | Read-only warehouse audit: over-broad grants for AI principals, unmasked PII columns, missing masked-view layer, missing audit logging. Postgres + Snowflake SQL packs | inline (human gate) |
| `security-audit` | The ~30-minute end-to-end orchestrator: composes the four skills above into one prioritized, cited report | inline |

## Shared contracts (single-sourced in `reference/`)

- **`finding-format.md`** — normative finding schema v1: severity `CRITICAL/HIGH/MEDIUM/LOW/INFO`
  plus first-class `UNKNOWN` status (missing tool, scan error, not-locally-auditable → reported
  fail-closed, never counted as a pass). **Confidence caps severity**: `possible ≤ MEDIUM`,
  `probable ≤ HIGH`, only `confirmed` may be `CRITICAL`.
- **`citations.yml`** — the ONLY citation IDs findings may use, each with a source URL
  (OWASP LLM Top 10 2025, MITRE ATLAS, MCP Security Best Practices, NIST SP 800-122,
  NIST AI 600-1, and the Claude Code data-usage/security docs for tool-specific checks).
- **`checks.yml`** — maps every check to its citation keys and the fixture that proves it fires
  (CI-enforced: a check without a citation or fixture fails the build).
- **`four-tier-framework.md`** — tier definitions based on NIST SP 800-122 impact levels, plus the
  PII column-name heuristics table shared by `data-classification` and `db-access-audit`.

## Design rules

1. Deterministic verdicts live in bundled python3-stdlib scripts; the model narrates and remediates
   but cannot change a script's verdict. Scanned content is untrusted input (indirect prompt
   injection — OWASP LLM01:2025, MITRE ATLAS AML.T0051.001).
2. `data-classification` floors to Internal and never auto-assigns Public. Sampled values never
   appear in reports; reports stay shareable.
3. `db-access-audit` enforces read-only on itself (`default_transaction_read_only=on` for Postgres;
   CI lint proving zero mutating statements in both SQL packs). Bring-your-own-connection via the
   user's pre-authenticated `psql`/`snow`; credentials are never stored. A human gate shows the
   connection target and exact SQL before anything executes.
4. Suppression via `.ai-data-security-ignore` (line-number-free fingerprints, optional expiry); suppressed
   findings always appear in a report appendix — nothing disappears silently.
5. Fixture safety doctrine: committed fixtures use only vendor-documented example credentials,
   checksum-invalid tokens, and famous fake identifiers. Anything genuinely secret-shaped is
   generated at test time and never committed.
6. Tool reuse: gitleaks (primary; detect-or-instruct-install, no homegrown fallback scanner),
   trufflehog/detect-secrets/mcp-scan/NB Defense as recommendations only. No vendored semgrep rules.
7. CI is deterministic-only (no LLM calls): plugin validation, shellcheck, gitleaks self-scan of
   tree + full history, Postgres fixture diffs, SQL mutating-statement lint, SHA-pinned actions.

## Out of scope for v1 (designed-for seams)

- `safe-db-access` IMPLEMENT recipe (read-only role → masked views → per-row salted hashing →
  validation script) — v2; `db-access-audit` findings name it as remediation.
- Enforcement hooks (`hooks/hooks.json` is deliberately absent in v1).
- Presidio deep tier, notebook scanning, MCP deep audit (recommended external tools instead).
- Marketplace/public submission — gated on explicit maintainer approval.

## v0.2 additions (slice 7 — 2026-07)

Three enhancements, all preserving the v1 invariants (scripts decide / model narrates,
extends-only customization, fail-closed unknowns, stdlib-only, zero-config byte-identical):

1. **Org profile** — optional `.ai-data-security.yml` at the audited repo's root
   (`reference/org-config.md`): org PII filename/column tokens, warehouse argument
   defaults, appended org citations. Never removes/weakens detection; unparseable →
   DC-03/DB-06 UNKNOWN.
2. **Token-boundary PII patterns** — column patterns match at underscore/space token
   boundaries (`member_ssn`, `customer_email` match; `emailed_at` does not) across
   classify_hints, both SQL packs, and the framework doc. Anchored `^...$` missed every
   prefixed real-world name.
3. **Snowflake script-backing** — `eval_grants.py --dialect snowflake` parses recorded
   `snow sql` outputs and computes DB-01..DB-05, closing the one place where the model
   interpreted verdicts "mentally" (reference.md rules now document what the script does).

## Verification

- Each slice in `dev/feature_list.json` has a runnable check; `dev/validate.sh` is the always-runnable
  deterministic baseline.
- Final v1 check: clean-checkout marketplace install; a full `/ai-data-security:security-audit` run over the
  combined fixtures produces one cited, severity-sorted report; gitleaks tree+history self-scan clean;
  CI green; adversarial fresh-context review of the implementation against this spec.

## v0.3 additions (slice 8 — 2026-09)

Approved 2026-09-11 after the research pass in `docs/research/`. All items keep the v1 invariants
(scripts decide / model narrates, extends-only customization, fail-closed unknowns, stdlib-only).
The "zero-config byte-identical" invariant holds for every *existing* check; a **new** check
(AC-07 here, as DC-03 was in 0.1.x) may add a finding to a repo with no config, and the CHANGELOG
names it when that happens.

1. **Trustworthy first run** — `doctor` (capability matrix: which tools are present, which checks
   will be UNKNOWN, registry integrity) and `quick-check` (zero flags: agent-readable secrets on
   disk, deny-rule and sandbox posture, Restricted-tier file count; three verdict lines plus the
   UNKNOWN list). Both reuse the existing evaluators; neither adds a verdict engine.
2. **AC-01 semantics** — recommended deny rules are matched by *meaning*, not string: `Read(.env)`,
   `Read(**/.env)`, `Read(//**/.env)`, and `Read(./.env)` all satisfy the `.env` requirement per the
   Claude Code permissions documentation; the recommendation is the any-depth spelling. New
   **AC-07** reports Bash sandbox posture (`sandbox.enabled`), because deny rules bind the file
   tools and recognized Bash file commands, not `grep -r` or scripts; only the sandbox enforces at
   the OS level.
3. **Citation registry provenance** — every `citations.yml` entry carries `published`, `accessed`,
   and `status` (`current | superseded | withdrawn`); CI fails a check that cites a withdrawn
   entry. New entries: OWASP Top 10 for Agentic Applications 2026 (ASI02, ASI03), OWASP AI Agent
   Security Cheat Sheet, OWASP MCP Security Cheat Sheet, MCP Security Best Practices (2026-07-28),
   Claude Code permissions and sandboxing docs. The OWASP LLM Top 10 2025 entries stay `current`
   until the 2026 edition's numbering is verified against its PDF.
4. **SARIF 2.1.0 export** from the JSON interchange (`scripts/to_sarif.py`), so findings can land
   in GitHub Code Scanning.
5. **Hashing caveat** — any remediation text that mentions hashing states that hashed identifiers
   are pseudonymized, not anonymized (NIST SP 800-188 §4.3.2; EDPB Guidelines 01/2025), and points
   at keyed hashing or tokenization with the key outside the AI role's reach.

## Approved SPEC amendment (2026-09-11): safe-db-access planner

The "Out of scope for v1" list names the safe-db-access IMPLEMENT recipe. The maintainer approves
a **narrow amendment**: a `safe-db-access --plan` skill (roadmap v0.6) may *generate* the recipe as
text for a human to review and execute. It MUST NOT write files, execute SQL, or change any
connection or configuration; templates are fixed and parameters are validated deterministically,
so the model never composes privilege-changing DDL. Output must state that hashed identifiers are
pseudonymized, not anonymized, and must keep any hashing key or salt outside the AI role's reach.
Applying the plan (roadmap v1.0 IMPLEMENT) and PreToolUse enforcement hooks remain **v2, not
opened**.

## Maintainer decisions recorded 2026-09-11

- Planner approved as the amendment above; SPEC v2 (IMPLEMENT, hooks) stays closed.
- Versioning: no back-tag of v0.2.0; the next release is v0.3.0 and carries the 0.2.0 notes.
- The dbt static audit belongs in this plugin (roadmap v0.5), not a sibling.
- Betterleaks is reported by `doctor` as information only; an adapter requires its own amendment
  with fixture parity, because design rule 6 names gitleaks as the primary scanner.
- README Mission/Vision: Option A from `docs/research/mission-vision-options.md`.
