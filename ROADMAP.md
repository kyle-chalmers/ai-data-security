# AI Data Security Roadmap

> What comes after v0.2.0, and why. Every item names the research finding it answers
> (`docs/research/2026-09-landscape.md`, claims C1–C12 and sources `S#` in `docs/research/sources.md`),
> the check or skill it touches, which of the four priorities it serves (**fix** · **first-run** ·
> **coverage** · **credibility**), a size (S/M/L), what CI will prove, and its SPEC status.
>
> **Version vocabulary.** Plugin releases use semver (`v0.2.0` today). `SPEC.md` uses scope labels:
> "v1" is the shipped audit-only scope, "v2" is IMPLEMENT flows, which are **not approved**. Any item
> marked *proposed SPEC v2 change* needs the maintainer's explicit approval before work starts; it is
> a proposal here, not a plan of record.
>
> The invariants every item must keep: scripts decide and the model narrates; extensions only add
> detection; unverifiable states fail closed to UNKNOWN; stdlib-only Python; a repo with no config
> behaves byte-identically to the previous release.

## Decisions recorded 2026-09-11 (maintainer)

Kyle approved the research pass's recommendations: the v0.6 planner is approved as a **narrow SPEC
amendment** (generated text, never applied; see `SPEC.md`); SPEC v2 for IMPLEMENT and enforcement
hooks stays closed; no back-tag of v0.2.0 (v0.3.0 is the next release); the dbt static audit lives
in this plugin; Betterleaks is information-only in `/doctor` until an adapter amendment proves
fixture parity; README Mission/Vision is Option A. Items below marked *approved amendment* or
*v1* can start; items marked *proposed SPEC v2 change* cannot.

## Where we are — v0.2.0 (July 2026)

Five audit skills, 20 checks (SS-01..05, AC-01..06, DC-01..03, DB-01..06), Postgres and Snowflake
SQL packs, org profile, token-boundary PII patterns, deterministic CI. Public since 2026-07-09;
v0.2.0 merged but never tagged. See `CHANGELOG.md`.

## v0.3 — Trustworthy first run (**first-run** + **credibility**)

The first run is the credibility test, so these ship together.

| Item | Finding | Touches | Size | CI proves | SPEC |
|---|---|---|---|---|---|
| `/ai-data-security:doctor` — detects gitleaks, `psql`, `snow`, docker; prints a capability matrix (what this machine can audit, what will be UNKNOWN) and the exact next command. Reports Betterleaks presence as **information only**: SPEC design rule 6 names gitleaks as the primary scanner, so a Betterleaks adapter is a separate SPEC amendment that must first prove output parity against the fixtures | gitleaks is feature-complete, successor Betterleaks (S50, S69); three of five benchmarked plugins ship a setup/health skill (Lane 2) | new skill + `dev/doctor.py` | M | fixture run with each tool absent → matrix rows flip to UNKNOWN, exit 0 | v1 (Betterleaks adapter: proposed SPEC amendment) |
| `/ai-data-security:quick-check <path>` — zero flags, under two minutes: secrets-on-disk, deny-rule and sandbox posture, Restricted-tier file count; three verdict lines and the UNKNOWN list | "dead simple" is one command and a stated time-to-value (Lane 2 benchmark); depth converts even at low reach (video 22 retro) | new skill reusing `eval_secrets`, `permeval`, `classify_hints` | M | combined fixture → exactly three verdict lines + citations; timed under 120 s in CI | v1 |
| AC-01 semantics fix: accept equivalent or stronger deny spellings (`Read(.env)` ≡ `Read(**/.env)`, and `Read(//**/.env)` for "any `.env` anywhere on the filesystem", all three documented in S2's deny-rule table) and recommend the any-depth form; add an **AC-07 sandbox posture** check (`sandbox.enabled`, `failIfUnavailable`) | C8: bare filenames match at any depth, `./path` is cwd-relative; deny rules do not cover `grep -r` or scripts; the sandbox merges deny paths into OS rules (S2, S3) | `permeval.py`, `.claude/settings.json`, `checks.yml`, `reference.md` | S | matcher tests for each spelling; hardened fixture stays clean; new fixture with sandbox off fires AC-07 | v1 |
| Citation registry upgrade: add OWASP Agentic Top 10 2026 `ASI03` and `ASI02` (S46), OWASP AI Agent Security Cheat Sheet (S12), OWASP MCP Security Cheat Sheet (S49), MCP spec security page dated 2026-07-28 (S48); re-verify `LLM01/02/06` against the 2026 LLM edition (S47) before citing it; record `published`, `accessed`, `status: current \| superseded \| withdrawn` per entry and fail CI on `withdrawn` | C3, C12; Codex C35 | `reference/citations.yml`, `checks.yml`, `run-fixture-checks.sh` | S | jq check that every entry has the three fields and no check cites a withdrawn ID | v1 |
| Positioning table by category replaces the 2026-07 README table; names **Claude Security** (S51) and `security-guidance` (S37) explicitly; adds agentsec-scanner and agent-audit (S65, S66) | Lane 2: same-publisher name collision is the biggest positioning risk | `README.md` | S | none (docs) | v1 |
| SARIF 2.1.0 exporter from the existing fenced-JSON interchange | agentsec-scanner and MCPScan already emit SARIF (S65, S36); GitHub Code Scanning ingests it | new `scripts/to_sarif.py` | S | fixture report → SARIF validates against the schema | v1 |
| Hygiene: tag/release v0.3.0 (v0.2.0 was never tagged and is not back-tagged), GitHub description and topics, companion-repo link, Mission/Vision block | `docs/research/quick-wins.md` #1, #2, #4, #5, #10 (#7 `validate.sh` hardening already landed in PR #3) | README, repo settings | S | validate.sh green | v1 |
| Hashing caveat text: any finding or remediation that mentions hashing states "pseudonymization, not anonymization" and points at keyed hashing or tokenization with the key outside the AI role's reach | C5 (S10, S61, S11, S55) | `db-access-audit/reference.md`, `four-tier-framework.md` | S | grep test that the phrase appears in rendered fixture reports | v1 |

## v0.4 — Decision-quality DB audit (**fix** groundwork + **credibility**) — shipped 2026-09-12 as v0.4.0

Make DB findings name a remediable boundary and say what they could not see.

| Item | Finding | Touches | Size | CI proves | SPEC |
|---|---|---|---|---|---|
| **DB-ID-01 effective AI identity** (Snowflake first): user `TYPE` (`PERSON` vs `SERVICE` / `SERVICE_AGENT`), `DEFAULT_SECONDARY_ROLE`, active secondary roles, full role hierarchy walk, `OWNERSHIP`/`MANAGE GRANTS` flags; Postgres: `INHERIT` membership walk, `BYPASSRLS`, superuser, ownership, PUBLIC defaults, `pg_write_server_files` / `pg_execute_server_program` membership | C1, C4, C10 (S18–S20, S26, S27, S77, S78; Lane 3) | `eval_grants.py`, both SQL packs, recorded fixtures | L | Snowflake recorded fixture with `TYPE=PERSON` + `ALL` → HIGH; with `SERVICE_AGENT` + `()` → clear; Postgres docker fixture with an inherited write role → DB-01 fires where it did not before | v1 |
| **DB-07 raw-to-curated boundary**: prove the AI principal has no path (direct, inherited, PUBLIC, future grants) to classified raw objects; replace DB-04's name-based "masked view exists" with object and grant evidence | C1, C6; Codex C35 | `eval_grants.py`, SQL packs | M | fixtures where a view is named `*_masked` but base grants remain → still HIGH | v1 |
| **DB-08 governed-control attachment**: masking or row-access policy attached to PII-named columns the AI principal can read; on Snowflake via `ACCOUNT_USAGE.POLICY_REFERENCES` with the `GOVERNANCE_VIEWER` database role, with the table-function's owner-only visibility reported as UNKNOWN, not clear | C6, C7 (S16, S79, S80) | Snowflake pack, `eval_grants.py` | M | recorded fixture with policy attached → DB-03 downgraded; fixture from an APPLY-only role → UNKNOWN | v1 |
| **DB-09 audit-trail quality**: edition (ACCESS_HISTORY Enterprise), which statement shapes are missing, result-cache reuse (`USE_CACHED_RESULT`, 31-day retention), Redshift `enable_user_activity_logging`, Postgres `pgaudit` presence and log sink; report the retention window and known gaps instead of a binary | C7 (S17, S56, S84–S86) | both packs, `reference.md` | M | fixtures per gap → each renders its caveat line | v1 |
| **DB-10 external write paths**: stages, `UNLOAD`, `COPY … TO PROGRAM`, DuckDB `enable_external_access`, cloud-storage credentials reachable from agent SQL | S87, S30, S31; `UNLOAD` per Lane 3 | new queries | M | Postgres fixture granting `pg_write_server_files` → CRITICAL | v1 |
| **Dynamic-table owner check** (Snowflake): curated objects that are dynamic tables report the owner role and whether `EXECUTE AS USER` is set | C6 (S53, S54) | Snowflake pack | S | recorded fixture → finding text names the owner | v1 |
| **Auditor-privilege precondition** in `/doctor` and the DB skill gate: Snowflake `SECURITY_VIEWER` + `GOVERNANCE_VIEWER` database roles; Redshift `sys:secadmin` for masking/RLS views; otherwise those checks are UNKNOWN up front | S79, S80, S84 | SKILL.md, `eval_grants.py` | S | fixture without the role → DB-08 UNKNOWN with the exact GRANT statement to fix it | v1 |
| `.ai-data-security-ignore` and org-profile parity for every new check | invariant | evaluators | S | existing suppression tests extended | v1 |

## v0.5 — Agent-config depth (**coverage** + **credibility**) — shipped 2026-09-12 as v0.5.0

| Item | Finding | Touches | Size | CI proves | SPEC |
|---|---|---|---|---|---|
| **AC-08 agent capability inventory**: from static config, list external-communication, filesystem, shell, browser, Git, cloud-CLI, and warehouse tools the agent holds; correlate with SS/DC findings into an **INFO-level** composition note. The finding cites T1 sources (OWASP Agentic ASI02, S46; OWASP AI Agent Security Cheat Sheet, S12); Willison's "lethal trifecta" (S7, T5) appears only as attributed commentary in the narration, never as a citation key | C2 framing 2, S63; Codex AC-07 | `permeval.py`, new `reference/capabilities.yml` | M | combined fixture → one INFO composition finding citing ASI02 and S12 | v1 |
| **AC-09 MCP and skill provenance**: unpinned `npx`/`uvx` packages, mutable git refs, credential-bearing env references, servers whose startup command is not shown, no lock or hash | C9, S48 (local server compromise), S64 (pinning), AST02/AST07 (S13, draft) | `permeval.py` | M | fixture `.mcp.json` with `npx -y some-pkg@latest` → MEDIUM | v1 |
| **AC-10 write-capable warehouse MCP**: parse Snowflake MCP `sql_statement_permissions` YAML, Postgres MCP Pro `--access-mode`, Toolbox `tools.yaml` statements; Databricks MCP → defer to DB checks | §7b (S81–S83) | `permeval.py` | M | fixtures per server → HIGH when writes enabled, UNKNOWN when config not found | v1 |
| **AC-11 local sensitive sinks**: transcripts retention (`cleanupPeriodDays`), DuckDB `~/.duckdb/stored_secrets`, shell history readable, MCP config with plaintext tokens (extend AC-03 with S49's rule) | C9 (S9, S31, S49) | `permeval.py`, `eval_secrets.py` paths | S | fixture home dir → each sink listed with counts only | v1 |
| Agent-tool config paths: Windsurf, Cline, Roo Code, Continue, GitHub Copilot CLI, OpenCode | agentsec-scanner's list (S65) | `permeval.py` path table, fixtures | M | fixture per tool → MCP credential literal detected | v1 |
| PII validators: phone (E.164 and NANP), IBAN (mod-97), IPv4/IPv6 | coverage boundary from repo recon | `classify_hints.py`, framework doc | S | matcher tests; no value ever appears in evidence | v1 |
| **dbt static audit** (`dbt-governance-audit`): PII `meta` tags per model and column, exposures consuming tagged models, masking package presence in `packages.yml`; every finding says a missing tag is not proof of no PII. Decided 2026-09-11: lives in this plugin | Lane 3 dbt addendum; Codex C35 | new skill, stdlib YAML-subset parser or JSON manifest | L | fixture dbt project → tagged column without downstream masking → MEDIUM | v1 |

## v0.6 — safe-db-access **planner** (**fix**, read-only) — *approved SPEC amendment, 2026-09-11* — shipped 2026-09-12 as v0.6.0

SPEC.md listed the safe-db-access IMPLEMENT recipe under "Out of scope for v1"; the maintainer approved
a narrow amendment (recorded in `SPEC.md`) allowing the recipe to be **generated as text** for human
review and execution. The planner MUST NOT write files, execute SQL, or change connections; templates
are fixed and parameters validated deterministically.

| Item | Finding | Touches | Size | CI proves | SPEC |
|---|---|---|---|---|---|
| `/ai-data-security:safe-db-access --plan`: from the audit's JSON, select a reviewed, platform-specific template and emit to stdout (never to disk, never executed): (1) service identity — Snowflake `CREATE USER … TYPE = SERVICE_AGENT` with `DEFAULT_SECONDARY_ROLES = ()`, Postgres role with `NOINHERIT` and no file roles; (2) curated schema grants; (3) masking layer — platform masking policy where the edition allows, `IS_AGENT_ACTIVATED()` in the policy body on Snowflake, otherwise a curated view; (4) pseudonymization — keyed hash with the key outside the AI role's reach or External Tokenization, **not** a same-schema salt table; (5) audit logging with the retention caveat; (6) a validation script that proves the analytics query succeeds and the raw read is refused; (7) rollback statements. Human executes; audit re-runs; before/after attached | Thesis principles corrected by C4–C7, C10 (S10, S19, S53, S55, S61, S77, S80) | new skill, `templates/{snowflake,postgres}/*.sql`, deterministic parameter validation | L | template render is byte-stable per fixture; SQL lint proves the planner itself writes nothing; Postgres docker fixture executes the plan manually in CI and the validation script passes | approved amendment (SPEC.md, 2026-09-11) |

## v1.0 — safe-db-access **IMPLEMENT** (**fix**) — *proposed SPEC v2 change; requires explicit approval*

Applying the plan (writing files, running DDL, changing MCP connections) breaks the v1 read-only
invariant. Before any work: a written safety case, a supported-architecture list, a "do not
generate" policy (no ACCOUNTADMIN steps, no key generation, no credential rotation, no identity
provisioning without a human), platform security review, and end-to-end fixtures. Codex's
recommendation, adopted here: the first "generate the fix" experience should be the v0.6 plan-and-
proof kit, not an applier.

## v1.x — Platform coverage (**coverage**), in auditability order

*Numbering note (2026-09-13): coverage ships as 0.7, 0.8, … because v1.0 is reserved for IMPLEMENT
under a SPEC v2 that is not open; "v1.x" here meant "after the planner". Shipped: Databricks
Unity Catalog pack in v0.7.0 (2026-09-13), plus the v0.4-gate carry-over (Snowflake audit-session
`CURRENT_ROLE()` compared to `--role`); Redshift pack in v0.8.0 (2026-09-13); BigQuery pack (partial by
design: explicit bindings + project IAM) in v0.9.0 (2026-09-13); Fabric Warehouse pack (partial by design:
SQL grants + optional SQL-audit status; workspace roles stated as UNKNOWN) in v0.10.0 (2026-09-13); Lake Formation
pack (partial by design: recorded AWS CLI JSON; IAM policies by name) in v0.11.0 (2026-09-13).*

Databricks (system tables, ABAC exempt principals; S22, S60) → Redshift (SVV views with the
`sys:secadmin` precondition; S21, Lane 3) → BigQuery as **partial** (explicit bindings only; S23)
→ Fabric via recorded API output (mode check first; S28, S29) → Lake Formation via recorded JSON
(S32, S33) → DuckDB as a posture check, not a grants pack (S30, S31). MotherDuck stays UNKNOWN
until its controls are verified.

## Separate line — enforcement hooks — *proposed SPEC v2 change*

PreToolUse gates (block a push while a rotate-first finding is open; block a warehouse MCP add
whose config enables writes). This is an enforcement product, not an audit; it is tracked here so
it is not mistaken for coverage. Not started until approved.

## Deliberately not building

From the research (Codex C36 list, confirmed by SPEC): a runtime MCP proxy or gateway; LLM-scored
verdicts or severity; a homegrown secrets scanner when neither gitleaks nor Betterleaks is present;
prompt redaction by default; live starting of unknown MCP servers during an audit; direct
remediation execution, credential rotation, key generation, or identity provisioning; "one-click
compliance". Also not a multi-harness (Codex) port: `security-audit` depends on forked subagents
and fixtures cannot prove orchestration parity (2026-09-08 feasibility note).

## Open questions for the maintainer

All four questions from the research pass were answered on 2026-09-11 (see "Decisions recorded"
above). Remaining open item: when to open SPEC v2 at all, which is deferred until the planner has
shipped and been dogfooded.
