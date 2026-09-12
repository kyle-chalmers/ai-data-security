# AI Data Security — landscape research, September 2026

_Research pass of 2026-09-11 on how the `ai-data-security` plugin should evolve. Every source
below is listed in `sources.md` with its evidence tier (T1 standards · T2 vendor docs · T3 research
or talks · T4 tool docs · T5 commentary) and a fetched-by-the-author flag. A claim in this report
rests on at least two independent T1–T4 sources unless it says otherwise. Codex (OpenAI's CLI) ran
as an independent researcher; its claims were verified one by one in `codex-run/reconciliation.md`._

## 1. The thesis, stated as a hypothesis

The video **"So AI Can Access Your Database's PII, What to Do?"** (S1, 2026-05-18) argues: an AI
coding agent connected to a warehouse through an MCP server or CLI has no identity of its own. It
runs as whatever role the human's connection authenticates as, so every row it reads leaves the
network for the model provider. The proposed fix has three principles:

1. **Schema segregation.** The AI role gets USAGE only on a curated schema of masked views, never
   on the raw schema.
2. **Hashing as irreversibility.** PII columns the AI still needs for joins are hashed (SHA-256)
   with a per-row salt kept in a `SALT_KEYS` table, so joins work but values are not recoverable.
3. **Identity selection.** A per-human AI service user holds only the `AI_AGENT` role, because a
   personal user's secondary roles silently widen every session.

Declared non-goals: prompt injection and provider-side retention or routing.

The plugin (v0.2.0) audits the *problem* with 20 deterministic checks (secrets exposure, agent
config, file classification, Postgres/Snowflake grants). It does not yet generate the fix. This pass
treats the three principles as hypotheses and looks for evidence for, against, and beyond them.

## 2. Competing framings considered

Codex was asked to rank threat-model framings before reading the thesis as a recommendation. Its
ranking (an inference, adopted here after checking the underlying sources) was:

| Rank | Framing | Why it ranks there | Does the plugin address it today? |
|---|---|---|---|
| 1 | **Data-access boundary / blast radius**: what can the identity read, write, or alter | Directly observable, deterministic to audit, strongest incident evidence (S45, S72, S75) | Yes: DB-01..DB-05, SS-01..04, DC-01..02 |
| 2 | **Lethal-trifecta exfiltration**: private data + untrusted content + external channel (S7) | Highest-consequence composition risk; the thesis removes only one leg (raw data) | Partly: AC-02 allow rules, AC-03 MCP credentials; no capability inventory |
| 3 | **Agent-config and MCP/skill supply chain**: what the instructions, server commands, scopes, and skills let the agent do (S48, S13, S64) | The seam where most 2025–2026 incidents entered (S62, S63) | Shallow: AC-03/AC-04 config hygiene only |
| 4 | **Non-human identity lifecycle**: is the agent's credential dedicated, attributable, scoped, rotated, offboarded (S34, S74, S75, S76) | The thesis prefers a dedicated identity but audits only role names | No lifecycle evidence today |
| 5 | **Ordinary hygiene, made worse by agents**: secrets in repos, plaintext transcripts, PII in exports, broad grants | Real, but AI is an amplifier, not the root cause | Yes: this is most of v1 |

Where the thesis fits: it is the right architecture for framing 1 and a useful mitigation inside
framing 2. It says nothing about framings 3 and 4, and the disconfirmation lane found that its
second principle overstates what hashing buys (claim 5 below).

## 3. What the evidence supports: twelve checkable claims

Each claim names its sources by `S#` and the strongest counter-evidence found.

**Claim 1. In every connection mode examined, the agent inherits the connection identity's
privileges; none of these modes automatically downscopes the authenticated identity.**
Snowflake sessions aggregate the primary role, all active secondary roles, and everything below
them in the hierarchy (S20). Fabric SQL endpoints in delegated mode read OneLake as the *item
owner*, not the caller (S29). Local DuckDB "executes SQL with the full privileges of the user
running it" (S30). The MCP specification treats token passthrough as a forbidden anti-pattern
precisely because servers otherwise act on tokens issued for something else (S48). The MCP spec's
scope-minimization guidance (S48) is the exception that proves the rule: downscoping exists only
where a server implements OAuth scopes, which none of the warehouse MCP servers in §7b do.
*Counter-evidence sought and not found* (Lane 4): no vendor documents an automatically reduced
privilege set for MCP or CLI sessions. **The load-bearing claim of the thesis stands for the modes
examined** (Snowflake and Postgres connectors, Fabric delegated mode, DuckDB, the four MCP servers).

**Claim 2. Over-privileged AI access is measurably associated with incidents.** Teleport's 2026
interviews of 205 infrastructure and security leaders: 17% incident rate where AI was limited to
necessary permissions versus 76% where it was over-privileged; 70% say AI has more access than a
human in the same role; static credentials add roughly 20 points (S45). IBM's 2025 study: 13% of
organizations reported an AI-model or AI-application breach and 97% of those lacked AI access
controls (S72). CSA, March 2026: 74% say agents often receive more access than necessary (S75).
*Qualifier:* all three are surveys or interviews, so this is correlation, and the 17%/76% figure is
Teleport's, not Zscaler's (an attribution error in this pass's own plan, caught by Lane 1).

**Claim 3. Least privilege and scope minimization for agent tools are now written down in
standards.** OWASP's AI Agent Security Cheat Sheet: "Grant agents the minimum tools required" and
"Implement per-tool permission scoping" (S12). The MCP spec's Scope Minimization section names
omnibus scopes (`*`, `db:*`, `admin`) as the failure and progressive step-up as the fix (S48).
OWASP's MCP Security Cheat Sheet: per-server scoped credentials, short-lived tokens over PATs,
OS-native credential storage, never plaintext tokens in MCP config (S49). OWASP Agentic Top 10 2026
gives the failure a name and number, **ASI03 Identity & Privilege Abuse** (S46); the beta MCP Top
10 adds MCP02 Privilege Escalation via Scope Creep (S58, cite as beta).

**Claim 4. Inherited and default grants widen access silently, on every platform.** Snowflake
`DEFAULT_SECONDARY_ROLES = ('ALL')` is a per-user property (S19) and `USE SECONDARY ROLES ALL`
re-evaluates every statement (S18). Postgres grants PUBLIC `CONNECT`/`TEMP` on databases and
`EXECUTE` on functions by default, and owners always hold all grant options (S27). Fabric workspace
Admins, Members, and Contributors "already have read and write permissions on all data" and are
not affected by OneLake security roles (S28). Databricks ABAC policies exempt any principal listed
in `EXCEPT` (S60). *Implication:* a check that reads only direct grants under-reports access; the
plugin's DB-01 does this today for Postgres role membership (Lane 3).

**Claim 5. Hashing is pseudonymization, not anonymization, and per-row salt in the same database
does not change that.** NIST SP 800-188 §4.3.2: "If a hashing key is not used or is discovered by
an attacker, it is possible for an attacker to perform a brute force search"; hashing or encryption
"to protect direct identifiers is not recommended" (S10). The EDPB's 2025 pseudonymisation
guidelines: pseudonymised data "is personal data" and the additional information (the key or salt)
"must be kept separately" (S61). OWASP's salting guidance: a unique salt defeats precomputed
tables but "fast hashing algorithms such as SHA-256 … allow attackers to perform large numbers of
guesses quickly" (S11). Snowflake's own stronger option is External Tokenization, which keeps the
reversible mapping outside the warehouse (S55, Enterprise). *What holds:* the video's core point,
that raw values must not reach the agent and that unsalted hashes of low-entropy identifiers are
susceptible to guessing and re-identification, is reinforced. What overstates is the word
"irreversibility" and the `SALT_KEYS`-in-the-same-schema design.

**Claim 6. Masked-view layers have documented bypass and inference limits.** Snowflake DDM rewrites
masked columns in projections, join predicates, WHERE, ORDER BY, and GROUP BY (S16); the inference
that a masked column used in a predicate can still leak through match/no-match follows from that
behaviour but is this report's inference, not a Snowflake-documented bypass. Dynamic tables refresh under
the **owner** role unless `EXECUTE AS USER` is set (S53, S54, Feb 2026), so a curated schema
materialized as a dynamic table can be refreshed by a wider role than `AI_AGENT`. BigQuery
documents query-duration, billing, and error-message side channels for RLS and recommends
separate tables for the most sensitive rows (S24, S25). Postgres RLS is bypassed by superusers,
`BYPASSRLS`, and owners, and referential-integrity checks are a covert channel (S26). Differencing
attacks on aggregates are why Snowflake ships differential privacy as a separate feature (S57).

**Claim 7. Audit trails have edition, statement-shape, and cache gaps.** Snowflake ACCESS_HISTORY
requires Enterprise and "does not always" record every QUERY_HISTORY row (S17). Persisted query
results live 24 hours, extended on reuse up to 31 days, and are reusable by any role with
privileges on the underlying tables (S56). Redshift's masking attachment view returns zero rows to
anyone below `sys:secadmin`, indistinguishable from "no policy" (S84), and audit logging plus the
query-text user activity log are off by default (S85). Postgres `pgaudit` writes to the server log,
not a queryable table, and cannot reliably audit superusers (S86). *Implication:* DB-05 must report **what it could not see**, not
just whether logging exists.

**Claim 8. Agent-tool deny rules are a partial boundary; OS sandboxing is the enforced one.**
Claude Code's Read/Edit deny rules apply to the built-in file tools, to recognized Bash file
commands (`cat`, `head`, `tail`, `sed`) and redirections, but not to `grep -r` or scripts that open
files themselves (S2). The sandbox merges deny paths into OS-level filesystem rules for Bash and
its children (S3). Bare filenames match at any depth (`Read(.env)` ≡ `Read(**/.env)`), while the
`./path` form is cwd-relative (S2). `.claudeignore` was never shipped (S43). Rehberger's
CVE-2025-55284 shows the failure mode: allowlisted `ping`/`nslookup` became a DNS exfiltration
channel for `.env` contents until v1.0.4 removed them (S63). *Plugin impact:* AC-01 recommends and
string-matches `Read(./.env)`; an equivalent or stronger rule spelled `Read(.env)` is flagged as
missing (false positive), and the recommendation itself is the narrower spelling.

**Claim 9. Sensitive data persists in local artifacts the warehouse boundary never sees.** Claude
Code stores transcripts in plaintext under `~/.claude/projects/` for 30 days by default (S9).
DuckDB persistent secrets are "stored in unencrypted binary format" in `~/.duckdb/stored_secrets`
(S31). OWASP warns against plaintext OAuth tokens in MCP config files (S49). The MCP spec requires
clients to show the exact startup command of a local server and recommends sandboxing it (S48).

**Claim 10. Non-human identity lifecycle is a recognized, largely unsolved gap.** Okta's ISPM
defines NHIs to include "service accounts, API keys, tokens … AI agents" and tracks rotation,
expiry, and staleness (S34). CSA surveys: only 20% had formal API-key offboarding in 2024 (S59);
in 2026, 84% doubt they could pass an agent-focused audit (S74), 33% do not know how often agent
credentials rotate and 68% cannot tell agent from human activity (S75), 82% have unknown agents and
only 21% have decommissioning processes (S76). NIST launched an AI Agent Standards Initiative on
agent identity and authorization in February 2026 (S68). Snowflake's `CREATE USER … TYPE = SERVICE
| SERVICE_AGENT` (S19) makes "is the AI principal a service identity?" a checkable fact, and its
agent-identity feature (GA 2026-07-23) marks agent sessions in `QUERY_HISTORY.agent_type` and
`ACCESS_HISTORY.agents_info` and lets a masking policy call `IS_AGENT_ACTIVATED()` so "regulated or
high-risk data isn't returned to an agent, even when the user's role would otherwise allow it"
(S77, S78). That is the thesis's identity-selection principle, productized by the vendor.

**Claim 11. Vendors are shipping native agent governance; the audit should verify its use, not
replace it.** Snowflake's June 2026 framework: distinct agent identities, RBAC and masking at the
data layer, tool invocations "visible, reviewable and governed" (S52). Databricks ABAC with
governed tags is the centralized alternative to per-table masks (S22, S60). Fabric OneLake
security scopes to rows and columns but only for Viewers (S28). IBM's 2026 report tells readers to
"secure agentic identities" with "tightly scoped permissions continuously enforced at runtime"
(S73). *Implication:* the plugin's differentiator is correlating agent-readable local material with
effective warehouse access and governed-data evidence in one reproducible report, which none of the
native features do across tools.

**Claim 12. A point-in-time audit needs an explicit drift story.** OWASP requires security testing
"after material changes to prompts, tools, memory, retrieval, policies, or model providers" (S12).
The draft Agentic Skills Top 10 names AST07 Update Drift (S13); the beta MCP Top 10 names MCP08 Lack
of Audit and Telemetry (S58). The plugin can honestly stop at "re-run on change, with a dated
baseline"; continuous monitoring is a different product (Codex "do not build" list, C36).

## 4. Threat map

| Trifecta leg (S7) | Repo / files | Agent config | MCP layer | Warehouse role | Provider / transcript |
|---|---|---|---|---|---|
| **Private data** | PII in exports (DC-01/02); secrets (SS-01..04); DuckDB secrets (S31) | `additionalDirectories`, missing deny rules (AC-01), `./`-only spellings (S2) | Warehouse MCP authenticating as a personal user (S1, S19) | Inherited/secondary/PUBLIC grants (claim 4); masked columns in predicates (S16); dynamic-table owner refresh (S53) | Plaintext transcripts 30 d (S9); result cache 31 d (S56) |
| **Untrusted content** | Query results and files read as instructions (S63) | Skills and instruction files (S13, S65) | Tool descriptions / poisoning (S64); local server startup commands (S48) | — | — |
| **External channel** | — | Allow rules for network commands (S63); `Bash(npx:*)` (AC-02) | Any server with egress; token passthrough (S48) | External stages, `UNLOAD` (Lane 3), `COPY … TO PROGRAM` via `pg_execute_server_program` (S87), DuckDB secrets (S30) | Provider retention tier (AC-06, S9) |
| **Operational controls the thesis omits** | Rotation of leaked secrets (SS-04 rotate-first exists) | Sandbox off by default; `failIfUnavailable` (S3) | Scope creep MCP02 (S58) | Service-user rotation and offboarding (S34, S75, S76); `EXECUTE AS USER` (S54); audit log gaps (claim 7) | Retention setting (S9) |

## 5. Gap matrix: claims and principles against today's checks

Cells: **covered** · **partial** · **absent** · **not auditable read-only**.

| Row | SS | AC | DC | DB | Competitor category covering it | Native platform feature |
|---|---|---|---|---|---|---|
| P1 schema segregation (AI role reaches curated schema only) | — | — | — | partial (DB-02 base-table reads, DB-04 name-based view layer) | DAM/DSPM vendors, commercial | RBAC everywhere |
| P2 hashing / masking of PII the agent can read | — | — | — | partial (DB-03 column names; no policy-attachment evidence) | dbt masking packages enforce, do not discover | DDM (Snowflake Ent.), UC masks/ABAC, Redshift DDM, BigQuery policy tags |
| P3 identity selection (service identity, not personal; no widening) | — | — | — | absent (role name only; no `TYPE`, no secondary roles, no inheritance walk) | CIEM / NHI products | Snowflake `TYPE=SERVICE`, `DEFAULT_SECONDARY_ROLES` (S19); Redshift `IAM:` prefix (Lane 3) |
| C4 inherited/default grants | — | — | — | partial (Snowflake hierarchy via SHOW GRANTS; Postgres `INHERIT`/PUBLIC absent) | — | S19, S27, S28, S60 |
| C5 hashing caveat and salt/key separation | — | — | — | absent (no check, no caveat text) | tokenization vendors | External Tokenization (S55) |
| C6 masking bypass: predicates, owner refresh, exempt principals, RLS bypass | — | — | — | absent | — | S16, S53, S60, S26 |
| C7 audit gaps: edition, shape, cache, secadmin-only views, log-file sinks | — | — | — | partial (DB-05 existence only; DB-06 UNKNOWN exists) | DAM | S17, S56, Lane 3 |
| C8 deny-rule semantics and sandbox | — | partial (AC-01 exact-string match on `./` spelling; no sandbox check; AC-02 env runners) | — | — | agentsec-scanner (S65) covers more tools | S2, S3 |
| C9 local artifacts (transcripts, DuckDB secrets, MCP config tokens) | partial (gitleaks on repo only) | partial (AC-05 transcripts INFO; AC-03 MCP literals) | — | — | agent-audit reads session logs (S66) | — |
| C10 identity lifecycle (rotation, expiry, decommissioning) | — | — | — | not auditable read-only from the warehouse alone (partial via `USERS` metadata) | CIEM (Okta ISPM S34, Entra S40) | — |
| C11 native governance in use (masking policies, ABAC tags, agent identity) | — | — | — | absent | — | S16, S22, S52 |
| C12 drift / re-test on change | — | — | — | — (no baseline fingerprint) | CI scanners with SARIF (S36, S65) | — |
| Warehouse MCP server is write-capable (config-level) | — | absent (AC-03 looks for credentials, not capabilities) | — | — | Snyk agent-scan runs the server to find out (S35) | Snowflake MCP `sql_statement_permissions` YAML (S81); Postgres MCP Pro `--access-mode=restricted` (S82); Toolbox `tools.yaml` statements (S83); Databricks Labs MCP has none (Lane 3) |
| Agent-tool coverage beyond Claude/Cursor/Gemini/Codex | — | absent (Windsurf, Cline, Roo, Continue, Copilot) | — | — | agentsec-scanner covers Continue/Roo/Cline (S65) | — |
| Warehouses beyond Postgres/Snowflake | — | — | — | absent | — | §7 |

## 6. Positioning by category (supersedes the README's 2026-07 table)

| Category | Representative tools (author-fetched where an `S#` is given; otherwise Lane-2 leads, not re-verified) | What they do | Relation to ai-data-security |
|---|---|---|---|
| Anthropic's own scanners | **Claude Security** (S51): Mythos 5.1 multi-agent code-vulnerability scans, patches, scheduled scans, CSV/Markdown export, Slack/Jira webhooks; Enterprise beta + Claude Code plugin beta. **security-guidance** (S37): pattern warnings, LLM diff review, commit review of Claude-written code | Vulnerabilities in code | **Different scope, same publisher.** Neither mentions warehouses, grants, or PII exposure. Name the distinction in the README; users will search "Claude security" first |
| Coding-agent config and forensic scanners | agentsec-scanner (S65): 7 agent tools, 53 secret rules, 18 MCP rules, SARIF; agent-audit (S66): session-log forensics, 296+ patterns | Config hygiene and forensics across many agent tools | **Closest overlap with `ai-config-audit`**, and broader tool coverage. They do not touch warehouses, PII classification, or the exposure matrix |
| MCP scanners and gateways | mcp-scan (S64), Snyk Agent Scan (S35; starts servers with consent, JSON), MCPScan (S36; SARIF, early-stage) | Tool poisoning, rug pulls, credential leaks inside MCP servers | Complement. Keep AC checks static; recommend these for internals. Do not start unknown servers during an audit |
| Secrets engines | gitleaks (S50): **feature complete, security patches only**, successor Betterleaks (S69) | Detection in repos and history | **Hard dependency.** Plan a Betterleaks adapter; keep fail-closed UNKNOWN when neither is present |
| PII discovery and catalogs | Presidio (S44; moving to the data-privacy-stack org), OpenMetadata auto-classification (S70), Macie (S38, S3-only) | Text/NER PII detection; catalog-wide tagging; cloud DSPM | Complement. Presidio remains the "deep tier" candidate; catalogs govern at platform scale |
| Policy-as-code and enforcement | OPA (S39), dbt masking packages (Lane 2) | Enforce policy once written | The remediation layer for what the audit finds |
| Non-human identity / CIEM | Okta ISPM (S34), Entra Workload ID (S40) | Lifecycle of service identities | Complement. The plugin can check *evidence* of a dedicated identity, not run its lifecycle |
| Prompt-side redaction | claude-code-privacy-guard, privacy proxies (Lane 2, not fetched) | Mask data in the live prompt | Complement; protects the conversation, not the disk or warehouse |
| Notebook scanning | NB Defense (README; maintenance not re-verified) | Secrets/PII in notebooks | Keep delegating; re-check maintenance before citing |
| Red-teaming | garak, promptfoo (README) | Adversarial testing of models | Out of scope |

Among the tools reviewed, none does all four of: warehouse grants for the AI principal,
unmasked-PII-column detection tied to that principal, file classification with counts-never-values,
and the secrets exposure matrix. That combination, delivered locally and free, is the lane. The
survey covered the categories above, not the whole market.

## 7. Platform governance, judged by read-only auditability

| Platform | Native controls | What a least-privileged auditor can prove | What it cannot | Sources |
|---|---|---|---|---|
| Snowflake | DDM and row-access policies (Enterprise), tag-based masking, External Tokenization (Enterprise), ACCESS_HISTORY (Enterprise), user types `PERSON / SERVICE / SERVICE_AGENT` (GA 2026-07-23), **agent identity** (`QUERY_HISTORY.agent_type`, `ACCESS_HISTORY.agents_info`, `IS_AGENT_ACTIVATED()` usable inside policies), secondary roles, dynamic-table `EXECUTE AS USER` | With `SNOWFLAKE.SECURITY_VIEWER`: GRANTS_TO_ROLES, ROLES, LOGIN_HISTORY; with `GOVERNANCE_VIEWER`: ACCESS_HISTORY, MASKING_POLICIES, QUERY_HISTORY, TAG_REFERENCES (S79); user `TYPE` and `DEFAULT_SECONDARY_ROLE` from ACCOUNT_USAGE.USERS; whether the AI principal's sessions are agent-marked (S77) | POLICY_REFERENCES as a table function returns only objects the caller owns unless it holds global APPLY (S80): a silent partial result, not an error; ACCOUNT_USAGE latency up to 120–180 min; masking on Standard edition (feature absent, not misconfigured); cached-result reads (S56) | S16–S20, S53–S57, S77–S80 |
| Databricks Unity Catalog | Row filters and column masks (SQL UDFs), ABAC with governed tags, `EXCEPT` exemptions, system tables | Policy attachment and exempt principals through system tables and REST | Exempt-principal semantics per policy require reading each policy | S22, S60 |
| BigQuery | Policy tags, RLS (with side channels), data masking layered on RLS, `OBJECT_PRIVILEGES` | Explicit bindings only; needs `bigquery.tables.getIamPolicy` | **Inherited bindings** (project/folder/org) are not in `OBJECT_PRIVILEGES` (S23), so effective access is partial without IAM-level read | S23–S25 |
| Redshift | RBAC, RLS, DDM, IAM database auth (`IAM:` username prefix), audit logging to S3/CloudWatch | Relation privileges and role grants (superuser or `ACCESS SYSTEM TABLE`); masking/RLS attachment only as `sys:secadmin` (S84) | Below `sys:secadmin` the masking views return zero rows silently (S84); audit logging and the user-activity log are off by default (S85); RLS attachment view and `IAM:` prefix per Lane 3 (T2 AWS docs, not re-fetched) | S21, S84, S85, Lane 3 |
| PostgreSQL | Object privileges, RLS, `security_barrier` views, `pgaudit` (extension), `anon` (extension), predefined file/program roles | Direct grants, role membership and `INHERIT`, `BYPASSRLS`, ownership, PUBLIC defaults, `pg_write_server_files` / `pg_execute_server_program` membership (S87), extension presence | Masking and audit depend on optional extensions; `pgaudit` logs to the server log and cannot reliably audit superusers (S86); `default_transaction_read_only` still allows temp-table writes and can be unset by the session (Lane 3, T2 PostgreSQL docs, not re-fetched) | S26, S27, S86, S87, Lane 3 |
| Microsoft Fabric / OneLake | OneLake security roles (object/column/row) for Viewers; SQL endpoint user-identity vs **delegated** mode | Workspace role of the AI identity; endpoint mode | Anything about masking if the identity is Admin/Member/Contributor or the endpoint is delegated (default for new endpoints) | S28, S29 |
| AWS Lake Formation | LF-tags, column permissions, data cell filters, `GetEffectivePermissionsForPath`, CloudTrail `GetDataAccess` | Effective permissions and tags via read/list IAM actions; data access events per principal | Requires an explicit audit principal with those IAM actions | S32, S33 |
| DuckDB / MotherDuck | No roles locally; `enable_external_access`, `lock_configuration`, `-safe`; unencrypted persistent secrets | File and config posture, secrets directory presence | Anything role-based; MotherDuck controls not verified | S30, S31 |
| dbt (static) | `meta` tags (`contains_pii` is a community convention, not a dbt Labs standard), exposures, third-party masking packages (`dbt-snow-mask` 0.1.7, `dbt-snowmask`; both community, low adoption signal) | Which models and columns carry a PII tag, which exposures consume them, whether a masking package is declared in `packages.yml`, all from YAML with no connection | Absence of a tag is not absence of PII; whether the warehouse enforces what the YAML declares | Lane 3 (T2 dbt docs and package READMEs; not re-fetched by the author) |

### 7b. Warehouse MCP servers: where "write-capable" is decided

| Server | Authenticates as | Write control | Detectable artifact for `ai-config-audit` | Source |
|---|---|---|---|---|
| Snowflake-Labs/mcp (official) | Whatever the Python connector is given: password, key pair, OAuth/SSO, PAT; "honors the RBAC permissions assigned to the specified role" | `sql_statement_permissions` list of statement types set True/False, `Unknown: False`, `All: True`; **no dedicated read-only flag** | The YAML passed with `--service-config-file` (no fixed path; find it from the MCP launch command in `.mcp.json` / `~/.claude.json`) | S81 |
| Postgres MCP Pro (crystaldba) | `DATABASE_URI` connection string | `--access-mode=restricted`: read-only transactions, time limits, SQL parsing rejects COMMIT/ROLLBACK | The literal `--access-mode=restricted` in the launch args; its absence means unrestricted in the documented examples | S82 |
| MCP Toolbox for Databases (Google) | Integrated IAM / env-var credentials per source | None global; each tool is a declared SQL statement | `tools.yaml`: grep tool statements for anything other than SELECT | S83 |
| Databricks Labs MCP | Credentials "with access to required APIs"; type unstated | None documented | Nothing to grep; capability equals the identity's Unity Catalog grants (push to DB checks) | Lane 3 (T2 repo; not re-fetched) |

The practical rule: only Postgres MCP Pro has a first-class read-only switch. For Snowflake the
check is a YAML parse; for Toolbox it is a statement scan; for Databricks the question collapses
back into the warehouse grants audit.

**Coverage order suggested by the evidence:** Snowflake depth first (the thesis platform, richest
metadata, service-user types), then Postgres depth (CI-testable; add `INHERIT`/PUBLIC/`BYPASSRLS`/
file-role checks), then Databricks and Redshift (strong system tables; Redshift needs a
`sys:secadmin` precondition), then BigQuery (partial by design), Fabric and Lake Formation via
recorded API output, DuckDB as a posture check rather than a grants pack. Codex ranked BigQuery
first; Lane 3's auditability criteria move it down because inherited bindings are invisible.

## 8. Codex versus Claude: what only one found

Only Codex, kept after verification: NIST SP 800-188 §4.3.2 as the primary source against
"irreversibility" (S10); OWASP's AI Agent Security Cheat Sheet and draft Agentic Skills Top 10 as
citation candidates (S12, S13); Fabric's delegated-mode default and Admin/Member bypass (S28, S29);
DuckDB's unencrypted secrets directory as a scanner target (S31); BigQuery `OBJECT_PRIVILEGES`
omitting inherited bindings (S23).

Only the Claude lanes: the Teleport 17%/76% statistic and its correct attribution (S45); gitleaks
declaring itself feature complete (S50, S69); the full ASI list from OWASP's announcement (S46);
the MCP spec's 2026-07-28 Scope Minimization section (S48); Rehberger's CVE and the 39C3 talk
(S62, S63); the EDPB guidelines text (S61); dynamic-table owner refresh and `EXECUTE AS USER`
(S53, S54); Redshift `sys:secadmin` zero-row trap and Postgres extension dependence (Lane 3); the
2026 CSA identity figures (S74–S76); the deny-rule depth semantics that affect AC-01 (S2).

Codex errors caught: a community YouTube tutorial labelled as a Snowflake vendor source; the 2025
LLM Top 10 cited while 2026 is current; a public-review draft presented as a standard.
Claude-lane errors caught: Lane 4 quoted CSA figures (78%, 92%) that the cited page does not
contain; Lane 1 could not open MITRE ATLAS technique pages, so its new ATLAS candidates are
unverified; Lane 2's "PolicyAware" seed does not resolve to a real tool.

## 9. Implications, by Kyle's four priorities

**Generate the fix (safe-db-access).** The evidence supports a *planner*, not an applier: emit
reviewed, platform-specific SQL and a validation script, executed by a human, then re-audit (Codex
C35/C36; SPEC §Out of scope). The recipe must change from the video in three places: keep the
hashing key or salt outside the AI role's reach and prefer keyed hashing or tokenization for
direct identifiers (S10, S61, S55); create the AI principal as `TYPE = SERVICE` with
`DEFAULT_SECONDARY_ROLES = ()` (S19); and if the curated layer is a dynamic table, set `EXECUTE AS
USER` or verify the owner role (S53, S54). *What the evidence does not support:* any claim that
the resulting data is anonymous or that the setup is "safe".

**Dead-simple install and first run.** One command is table stakes and a named setup or health
skill is now expected (Lane 2 benchmark: three of five plugins ship one). The first run must show
prerequisites (gitleaks or Betterleaks, `psql`, `snow`), what it will and will not verify, and
UNKNOWNs up front. gitleaks' freeze (S50) means the doctor should detect both scanners. *Not
supported:* zero-invocation always-on behavior, which is a hook product, not an audit.

**Broader coverage.** Order by auditability, not by market share (§7). The highest-leverage
additions are not new warehouses but new *evidence* on the existing two: user type and secondary
roles, inheritance walk, policy attachment, audit-log gaps, dynamic-table owner. Agent-tool
coverage should follow agentsec-scanner's list (Continue, Roo, Cline, Windsurf) (S65). A dbt
static audit multiplies coverage across every warehouse (pending Lane 3 detail). *Not supported:*
a MotherDuck pack (controls unverified) or BigQuery "effective access" claims (S23).

**Credibility and standards.** Add ASI03 and ASI02 from the 2026 Agentic Top 10 (S46); re-verify
LLM01/02/06 against the 2026 LLM edition before citing it (S47); add the OWASP AI Agent and MCP
cheat sheets (S12, S49) and the MCP spec's dated security page (S48); cite MCP02/MCP08 and
AST03/AST07 only as beta/draft (S58, S13); record publication and access dates and a
`current | superseded | withdrawn` status per citation (Codex C35). Replace the video's IBM 2025
statistic with the 2026 report where a fresher number helps (S72, S73), and never attribute the
17%/76% figure to Zscaler (S45). *Not supported:* CIS section-level citations until the gated PDFs
are read (S67); MITRE ATLAS additions until primary pages are fetched.

## 10. Coverage limits of this pass

- Lane 3 covered Redshift and PostgreSQL in depth and, in a follow-up, Snowflake auditor roles,
  dbt, and warehouse MCP servers; Databricks, BigQuery, Fabric, Lake Formation, and DuckDB rest on
  the author's own fetches (S22–S33, S60) and Codex's verified claims rather than a full lane.
- Snowflake's agent-identity feature (S77, S78) postdates the thesis video by two months and is
  not yet reflected in the plugin, the video, or the demo repo.
- The OWASP LLM Top 10 2026 and CIS benchmark PDFs were not opened; item lists come from landing
  pages or remain unverified.
- Conference talks were verified by page metadata, not watched; timestamps quoted by Codex are
  unverified.
- MITRE ATLAS technique pages returned 404 to the fetcher; the registry's three IDs are assumed
  current and no new IDs are proposed.
- All survey statistics (Teleport, IBM, CSA) are self-reported and correlational.
