# Changelog

All notable changes to AI Data Security are documented here. This project follows
[Semantic Versioning](https://semver.org). Dates are ISO-8601.

## [0.11.0] — 2026-09-13

AWS Lake Formation pack (coverage, fifth platform), **partial by design**: recorded AWS CLI JSON,
no SQL. Lake Formation grants are explicit; where IAM alone governs (IAMAllowedPrincipals, hybrid
access mode, unregistered locations, S3 policies) the report says so.

### Added
- **`db-access-audit --dialect lakeformation`** (recorded via `--recorded <dir>`; seven JSON
  captures from the user's own AWS CLI: the principal's and everyone's `list-permissions`,
  `get-data-lake-settings`, `list-data-cells-filter`, Glue `get-tables`, `list-resources`,
  `list-attached-role-policies`). The module evaluates table / TableWithColumns (inclusion and
  exclusion lists) / TableWildcard / database / catalog / data-location grants, grantable
  permissions, catalog `SUPER_USER`, `IAMAllowedPrincipals` and `ALLIAMPrincipals` as everyone-paths,
  data cells filters (counted as protection only when granted with SELECT and captured) beside the
  TableWithColumns column controls, 'Use only IAM access control' defaults and data lake admins
  (DB-07), IAM users vs roles and AWS-managed S3 policies by name (DB-ID-01; inline / customer /
  group policies always DB-06), hybrid-mode locations judged per principal from
  `list-lake-formation-opt-ins` (DB-07, or DB-06 without opt-ins), DATA_LOCATION_ACCESS (DB-10),
  CloudTrail trails from `describe-trails` (DB-05, or DB-06 without it), and states that
  GetDataAccess carries no query text and that direct S3 reads appear only as S3 data events.
  LF-tag-based and conditional grants are never resolved: they surface as DB-06. Six AWS pages
  fetched live (+1 from the research pass) for the citation registry.
- `doctor` lists the Lake Formation pack (`aws`).

## [0.10.0] — 2026-09-13

Microsoft Fabric Warehouse / SQL analytics endpoint pack (coverage, fourth platform), **partial by
design**: T-SQL sees GRANT/DENY, roles, masks, and policies; it cannot see workspace roles or item
permissions, which the report repeats on every finding.

### Added
- **`db-access-audit --dialect fabric`** (recorded via `--recorded <dir>`; live capture through the
  user's own `sqlcmd -G` over TDS 1433, Entra authentication only). Six T-SQL pack files over
  `sys.database_principals`, `sys.database_role_members`, `sys.database_permissions` (database /
  schema / object / column, GRANT / DENY / grant-with-grant-option), `sys.columns` +
  `sys.masked_columns`, `sys.views` + `sys.security_policies`, and `queryinsights`; each file emits
  its own header so `sqlcmd -h -1` CSV is self-describing. Optional `audit_status.json` from the
  Fabric REST `settings/sqlAudit` endpoint and `endpoint_mode.json` (a lakehouse SQL analytics
  endpoint in OneLake user-identity mode makes every table-access verdict UNKNOWN). The module walks
  role membership transitively, treats the fixed roles `db_owner` / `db_datareader` /
  `db_datawriter` / `db_ddladmin` and schema/object **ownership** as authority with no permission
  rows, applies the Database Engine precedence rules (DENY beats GRANT at a covering scope; a
  column-level GRANT overrides an object-level DENY; CONTROL implies SELECT, ALTER does not), shows
  each PII column's dynamic data mask and whether UNMASK / CONTROL / ownership makes it non-binding,
  treats EXECUTE on procedures and functions as an opaque read path (DB-06), and reports SQL audit
  logs as DISABLED (MEDIUM) / enabled without predicate (INFO with groups and retention) / with a
  predicate or malformed or not captured (DB-06), noting when no selected action covers SELECT.
  Free-text CSV fields are `QUOTENAME`-quoted (mask functions contain commas). DB-10 is an INFO that
  OneLake, shortcuts, and Direct Lake read the same Delta files outside the SQL endpoint. A permanent
  DB-06 states that workspace roles (Admin/Member/Contributor = CONTROL, Viewer = ReadData on every
  table) and item permissions are not visible from T-SQL. Ten Microsoft Learn pages fetched live for
  the citation registry.
- `doctor` lists the Fabric pack (`sqlcmd`).

## [0.9.0] — 2026-09-13

Google BigQuery pack (coverage, third platform), **partial by design** as the roadmap promised:
explicit object bindings plus the project IAM policy, with everything else stated as UNKNOWN.

### Added
- **`db-access-audit --dialect bigquery`** (recorded via `--recorded <dir>`; live capture through
  the user's own `bq` and `gcloud`). SQL over `INFORMATION_SCHEMA.OBJECT_PRIVILEGES` (queried per
  dataset and per table, as the view requires), `COLUMNS`, `TABLES`/`VIEWS`, and `JOBS`; JSON
  captures for the project IAM policy (the inherited access OBJECT_PRIVILEGES never lists),
  user-managed service-account keys, the `_Default` log bucket, and row access policies; policy
  tags from `bq show --schema`. The module maps IAM roles to capabilities (dataViewer / dataEditor
  / dataOwner / admin), applies project-level roles to every dataset, dataset-level to every
  table, `allUsers` / `allAuthenticatedUsers` to everyone, and notes access as latent when the
  principal has no `jobUser`/`user` role in the project. Basic roles (Owner / Editor / Viewer) are
  identity breadth, not table access; conditional bindings are excluded; grants on views are kept
  out of PII exposure. PII names come from `COLUMN_FIELD_PATHS` (nested STRUCT fields count).
  DB-08 joins policy tags AND data policies to readable PII fields. DB-05 is INFO (Data Access
  logs are on by default); DB-09 reports the principal's own cache hits and `_Default` retention.
  DB-10 covers project-level Cloud Storage write roles and readable EXTERNAL tables. A `bq ls`
  manifest proves the per-table capture completed. Permanent DB-06s for: explicit-bindings-only,
  group / domain / principal-set membership, custom roles, conditional bindings, deny policies and
  principal access boundaries, authorized views, taxonomy and data-policy IAM. Eight BigQuery doc
  pages verified for the citation registry.
- Module dialects may declare `JSON_INPUTS` (and `OPTIONAL_JSON_INPUTS`); the loader reads
  `<name>.json`, and a missing or invalid required file is a DB-06 naming the capture command.
- `doctor` lists the BigQuery pack (`bq` + `gcloud`).

## [0.8.0] — 2026-09-13

Amazon Redshift pack (coverage, second platform). Invariants unchanged; other dialects' verdicts
unchanged on the same inputs.

### Added
- **`db-access-audit --dialect redshift`** (recorded CSVs via `--recorded <dir>`; live capture is
  plain `psql --csv` on port 5439). Twelve read-only pack files over the SVV views and the
  PostgreSQL-derived catalog. The module models Redshift's identity semantics: a database user,
  its roles walked transitively through `svv_role_grants`, its groups (`pg_group`), and PUBLIC;
  schema USAGE required before a relation grant counts (otherwise a LOW latent grant); scoped
  `TABLES` grants at schema *and database* level cover future tables; relation **ownership** is
  write authority with no grant row; **column-level** SELECT/UPDATE grants (`svv_column_privileges`)
  are read/write paths with no relation row; object names compare lowercased unless
  `enable_case_sensitive_identifier` is true, identity names as recorded. DB-ID-01 flags superusers
  (CRITICAL), password-authenticated agents (no `IAM:`/`IAMA:` prefix), transitive `sys:*` admin
  roles (CRITICAL), group membership, and ownership. DB-08 joins the **output columns** of
  `svv_attached_masking_policy` to readable PII columns *for the agent's identities or PUBLIC* (a
  policy attached to another role does nothing) and, like DB-04, is UNKNOWN when the capture ran
  below `sys:secadmin`, because those views return zero rows. Below superuser, every grant-derived
  verdict is declared partial (`svv_relation_privileges` hides other identities' rows). DB-05 reads
  `enable_user_activity_logging`; DB-09 states the SQL-invisible export setting and
  SYS_QUERY_HISTORY's own-rows rule; DB-10 covers USAGE on external schemas plus UNLOAD / COPY /
  EXTERNAL FUNCTION grants from `svv_iam_privileges` (UNLOAD → CRITICAL), with a narrow DB-06 for
  bucket-level IAM/S3 authorization. Thirteen Redshift doc pages fetched live for the registry.
- `doctor` lists the Redshift pack (psql).

## [0.7.0] — 2026-09-13

Platform coverage begins (ROADMAP "v1.x", shipped as 0.7+): the Databricks Unity Catalog pack,
plus the Snowflake carry-over from the v0.4 review gate. Invariants unchanged; Postgres and
Snowflake verdicts unchanged on the same inputs.

### Added
- **`db-access-audit --dialect databricks`** (recorded CSVs via `--recorded <dir>`; live capture
  through the user's own Databricks SQL CLI). Seven read-only pack files over
  `system.information_schema` plus `SHOW GROUPS WITH USER`. The module models Unity Catalog's
  identity semantics: principal kind by shape (applicationId UUID = service principal, email =
  user, group), group grants apply to members, catalog/schema grants apply to every child object
  (`INHERITED_FROM`), `account users` is everyone. Every check DB-01..DB-10 and DB-ID-01 fires with
  evidence that says how a grant reaches the principal (`direct`, `via group`, `inherited from`).
  DB-08 joins `COLUMN_MASKS` to readable PII columns and states that ABAC exemptions are not
  visible. DB-10 covers external locations, storage credentials, and volumes. A permanent DB-06
  states the INFORMATION_SCHEMA own-grants visibility precondition.
- **Evaluator dialect modules** (`scripts/dialects/<platform>.py`, `PACK` + `evaluate`) so
  further platforms add a module and a pack, not more branches in `eval_grants.py`.
- **Snowflake `identity.sql` statement 3**: `CURRENT_USER()`, `CURRENT_ROLE()`,
  `CURRENT_SECONDARY_ROLES()` of the audit session. When the audit runs as the AI user, a session
  role that differs from `--role` becomes DB-ID-01 evidence; active secondary roles (parsed from the
  documented JSON) are named and make every verdict provisional via a DB-06 (their grants were not
  captured); an older two-statement capture is a DB-06 UNKNOWN for that comparison.
- The Databricks module models Unity Catalog's effective-access rule (SELECT counts only with USE CATALOG + USE SCHEMA on the path; otherwise a LOW latent-grant finding), treats MANAGE and catalog/schema ownership as control-plane reach (DB-ID-01 CRITICAL, DB-01), cascades catalog/schema READ/WRITE VOLUME into DB-10, compares identifiers casefolded, and reports DB-04 as UNKNOWN when view definitions are not visible to the capturing user.
- `doctor` detects `dbsqlcli`; six Databricks doc pages fetched live and added to the citation registry.
- Evaluator CSV loaders now validate the header of a zero-row capture too (a wrong-column, empty file used to pass as "nothing found").

### Changed
- `eval_grants` `--grants/--pii/--views/--settings` are required per dialect rather than globally
  (module dialects take `--recorded`). The planner refuses non-Postgres/Snowflake dialects with a
  plain message (no templates yet) instead of "dialect unknown".

## [0.6.0] — 2026-09-12

The safe-db-access **planner** (ROADMAP v0.6; approved SPEC amendment 2026-09-11): the first
"generate the fix" experience, delivered as reviewable text. Invariants unchanged. Existing
finding verdicts are unchanged on the same inputs; DB-03's remediation text now points at keyed
hashing and the planner instead of "per-row salted hashing", and the JSON gains `plan_inputs`.

### Added
- **`/ai-data-security:safe-db-access --audit <eval.json>`**: renders, for Postgres and Snowflake,
  (1) a service identity (`NOINHERIT`/no server roles; `TYPE = SERVICE_AGENT`,
  `DEFAULT_SECONDARY_ROLES = ()`), (2) a key vault for keyed-hash pseudonymization with the key
  outside the AI role's reach, (3) a curated schema of masked views (Restricted omitted,
  Confidential hashed; Snowflake secure views plus an `IS_AGENT_ACTIVATED()` masking policy on
  Enterprise+), (4) revoke-raw / grant-curated incl. default privileges, PUBLIC (flagged REVIEW),
  stages, (5) audit trail with the retention caveat, (6) a validation script run *as the AI role*,
  with PUBLIC revocations rendered commented out unless `--include-public-revokes` (they affect
  every role), curated view names that cannot collide across schemas, and Snowflake masking
  policies attached only to STRING-typed columns (others make the plan INCOMPLETE),
  (7) rollback. Fixed templates; every identifier validated; hostile names are listed under NOT
  RENDERED and never reach SQL; missing inputs make the plan INCOMPLETE. The planner never
  connects, executes, or writes a file. Every plan states that hashed identifiers are pseudonymized,
  not anonymized.
- **`columns.sql`** in the Postgres pack (read-only; names and types only) and `--columns` on the
  evaluator, so curated views can name their columns explicitly.
- **`plan_inputs`** in the db-access-audit JSON (`eval_grants` tool version 3 → 4): value-free
  structured facts the planner consumes; independent of findings, `null` when an input is missing.
- **CI proof**: the Postgres docker fixture now renders the plan, applies it as the DBA, runs the
  validation script as `ai_agent` (every row `ok = t`), proves a raw read is refused and the
  curated query succeeds, re-audits (DB-01/02/03/04/07/10/ID-01 gone), rolls back, and re-audits
  (pack outputs back to the goldens). Both dialects' renders are diffed against goldens; refusal
  paths are tested; `dev/validate.sh` lints the planner for connect/execute/write primitives.

### Changed
- **Pseudonymized tier** (evaluator, both dialects): a PII-named column with a `_pseudo` / `_hash`
  / `_hmac` / `_token` suffix **on a view whose definition hashes or masks** is reported by DB-03
  as INFO ("still personal data", NIST SP 800-188 §4.3.2) and no longer counted by DB-08 as
  unattached raw PII. Provenance, not names: a base-table column named `ssn_hash` stays Restricted,
  and without a views input nothing is pseudonymized. Without this tier the plan's own output
  re-triggers the findings it fixed.
- `identity.sql` (Postgres) now records the grantor of each default privilege
  (`default_acl` detail is `grantor:PRIVILEGE`), because `ALTER DEFAULT PRIVILEGES` must say
  `FOR ROLE <grantor>` to have any effect on that grantor's future objects.
- `doctor` lists the planner; `security-audit` phase 4b appends the plan after a DB audit with
  findings; `db-access-audit` step 6 offers it.

## [0.5.0] — 2026-09-12

Agent-config depth (ROADMAP v0.5): the config-side checks now cover the seams where 2025–2026
incidents actually entered (unpinned MCP packages, write-capable warehouse servers, credential
files outside the repo) and six more agent tools. Plus a new static dbt audit and three more
content validators. Invariants unchanged; existing findings byte-identical on the same inputs
(the evaluators' tool versions change, and new checks may add findings).

### Added
- **AC-08 capability inventory (INFO).** When warehouse-shaped MCP servers and external channels
  (remote MCP servers, network allow rules) are both configured, one INFO finding lists them and
  cites OWASP ASI02 and the AI Agent Security Cheat Sheet. It is an inventory, never a detection.
- **AC-09 MCP server provenance.** `npx` / `uvx` / `bunx` / `pipx run` / `pnpm dlx` packages without
  an exact pin (`@x.y.z` or `==x.y.z`), `@latest`, and git/URL sources without a full commit SHA
  (MEDIUM, probable).
- **AC-10 write-capable warehouse MCP.** Snowflake-Labs/mcp `sql_statement_permissions` (read from
  the YAML named by `--service-config-file`), Postgres MCP Pro `--access-mode`, Toolbox `tools.yaml`
  statements (HIGH when writes are enabled, including `Unknown: True` and data-modifying CTEs; tool
  statements are never echoed); Databricks MCP has no write control (INFO). A config that cannot be
  found or parsed, a remote Postgres MCP whose mode lives server-side, and a Toolbox statement the
  matcher cannot classify are each an **UNKNOWN**, never a pass.
- **AC-11 local sensitive sinks.** DuckDB persistent secrets (`~/.duckdb/stored_secrets`, stored
  unencrypted), credential-shaped keys with literal values in `~/.snowflake/connections.toml`,
  `~/.databrickscfg`, `~/.dbt/profiles.yml`, `~/.aws/credentials`, `~/.pgpass` (key names only),
  and shell history files with no `*_history` deny rule.
- **Six more agent tools** in the MCP config matrix: VS Code / Copilot `.vscode/mcp.json` (with
  `headers` scanned by key name), Windsurf, Cline, Roo Code, Continue (`config.yaml` and
  `.continue/mcpServers/*`), GitHub Copilot CLI, OpenCode (`mcp.servers`; list-form `command`).
- `scripts/yaml_subset.py`: one shared stdlib YAML-subset reader for every YAML the plugin
  inspects; unsupported shapes raise, and callers report UNKNOWN.
- **Content validators**: IBAN (mod-97 → Restricted), phone (E.164 / NANP → Confidential), IPv4
  (→ Confidential). Counts only.
- **`/ai-data-security:dbt-governance-audit`**: static audit of a dbt project's YAML (no
  connection): DBT-01 PII-tagged models consumed by exposures with no masking layer declared,
  DBT-02 likely-PII columns without a PII tag, DBT-03 UNKNOWN for unparseable files and
  `depends_on` forms it cannot read, DBT-04 INFO on masking packages. Masking is honored only when
  declared per model (`meta.masked` and friends) or as a package; a model merely *named* like a
  masked layer is reported as a hint. Every finding states that a missing tag is not proof of no PII.
- Citation: MCP Security Best Practices, Local MCP Server Compromise section.

### Changed
- `permeval` tool version 2 → 3; `classify_hints` 2 → 3. AC-03 now also flags credential-shaped
  `headers` keys (including `Authorization`) on remote MCP servers.

## [0.4.0] — 2026-09-12

The decision-quality DB audit (ROADMAP v0.4). DB findings now name a remediable boundary and say
what they could not see. Every new input is optional and fails closed: a missing capture is a
DB-06 UNKNOWN with the exact statement to run, never a pass. Invariants unchanged (scripts decide,
model narrates; extends-only; stdlib-only). The DB-01..DB-05 finding payloads are unchanged on the
same inputs; the evaluator's tool version and the four "not captured" DB-06 entries are the only
differences a 0.3.0 caller sees.

### Added
- **DB-ID-01 effective identity.** Postgres: superuser / BYPASSRLS / CREATEROLE / replication
  attributes (CRITICAL), owned relations, and INHERIT role memberships walked recursively.
  Snowflake: `DESCRIBE USER` + `SHOW GRANTS TO USER` — a `TYPE = PERSON` user, `DEFAULT_SECONDARY_ROLES
  = ('ALL')`, more than one role granted to the agent's user, or a `DEFAULT_ROLE` different from
  the audited role (HIGH). A capture without `TYPE` is UNKNOWN, not a finding. The role name is not
  the boundary; the user's type, default role, and secondary roles are (Snowflake agent identity,
  GA 2026-07-23).
- **DB-07 raw-to-curated boundary crossed indirectly.** Postgres: SELECT reachable through
  inherited role grants, PUBLIC grants, or `ALTER DEFAULT PRIVILEGES`. Snowflake: `USAGE` on
  ROLE (inheritance). Revoking direct SELECTs would not close these.
- **DB-08 governed-control attachment.** Postgres: readable PII columns with no PostgreSQL
  Anonymizer (`anon`) masking label, with RLS state reported and the absence of any masking
  mechanism stated. Snowflake: `ACCOUNT_USAGE.POLICY_REFERENCES` (needs
  `SNOWFLAKE.GOVERNANCE_VIEWER`; the INFORMATION_SCHEMA table function is deliberately not used
  because it returns only owned objects); dynamic tables refreshing as their owner without
  `EXECUTE AS USER` are an INFO note.
- **DB-09 audit-trail quality.** Postgres: pgaudit loaded and configured, per-role
  `log_statement`, collector and destination. Snowflake: who holds `GOVERNANCE_VIEWER`, and
  `USE_CACHED_RESULT` for the AI user (cache hits show 0 rows in access history). Probable at
  best on Snowflake, as DB-05 already was. The holder query reads `ACCOUNT_USAGE.GRANTS_TO_ROLES`
  (needs `SNOWFLAKE.SECURITY_VIEWER`) because `SHOW GRANTS` has no `OF DATABASE ROLE` form.
- **DB-10 paths outside the database.** Postgres: `pg_write_server_files` /
  `pg_execute_server_program` (CRITICAL, they bypass all database permission checks) /
  `pg_read_server_files`, foreign servers the role may USE, and EXECUTE on server-reaching
  functions (`dblink*`, `pg_read_file`, `pg_ls_dir`, `lo_import`/`lo_export`); installed network
  extensions are reported as context, not as a finding. Snowflake: `USAGE` on STAGE,
  INTEGRATION, or EXTERNAL VOLUME.
- New pack files: Postgres `identity.sql`, `policy_attachment.sql`, `external_paths.sql`,
  `audit_quality.sql`; Snowflake `identity.sql`, `policy_references.sql`, `audit_quality.sql`;
  `masked_views.sql` gains `SHOW DYNAMIC TABLES`. Evaluator inputs `--identity`, `--policies`,
  `--external`, `--audit-quality`; skill argument `--user <ai-user>` for Snowflake.
- **Auditor-privilege precondition** stated in the skill gate and reference: `GRANT DATABASE ROLE
  SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE <auditor>` (policy references) and `SNOWFLAKE.SECURITY_VIEWER`
  (grants to roles); without them DB-08/DB-09 are UNKNOWN, and the audit never asks to run as
  ACCOUNTADMIN. Recorded Snowflake inputs are header-validated per statement; a renamed or missing
  column fails closed to DB-06 instead of silently passing.
- Citations: Snowflake agent identity and access-control overview, NIST SP 800-188 §4.3.2,
  PostgreSQL predefined roles.
- Fixtures: the Postgres fixture gains an inherited analyst group, a PUBLIC grant, default
  privileges, and `pg_write_server_files`; goldens regenerated; Snowflake recorded fixtures
  for identity, policy references, audit quality, a stage grant, role inheritance, a dynamic table.

### Changed
- `eval_grants` tool version 2 → 3. Remediation text names the service-identity target
  (`SERVICE_AGENT`, `DEFAULT_SECONDARY_ROLES = ()`; NOINHERIT on Postgres) and keyed hashing or
  tokenization with the key outside the AI role's reach.

## [0.3.0] — 2026-09-11

The trustworthy-first-run release, shaped by the September 2026 research pass (`docs/research/`).
Every v1 invariant holds: scripts decide and the model narrates, extensions only add detection,
unverifiable states fail closed to UNKNOWN, stdlib-only, and a repo with no config behaves
byte-identically to 0.2.0 except where a check was corrected below.

### Added
- **`/ai-data-security:doctor`** — detects gitleaks, `psql`, `snow`, docker, `claude`, `jq`;
  verifies the citation/check registry and that every evaluator compiles; reports Bash sandbox
  posture; prints a capability matrix naming which checks will be UNKNOWN on this machine.
  Betterleaks (gitleaks' successor) is reported for information only (SPEC design rule 6).
- **`/ai-data-security:quick-check <path>`** — zero flags, three verdict lines (agent-readable
  secrets on disk, deny-rule and sandbox posture, Restricted/Confidential file counts) plus the
  full UNKNOWN list, reusing the existing evaluators with citations and fingerprints intact.
  Says out loud what it does not do (no git history, no warehouse, AC-06 always UNKNOWN); a
  suppressed finding is reported as suppressed, never as a pass; each lane has a 35-second
  budget so the whole run stays under two minutes and a timeout becomes an UNKNOWN. Evaluator
  stderr is never surfaced (fixed error categories only), keeping the evaluators as the
  redaction boundary.
- **AC-07 Bash sandbox posture** — reports when `sandbox.enabled` is not true in user settings or
  the project's `settings.local.json`. Deny rules bind Claude's file tools and recognized Bash
  file commands, not `grep -r` or scripts; only the sandbox enforces the same paths at the OS
  level (Claude Code permissions and sandboxing docs, verified 2026-09-11).
- **SARIF 2.1.0 export** (`scripts/to_sarif.py`; `security-audit … --sarif <file>`): severities map
  to SARIF levels, UNKNOWNs become tool notifications, suppressions carry their reason, every
  result carries the plugin fingerprint. Adds no content and withholds the one unredacted field
  (free-text suppression reasons), so it is as shareable as the report.
- **Citation provenance** — every `reference/citations.yml` entry now records `published`,
  `accessed`, and `status` (`current | superseded | withdrawn`); CI fails a check that cites a
  withdrawn entry. New entries: OWASP Top 10 for Agentic Applications 2026 (ASI02, ASI03), OWASP
  AI Agent Security Cheat Sheet, OWASP MCP Security Cheat Sheet, MCP Security Best Practices
  (dated 2026-07-28), Claude Code permissions and sandboxing docs. DB-01/DB-02 now cite ASI03,
  DB-05 the agent cheat sheet, AC-02 ASI02, AC-03 the MCP cheat sheet.
- **Mission and Vision** in the README, a category-level "what this is not" table (naming
  Anthropic's Claude Security plugin), and `ROADMAP.md`.
- **SPEC amendment** (recorded in `SPEC.md`): a read-only `safe-db-access --plan` may generate the
  remediation recipe as text for human execution. Applying it, and enforcement hooks, remain v2.

### Changed
- **AC-01 matches deny rules by meaning, not spelling.** `Read(.env)`, `Read(**/.env)`,
  `Read(./.env)`, `Read(/.env)`, and `Read(//**/.env)` all satisfy the `.env` requirement; 0.2.0
  compared strings and flagged the stronger any-depth spelling as "missing". The recommendation is
  now the bare-name spelling (a bare filename matches at every depth; `./.env` covers only the
  project root). Regression-locked in `tests/test_matchers.py`. `permeval` tool version 1 → 2.
- The AC-01 subprocess caveat now states the documented boundary precisely (file tools plus
  `cat`/`head`/`tail`/`sed` and redirections; not `grep -r` or scripts) and points at AC-07.
- **Hashing caveat** in `db-access-audit/reference.md` and the four-tier framework: hashed
  identifiers are pseudonymized, not anonymized (NIST SP 800-188 §4.3.2; EDPB Guidelines 01/2025);
  keyed hashing or tokenization with the key outside the AI role's reach is the recommendation,
  and Snowflake's `SERVICE_AGENT` user type (GA 2026-07-23) with `DEFAULT_SECONDARY_ROLES = ()`
  is the identity target.
- The repo's own `.claude/settings.json` and the hardened fixture use the any-depth spellings.

### Fixed
- README "companion content repo" link pointed at this repository; it now points at
  `ai-data-security-demo`.

### Notes
- v0.2.0 (2026-07-15) was merged but never tagged; it is not back-tagged. This release carries
  its notes below.
- OWASP published the LLM Top 10 2026 edition on 2026-08-03. The LLM01/02/06 entries stay
  `current` and cite the 2025 edition until the 2026 renumbering is verified against its PDF.
- MITRE ATLAS technique pages returned 404 to the research fetcher; the three ATLAS entries are
  unchanged and flagged for re-verification before the next release.

## [0.2.0] — 2026-07-15

The adaptability release: the audit learns an organization's vocabulary without giving up a
single v1 invariant — scripts still decide, extensions only ever add detection, unverifiable
states still fail closed, and a repo with no config behaves byte-identically to v0.1.x.

### Added
- **Org profile** — an optional `.ai-data-security.yml` at the audited repo's root
  (JSON-formatted, stdlib-parsed; see `reference/org-config.md`): org-specific PII filename and
  column tokens at either floor, warehouse argument defaults for db-access-audit, and org
  citations appended to matching findings. Extends-only by construction (tokens are validated
  identifiers, so a config line can never inject regex syntax or relax a builtin); a
  present-but-unparseable profile surfaces as a DC-03/DB-06 UNKNOWN — never silently ignored.
- **Snowflake verdicts are script-computed.** `eval_grants.py --dialect snowflake` parses the
  recorded `snow sql` outputs (the same files `--recorded` air-gapped runs use) and computes
  DB-01..DB-05 mechanically — closing the one place where v1 asked the model to apply
  reference.md's interpretation table "mentally". DB-05 stays capped at `probable` (partly
  organizational); malformed recorded output fails closed to DB-06.
- **Marketplace `renames` map** (`datawarden` → `ai-data-security`) so installs under the old
  name migrate instead of breaking (Claude Code ≥ 2.1.193).
- **System-evolution retro** at the end of `/security-audit`: when the audit missed or
  over-flagged, fix the layer — org profile, ignore file, worker skill, or evaluator pattern —
  and file plugin gaps against the plugin repo.

### Changed
- **PII column patterns now match at token boundaries** across `classify_hints.py`, both SQL
  packs, and the four-tier framework: `member_ssn`, `customer_email`, and `email_address`
  match; `emailed_at` does not. The anchored `^…$` patterns missed every prefixed real-world
  column name. The SQL packs also accept `org_restricted`/`org_confidential` regex variables
  (no-op default `(^|_)(__none__)(_|$)`).
- Evaluator tool versions: `classify_hints` and `eval_grants` 1 → 2 (reports show which
  behavior produced a verdict).

### Deferred (noted for a future release)
- Skill trigger evals (skill-creator description-tuning); submission to
  `claude-plugins-community`; the v2 enforcement hooks and safe-db-access IMPLEMENT recipe
  already on the roadmap.

## [0.1.2] — 2026-07-09

### Changed
- **Renamed the plugin `datawarden` → `ai-data-security`** to match the AI Data Security series.
  This changes the repository, the command prefix (`/ai-data-security:<skill>`), the marketplace
  install id (`ai-data-security@ai-data-security`), and the suppression-file convention
  (`.datawarden-ignore` → `.ai-data-security-ignore`). No functional change to any skill. GitHub
  redirects the old repo URL, but existing installs should be reinstalled under the new name:
  ```bash
  claude plugin marketplace remove datawarden 2>/dev/null; claude plugin uninstall datawarden 2>/dev/null
  claude plugin marketplace add kyle-chalmers/ai-data-security
  claude plugin install ai-data-security@ai-data-security
  ```

## [0.1.1] — 2026-07-09

### Fixed
- **data-classification filename precision** — a source-code or docs filename that merely contains
  a sensitive word (`eval_secrets.py`, `payment_service.go`, `security.md`) no longer floors the
  file by name alone; classification of source/doc files is now content-driven. Data/config files
  (`.env`, `credentials.json`, `secrets.yaml`, `.csv`, `.pem`) still floor on their name, and real
  secrets hardcoded inside source are still caught by content scanning.

### Added
- AI Data Security now passes its own `ai-config-audit` — a `.claude/settings.json` ships the secret
  deny-rules AC-01 recommends.
- A repository `.ai-data-security-ignore` triages AI Data Security's own example/fake PII (docs, tests,
  fixtures) so a self-audit returns clean-with-appendix; every entry is visible and reasoned.

## [0.1.0] — 2026-07-09

First public release. Feature-complete v1: audit-only, read-only, every finding cites a standard.

### Skills

- **secrets-scanner** — gitleaks history + working-tree scans, plus the exposure matrix gitleaks
  does not compute (on-disk × in-history × agent-readable × pushed-to-remote); a pushed secret is
  always a rotate-first CRITICAL. Fails closed to UNKNOWN if gitleaks is absent.
- **ai-config-audit** — permission deny/allow rules (flags env-runner wildcard grants), MCP configs
  across Claude/Cursor/Gemini/Codex, plaintext transcripts, and a fail-closed UNKNOWN for the
  consumer retention/training tier (not locally auditable).
- **data-classification** — the 4-tier framework (Public/Internal/Confidential/Restricted, based on
  NIST SP 800-122), deterministic floors (never auto-Public), content validators (Luhn, SSN format);
  reports carry counts and column names, never data values.
- **db-access-audit** — read-only Postgres and Snowflake packs; audits AI-principal write grants,
  raw base-table reads, unmasked PII columns, missing masked views, and missing audit logging.
  Human-gated; supports an air-gapped `--recorded` mode.
- **security-audit** — the ~30-minute orchestrator that merges all of the above into one
  deduplicated, cited report with a severity-ranked Top-5 (rotate-first override).

### Design

- Deterministic stdlib-Python evaluators own every verdict; the model narrates but cannot change
  severity, confidence, or exposure. Severity is capped by confidence; unverifiable checks are
  first-class UNKNOWN (fail-closed). Suppressions (`.ai-data-security-ignore`) always appear in an appendix.
- Verified-only citation registry (OWASP LLM Top 10 2025, MITRE ATLAS, MCP Security Best Practices,
  NIST SP 800-122, NIST AI 600-1).

### Quality

- CI (deterministic, no LLM calls): plugin validation, shellcheck, SQL read-only lint, gitleaks
  self-scan of tree and full history, dockerized Postgres fixture diffs; all GitHub Actions
  SHA-pinned. Fixtures use only vendor-documented or famous-fake values; secret-shaped test data is
  generated at test time, never committed.
- Hardened against two internal adversarial passes (a fresh-context review and an edge-case bug
  hunt): permission-glob precision, uniform fail-closed suppression, a value-leak in classification
  evidence, crash-resistance on hostile inputs, and a regex ReDoS were all fixed and regression-locked.

[0.11.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.11.0
[0.10.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.10.0
[0.9.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.9.0
[0.8.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.8.0
[0.7.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.7.0
[0.6.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.6.0
[0.5.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.5.0
[0.4.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.4.0
[0.3.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.3.0
[0.1.2]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.2
[0.1.1]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.1
[0.1.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.0
