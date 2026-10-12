# Glossary

What the words and codes in an AI Data Security report mean. If a report uses a term that is not
here, that is a documentation bug: please open an issue.

## Reading a report

**Finding.** A check ran and found a problem. Every finding names the object (a file path, a
config rule, a table or column), the evidence, the fix, and the standard it cites.

**UNKNOWN.** A check could not reach a verdict: a tool is missing, a file was unreadable, the
setting lives somewhere no local audit can see (such as your Claude account's retention tier), or
the check ran but found something it cannot classify safely and hands to a human. An UNKNOWN
is never counted as a pass. The report states how many there are next to the finding count and
says what to do about each one.

**Fail closed.** The rule behind UNKNOWN: when the plugin cannot verify something, it says so
instead of assuming the safe answer. A missing gitleaks install makes the secrets lane UNKNOWN;
it never makes it clean.

**Severity.** How bad the problem is if real: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
(inventory, not a problem). Secrets that have left the machine are always listed first.

**Confidence.** How sure the evidence is: `confirmed` (validated, e.g. a card number that passes
the Luhn check), `probable`, or `possible` (a name or pattern hint only). Confidence caps
severity: a `possible` finding can be at most MEDIUM and a `probable` one at most HIGH, so a
guess can never reach CRITICAL. The bundled scripts assign confidence; the model may lower it
with a stated reason and can never raise it.

**Check ID.** The short code on each finding (`SS-03`, `AC-07`, `DB-08`). The prefix names the
skill: `SS` secrets-scanner, `AC` ai-config-audit, `DC` data-classification, `DBT`
dbt-governance-audit, `DB` db-access-audit. The full list is at the bottom of this page.

**Fingerprint and suppression.** Each finding has a fingerprint such as
`SS-03:.env:generic-api-key`. Listing it in `.ai-data-security-ignore` at the audited folder's
root (with an optional `expires=` date and `reason=`) moves the finding to the report's
Suppressed appendix. It is still shown there; nothing disappears silently.

**Org profile.** An optional `.ai-data-security.yml` at the project root that adds your own
sensitive column names or warehouse defaults. It can only add detection, never remove it. See
[reference/org-config.md](../reference/org-config.md).

**SARIF.** A standard JSON format for static-analysis results. `security-audit --sarif <file>`
writes one so GitHub Code Scanning can show the findings on a pull request.

## Agents and their configuration

**Agent-readable.** A file the AI coding agent can open with its file tools because no deny rule
blocks it. Your `.gitignore` does not stop an agent from reading a file.

**Deny rule.** An entry under `permissions.deny` in Claude Code settings, such as
`Read(**/.env)`. It blocks the agent's own file tools but does not bind programs the agent runs
(a `grep -r` or a Python script can still read the file). That gap is why AC-07 exists.

**Sandbox.** Claude Code's OS-level Bash sandbox (`sandbox.enabled`). It applies the deny paths to
every subprocess, which closes the gap deny rules leave.

**MCP server.** A Model Context Protocol server: a plugin process that gives an agent extra
tools, such as running SQL against your warehouse. Its config can hold credentials and can allow
writes, which the AC checks inspect without starting the server.

**Unpinned package.** An MCP server launched with something like `npx some-server` or
`@latest`, so whatever version is published next runs on your machine without review.

**Transcript.** The session history an agent stores on disk. It can contain anything you or the
agent pasted, including secrets and query results.

## Your data

**The four tiers.** Every file is labelled Public, Internal, Confidential, or Restricted
([reference/four-tier-framework.md](../reference/four-tier-framework.md)). Nothing is
automatically labelled Public; the floor is Internal.

- **Confidential**: data that identifies people or commercial terms, such as customer emails,
  names, and contracts.
- **Restricted**: data whose exposure is severe, such as Social Security numbers, payment card
  numbers (PAN), health records, and credentials. It should never enter an AI context.

**Validator.** A content check that upgrades a guess to `confirmed`: the SSN format rules, the
Luhn check for card numbers, IBAN mod-97, phone, IPv4. Reports carry counts and column names only,
never the values. A file can also reach a tier by a column or file name alone (a `*credential*`
or `*.pem` file is Restricted); those findings carry `probable` confidence, while a validator hit
is `confirmed`. Check the confidence on a `DC-01` or `DC-02` to see which it was.

**Pseudonymized.** Data replaced by a hash or token. It is still personal data (NIST SP 800-188),
so the key must sit outside the AI role's reach. The plugin never calls hashed data anonymized.

**Exposure matrix.** The four questions secrets-scanner answers for each secret: is it on disk,
is it in git history, can the agent read it, and has it been pushed to a remote? A pushed secret
has to be rotated, so it outranks everything else.

## Warehouses

**AI principal.** The database identity your AI tooling connects as: a role, user, service
principal, or IAM member, depending on the warehouse. `--role` names it.

**Effective identity.** Everything that identity can actually do once you count its user type,
secondary roles, inherited roles, group membership, ownership, and special flags such as
superuser. It is often much wider than the role name suggests (DB-ID-01).

**Secondary roles.** A Snowflake feature that lets a session use the privileges of every role
granted to the user at once, beyond the one role it is "using". An agent user with
`DEFAULT_SECONDARY_ROLES = ('ALL')` effectively holds all of them.

**Indirect path.** Access the AI principal gets without a direct grant: through an inherited
role, a grant to `PUBLIC` (everyone), or **default privileges** (grants applied automatically to
tables created later). DB-07 looks for these.

**Base table versus governed view.** A base table holds the raw rows. A governed (curated, masked)
view exposes only what the agent should see, with sensitive columns hashed, masked, or left out.
The safe target is an AI principal that can read only governed views.

**Masking policy.** A warehouse control attached to a column that hides its value from roles that
should not see it. DB-08 checks that one is actually attached, not just that a view is named
`*_masked`.

**Audit trail.** A log of the queries the AI principal ran, readable by someone who will look.
DB-05 and DB-09 check that it exists and name its blind spots, such as results served from cache.

**Paths outside the database.** Ways a principal can reach files or systems beyond the
warehouse: stages, external locations, `COPY ... TO PROGRAM`, server file roles (DB-10).

**Pack.** The set of read-only queries and the evaluator module for one warehouse. Pick one with
`--dialect`.

**Partial by design.** A pack where part of the access model cannot be seen from the queries the
plugin runs (BigQuery folder and organization IAM, group membership, and custom roles; Fabric
workspace roles; Lake Formation tag-based grants). The missing parts are reported as UNKNOWN on
every run.

**Explicit bindings.** In BigQuery, the IAM grants written directly on the project, dataset, or
table being audited. Access inherited from a folder or organization, or through a group, is not
an explicit binding on that resource, which is why the BigQuery pack is partial.

**Posture pack.** The DuckDB pack. DuckDB has no users or grants (whoever opens the file can do
everything), so it checks the file, the process guards, and the paths out instead.

**Recorded mode.** `--recorded <dir>` audits query output someone captured earlier, so the audit
itself never connects. A DBA can run the capture and an analyst can run the audit.

## Neighbouring tools the README mentions

**DSPM** (data security posture management) finds sensitive data across cloud stores. **CIEM**
(cloud infrastructure entitlement management) governs cloud permissions. A **SIEM** collects and
alerts on security logs. This plugin sits beside those; it does not replace them.

## Every check ID

<!-- checks:start (generated by dev/gen_glossary.py; edit reference/checks.yml instead) -->

**secrets-scanner**

| ID | What it means |
|---|---|
| `SS-01` | Secret present in git history (local only) |
| `SS-02` | Secret on disk, covered by a permission deny rule (still readable by subprocesses) |
| `SS-03` | Secret on disk and agent-readable (no permission deny rule covers it) |
| `SS-04` | Secret pushed to a git remote (rotate first) |
| `SS-05` | Secrets scan could not run (gitleaks unavailable or scan error) |

**ai-config-audit**

| ID | What it means |
|---|---|
| `AC-01` | Missing recommended secret deny rules in project Claude settings |
| `AC-02` | Allow rule grants arbitrary execution via an env-runner wildcard |
| `AC-03` | Credential-shaped literal value in an MCP server config |
| `AC-04` | MCP server configured with trust:true (bypasses tool-call confirmations) |
| `AC-05` | Plaintext session transcripts on disk |
| `AC-06` | Consumer retention/training tier is not locally auditable (always UNKNOWN) |
| `AC-07` | Bash sandbox not enabled (deny rules bind the tool layer only) |
| `AC-08` | Private data sources and external channels both configured (capability inventory; INFO) |
| `AC-09` | MCP server runs an unpinned package (npx/uvx/@latest/mutable ref) |
| `AC-10` | Warehouse MCP server is write-capable by its own configuration (or its config could not be found → UNKNOWN) |
| `AC-11` | Local sensitive sinks: DuckDB persistent secrets, credential-shaped literals in warehouse CLI configs, shell history without a deny rule |

**data-classification**

| ID | What it means |
|---|---|
| `DC-01` | Restricted-tier file on disk (validated SSN, card, or IBAN content, or a Restricted column or file name) |
| `DC-02` | Confidential-tier file on disk (validated email, phone, or IP content, or a Confidential column or file name) |
| `DC-03` | Classification could not run over part of the target (unreadable content) |

**db-access-audit**

| ID | What it means |
|---|---|
| `DB-01` | AI principal holds write privileges (INSERT/UPDATE/DELETE/TRUNCATE) |
| `DB-02` | AI principal reads base tables directly instead of governed views |
| `DB-03` | PII-named columns readable unmasked by the AI principal |
| `DB-04` | No masked/governed view layer detected |
| `DB-05` | No audit trail of the AI principal's queries |
| `DB-06` | DB audit could not run or principal unconfirmed (UNKNOWN / confidence cap) |
| `DB-ID-01` | AI principal's effective identity is wider than its role (user type, secondary roles, ownership, inheritance, superuser/BYPASSRLS) |
| `DB-07` | Raw-to-curated boundary crossed by an indirect path (inherited role grants, PUBLIC grants, default privileges) |
| `DB-08` | No governed control (masking policy / label) attached to PII columns the AI principal can read |
| `DB-09` | Audit trail of the AI principal has known blind spots (unreadable, unconfigured, or cache-skipped) |
| `DB-10` | AI principal has paths outside the database (server file/program roles, foreign servers, stages, integrations) |

**dbt-governance-audit**

| ID | What it means |
|---|---|
| `DBT-01` | Exposure consumes PII-tagged dbt model(s) with no masking layer declared |
| `DBT-02` | Likely-PII dbt columns carry no PII tag (declaration gap; not proof of no PII) |
| `DBT-03` | dbt YAML could not be parsed (UNKNOWN, fail-closed) |
| `DBT-04` | Masking packages declared in packages.yml (INFO inventory) |

<!-- checks:end -->
