# Expected findings — Snowflake recorded fixtures

The skill, given `--dialect snowflake --recorded tests/fixtures/snowflake --role AI_AGENT
--confirm`, must derive from the recorded outputs (interpretation rules in
`skills/db-access-audit/reference.md`):

| Check | Severity | Grounds (from the recorded outputs) |
|---|---|---|
| DB-01 | CRITICAL | `INSERT` and `UPDATE` on TABLE `ANALYTICS.APP.CUSTOMERS` granted to `AI_AGENT` |
| DB-02 | HIGH | `SELECT` with `granted_on = TABLE` on `ANALYTICS.APP.CUSTOMERS` and `ANALYTICS.APP.ORDERS` (no view grants at all) |
| DB-03 | HIGH | Restricted-floor columns `SSN`, `CARD_NUMBER` on `APP.CUSTOMERS`, a table the role can SELECT |
| DB-03 | MEDIUM | Confidential-floor columns `EMAIL`, `FULL_NAME` on the same readable table |
| DB-04 | MEDIUM | Zero masking policies in the account AND zero views in `ANALYTICS` (a dynamic table `CUSTOMER_MASK_DT` exists, owned by `SYSADMIN`, no EXECUTE AS USER) |
| DB-05 | ≤ MEDIUM, confidence ≤ probable | Only `ACCOUNTADMIN` holds `IMPORTED PRIVILEGES` on the `SNOWFLAKE` database; no evidence anyone reviews the AI role's query history (partly organizational) |

Report requirements: header states **"Snowflake support: fixture-validated"** (or, for a real
run, that outputs were recorded, not live); every finding cites a `citations.yml` entry; no row
data appears (the fixtures contain none); severities respect the confidence caps in
`reference/finding-format.md`.

Without `--confirm` (principal unconfirmed), all severities must cap at MEDIUM/possible and a
DB-06 unknown must say why.

## v0.4 additions (identity, boundary, attachment, audit quality, external paths)

With `identity.txt`, `policy_references.txt`, and `audit_quality.txt` also recorded:

| Check | Severity | Grounds |
|---|---|---|
| DB-ID-01 | HIGH | User `AI_AGENT` has `TYPE = PERSON` (not SERVICE / SERVICE_AGENT) and `DEFAULT_SECONDARY_ROLES = ["ALL"]`; roles `AI_AGENT` and `ANALYST` are granted to it, and role `AI_AGENT` itself inherits `ANALYST` (USAGE on ROLE) |
| DB-07 | HIGH | The raw-to-curated boundary is crossed by inheritance: `ANALYST` reaches the AI session through secondary roles and role inheritance, so the boundary is only as tight as `ANALYST` |
| DB-08 | HIGH | Zero policy references in `ANALYTICS` while Restricted columns are readable (`SSN`, `CARD_NUMBER`); dynamic table `CUSTOMER_MASK_DT` refreshes as `SYSADMIN` (`execute_as_user` is NULL) — INFO note |
| DB-09 | MEDIUM (probable) | `ACCOUNT_USAGE.GRANTS_TO_ROLES` shows nobody holds `SNOWFLAKE.GOVERNANCE_VIEWER` (no non-admin can read ACCESS_HISTORY); `USE_CACHED_RESULT = true` for the AI user, so cache hits do not appear as reads |
| DB-10 | HIGH | `USAGE` on STAGE `ANALYTICS.APP.EXPORTS`: the AI role can `COPY INTO` a stage — an external write path |

If `identity.txt` / `policy_references.txt` / `audit_quality.txt` are absent, the corresponding checks are DB-06 UNKNOWN with the exact statement (and the `GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER …` precondition) to capture them.
