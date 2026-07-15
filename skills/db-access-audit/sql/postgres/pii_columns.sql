-- pii_columns.sql — columns whose names match the shared PII patterns
-- (reference/four-tier-framework.md), outside system schemas.
-- Patterns are token-boundary matches: `member_ssn`, `customer_email`, and
-- `email_address` match; `emailed_at` does not (no `email` token).
-- Org extensions (reference/org-config.md) arrive as two extra regexes; pass
-- '(^|_)(__none__)(_|$)' for both when no org profile exists.
-- Read-only. Run with:
--   psql --csv -v org_restricted="(^|_)(__none__)(_|$)" \
--              -v org_confidential="(^|_)(__none__)(_|$)" -f pii_columns.sql
SELECT c.table_schema,
       c.table_name,
       c.column_name,
       c.data_type,
       CASE
         WHEN c.column_name ~* '(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)(_|$)'
           OR c.column_name ~* :'org_restricted'
           THEN 'Restricted'
         ELSE 'Confidential'
       END AS tier_floor
FROM information_schema.columns c
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND (c.column_name ~* '(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)(_|$)'
       OR c.column_name ~* :'org_restricted'
       OR c.column_name ~* :'org_confidential')
ORDER BY c.table_schema, c.table_name, c.column_name;
