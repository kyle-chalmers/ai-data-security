-- pii_columns.sql — PII-named columns in the target database (INFORMATION_SCHEMA is
-- per-database in Snowflake; run once per database of interest).
-- Patterns mirror reference/four-tier-framework.md and are token-boundary matches:
-- `member_ssn`, `customer_email`, `email_address` match; `emailed_at` does not.
-- Org extensions (reference/org-config.md) arrive as two extra regexes; define both
-- as (^|_)(__none__)(_|$) when no org profile exists.
-- Read-only. Run with:
--   snow sql -c <connection> -D "db=YOUR_DATABASE" \
--     -D "org_restricted=(^|_)(__none__)(_|$)" -D "org_confidential=(^|_)(__none__)(_|$)" \
--     -f pii_columns.sql
SELECT table_schema,
       table_name,
       column_name,
       data_type,
       CASE
         WHEN REGEXP_LIKE(column_name,
              '.*(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)(_|$).*', 'i')
           OR REGEXP_LIKE(column_name, '.*&{ org_restricted }.*', 'i')
           THEN 'Restricted'
         ELSE 'Confidential'
       END AS tier_floor
FROM &{ db }.INFORMATION_SCHEMA.COLUMNS
WHERE table_schema <> 'INFORMATION_SCHEMA'
  AND (REGEXP_LIKE(column_name,
       '.*(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)(_|$).*', 'i')
       OR REGEXP_LIKE(column_name, '.*&{ org_restricted }.*', 'i')
       OR REGEXP_LIKE(column_name, '.*&{ org_confidential }.*', 'i'))
ORDER BY table_schema, table_name, column_name;
