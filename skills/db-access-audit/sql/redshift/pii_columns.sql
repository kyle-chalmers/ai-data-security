-- pii_columns.sql — PII-named columns with their tier floor (token-boundary patterns mirror
-- reference/four-tier-framework.md). Redshift's POSIX operator is case-sensitive, hence LOWER().
-- Names and types only, never values. Read-only.
SELECT c.table_schema, c.table_name, c.column_name, c.data_type,
       CASE WHEN LOWER(c.column_name) ~ '(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)(_|$)'
              OR LOWER(c.column_name) ~ :'org_restricted'
            THEN 'Restricted' ELSE 'Confidential' END AS tier_floor
FROM svv_columns c
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
  AND (LOWER(c.column_name) ~ '(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)(_|$)'
       OR LOWER(c.column_name) ~ :'org_restricted'
       OR LOWER(c.column_name) ~ :'org_confidential')
ORDER BY c.table_schema, c.table_name, c.column_name;
