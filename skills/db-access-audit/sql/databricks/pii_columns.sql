-- pii_columns.sql — PII-named columns in the catalog with their tier floor (token-boundary
-- patterns mirror reference/four-tier-framework.md; names only, never values). Org profile
-- tokens (reference/org-config.md) are appended by the skill as extra alternatives when present.
-- Read-only. Substitute ${catalog}.
SELECT c.table_catalog AS catalog, c.table_schema, c.table_name, c.column_name, c.data_type,
       CASE WHEN c.column_name RLIKE '(?i)(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)(_|$)'
            THEN 'Restricted' ELSE 'Confidential' END AS tier_floor
FROM system.information_schema.columns c
WHERE c.table_catalog = '${catalog}'
  AND c.table_schema <> 'information_schema'
  AND c.column_name RLIKE '(?i)(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)(_|$)'
ORDER BY c.table_schema, c.table_name, c.column_name;
