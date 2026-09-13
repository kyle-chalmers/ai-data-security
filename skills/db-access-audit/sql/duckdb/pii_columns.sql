-- pii_columns.sql — PII-named columns (underscore OR space token boundaries, per the plugin's PII rule) of BASE TABLES across attached databases (names and types only;
-- views are derived objects and are judged in masked_views.sql). Read-only. '(none)' sentinel keeps the
-- CSV header when nothing matches (the CLI prints nothing for an empty result).
WITH hits AS (
  SELECT c.database_name, c.schema_name, c.table_name, c.column_name, c.data_type,
         CASE WHEN regexp_matches(lower(c.column_name), '(^|[_ ])(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)([_ ]|$)')
              THEN 'Restricted' ELSE 'Confidential' END AS tier_floor
  FROM duckdb_columns() c
  JOIN duckdb_tables() t ON t.database_name = c.database_name AND t.schema_name = c.schema_name AND t.table_name = c.table_name
  WHERE NOT c.internal AND NOT t.internal
    AND regexp_matches(lower(c.column_name), '(^|[_ ])(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)([_ ]|$)')
)
SELECT * FROM hits
UNION ALL
SELECT '(none)', '', '', '', '', '' WHERE NOT EXISTS (SELECT 1 FROM hits)
ORDER BY 1, 2, 3, 4;
