-- pii_columns.sql — PII-named fields in the dataset, INCLUDING nested STRUCT/RECORD fields, via
-- COLUMN_FIELD_PATHS (field_path is the full dotted path). Token-boundary patterns mirror
-- reference/four-tier-framework.md. Names and types only. Read-only. Substitute ${project}, ${dataset}.
SELECT table_schema, table_name, column_name, field_path, data_type,
       CASE WHEN REGEXP_CONTAINS(LOWER(field_path), r'(^|_|\.)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)(_|$|\.)')
            THEN 'Restricted' ELSE 'Confidential' END AS tier_floor
FROM `${project}`.`${dataset}`.INFORMATION_SCHEMA.COLUMN_FIELD_PATHS
WHERE REGEXP_CONTAINS(LOWER(field_path), r'(^|_|\.)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)(_|$|\.)')
ORDER BY table_name, field_path;
