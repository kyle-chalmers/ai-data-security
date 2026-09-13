-- 6. VALIDATION — run this AS the AI identity (USE ROLE {{ai_role}}, or connect as {{ai_user}}) ---------
-- Every statement here is meant to SUCCEED and return one row whose `actual` equals `expected`; a
-- statement that errors is itself a failed check. The commented probes at the end are optional
-- manual checks that are EXPECTED to error. Snowflake support in this plugin is fixture-validated,
-- not live-tested: this section is how you prove the plan on your account.
USE ROLE {{ai_role}};
SELECT 'session identity' AS check_name, '{{ai_user}}/{{ai_role}}' AS expected,
       CURRENT_USER() || '/' || CURRENT_ROLE() AS actual;                                  -- EXPECT: actual = expected
SELECT 'no secondary roles active' AS check_name, '[]' AS expected,
       PARSE_JSON(CURRENT_SECONDARY_ROLES()):roles::STRING AS actual;                       -- EXPECT: actual = []
SELECT 'no privileges in {{vault}}' AS check_name, 0 AS expected, COUNT(*) AS actual
FROM {{db}}.INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE = '{{ai_role}}' AND TABLE_SCHEMA = '{{vault}}';  -- EXPECT: actual = 0
{{schema_checks}}{{view_checks}}{{raw_checks}}SHOW GRANTS TO ROLE {{ai_role}};                                -- EXPECT: USAGE on {{db}} and {{db}}.{{curated}}, SELECT on views only

