SELECT 'no table privileges in {{schema}}' AS check_name, 0 AS expected, COUNT(*) AS actual
FROM {{db}}.INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE = '{{ai_role}}' AND TABLE_SCHEMA = '{{schema}}';   -- EXPECT: actual = 0
