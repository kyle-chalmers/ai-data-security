SELECT '{{curated}}.{{view}} readable' AS check_name, TRUE AS expected, COUNT(*) >= 0 AS actual FROM {{db}}.{{curated}}.{{view}};   -- EXPECT: actual = TRUE
