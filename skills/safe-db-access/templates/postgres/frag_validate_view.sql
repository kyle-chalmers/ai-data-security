    UNION ALL SELECT 'curated view {{curated}}.{{view}} readable', 'true', has_table_privilege('{{curated}}.{{view}}', 'SELECT')::text
    UNION ALL SELECT 'curated view {{curated}}.{{view}} NOT writable', 'false', has_table_privilege('{{curated}}.{{view}}', 'INSERT')::text
    UNION ALL SELECT 'analytics query on {{curated}}.{{view}} runs', 'true', (SELECT count(*) >= 0 FROM {{curated}}.{{view}})::text
