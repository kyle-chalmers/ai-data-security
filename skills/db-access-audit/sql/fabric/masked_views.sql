-- masked_views.sql — the view inventory, whether each definition shows a masking signal, and the
-- row-level security policies in force (sys.security_policies / sys.security_predicates). Read-only.
SELECT 'kind,schema_name,object_name,detail,has_masking_signal' AS line
UNION ALL
SELECT CONCAT('view,', s.name, ',', v.name, ',,', CASE WHEN LOWER(m.definition) LIKE '%hashbytes%' OR LOWER(m.definition) LIKE '%mask%' OR LOWER(m.definition) LIKE '%substring%' OR LOWER(m.definition) LIKE '%left(%' OR LOWER(m.definition) LIKE '%right(%' OR LOWER(m.definition) LIKE '%replicate(%' THEN '1' ELSE '0' END)
FROM sys.views v
JOIN sys.schemas s ON s.schema_id = v.schema_id
LEFT JOIN sys.sql_modules m ON m.object_id = v.object_id
UNION ALL
SELECT CONCAT('rls_policy,', ts.name, ',', t.name, ',', sp.name, '/', CASE WHEN sp.is_enabled = 1 THEN 'enabled' ELSE 'disabled' END, ',')
FROM sys.security_policies sp
JOIN sys.security_predicates pr ON pr.object_id = sp.object_id
JOIN sys.tables t ON t.object_id = pr.target_object_id
JOIN sys.schemas ts ON ts.schema_id = t.schema_id;
