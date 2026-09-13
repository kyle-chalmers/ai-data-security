-- ownership.sql — who owns each schema and each object (an object with no explicit owner is owned
-- by its schema's owner). Owners hold CONTROL on what they own with no permission row. Read-only.
SELECT 'kind,schema_name,object_name,object_type,owner_name' AS line
UNION ALL
SELECT CONCAT('schema,', QUOTENAME(s.name, '"'), ',,,', QUOTENAME(p.name, '"'))
FROM sys.schemas s JOIN sys.database_principals p ON p.principal_id = s.principal_id
UNION ALL
SELECT CONCAT('object,', QUOTENAME(s.name, '"'), ',', QUOTENAME(o.name, '"'), ',', o.type_desc, ',', QUOTENAME(COALESCE(po.name, ps.name), '"'))
FROM sys.objects o
JOIN sys.schemas s ON s.schema_id = o.schema_id
LEFT JOIN sys.database_principals po ON po.principal_id = o.principal_id
LEFT JOIN sys.database_principals ps ON ps.principal_id = s.principal_id
WHERE o.type IN ('U', 'V', 'P', 'FN', 'IF', 'TF');
