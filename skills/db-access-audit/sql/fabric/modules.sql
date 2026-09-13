-- modules.sql — stored procedures and functions (things EXECUTE reaches) and whether their definition
-- is visible to the capture. A module can return PII regardless of table grants on the caller, so the
-- evaluator treats EXECUTE on a module as an opaque read path (UNKNOWN), never as clean. Read-only.
SELECT 'schema_name,module_name,module_type,definition_visible' AS line
UNION ALL
SELECT CONCAT(QUOTENAME(s.name, '"'), ',', QUOTENAME(o.name, '"'), ',', o.type_desc, ',', CASE WHEN m.definition IS NULL THEN '0' ELSE '1' END)
FROM sys.objects o
JOIN sys.schemas s ON s.schema_id = o.schema_id
LEFT JOIN sys.sql_modules m ON m.object_id = o.object_id
WHERE o.type IN ('P', 'FN', 'IF', 'TF');
