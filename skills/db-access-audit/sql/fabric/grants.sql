-- grants.sql — every explicit database, schema, object, and COLUMN permission (GRANT / DENY / grant
-- with grant option / column REVOKE exceptions) with the grantee and the object's type. class 0 =
-- database, 3 = schema, 1 = object; minor_id > 0 = a column. DENY always wins over GRANT. Read-only.
SELECT 'class_desc,schema_name,object_name,object_type,column_name,permission_name,state_desc,grantee_name,grantee_type' AS line
UNION ALL
SELECT CONCAT(pe.class_desc, ',', ISNULL(s.name, ISNULL(sch.name, '')), ',', ISNULL(o.name, ''), ',', ISNULL(o.type_desc, ''), ',',
              ISNULL(c.name, ''), ',', pe.permission_name, ',', pe.state_desc, ',', QUOTENAME(pr.name, '"'), ',', pr.type_desc)
FROM sys.database_permissions pe
JOIN sys.database_principals pr ON pr.principal_id = pe.grantee_principal_id
LEFT JOIN sys.objects o ON pe.class = 1 AND o.object_id = pe.major_id
LEFT JOIN sys.schemas s ON o.schema_id = s.schema_id
LEFT JOIN sys.schemas sch ON pe.class = 3 AND sch.schema_id = pe.major_id
LEFT JOIN sys.columns c ON pe.class = 1 AND pe.minor_id > 0 AND c.object_id = pe.major_id AND c.column_id = pe.minor_id
WHERE pe.class IN (0, 1, 3);
