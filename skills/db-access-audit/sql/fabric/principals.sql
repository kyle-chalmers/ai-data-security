-- principals.sql — database principals and their type: E = external (Entra) user or service principal,
-- X = external Entra group, R = role, S = SQL user (not possible in Fabric), plus fixed roles
-- (db_owner, db_datareader, db_datawriter ...). Also who is dbo. Read-only.
SELECT 'name,principal_id,type,type_desc,authentication_type_desc,is_fixed_role,owning_principal' AS line
UNION ALL
SELECT CONCAT(QUOTENAME(p.name, '"'), ',', p.principal_id, ',', p.type, ',', p.type_desc, ',', ISNULL(p.authentication_type_desc, ''), ',',
              CAST(p.is_fixed_role AS varchar(1)), ',', ISNULL(op.name, ''))
FROM sys.database_principals p
LEFT JOIN sys.database_principals op ON op.principal_id = p.owning_principal_id
WHERE p.type IN ('E', 'X', 'R', 'S', 'G', 'U');
