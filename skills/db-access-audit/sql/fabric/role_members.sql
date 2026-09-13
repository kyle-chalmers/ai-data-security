-- role_members.sql — database role membership (fixed and custom roles). db_owner / db_datareader /
-- db_datawriter / db_ddladmin memberships are not in sys.database_permissions; they are authority
-- with no permission row. Read-only.
SELECT 'role_name,member_name,member_type' AS line
UNION ALL
SELECT CONCAT(QUOTENAME(r.name, '"'), ',', QUOTENAME(m.name, '"'), ',', m.type_desc)
FROM sys.database_role_members rm
JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id;
