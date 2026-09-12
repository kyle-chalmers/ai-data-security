-- external_paths.sql — ways the AI principal's SQL can reach OUTSIDE the database: server-side
-- file and program roles (bypass all database permission checks), foreign servers it may use,
-- and extensions that open network or file paths.
-- Rows are (kind, name, detail). Read-only. Run with: psql --csv -v ai_role='<role>' -f external_paths.sql
WITH RECURSIVE closure AS (
  SELECT r.oid AS role_oid, r.rolname FROM pg_roles r WHERE r.rolname = :'ai_role'
  UNION
  SELECT g.oid, g.rolname FROM closure c
  JOIN pg_auth_members m ON m.member = c.role_oid
  JOIN pg_roles g ON g.oid = m.roleid
)
SELECT 'server_role' AS kind, c.rolname AS name,
       CASE c.rolname WHEN 'pg_write_server_files' THEN 'write files on the server'
                      WHEN 'pg_execute_server_program' THEN 'execute programs on the server'
                      WHEN 'pg_read_server_files' THEN 'read any file the server can' END AS detail
FROM closure c
WHERE c.rolname IN ('pg_write_server_files', 'pg_execute_server_program', 'pg_read_server_files')
UNION ALL
SELECT 'foreign_server', s.srvname, fdw.fdwname
FROM pg_foreign_server s JOIN pg_foreign_data_wrapper fdw ON fdw.oid = s.srvfdw
WHERE has_server_privilege(:'ai_role', s.srvname, 'USAGE')
UNION ALL
-- Functions that reach files, programs, or other servers, when the principal may EXECUTE them
-- (they are superuser-only unless someone granted them; a grant is the finding).
SELECT 'function', n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       CASE WHEN p.proname LIKE 'dblink%' THEN 'connect to another database'
            WHEN p.proname IN ('pg_read_file', 'pg_read_binary_file', 'pg_ls_dir', 'lo_import') THEN 'read server files'
            WHEN p.proname IN ('lo_export') THEN 'write server files'
            ELSE 'server-side access' END
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proname IN ('dblink', 'dblink_connect', 'dblink_connect_u', 'dblink_exec', 'dblink_open',
                    'pg_read_file', 'pg_read_binary_file', 'pg_ls_dir', 'lo_import', 'lo_export')
  AND has_function_privilege(:'ai_role', p.oid, 'EXECUTE')
UNION ALL
SELECT 'extension', e.extname, e.extversion
FROM pg_extension e WHERE e.extname IN ('postgres_fdw', 'dblink', 'file_fdw', 'adminpack')
ORDER BY 1, 2, 3;
