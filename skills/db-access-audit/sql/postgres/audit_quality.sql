-- audit_quality.sql — how good is the audit trail, not just whether one exists: pgaudit
-- extension and its settings, per-role logging overrides for the AI principal, and where
-- logs go. Rows are (name, setting). Read-only. Run with: psql --csv -v ai_role='<role>' -f audit_quality.sql
SELECT s.name, s.setting
FROM pg_settings s
WHERE s.name IN ('log_destination', 'logging_collector', 'log_statement', 'log_min_duration_statement',
                 'log_connections', 'log_disconnections', 'shared_preload_libraries')
   OR s.name LIKE 'pgaudit.%'
UNION ALL
SELECT 'extension:pgaudit', e.extversion FROM pg_extension e WHERE e.extname = 'pgaudit'
UNION ALL
SELECT 'role_setting:' || split_part(cfg, '=', 1), split_part(cfg, '=', 2)
FROM pg_db_role_setting rs
JOIN pg_roles r ON r.oid = rs.setrole, LATERAL unnest(rs.setconfig) AS cfg
WHERE r.rolname = :'ai_role'
ORDER BY 1, 2;
