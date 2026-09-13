-- 5. AUDIT TRAIL --------------------------------------------------------------------------------
-- Per-role statement logging needs no restart and records every statement the AI role runs in the
-- server log (DB-05 / DB-09). The log's RETENTION is decided outside the database (log rotation,
-- log shipping); this plan cannot set it, so check it. Object-level audit of SELECTs needs pgaudit
-- in shared_preload_libraries (a restart), which is out of this plan's scope:
--   shared_preload_libraries = 'pgaudit'   then   ALTER ROLE {{ai_role}} SET pgaudit.log = 'read, write';
ALTER ROLE {{ai_role}} SET log_statement = 'all';
ALTER ROLE {{ai_role}} SET log_min_duration_statement = 0;

