-- identity.sql — the AI user's attributes, the roles it holds (svv_user_grants; svv_role_grants is
-- captured whole so the evaluator can walk role-to-role grants), the groups it is in (pg_group),
-- and the AUDITOR's own standing (superuser? sys:secadmin? sys:monitor?) so the evaluator knows
-- whether empty policy/grant results are real or a visibility artefact. Read-only.
SELECT 'attr' AS kind, 'usesuper' AS name, u.usesuper::text AS detail FROM pg_user u WHERE u.usename = :'ai_user'
UNION ALL SELECT 'attr', 'usecreatedb', u.usecreatedb::text FROM pg_user u WHERE u.usename = :'ai_user'
UNION ALL SELECT 'attr', 'exists', 'true' FROM pg_user u WHERE u.usename = :'ai_user'
UNION ALL SELECT 'user_role', g.role_name, 'direct' FROM svv_user_grants g WHERE g.user_name = :'ai_user'
UNION ALL SELECT 'role_role', r.role_name, r.granted_role_name FROM svv_role_grants r
UNION ALL SELECT 'group', g.groname, 'member' FROM pg_group g, pg_user u WHERE u.usename = :'ai_user' AND u.usesysid = ANY (g.grolist)
UNION ALL SELECT 'auditor', 'user', current_user
UNION ALL SELECT 'auditor', 'usesuper', u.usesuper::text FROM pg_user u WHERE u.usename = current_user
UNION ALL SELECT 'auditor', 'role', g.role_name FROM svv_user_grants g WHERE g.user_name = current_user
ORDER BY 1, 2, 3;
