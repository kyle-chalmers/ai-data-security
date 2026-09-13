-- 6. VALIDATION — run this AS {{ai_role}} (psql -U {{ai_role}} ... -f this_section) ----------------
-- Every row must show ok = t. The first rows prove the analytics surface works; the rest prove
-- the raw surface, the vault, inherited roles, and server roles are gone.
SELECT check_name, expected, actual, (expected = actual) AS ok FROM (
    SELECT 'session role is the AI role' AS check_name, '{{ai_role}}' AS expected, current_user::text AS actual
    UNION ALL SELECT 'role does not inherit', 'false', (SELECT rolinherit::text FROM pg_roles WHERE rolname = current_user)
    UNION ALL SELECT 'role is not superuser', 'false', (SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user)
    UNION ALL SELECT 'role cannot bypass RLS', 'false', (SELECT rolbypassrls::text FROM pg_roles WHERE rolname = current_user)
    UNION ALL SELECT 'curated schema usable', 'true', has_schema_privilege('{{curated}}', 'USAGE')::text
    UNION ALL SELECT 'vault schema NOT usable', 'false', has_schema_privilege('{{vault}}', 'USAGE')::text
    UNION ALL SELECT 'vault.hash_pii NOT executable', 'false', (SELECT has_function_privilege(p.oid, 'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '{{vault}}' AND p.proname = 'hash_pii')::text
{{view_checks}}{{raw_checks}}{{membership_checks}}) AS checks
ORDER BY check_name;

