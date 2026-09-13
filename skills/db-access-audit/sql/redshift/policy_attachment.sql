-- policy_attachment.sql — dynamic data masking and row-level security policies ATTACHED to
-- relations, with the grantee each applies to. A masking policy protects its OUTPUT columns
-- (input_columns are the expression's inputs and may differ). Superusers and sys:secadmin see
-- everything; everyone else sees ZERO ROWS (the evaluator treats an empty result from a
-- non-secadmin capture as UNKNOWN, never as "no policies"). Read-only.
SELECT 'masking' AS kind, schema_name AS table_schema, table_name, grantee, grantee_type,
       output_columns, input_columns, policy_name, priority::text AS detail
FROM svv_attached_masking_policy
UNION ALL
SELECT 'rls', relschema, relname, grantee, granteekind, NULL, NULL, polname,
       'is_rls_on=' || is_rls_on::text || ';is_pol_on=' || is_pol_on::text
FROM svv_rls_attached_policy
ORDER BY kind, table_schema, table_name, grantee;
