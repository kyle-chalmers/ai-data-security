-- ai_principals.sql — database users with hints: IAM-auth users (IAM:/IAMA: prefix), superusers,
-- and names that suggest service or AI use. Helps the user name the AI principal. Read-only.
SELECT usename AS user_name, usesuper AS is_superuser,
       CASE WHEN usename LIKE 'IAM:%' OR usename LIKE 'IAMA:%' THEN 'iam_temporary_credentials' ELSE 'database_password_or_iam_identity' END AS auth_hint
FROM pg_user
WHERE usename NOT LIKE 'ds:%'
ORDER BY usename;
