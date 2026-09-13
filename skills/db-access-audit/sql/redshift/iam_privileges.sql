-- iam_privileges.sql — IAM-role privileges explicitly granted to identities: COPY (load from S3),
-- UNLOAD (write query results to S3), CREATE MODEL, EXTERNAL FUNCTION. UNLOAD granted to the AI
-- user, one of its roles/groups, or PUBLIC is a write path out of the database (DB-10). Whether the
-- IAM role itself may write a given bucket is IAM/S3 policy, which SQL cannot see. Read-only.
SELECT iam_arn, command_type, identity_name, identity_type
FROM svv_iam_privileges
ORDER BY identity_type, identity_name, command_type, iam_arn;
