-- audit_logging.sql — what the database itself can say about the audit trail and identifier rules:
-- the user-activity log parameter (false by default; without it the S3/CloudWatch audit log has
-- connections and user changes but not query text), whether identifiers are case-sensitive (drives
-- how the evaluator compares names), and whether the auditor is a superuser (the only standing
-- that sees every identity's rows in SVV_RELATION_PRIVILEGES). Export to S3/CloudWatch is a cluster
-- setting invisible from SQL (`aws redshift describe-logging-status`), reported UNKNOWN. Read-only.
SELECT 'enable_user_activity_logging' AS name, current_setting('enable_user_activity_logging') AS setting
UNION ALL SELECT 'enable_case_sensitive_identifier', current_setting('enable_case_sensitive_identifier')
UNION ALL SELECT 'auditor_is_superuser', u.usesuper::text FROM pg_user u WHERE u.usename = current_user;
