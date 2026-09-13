-- audit_logging.sql — what the warehouse itself can say about the audit trail: whether Query Insights
-- (queryinsights.exec_requests_history, 30 days, full text for Admin/Member/Contributor) is readable
-- by this connection and how many of the principal's statements it holds. ${principal} is substituted
-- ONLY after the skill validated it against ^[A-Za-z0-9._@ -]{1,128}$ (no quotes, semicolons, or
-- dashes-dashes), and is doubled-quote-safe because that class excludes the single quote. Read-only.
SELECT 'name,setting' AS line
UNION ALL SELECT CONCAT('query_insights_readable,', 'true')
UNION ALL SELECT CONCAT('principal_statements_30d,', CAST(COUNT(*) AS varchar(20))) FROM queryinsights.exec_requests_history WHERE login_name = '${principal}'
UNION ALL SELECT CONCAT('total_statements_30d,', CAST(COUNT(*) AS varchar(20))) FROM queryinsights.exec_requests_history;
