-- audit_logging.sql — the audited principal's own job history: how many of ITS jobs in 30 days were
-- served from the results cache (a cached read re-reads data without a fresh table access record).
-- Data Access audit logs are ON by default for BigQuery; their RETENTION is the _Default log bucket's
-- (log_bucket.json). JOBS keeps 180 days and needs bigquery.jobs.listAll AND bigquery.jobs.create;
-- jobs billed to another project are not here (stated). ${principal_email} is the member string
-- without its prefix. Read-only.
SELECT 'jobs_visible' AS name, 'true' AS setting
UNION ALL
SELECT 'principal_cache_hit_jobs_last_30d', CAST(COUNTIF(cache_hit) AS STRING)
FROM `${project}`.`region-${region}`.INFORMATION_SCHEMA.JOBS
WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY) AND LOWER(user_email) = LOWER('${principal_email}')
UNION ALL
SELECT 'principal_jobs_last_30d', CAST(COUNT(*) AS STRING)
FROM `${project}`.`region-${region}`.INFORMATION_SCHEMA.JOBS
WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY) AND LOWER(user_email) = LOWER('${principal_email}');
