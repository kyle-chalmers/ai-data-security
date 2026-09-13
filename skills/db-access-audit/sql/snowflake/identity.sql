-- identity.sql — the AI principal's effective identity in Snowflake: the USER the agent
-- authenticates as (TYPE, default and secondary roles) and every role granted to it.
-- Interpretation (computed by eval_grants.py): TYPE not in {SERVICE, SERVICE_AGENT} -> DB-ID-01
-- (personal user); DEFAULT_SECONDARY_ROLES = ('ALL') -> DB-ID-01 (every granted role is active in
-- every session); more than one role granted -> the secondary-role blast radius is those roles.
-- Statement 3 (v0.7) records the AUDIT SESSION's own identity. When the audit is run as the AI user
-- itself, eval_grants compares CURRENT_ROLE() to --role (a mismatch is DB-ID-01: the session's real
-- privilege set differs from the one audited) and reports any active secondary roles. When the
-- session is another user, the statement is informational.
-- Read-only. Run with: snow sql -c <connection> -D "user=YOUR_AI_USER" -f identity.sql
DESCRIBE USER &{ user };
SHOW GRANTS TO USER &{ user };
SELECT CURRENT_USER() AS session_user_name,
       CURRENT_ROLE() AS session_role_name,
       CURRENT_SECONDARY_ROLES() AS session_secondary_roles;
