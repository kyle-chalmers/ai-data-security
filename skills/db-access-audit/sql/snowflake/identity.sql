-- identity.sql — the AI principal's effective identity in Snowflake: the USER the agent
-- authenticates as (TYPE, default and secondary roles) and every role granted to it.
-- Interpretation (computed by eval_grants.py): TYPE not in {SERVICE, SERVICE_AGENT} -> DB-ID-01
-- (personal user); DEFAULT_SECONDARY_ROLES = ('ALL') -> DB-ID-01 (every granted role is active in
-- every session); more than one role granted -> the secondary-role blast radius is those roles.
-- Read-only. Run with: snow sql -c <connection> -D "user=YOUR_AI_USER" -f identity.sql
DESCRIBE USER &{ user };
SHOW GRANTS TO USER &{ user };
