-- identity.sql — every group the AI principal belongs to, directly (directGroup = true) or through
-- nesting (directGroup = false). Grants to any of these groups apply to the principal. The skill
-- substitutes ${principal_kind} = USER (users and service principals, the latter by applicationId)
-- or GROUP (when the principal is itself a group), and ${principal} as a back-ticked identifier.
-- SHOW GROUPS needs administrator privileges; without them the capture fails and eval_grants
-- reports DB-06. If WITH USER rejects an applicationId, build identity.csv from the SCIM API
-- (see README.md).
-- Read-only.
SHOW GROUPS WITH ${principal_kind} `${principal}`;
