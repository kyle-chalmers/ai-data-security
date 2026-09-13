    UNION ALL SELECT 'NOT a member of {{member}}', 'false', pg_has_role(current_user, '{{member}}', 'MEMBER')::text
