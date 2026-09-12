-- masked_views.sql — does a masked/governed layer exist? Three signals: dynamic masking
-- policies anywhere in the account, the view inventory of the target database, and dynamic
-- tables (which refresh with their OWNER's privileges unless EXECUTE AS USER is set).
-- Read-only. Run with: snow sql -c <connection> -D "db=YOUR_DATABASE" -f masked_views.sql
SHOW MASKING POLICIES IN ACCOUNT;
SHOW VIEWS IN DATABASE &{ db };
SHOW DYNAMIC TABLES IN DATABASE &{ db };
