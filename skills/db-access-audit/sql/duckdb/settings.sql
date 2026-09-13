-- settings.sql — the process-level guards DuckDB offers (defaults shown by this session; the agent's own
-- process may differ). enable_external_access=false blocks file/URL reads and extension installs;
-- lock_configuration=true freezes them; allow_unsigned_extensions / autoinstall / autoload / community
-- extensions widen the supply chain; allow_persistent_secrets keeps credentials on disk unencrypted; enable_logging +
-- enabled_log_types (QueryLog) + logging_storage / log_query_path are the only query-log facilities. Read-only.
SELECT name, value FROM duckdb_settings()
WHERE name IN ('enable_external_access', 'lock_configuration', 'allow_unsigned_extensions', 'autoinstall_known_extensions',
               'autoload_known_extensions', 'allow_community_extensions', 'allow_persistent_secrets', 'disabled_filesystems',
               'allowed_directories', 'allowed_paths', 'secret_directory', 'extension_directory', 'access_mode',
               'enable_logging', 'enabled_log_types', 'logging_storage', 'log_query_path')
ORDER BY name;
