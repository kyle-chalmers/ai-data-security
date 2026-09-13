-- extensions.sql — installed/loaded extensions. httpfs / azure / aws / iceberg / delta / postgres / mysql /
-- sqlite / motherduck are paths OUT of the file (remote reads and writes). Read-only.
SELECT extension_name, loaded, installed, install_mode, installed_from FROM duckdb_extensions()
WHERE installed OR loaded ORDER BY extension_name;
