DuckDB posture pack (v0.12) — a POSTURE check, not a grants pack: DuckDB has no roles and "executes SQL
with the full privileges of the user running it". Whoever can open the file can read and write all of
it, so the questions are about the FILE, the PROCESS SETTINGS, and the PATHS OUT (httpfs, secrets,
attached databases, extensions), not about GRANTs. Capture with the user's own duckdb CLI, read-only:

    duckdb -readonly -csv -header <path/to/db.duckdb> < sql/duckdb/<file>.sql > <tmp>/<file>.csv

Also record the file itself (never its contents):

    GI=$(git check-ignore -q <db.duckdb> 2>/dev/null && echo ignored || { git rev-parse 2>/dev/null && echo not_ignored || echo not_in_repo; })
    printf 'path,size,mode,uid,gid,mtime,git_ignore\n'                       > <tmp>/file.csv
    stat -f "%N,%z,%Lp,%u,%g,%m,$GI" <db.duckdb>                             >> <tmp>/file.csv     # macOS
    stat -c "%n,%s,%a,%u,%g,%Y,$GI" <db.duckdb>                              >> <tmp>/file.csv     # Linux

The CLI prints NOTHING (no header, zero bytes) for an empty result — observed with DuckDB v1.4.1 both via stdin
and with -c — so secrets / pii_columns / masked_views emit a `(none)` sentinel row that the evaluator drops;
without it an empty capture would read as a failed one.
`--role` is unused (pass the OS user or `local`); DB-ID-01 is about the process, not a database identity.
Settings captured through duckdb_settings() reflect the CAPTURE session (which is opened -readonly, so
`access_mode` says nothing about the agent's process), not necessarily the agent's process: the evaluator says
so, and reports the agent's open mode as UNKNOWN. MotherDuck (`md:` databases) stays UNKNOWN.
