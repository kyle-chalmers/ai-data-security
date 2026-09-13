"""DuckDB / MotherDuck — a POSTURE pack (see sql/duckdb/README.md). DuckDB has no roles: whoever can
open the file has every privilege. The checks map onto the DB-* ids as posture questions: is the
file itself the boundary (mode bits, git tracking), can the process reach outside it (external
access, httpfs/cloud extensions, remote/MotherDuck attachments, persistent secrets), is there any
governed layer (views with masking), and is anything recorded (there is no query log).
"""

import re

CLOUD_EXT = {"httpfs", "aws", "azure", "gcs", "iceberg", "delta", "postgres", "postgres_scanner", "mysql", "mysql_scanner", "sqlite", "sqlite_scanner", "motherduck", "ducklake", "spatial"}
REMOTE_SCHEMES = ("s3://", "gs://", "gcs://", "az://", "azure://", "abfss://", "http://", "https://", "md:", "r2://", "hf://")

PACK = {
    "settings": {"name", "value"},  # incl. enable_logging / enabled_log_types / logging_storage / log_query_path / allowed_* / access_mode
    "extensions": {"extension_name", "loaded", "installed"},
    "databases": {"database_name", "path", "type", "readonly"},
    "secrets": {"name", "type", "provider", "persistent", "storage"},
    "pii_columns": {"database_name", "schema_name", "table_name", "column_name", "tier_floor"},
    "masked_views": {"database_name", "schema_name", "view_name", "has_masking_signal"},
    "file": {"path", "size", "mode", "uid", "gid", "mtime"},
}
CAPTURE = "duckdb -readonly -csv -header <db.duckdb> < sql/duckdb/<file>.sql  (file.csv from stat; see README)"
PRECONDITION = ("duckdb_settings() shows the CAPTURE session's values (opened -readonly); the agent's own process may set them differently, "
                "and a process that can open the file can also change every setting unless lock_configuration was set first. The agent "
                "process's open mode (read-only vs read-write) is not observable from the capture. MotherDuck controls are not verified.")


MODE_RE = re.compile(r"^[0-7]{3,4}$")
SECRET_STORAGE_HINT = {"local_file": "unencrypted files under secret_directory"}


def _list(v):
    """DuckDB renders list settings as [] or ['a', 'b']; return the names inside."""
    s = str(v or "").strip()
    if s in ("", "[]", "NULL"):
        return []
    return [x.strip().strip("'\"") for x in s.strip("[]").split(",") if x.strip()]


def _truthy(v):
    return str(v).strip().lower() in ("1", "t", "true", "yes")


def _rows(rows):
    """Drop the '(none)' sentinel the pack's SQL emits so an empty result still carries its CSV header."""
    if rows is None:
        return None
    return [r for r in rows if str(next(iter(r.values()), "")).strip() != "(none)"]


def evaluate(role, tables, confidence, unknowns, finding):
    findings = []
    settings, exts, dbs, secrets = tables.get("settings"), tables.get("extensions"), tables.get("databases"), _rows(tables.get("secrets"))
    pii, views, fileinfo = _rows(tables.get("pii_columns")), _rows(tables.get("masked_views")), tables.get("file")
    kv = {s["name"]: s["value"] for s in (settings or [])}
    unknowns.append({"check_id": "DB-06", "reason": "DuckDB has no identities or grants: every DB-* verdict below is about the file, the process, and its paths out; 'the AI principal' is whatever OS process opens the file.",
                     "action": "Treat the database file like a credential: restrict who can read it and which process can open it."})

    # ---- DB-01 / DB-ID-01: the file is the boundary ----
    unknowns.append({"check_id": "DB-06", "reason": "the agent process's open mode is not observable: the capture session is -readonly by recipe, so access_mode says nothing about the agent; assume it can write everything unless its own launch uses -readonly / access_mode=READ_ONLY.",
                     "action": "Check the agent's launch (MCP server args, connection string) for -readonly or READ_ONLY."})
    if fileinfo is not None:
        row = fileinfo[0] if len(fileinfo) == 1 else None
        mode = str(row.get("mode", "")).strip() if row else ""
        size_ok = str(row.get("size", "")).strip().isdigit() if row else False
        if row is None or not MODE_RE.match(mode) or not size_ok:
            unknowns.append({"check_id": "DB-06", "reason": f"file.csv is not one well-formed stat row (rows={len(fileinfo)}, mode={mode or '?'}): file mode, ownership and git exposure were not assessed.",
                             "action": "Re-capture file.csv exactly as sql/duckdb/README.md shows (one row; mode as octal digits)."})
            fileinfo = None
    if fileinfo is not None:
        perms = mode[-3:]
        other, grp = int(perms[-1]), int(perms[-2])
        world_w, world_r = bool(other & 2), bool(other & 4)
        world = world_r or world_w
        group = bool(grp & 6)
        problems = []
        if world:
            problems.append(f"file mode {mode}: {'world-writable' if world_w else 'world-readable'} — every local user (and every process an agent spawns) can open it" + (" and change it" if world_w else " and read every table"))
        elif group:
            problems.append(f"file mode {mode}: group-accessible")
        if problems:
            findings.append(finding(
                "DB-01", "Whoever opens the DuckDB file holds every privilege",
                "CRITICAL" if world_w else "HIGH", confidence, str(row.get("path", "file")),
                "; ".join(problems) + ". DuckDB runs with the full privileges of the user running it; there is no GRANT to revoke, and any process that opens the file read-write can INSERT/UPDATE/DELETE/DROP everything.",
                ["chmod 600 the file; open it with -readonly (or access_mode = READ_ONLY) in the agent's process; serve the agent a separate read-only copy or a Parquet export of curated views."],
            ))
        findings.append(finding(
            "DB-ID-01", "The AI principal is the OS process that opens the file",
            "HIGH" if (world or group) else "INFO", confidence, str(row.get("path", "file")),
            f"owner uid {row.get('uid', '?')}, gid {row.get('gid', '?')}, mode {mode}, size {row.get('size', '?')} bytes, mtime {row.get('mtime', '?')}. "
            "There is no database identity: an agent's process inherits the invoking user's filesystem rights, and every setting below is changeable by that process unless lock_configuration is on.",
            ["Run the agent under a dedicated OS user with read access to a curated copy only; never point it at the production file."],
        ))
    # ---- DB-02 / DB-03 ----
    if pii is not None:
        exposed = pii
        for tier, sev in (("Restricted", "HIGH"), ("Confidential", "MEDIUM")):
            cols = sorted(f"{p['database_name']}.{p['schema_name']}.{p['table_name']}.{p['column_name']}" for p in exposed if p["tier_floor"] == tier)
            if cols:
                findings.append(finding(
                    "DB-03", f"{tier}-tier columns in the file, readable by any process that opens it",
                    sev, confidence, ";".join(cols[:3]),
                    f"PII-named columns at {tier} floor: {', '.join(cols)} (column names only; no data sampled). No column-level control exists in DuckDB.",
                    ["Keep raw PII out of the file the agent opens: export curated views (hashed/omitted columns) to a separate file or Parquet."],
                ))
        if exposed:
            findings.append(finding(
                "DB-02", "The agent reads base tables directly",
                "HIGH", confidence, "duckdb",
                f"{len({(p['database_name'], p['schema_name'], p['table_name']) for p in exposed})} table(s) with PII-named columns are readable in full; DuckDB has no view-only grant.",
                ["Materialize a curated database file containing only masked views/tables; attach it read-only for the agent."],
            ))
    # ---- DB-04 ----
    if views is not None and pii:
        # only meaningful when raw PII columns exist in the file; with none, there is nothing to mask
        signals = sorted(f"{v['database_name']}.{v['schema_name']}.{v['view_name']}" for v in views if _truthy(v.get("has_masking_signal")))
        if not signals:
            findings.append(finding(
                "DB-04", "No masked/governed view layer detected",
                "MEDIUM", confidence, "views",
                f"{len(views)} view(s), none with a masking-looking expression in its SQL. Even with masked views, the raw tables stay readable in the same file.",
                ["Create masked views, then COPY them to a separate curated file that the agent opens; the view layer only helps if the raw file is out of reach."],
            ))
        else:
            # a substring (md5/hash/substr/mask...) is a hint, never proof that the PII columns are transformed
            unknowns.append({"check_id": "DB-04", "reason": f"view(s) {', '.join(signals)} contain a masking-looking expression; whether the PII columns themselves are transformed (and not also exposed raw) was not verified, and the raw tables stay readable in the same file regardless.",
                             "action": "Read the view SQL; a curated layer only counts once it lives in a separate file the agent opens instead of this one."})
    # ---- DB-05 / DB-09 ----
    if settings is not None:
        log_on = str(kv.get("enable_logging", "0")).strip().lower() in ("1", "true", "t")
        log_types = {x.lower() for x in _list(kv.get("enabled_log_types", ""))} | ({x.strip().lower() for x in str(kv.get("enabled_log_types", "")).split(",") if x.strip()})
        storage = str(kv.get("logging_storage", "memory")).strip().lower()
        legacy = str(kv.get("log_query_path", "NULL")).strip()
        query_log = log_on and ("querylog" in log_types or not log_types) and storage not in ("", "memory", "stdout")
        if query_log or (legacy and legacy.upper() != "NULL"):
            findings.append(finding(
                "DB-05", "Query logging is enabled in the capture session (per-process; the agent's process must match)",
                "INFO", "probable" if confidence == "confirmed" else confidence, "duckdb_settings",
                f"enable_logging={kv.get('enable_logging')} enabled_log_types={kv.get('enabled_log_types') or 'all'} logging_storage={storage}" + (f"; log_query_path set" if legacy and legacy.upper() != "NULL" else "")
                + ". DuckDB logging is a per-process setting with no tamper protection: the agent's own process decides whether it is on, and the log is readable/deletable by that process.",
                ["Enable QueryLog to a file the agent cannot write in the agent's own process (init script + lock_configuration); keep agent-layer logs as well."],
            ))
        else:
            findings.append(finding(
                "DB-05", "No query log in the capture session; DuckDB has none by default",
                "MEDIUM", "probable" if confidence == "confirmed" else confidence, "duckdb_settings",
                f"enable_logging={kv.get('enable_logging', '0')} logging_storage={storage} enabled_log_types={kv.get('enabled_log_types') or '(none)'} log_query_path={legacy or 'NULL'}: nothing records who read what unless the agent's own process turns on QueryLog to a file (memory/stdout storage vanishes with the process). What the agent queried is otherwise known only from its transcript.",
                ["Log at the agent layer (MCP server / harness) and keep transcripts; or enable QueryLog to a file in the agent's process and lock the configuration."],
            ))
    if settings is not None:
        problems = []
        if str(kv.get("enable_external_access", "true")).lower() != "false":
            problems.append("enable_external_access is on: the process can read/write any local file, URL, or bucket the OS user can, and install extensions")
        if str(kv.get("lock_configuration", "false")).lower() != "true":
            problems.append("lock_configuration is off: the agent's own SQL can flip every guard (SET enable_external_access=true)")
        for name in ("autoinstall_known_extensions", "autoload_known_extensions", "allow_community_extensions"):
            if str(kv.get(name, "true")).lower() != "false":
                problems.append(f"{name} is on: a query can pull an extension from the network")
        if str(kv.get("allow_unsigned_extensions", "false")).lower() == "true":
            problems.append("allow_unsigned_extensions is on")
        if str(kv.get("allow_persistent_secrets", "true")).lower() != "false":
            problems.append("allow_persistent_secrets is on: CREATE PERSISTENT SECRET writes credentials to disk unencrypted")
        allow_dirs, allow_paths = _list(kv.get("allowed_directories")), _list(kv.get("allowed_paths"))
        if allow_dirs or allow_paths:
            problems.append(f"allowlisted locations stay reachable even with enable_external_access=false: directories {allow_dirs or '[]'}, paths {allow_paths or '[]'} (review each as a deliberate exception)")
        if not _list(kv.get("disabled_filesystems")) and str(kv.get("enable_external_access", "true")).lower() != "false":
            problems.append("disabled_filesystems is empty: LocalFileSystem and HTTPFileSystem stay enabled")
        if problems:
            findings.append(finding(
                "DB-09", "Process guards are at their permissive defaults (as seen by the capture session)",
                "HIGH", "probable" if confidence == "confirmed" else confidence, "duckdb_settings",
                "; ".join(problems) + ". These are the capture session's values; the agent's process must set them itself, before lock_configuration.",
                ["In the agent's process, first: SET enable_external_access=false; SET autoinstall_known_extensions=false; SET autoload_known_extensions=false; SET allow_community_extensions=false; then SET lock_configuration=true. Or run the CLI with -safe."],
            ))
    # ---- DB-07: paths that widen beyond the file ----
    attached = [d for d in (dbs or []) if not _truthy(d.get("internal", "false"))]
    remote = [d for d in attached if str(d.get("path", "")).lower().startswith(REMOTE_SCHEMES)]
    local_extra = [d for d in attached if d not in remote and str(d.get("path", "")) not in ("", ":memory:")]
    if dbs is not None and (remote or len(local_extra) > 1):
        remote_txt = ", ".join(f"{d['database_name']} ({d['path']}, {'read-only' if _truthy(d.get('readonly')) else 'writable'})" for d in remote)
        local_txt = ", ".join(f"{d['database_name']} ({d['path']})" for d in local_extra)
        findings.append(finding(
            "DB-07", "Attached databases widen the boundary beyond one file",
            "HIGH", confidence, "duckdb_databases",
            (f"Remote/cloud attachments: {remote_txt}. " if remote else "")
            + (f"Local attachments: {local_txt}. " if len(local_extra) > 1 else "")
            + "Every attached database is readable and, unless attached READ_ONLY, writable with the same privileges. MotherDuck (md:) access controls are not verified by this audit.",
            ["Detach what the agent does not need; attach the rest READ_ONLY; keep MotherDuck tokens out of the agent's environment."],
        ))
    # ---- DB-10: paths out ----
    ext_names = {str(e["extension_name"]).lower() for e in (exts or []) if _truthy(e.get("loaded")) or _truthy(e.get("installed"))}
    cloud = sorted(ext_names & CLOUD_EXT)
    persistent = [s for s in (secrets or []) if _truthy(s.get("persistent"))]
    egress_blocked = settings is not None and str(kv.get("enable_external_access", "true")).lower() == "false" and str(kv.get("lock_configuration", "false")).lower() == "true" \
        and not _list(kv.get("allowed_directories")) and not _list(kv.get("allowed_paths"))
    if exts is not None or secrets is not None:
        problems = []
        if cloud:
            problems.append(f"network/cloud extension(s) installed or loaded: {', '.join(cloud)}" + (" — COPY ... TO 's3://...' and remote reads are one statement away" if not egress_blocked else " (installed; remote reads/writes blocked while enable_external_access=false is locked)"))
        if persistent:
            by_storage = {}
            for s in persistent:
                by_storage.setdefault(str(s.get("storage", "")).strip() or "?", []).append(f"{s['name']} ({s['type']})")
            parts = []
            for st, names in sorted(by_storage.items()):
                where = SECRET_STORAGE_HINT.get(st, f"storage backend '{st}'")
                parts.append(f"{', '.join(sorted(names))} in {where}" + (f" ({kv.get('secret_directory', '~/.duckdb/stored_secrets')})" if st == "local_file" else ""))
            problems.append(f"{len(persistent)} persistent secret(s): {'; '.join(parts)} — credentials at rest that any process opening the same DuckDB config can use and read")
        if problems:
            sev = "CRITICAL" if (cloud and persistent) else "HIGH"
            if egress_blocked:
                sev = "MEDIUM"
            findings.append(finding(
                "DB-10", "The process can reach outside the database file" if not egress_blocked else "Residual paths out: extensions installed and secrets at rest (egress blocked in the capture session)",
                sev, "probable" if (egress_blocked and confidence == "confirmed") else confidence, "extensions/secrets",
                "; ".join(problems) + ("." if not egress_blocked else ". The block is the capture session's setting; the agent's process must set and lock the same before this is a pass."),
                ["Uninstall cloud extensions the agent does not need; use temporary secrets (or credential chain) instead of persistent ones; set enable_external_access=false in the agent's process and lock the configuration."],
            ))
    # ---- DB-08: git exposure of the file ----
    if fileinfo is not None and str(fileinfo[0].get("git_ignore", "")).strip() == "not_ignored" and pii:
        findings.append(finding(
            "DB-08", "The database file is inside a repository and not ignored",
            "HIGH", confidence, str(fileinfo[0].get("path", "file")),
            "A .duckdb file with PII columns sits in a git working tree without a .gitignore rule: one `git add .` ships the data (and any secrets in it) to the remote.",
            ["Add the file to .gitignore; move data files out of the repo; run the secrets-scanner on history."],
        ))

    plan_inputs = {
        "dialect": "duckdb", "role": role, "posture": True,
        "settings": kv, "cloud_extensions": cloud, "persistent_secrets": [s["name"] for s in persistent],
        "attached": [{"name": d["database_name"], "path": d["path"], "readonly": _truthy(d.get("readonly"))} for d in attached],
        "pii_columns": [{"schema": f"{p['database_name']}.{p['schema_name']}", "table": p["table_name"], "column": p["column_name"], "type": p.get("data_type"), "tier": p["tier_floor"]} for p in (pii or [])],
        "inputs_present": {k: tables.get(k) is not None for k in PACK},
        "planner_supported": False, "partial_by_design": True,
    }
    return findings, plan_inputs
