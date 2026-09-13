#!/usr/bin/env python3
"""Deterministic verdicts for the ai-data-security db-access-audit skill.

Two dialects, one check map:

  --dialect postgres (default): consumes the CSV outputs of the read-only SQL pack
  (grants.csv, pii_columns.csv, masked_views.csv, audit_logging.csv).

  --dialect snowflake: consumes recorded `snow sql` outputs (the ASCII tables SHOW
  GRANTS / SHOW MASKING POLICIES / SHOW VIEWS / the pii_columns SELECT print) —
  the same files a `--recorded <dir>` air-gapped run reads. Verdicts that used to
  be "interpretation rules the model applies mentally" (reference.md) are computed
  here so both dialects honor the plugin's scripts-decide/model-narrates split.

  DB-01  AI principal holds write privileges (INSERT/UPDATE/DELETE/TRUNCATE/OWNERSHIP)
  DB-02  AI principal holds SELECT on base tables (not views)
  DB-03  PII-named columns readable unmasked by the AI principal
  DB-04  no masked/governed view layer exists
  DB-05  no audit trail of queries (pg: no pgaudit/statement logging; sf: nobody
         beyond account admins can even review QUERY_HISTORY — probable at best,
         this check is partly organizational)

  v0.4 (optional inputs; each missing input is a DB-06 UNKNOWN, never a pass):
  DB-ID-01 effective identity: superuser/BYPASSRLS/CREATEROLE, table ownership, role
           inheritance (pg); user TYPE not SERVICE/SERVICE_AGENT, DEFAULT_SECONDARY_ROLES=ALL,
           extra roles granted to the user, role inheritance (sf)
  DB-07  raw-to-curated boundary crossed by an indirect path: inherited grants, PUBLIC grants,
         default privileges (pg); role inheritance / secondary roles (sf)
  DB-08  no governed control attached to readable PII columns: no anon masking label / RLS (pg);
         zero POLICY_REFERENCES for the database (sf); dynamic tables refreshing as their owner
  DB-09  audit-trail quality: pgaudit absent or not configured, per-role logging absent (pg);
         nobody holds GOVERNANCE_VIEWER, result cache reuse on for the AI user (sf)
  DB-10  external write paths: pg_write_server_files / pg_execute_server_program membership,
         foreign servers, dblink/file_fdw (pg); USAGE on STAGE / INTEGRATION (sf)

If the AI principal was NOT explicitly confirmed by the user (--principal-confirmed absent),
confidence drops to "possible", capping severity at MEDIUM per reference/finding-format.md.

An optional org profile (.ai-data-security.yml, JSON-formatted — see
reference/org-config.md) may append org-specific citations to findings; it can never
remove or weaken one. Auto-discovered next to the --ignore-dir root.

The model narrates this output; it does not change these verdicts. Stdlib only. Read-only
except the optional --emit-json path. Reports carry object and column names — never row data.
"""

import argparse
import csv
import datetime
import json
import os
import re

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCHEMA_VERSION = 1
WRITE_PRIVS = {"INSERT", "UPDATE", "DELETE", "TRUNCATE"}
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_CAP = {"possible": "MEDIUM", "probable": "HIGH", "confirmed": "CRITICAL"}


# Column sets each query output must have; a present-but-malformed CSV (missing/renamed
# column) is failed closed to a DB-06 UNKNOWN rather than crashing with a KeyError.
REQUIRED_COLUMNS = {
    "grants": {"table_schema", "table_name", "privilege_type", "object_kind"},
    "pii_columns": {"table_schema", "table_name", "column_name", "tier_floor"},
    "columns": {"table_schema", "table_name", "column_name", "data_type", "ordinal_position"},
    "masked_views": {"has_masking_signal"},
    "audit_logging": {"name", "setting"},
    "identity": {"kind", "name", "detail"},
    "policy_attachment": {"kind", "name", "detail"},
    "external_paths": {"kind", "name", "detail"},
    "audit_quality": {"name", "setting"},
}
# Required column names per recorded Snowflake statement (lowercased by parse_show_tables). A table
# missing any of them is malformed: its checks fail closed to DB-06 instead of silently passing.
REQUIRED_COLUMNS_SF = {
    "grants": [{"privilege", "granted_on", "name"}],
    "pii_columns": [{"table_schema", "table_name", "column_name", "tier_floor"}],
    "masked_views": [{"name"}, {"name"}],           # statement 3 (dynamic tables) is optional
    "audit_logging": [{"privilege", "grantee_name"}],
    "identity": [{"property"}, {"role"}],
    "policy_references": [{"policy_kind", "ref_schema_name", "ref_entity_name", "ref_column_name"}],
    "audit_quality": [{"grantee_name"}, {"key", "value"}],
}
UNSET_TOKENS = {"", "null", "none"}


def _unset(value):
    return (value or "").strip().lower() in UNSET_TOKENS


def sf_tables_ok(name, tables):
    """Header validation for a recorded Snowflake input: every required statement present with
    its required columns. Empty tables (header only) are fine; renamed/missing columns are not."""
    required = REQUIRED_COLUMNS_SF[name]
    if tables is None or len(tables) < len(required):
        return False
    for idx, cols in enumerate(required):
        header = set(getattr(tables[idx], "header", []) or [])
        for row in tables[idx]:
            header |= set(row.keys())
        if not cols.issubset(header):
            return False
    return True


SERVICE_USER_TYPES_SF = {"SERVICE", "SERVICE_AGENT", "LEGACY_SERVICE"}
EXTERNAL_GRANT_ON_SF = {"STAGE", "INTEGRATION", "EXTERNAL VOLUME"}
SERVER_ROLES_PG = {"pg_write_server_files", "pg_execute_server_program", "pg_read_server_files"}
GOVERNANCE_VIEW_ROLE = "GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE <auditor_role>;"


def v04_unknown(name, statement, unknowns, extra=""):
    unknowns.append({
        "check_id": "DB-06",
        "reason": f"input '{name}' not captured — its v0.4 check(s) did not run.{extra}",
        "action": f"Capture `{statement}` and re-run; do not treat this as a pass.",
    })


def csv_header(path):
    """Header row of a CSV file (so a zero-row capture with the wrong columns still fails closed)."""
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            return set(next(csv.reader(f), []))
    except OSError:
        return set()


def read_csv(path):
    if not path or not os.path.exists(path):
        return None
    # utf-8-sig strips a leading BOM some clients prepend, which would otherwise corrupt the
    # first column name.
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_show_tables(path):
    """Parse recorded `snow sql` output into a list of tables (list of row dicts).

    Handles the ASCII-table shape SHOW/SELECT print: `+---+` borders, a `| a | b |`
    header, a `|---|` separator, data rows. A file may hold several statements
    (e.g. masked_views.sql = SHOW MASKING POLICIES + SHOW VIEWS); fixture comment
    lines (`--`), blank lines, and "N Row(s) produced." trailers are skipped.
    Column names are lowercased. Returns None if the file is missing; [] if no
    table could be parsed (caller fails closed to DB-06).
    """
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        lines = f.read().splitlines()
    class _Table(list):
        header = []

    tables, header = [], None
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if stripped.startswith("+"):
                continue
            header = None  # comment / blank / "N Row(s) produced." ends the table
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if all(set(c) <= {"-"} for c in cells):
            continue  # the |---+---| header/body separator
        if header is None:
            header = [c.lower() for c in cells]
            tbl = _Table()
            tbl.header = header
            tables.append(tbl)
        else:
            row = dict(zip(header, cells))
            if len(cells) == len(header):
                tables[-1].append(row)
    return tables


def load_org_config(path):
    """Read the optional org profile. JSON-formatted .yml (the repo's citations.yml
    precedent) so the audit stays stdlib-only. Returns (config-or-None, error-or-None);
    a present-but-unparseable file is an error the caller must surface as an UNKNOWN —
    intended extensions silently not applying is a fail-open we don't allow."""
    if not path or not os.path.exists(path):
        return None, None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None, "top-level value is not an object"
        return data, None
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        return None, str(e)


def load_registry():
    with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
        citations = json.load(f)["citations"]
    with open(os.path.join(PLUGIN_ROOT, "reference", "checks.yml"), encoding="utf-8") as f:
        checks = json.load(f)["checks"]
    return citations, checks


def load_suppressions(target):
    """Same .ai-data-security-ignore contract as the other evaluators (see finding-format.md).
    Fail closed: an unparseable expiry counts as expired."""
    path = os.path.join(target, ".ai-data-security-ignore")
    entries = {}
    if not os.path.exists(path):
        return entries
    today = datetime.date.today()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            fingerprint = parts[0]
            expires, reason = None, ""
            for part in parts[1:]:
                if part.startswith("expires="):
                    expires = part.split("=", 1)[1]
                elif part.startswith("reason="):
                    reason = line.split("reason=", 1)[1]
            expired = False
            # `expires=` present but empty is malformed, not "no expiry" — fail closed.
            if expires is not None:
                try:
                    expired = datetime.date.fromisoformat(expires) < today
                except ValueError:
                    expired = True
            entries[fingerprint] = {"expires": expires, "reason": reason, "expired": expired}
    return entries


def finding(check_id, title, severity, confidence, obj, evidence, remediation):
    cap = CONFIDENCE_CAP[confidence]
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(cap):
        severity = cap
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file": obj,
        "evidence": evidence,
        "remediation": remediation,
        "rotate_first": False,
        "fingerprint": f"{check_id}:{obj}:db",
    }


WRITE_PRIVS_SF = WRITE_PRIVS | {"OWNERSHIP"}
ADMIN_ROLES_SF = {"ACCOUNTADMIN", "SECURITYADMIN"}
MASKING_NAME_SIGNAL = ("mask", "hash", "redact", "governed")


def snowflake_findings(args, confidence, unknowns):
    """Compute DB-01..DB-05 from recorded snow-sql outputs (reference.md's
    interpretation table, made mechanical)."""
    findings = []
    parsed = {}
    expected_tables = {"grants": 1, "pii_columns": 1, "masked_views": 2, "audit_logging": 1}
    paths = {"grants": args.grants, "pii_columns": args.pii,
             "masked_views": args.views, "audit_logging": args.settings}
    for name, path in paths.items():
        tables = parse_show_tables(path)
        if tables is None or len(tables) < expected_tables[name] or not sf_tables_ok(name, tables):
            if tables is None:
                got = "missing"
            elif len(tables) < expected_tables[name]:
                got = f"only {len(tables)} table(s) parsed"
            else:
                got = "has an unexpected header (renamed or missing columns)"
            unknowns.append({
                "check_id": "DB-06",
                "reason": f"recorded output '{name}' {got} — that part of the audit did not run.",
                "action": "Re-capture the exact pack query output and re-evaluate; "
                          "do not treat this as a pass.",
            })
            parsed[name] = None
        else:
            parsed[name] = tables

    readable = set()
    if parsed["grants"] is not None:
        rows = parsed["grants"][0]
        writes = sorted({
            f"{r.get('name', '?')}:{r.get('privilege', '?')}"
            for r in rows
            if r.get("privilege", "").upper() in WRITE_PRIVS_SF
            and r.get("granted_on", "").upper() == "TABLE"
        })
        if writes:
            findings.append(finding(
                "DB-01", f"AI principal '{args.role}' holds write privileges",
                "CRITICAL", confidence, args.role,
                f"Write grants held on tables: {', '.join(writes)}. An AI principal with write "
                "access can mutate or destroy data on a bad generation or injected instruction.",
                [
                    f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA <schema> FROM ROLE {args.role};",
                    "Re-run this audit to verify only SELECT-on-views remains.",
                ],
            ))
        base_selects = sorted({
            r.get("name", "?") for r in rows
            if r.get("privilege", "").upper() == "SELECT"
            and r.get("granted_on", "").upper() == "TABLE"
        })
        if base_selects:
            findings.append(finding(
                "DB-02", f"AI principal '{args.role}' reads base tables directly",
                "HIGH", confidence, args.role,
                f"SELECT with granted_on = TABLE (not VIEW): {', '.join(base_selects)}. Raw tables "
                "expose every column, including sensitive ones, with no masking layer in between.",
                [
                    "Create a curated schema of masked/governed views and grant SELECT on those views only.",
                    f"Then: REVOKE SELECT ON ALL TABLES IN SCHEMA <schema> FROM ROLE {args.role};",
                ],
            ))
        readable = {
            tuple(r.get("name", "").upper().split(".")[-2:])
            for r in rows
            if r.get("privilege", "").upper() == "SELECT"
            and r.get("granted_on", "").upper() in ("TABLE", "VIEW", "MATERIALIZED VIEW")
        }

    if parsed["pii_columns"] is not None and parsed["grants"] is not None:
        exposed = [
            r for r in parsed["pii_columns"][0]
            if (r.get("table_schema", "").upper(), r.get("table_name", "").upper()) in readable
        ]
        sf_views = parsed["masked_views"][1] if parsed.get("masked_views") and len(parsed["masked_views"]) > 1 else None
        pseudo_set = pseudonymized_set("snowflake", exposed, sf_views)
        pseudo_rows = [r for r in exposed if (r["table_schema"], r["table_name"], r["column_name"]) in pseudo_set]
        exposed = [r for r in exposed if (r["table_schema"], r["table_name"], r["column_name"]) not in pseudo_set]
        restricted = sorted(
            f"{r['table_schema']}.{r['table_name']}.{r['column_name']}"
            for r in exposed if r.get("tier_floor") == "Restricted"
        )
        confidential = sorted(
            f"{r['table_schema']}.{r['table_name']}.{r['column_name']}"
            for r in exposed if r.get("tier_floor") == "Confidential"
        )
        if restricted:
            findings.append(finding(
                "DB-03", f"Restricted-tier columns readable by '{args.role}'",
                "HIGH", confidence, ";".join(restricted[:3]),
                f"PII-named columns at Restricted floor readable unmasked: {', '.join(restricted)} "
                "(column names only; no data sampled).",
                [
                    "Serve these through masked views (omit SSN/PAN; keyed-hash the join keys).",
                    "Where joins are needed use keyed hashing (HMAC) or tokenization with the key outside the AI role's reach — not a salt table beside the data. /ai-data-security:safe-db-access renders this.",
                ],
            ))
        pseudonymized = sorted(
            f"{r['table_schema']}.{r['table_name']}.{r['column_name']}" for r in pseudo_rows
        )
        if pseudonymized:
            findings.append(finding(
                "DB-03", f"Pseudonymized PII-derived columns readable by '{args.role}' (still personal data)",
                "INFO", confidence, ";".join(pseudonymized[:3]),
                f"Pseudonymized columns readable (suffix _pseudo/_hash/_hmac/_token AND the object is a view whose definition hashes/masks): {', '.join(pseudonymized)}. "
                "Hashed identifiers remain personal data "
                "(NIST SP 800-188 §4.3.2); the key must stay outside the AI role's reach.",
                ["Confirm the key vault schema is not readable by the AI role and that the hash is keyed."],
            ))
        if confidential:
            findings.append(finding(
                "DB-03", f"Confidential-tier columns readable by '{args.role}'",
                "MEDIUM", confidence, ";".join(confidential[:3]),
                f"PII-named columns at Confidential floor readable unmasked: {', '.join(confidential)} "
                "(column names only; no data sampled).",
                ["Prefer masked or aggregated views for person-identifying columns."],
            ))

    if parsed["masked_views"] is not None:
        policies, views = parsed["masked_views"][0], parsed["masked_views"][1]
        named_signal = [
            v.get("name", "") for v in views
            if any(s in v.get("name", "").lower() for s in MASKING_NAME_SIGNAL)
        ]
        if not policies and not named_signal:
            findings.append(finding(
                "DB-04", "No masked/governed view layer detected",
                "MEDIUM", confidence, "views",
                f"{len(policies)} masking policies in the account and {len(views)} view(s) in the "
                "target database, none named like a masking/governed layer. AI access appears to "
                "go straight at raw objects.",
                [
                    "Stand up a curated schema of masked views as the only surface the AI role can read.",
                    "The ai-data-security v2 safe-db-access recipe implements this end-to-end.",
                ],
            ))

    if parsed["audit_logging"] is not None:
        holders = {
            r.get("grantee_name", "").upper()
            for r in parsed["audit_logging"][0]
            if r.get("privilege", "").upper() == "IMPORTED PRIVILEGES"
        }
        if not holders - ADMIN_ROLES_SF:
            # Partly organizational: the recorded output can prove nobody CAN review,
            # never that somebody DOES — confidence is probable at best (reference.md).
            db05_confidence = "probable" if confidence == "confirmed" else confidence
            findings.append(finding(
                "DB-05", "No audit trail review of the AI principal's queries",
                "MEDIUM", db05_confidence, "SNOWFLAKE database grants",
                f"Only {', '.join(sorted(holders)) or 'no role'} holds IMPORTED PRIVILEGES on the "
                "SNOWFLAKE database — no non-admin role can even review QUERY_HISTORY, and no "
                "evidence anyone monitors the AI role's queries.",
                [
                    "Grant IMPORTED PRIVILEGES on the SNOWFLAKE database to a governance role "
                    "and name an owner who reviews the AI role's QUERY_HISTORY.",
                ],
            ))

    findings += snowflake_v04_findings(args, confidence, unknowns, readable, parsed)
    return findings


def _secondary_roles(raw):
    """Active secondary roles from CURRENT_SECONDARY_ROLES(): documented as a JSON object with
    `roles` (comma-separated string) and `value` (e.g. ALL). A list is accepted defensively.
    Returns a sorted list (empty = none active), or None when the text is not that JSON."""
    text = (raw or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    roles = data.get("roles")
    if isinstance(roles, list):
        names = [str(r) for r in roles]
    elif isinstance(roles, str):
        names = [r.strip() for r in roles.split(",")]
    else:
        names = []
    return sorted({n.upper() for n in names if n})


def _desc_user(rows):
    """DESCRIBE USER rows -> {PROPERTY: effective value}.

    Snowflake renders the columns as `property | value | default | description` in some clients
    and `property | property_type | property_value | property_default` in others; both are
    accepted. When the value is unset/null the documented default applies (for
    DEFAULT_SECONDARY_ROLES that default is [ALL]), so the default column is the fallback."""
    out = {}
    for r in rows:
        prop = (r.get("property") or "").upper()
        if not prop:
            continue
        value = r.get("value", r.get("property_value", "")) or ""
        default = r.get("default", r.get("property_default", "")) or ""
        if value.strip().lower() in ("", "null", "none"):
            value = default
        out[prop] = value
    return out


def snowflake_v04_findings(args, confidence, unknowns, readable, parsed):
    findings = []
    role = args.role
    # ---- identity (DESCRIBE USER + SHOW GRANTS TO USER) ----
    ident = parse_show_tables(args.identity) if args.identity else None
    if ident is None or not sf_tables_ok("identity", ident):
        v04_unknown("identity", "snow sql -D \"user=<ai-user>\" -f identity.sql", unknowns,
                    " DB-ID-01 (user type, secondary roles) cannot be assessed.")
    else:
        props = _desc_user(ident[0])
        if "TYPE" not in props or "DEFAULT_SECONDARY_ROLES" not in props:
            v04_unknown("identity", "snow sql -D \"user=<ai-user>\" -f identity.sql", unknowns,
                        " DESCRIBE USER output lacks TYPE and/or DEFAULT_SECONDARY_ROLES; DB-ID-01 not assessed.")
        else:
            user_roles = sorted({r.get("role", "") for r in ident[1] if r.get("role")})
            utype = props.get("TYPE", "").upper()
            sec = props.get("DEFAULT_SECONDARY_ROLES", "").upper()
            sec_all = "ALL" in sec
            default_role = props.get("DEFAULT_ROLE", "").upper()
            problems = []
            if utype not in SERVICE_USER_TYPES_SF:
                problems.append(f"TYPE = {utype or 'unset'} (a person-type user; SERVICE or SERVICE_AGENT is the agent identity)")
            if sec_all:
                problems.append("DEFAULT_SECONDARY_ROLES = ('ALL'): every role granted to the user is active in every session")
            if len(user_roles) > 1:
                problems.append(f"{len(user_roles)} roles granted to the user: {', '.join(user_roles)}")
            if default_role and not _unset(default_role) and default_role != role.upper():
                problems.append(f"DEFAULT_ROLE is {default_role}, not the audited role {role}: sessions start with a different privilege set than the one audited")
            # v0.7: the audit session's own identity (statement 3, optional for older captures)
            session = ident[2][0] if len(ident) > 2 and ident[2] else None
            if session is None:
                unknowns.append({
                    "check_id": "DB-06",
                    "reason": "identity.sql statement 3 (CURRENT_USER/CURRENT_ROLE/CURRENT_SECONDARY_ROLES of the audit session) was not captured; the session's real role was not compared to --role.",
                    "action": "Re-capture identity.sql with the current pack (three statements).",
                })
            else:
                s_user = (session.get("session_user_name") or "").upper()
                s_role = (session.get("session_role_name") or "").upper()
                s_sec = session.get("session_secondary_roles") or ""
                ai_user = (props.get("NAME") or "").upper()
                if s_user and ai_user and s_user == ai_user:
                    if s_role and s_role != role.upper():
                        problems.append(f"the audit session ran AS the AI user with CURRENT_ROLE() = {s_role}, not the audited role {role}: the real privilege set is that role's")
                    active = _secondary_roles(s_sec)
                    if active is None:
                        unknowns.append({"check_id": "DB-06",
                                         "reason": "identity.sql statement 3: CURRENT_SECONDARY_ROLES() output could not be parsed as JSON; active secondary roles unknown.",
                                         "action": "Re-capture identity.sql; the value should look like {\"roles\":\"A,B\",\"value\":\"ALL\"}."})
                    elif active:
                        problems.append(f"the audit session (as the AI user) had secondary roles active: {', '.join(active)}")
                        unknowns.append({"check_id": "DB-06",
                                         "reason": f"secondary roles {', '.join(active)} were active in the audited session but only role {role}'s grants were captured; the session's effective access is wider than every DB-01..DB-10 verdict above.",
                                         "action": "Capture grants.sql for each active secondary role (SHOW GRANTS TO ROLE <r>) or set DEFAULT_SECONDARY_ROLES = () and re-audit."})
            if problems:
                findings.append(finding(
                    "DB-ID-01", f"AI principal's user identity widens its reach beyond role '{role}'",
                    "HIGH", confidence, props.get("NAME", "user"),
                    "; ".join(problems) + ". The role name is not the boundary; the user's type, default role, and secondary roles are.",
                    [
                        "Create the agent's user with TYPE = SERVICE_AGENT (or SERVICE) and DEFAULT_SECONDARY_ROLES = ().",
                        f"Grant only ROLE {role} to that user and set it as DEFAULT_ROLE; move analyst roles to the human's own user.",
                        "Agent identity (GA 2026-07-23) then marks the sessions in QUERY_HISTORY.agent_type.",
                    ],
                ))
    # ---- DB-07 boundary via role inheritance (from grants) ----
    inherited_roles = []
    if parsed.get("grants") is not None:
        inherited_roles = sorted({
            r.get("name", "?") for r in parsed["grants"][0]
            if r.get("granted_on", "").upper() == "ROLE" and r.get("privilege", "").upper() == "USAGE"
        })
    if inherited_roles:
        findings.append(finding(
            "DB-07", f"Raw-to-curated boundary crossed by role inheritance for '{role}'",
            "HIGH", confidence, role,
            f"Role '{role}' inherits {', '.join(inherited_roles)} (USAGE on ROLE). Everything those roles can "
            "read, the AI session can read; the curated boundary is only as tight as the weakest inherited role.",
            [
                f"REVOKE ROLE <inherited> FROM ROLE {role}; grant the specific view SELECTs the agent needs instead.",
                "Capture `SHOW GRANTS TO ROLE <inherited>` for each inherited role and re-audit them as AI principals.",
            ],
        ))
    # ---- DB-08 policy attachment + dynamic tables ----
    refs = parse_show_tables(args.policies) if args.policies else None
    pii_rows = parsed.get("pii_columns")[0] if parsed.get("pii_columns") else []
    readable_pii = [
        r for r in pii_rows
        if (r.get("table_schema", "").upper(), r.get("table_name", "").upper()) in readable
    ]
    sf_views = parsed["masked_views"][1] if parsed.get("masked_views") and len(parsed["masked_views"]) > 1 else None
    pseudo_set = pseudonymized_set("snowflake", readable_pii, sf_views)
    readable_pii = [r for r in readable_pii if (r["table_schema"], r["table_name"], r["column_name"]) not in pseudo_set]
    if refs is None or not sf_tables_ok("policy_references", refs):
        v04_unknown("policy_references", "snow sql -D \"db=<db>\" -f policy_references.sql", unknowns,
                    f" Requires `{GOVERNANCE_VIEW_ROLE}`; without it DB-08 stays UNKNOWN, not clear.")
    elif readable_pii:
        attached = {
            (r.get("ref_schema_name", "").upper(), r.get("ref_entity_name", "").upper(), r.get("ref_column_name", "").upper())
            for r in refs[0] if r.get("policy_kind", "").upper() in ("MASKING_POLICY", "MASKING POLICY")
        }
        unprotected = sorted(
            f"{r['table_schema']}.{r['table_name']}.{r['column_name']}" for r in readable_pii
            if (r.get("table_schema", "").upper(), r.get("table_name", "").upper(), r.get("column_name", "").upper()) not in attached
        )
        if unprotected:
            findings.append(finding(
                "DB-08", f"No masking policy attached to PII columns readable by '{role}'",
                "HIGH", confidence, ";".join(unprotected[:3]),
                f"{len(refs[0])} policy reference(s) in the database; none attached to: {', '.join(unprotected)}. "
                "Readable PII with no governed control is the raw value.",
                [
                    "Attach masking policies (Enterprise) or serve these columns only through masked views.",
                    "In the policy body, IS_AGENT_ACTIVATED() can withhold regulated data from agent sessions.",
                    "Hashed identifiers are pseudonymized, not anonymized (NIST SP 800-188 §4.3.2); keep keys outside the AI role's reach.",
                ],
            ))
    mv = parsed.get("masked_views")
    if mv is not None and len(mv) >= 3:
        for dt in mv[2]:
            owner = dt.get("owner", "")
            exec_as = dt.get("execute_as_user", "")
            if owner and _unset(exec_as):
                findings.append(finding(
                    "DB-08", f"Dynamic table {dt.get('name', '?')} refreshes with owner '{owner}' privileges",
                    "INFO", confidence, f"{dt.get('schema_name', '?')}.{dt.get('name', '?')}",
                    f"Dynamic table {dt.get('name', '?')} is owned by {owner} and has no EXECUTE AS USER; refreshes run "
                    "with the owner role's privileges, not the reader's, so a masked layer built as a dynamic table "
                    "inherits whatever the owner can see.",
                    ["Set EXECUTE AS USER (Feb 2026 feature) or own curated dynamic tables with a least-privilege role."],
                ))
    # ---- DB-09 audit quality ----
    aq = parse_show_tables(args.audit_quality) if args.audit_quality else None
    if aq is None or not sf_tables_ok("audit_quality", aq):
        v04_unknown("audit_quality", "snow sql -D \"user=<ai-user>\" -f audit_quality.sql", unknowns,
                    " DB-09 (who can review ACCESS_HISTORY; result-cache reuse) cannot be assessed. "
                    "Statement 1 needs GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE <auditor_role>;")
    else:
        holders = sorted({r.get("grantee_name", "") for r in aq[0] if not _unset(r.get("grantee_name"))})
        cache = {r.get("key", "").upper(): r.get("value", "") for r in aq[1]}
        cache_on = cache.get("USE_CACHED_RESULT", "").lower() == "true"
        problems = []
        if not holders:
            problems.append("no role holds SNOWFLAKE.GOVERNANCE_VIEWER, so no non-admin can read ACCESS_HISTORY (Enterprise+)")
        if cache_on:
            problems.append("USE_CACHED_RESULT = true for the AI user: reads served from the result cache (up to 31 days) show 0 rows in access history")
        if problems:
            db09_confidence = "probable" if confidence == "confirmed" else confidence
            findings.append(finding(
                "DB-09", "Audit trail of the AI principal has known blind spots",
                "MEDIUM", db09_confidence, "ACCESS_HISTORY",
                "; ".join(problems) + ". An audit trail nobody can read, or that skips cache hits, is not evidence of what the agent read.",
                [
                    GOVERNANCE_VIEW_ROLE + " — and name who reviews it.",
                    "ALTER USER <ai-user> SET USE_CACHED_RESULT = FALSE; so every agent read is recorded.",
                    "Use a SERVICE_AGENT user so QUERY_HISTORY.agent_type marks agent sessions.",
                ],
            ))
    # ---- DB-10 external write paths ----
    if parsed.get("grants") is not None:
        ext = sorted({
            f"{r.get('granted_on', '?')} {r.get('name', '?')}:{r.get('privilege', '?')}"
            for r in parsed["grants"][0]
            if r.get("granted_on", "").upper() in EXTERNAL_GRANT_ON_SF
        })
        if ext:
            findings.append(finding(
                "DB-10", f"AI principal '{role}' can reach external storage",
                "HIGH", confidence, role,
                f"Grants on external objects: {', '.join(ext)}. With USAGE on a stage or integration the role can "
                "COPY INTO an external location: a read-only-looking role with an exfiltration path.",
                [f"REVOKE USAGE ON STAGE <stage> FROM ROLE {role}; agents rarely need stages or integrations."],
            ))
    return findings


def postgres_v04_findings(args, confidence, unknowns, grants, pii):
    findings = []
    role = args.role
    readable_pii = []
    if grants is not None and pii is not None:
        readable = {(g["table_schema"], g["table_name"]) for g in grants if g["privilege_type"] == "SELECT"}
        readable_pii = [p for p in pii if (p["table_schema"], p["table_name"]) in readable]
        pseudo_set = pseudonymized_set("postgres", readable_pii, read_csv(args.views))
        readable_pii = [p for p in readable_pii if (p["table_schema"], p["table_name"], p["column_name"]) not in pseudo_set]

    def load(name, argpath, statement):
        data = read_csv(argpath) if argpath else None
        if data is None:
            v04_unknown(name, statement, unknowns)
            return None
        if data and not REQUIRED_COLUMNS[name].issubset(data[0].keys()):
            v04_unknown(name, statement, unknowns, " (unexpected columns)")
            return None
        return data

    ident = load("identity", args.identity, "psql --csv -v ai_role=<role> -f identity.sql")
    if ident is not None:
        attrs = {r["name"]: r["detail"] for r in ident if r["kind"] == "attr"}
        members = sorted({r["name"] for r in ident if r["kind"] == "member_of" and r["detail"] == "inherit"
                          and r["name"] not in SERVER_ROLES_PG})
        owns = sorted({r["name"] for r in ident if r["kind"] == "owns"})
        dangerous = [k for k in ("rolsuper", "rolbypassrls", "rolcreaterole", "rolreplication") if attrs.get(k) in ("t", "true", "True")]
        problems = []
        sev = "HIGH"
        if dangerous:
            problems.append(f"role attributes {', '.join(dangerous)} are set (superuser/BYPASSRLS/CREATEROLE bypass or can grant around every boundary)")
            sev = "CRITICAL"
        if owns:
            problems.append(f"owns {len(owns)} relation(s): {', '.join(owns[:5])} (owners hold all privileges and bypass RLS unless FORCE ROW LEVEL SECURITY)")
        if members:
            problems.append(f"inherits {len(members)} role(s) with INHERIT: {', '.join(members)}")
        if problems:
            findings.append(finding(
                "DB-ID-01", f"AI principal '{role}' identity is wider than its direct grants",
                sev, confidence, role,
                "; ".join(problems) + ". Direct grants understate what this session can do.",
                [
                    f"ALTER ROLE {role} NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOINHERIT; (as applicable)",
                    f"REVOKE <group_role> FROM {role}; and transfer any owned relations to an admin role.",
                ],
            ))
        # DB-07: indirect read paths to PII-bearing tables
        pii_tables = {(p["table_schema"], p["table_name"]) for p in pii} if pii is not None else None
        paths = []
        if pii_tables is None:
            unknowns.append({
                "check_id": "DB-06",
                "reason": "DB-07 needs pii_columns to name PII-bearing objects; that input was missing or malformed.",
                "action": "Re-run pii_columns.sql and re-evaluate; DB-07 was not assessed.",
            })
        else:
            for r in ident:
                if r["kind"] in ("inherited_grant", "public_grant"):
                    priv = r["detail"].split(":")[-1]
                    schema, _, table = r["name"].partition(".")
                    if priv == "SELECT" and (schema, table) in pii_tables:
                        paths.append(f"{r['kind']} {r['name']} via {r['detail']}")
                elif r["kind"] == "default_acl" and r["detail"].rsplit(":", 1)[-1] == "SELECT":
                    paths.append(f"default privileges {r['name']}: future tables readable automatically")
        if paths:
            findings.append(finding(
                "DB-07", f"Raw-to-curated boundary crossed by indirect grants for '{role}'",
                "HIGH", confidence, role,
                f"Indirect read paths to PII-bearing objects: {'; '.join(sorted(set(paths)))}. Revoking direct SELECTs "
                "would not close these.",
                [
                    "Revoke PUBLIC SELECT on raw tables; grant to specific roles instead.",
                    f"Give {role} NOINHERIT or remove it from group roles that reach raw schemas.",
                    f"ALTER DEFAULT PRIVILEGES IN SCHEMA <schema> REVOKE SELECT ON TABLES FROM {role};",
                ],
            ))
    pol = load("policy_attachment", args.policies, "psql --csv -v ai_role=<role> -f policy_attachment.sql")
    if pol is not None and readable_pii:
        exts = {r["name"] for r in pol if r["kind"] == "extension"}
        labelled = {r["name"] for r in pol if r["kind"] == "seclabel" and r["detail"] == "anon"}
        rls = {r["name"]: r["detail"] for r in pol if r["kind"] == "rls"}
        unprotected = sorted(
            f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" for p in readable_pii
            if f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" not in labelled
        )
        if unprotected:
            mech = "PostgreSQL Anonymizer (anon) is installed but not applied to them" if "anon" in exts \
                else "no masking mechanism is installed (PostgreSQL has none built in; `anon` is the usual extension)"
            rls_note = ", ".join(f"{k}: RLS {v}" for k, v in sorted(rls.items()) if k in
                                 {f"{p['table_schema']}.{p['table_name']}" for p in readable_pii})
            findings.append(finding(
                "DB-08", f"No governed control attached to PII columns readable by '{role}'",
                "HIGH", confidence, ";".join(unprotected[:3]),
                f"{len(unprotected)} readable PII column(s) carry no masking label: {', '.join(unprotected)}. {mech}. "
                f"Row security state: {rls_note or 'n/a'}.",
                [
                    "Serve PII through masked views the role can SELECT, or install `anon` (pin ≥ 3.2) and label columns.",
                    "Hashed identifiers are pseudonymized, not anonymized (NIST SP 800-188 §4.3.2); keep any key outside the AI role's reach.",
                ],
            ))
    aq = load("audit_quality", args.audit_quality, "psql --csv -v ai_role=<role> -f audit_quality.sql")
    if aq is not None:
        kv = {r["name"]: r["setting"] for r in aq}
        pgaudit_loaded = "pgaudit" in (kv.get("shared_preload_libraries") or "") or "extension:pgaudit" in kv
        role_log = kv.get("role_setting:log_statement")
        problems = []
        if not pgaudit_loaded:
            problems.append("pgaudit is not loaded (no object-level audit of SELECTs is possible without it)")
        elif not any(k.startswith("pgaudit.") and v not in ("", "none") for k, v in kv.items()):
            problems.append("pgaudit is loaded but pgaudit.log / pgaudit.role are not set")
        if not role_log and (kv.get("log_statement") or "none") == "none":
            problems.append(f"no per-role log_statement override for {role} and server log_statement=none")
        if kv.get("logging_collector") == "off" and kv.get("log_destination", "stderr") == "stderr":
            problems.append("logging_collector=off with log_destination=stderr: whatever is logged is not being collected to files")
        if problems:
            findings.append(finding(
                "DB-09", "Audit trail of the AI principal has known blind spots",
                "MEDIUM", confidence, "pg_settings",
                "; ".join(problems) + ". pgaudit writes to the server log, not a queryable table, and cannot reliably audit superusers.",
                [
                    "shared_preload_libraries='pgaudit'; CREATE EXTENSION pgaudit; set pgaudit.role to an audit role with SELECT on the AI-readable objects.",
                    f"ALTER ROLE {role} SET log_statement = 'all'; and ship the server log to durable storage.",
                ],
            ))
    ext = load("external_paths", args.external, "psql --csv -v ai_role=<role> -f external_paths.sql")
    if ext is not None:
        server_roles = sorted({r["name"] for r in ext if r["kind"] == "server_role"})
        servers = sorted({f"{r['name']} ({r['detail']})" for r in ext if r["kind"] == "foreign_server"})
        functions = sorted({f"{r['name']}: {r['detail']}" for r in ext if r["kind"] == "function"})
        extensions = sorted({r["name"] for r in ext if r["kind"] == "extension"})
        write_roles = [r for r in server_roles if r in ("pg_write_server_files", "pg_execute_server_program")]
        if server_roles or servers or functions:
            sev = "CRITICAL" if write_roles else "HIGH"
            parts = []
            if server_roles:
                parts.append(f"member of {', '.join(server_roles)} — these bypass all database-level permission checks and can reach superuser-level access")
            if servers:
                parts.append(f"USAGE on foreign server(s): {', '.join(servers)}")
            if functions:
                parts.append(f"EXECUTE on server-reaching function(s): {', '.join(functions)}")
            if extensions:
                parts.append(f"network/file extensions installed: {', '.join(extensions)} (context; not a grant by itself)")
            findings.append(finding(
                "DB-10", f"AI principal '{role}' has paths outside the database",
                sev, confidence, role,
                "; ".join(parts) + ".",
                [f"REVOKE {r} FROM {role};" for r in server_roles] +
                ([f"REVOKE USAGE ON FOREIGN SERVER <server> FROM {role};"] if servers else []) +
                ([f"REVOKE EXECUTE ON FUNCTION <function> FROM {role};"] if functions else []),
            ))
    return findings


PSEUDO_SUFFIX = re.compile(r"_(pseudo|pseudonym|pseudonymized|hash|hashed|hmac|token|tokenized)$", re.I)
HASH_SIGNAL_SF = re.compile(r"(sha2|sha1|md5|hash|hmac|mask|tokeniz)", re.I)


def pseudonymized_set(dialect, pii_rows, views_input):
    """(schema, table, column) triples that count as pseudonymized: the NAME carries a
    pseudonymization suffix AND the OBJECT is a view whose definition shows a hashing/masking
    signal (Postgres: masked_views.has_masking_signal; Snowflake: SHOW VIEWS `text`). A base-table
    column named ssn_hash is NOT pseudonymized: names are not evidence, provenance is. Anything
    unverifiable (no views input, no `text` column) is not pseudonymized — fail closed."""
    out = set()
    if not pii_rows or views_input is None:
        return out
    signal_objects = set()
    if dialect == "postgres":
        for v in views_input:
            if v.get("has_masking_signal") in ("t", "true", "True"):
                signal_objects.add((v.get("table_schema", ""), v.get("table_name", "")))
    else:
        for v in views_input:
            text = v.get("text")
            if text and HASH_SIGNAL_SF.search(text):
                signal_objects.add((v.get("schema_name", "").upper(), v.get("name", "").upper()))
    for r in pii_rows:
        s, n, c = r.get("table_schema", ""), r.get("table_name", ""), r.get("column_name", "")
        key = (s, n) if dialect == "postgres" else (s.upper(), n.upper())
        if PSEUDO_SUFFIX.search(c or "") and key in signal_objects:
            out.add((s, n, c))
    return out


def _split_sf_name(name):
    parts = (name or "").split(".")
    return parts if len(parts) == 3 else [None, None, name]


MODULE_DIALECTS = ["databricks", "redshift", "bigquery", "fabric", "lakeformation"]


def run_module_dialect(args, confidence, unknowns):
    """v0.7: load skills/db-access-audit/scripts/dialects/<dialect>.py and feed it the recorded
    CSVs. Missing or malformed file -> DB-06 UNKNOWN naming the capture; the module sees None."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dialects", f"{args.dialect}.py")
    spec = importlib.util.spec_from_file_location(f"dialect_{args.dialect}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tables = {}
    for name, required in module.PACK.items():
        path = os.path.join(args.recorded, f"{name}.csv")
        rows = read_csv(path)
        header = csv_header(path) if rows is not None else set()
        if rows is None:
            unknowns.append({"check_id": "DB-06",
                             "reason": f"recorded output '{name}.csv' missing — that part of the audit did not run.",
                             "action": f"Capture it: {module.CAPTURE.replace('<file>', name)}; do not treat this as a pass."})
            tables[name] = None
        elif not required.issubset(header):
            missing = ", ".join(sorted(required - header))
            unknowns.append({"check_id": "DB-06",
                             "reason": f"recorded output '{name}.csv' has an unexpected header (missing: {missing}) — that check did not run.",
                             "action": "Re-run the exact pack query; do not treat this as a pass."})
            tables[name] = None
        else:
            tables[name] = rows
    optional_json = set(getattr(module, "OPTIONAL_JSON_INPUTS", set()))
    for name, capture in getattr(module, "JSON_INPUTS", {}).items():
        path = os.path.join(args.recorded, f"{name}.json")
        if not os.path.exists(path):
            tables[name] = None
            if name in optional_json:
                continue  # the module decides whether its absence matters
            unknowns.append({"check_id": "DB-06",
                             "reason": f"recorded output '{name}.json' missing — that part of the audit did not run.",
                             "action": f"Capture it: {capture}; do not treat this as a pass."})
            tables[name] = None
            continue
        try:
            with open(path, encoding="utf-8") as f:
                tables[name] = json.load(f)
        except (OSError, ValueError) as exc:
            unknowns.append({"check_id": "DB-06",
                             "reason": f"recorded output '{name}.json' is not valid JSON ({exc.__class__.__name__}) — that check did not run.",
                             "action": "Re-capture the exact command; do not treat this as a pass."})
            tables[name] = None
    if getattr(module, "PRECONDITION", None):
        unknowns.append({"check_id": "DB-06",
                         "reason": f"precondition for a complete {args.dialect} capture: {module.PRECONDITION}",
                         "action": "If the capture did not meet it, the grants are partial; re-capture before trusting a clean result."})
    return module.evaluate(args.role, tables, confidence, unknowns, finding)


def build_plan_inputs(args):
    """Structured, value-free facts for the safe-db-access planner (v0.6). Independent of the
    findings above: re-reads the same inputs so a missing input is `null` here, never guessed.
    Object names are passed through as captured; the planner validates every identifier before
    it renders anything."""
    pi = {"dialect": args.dialect, "role": args.role, "database": None, "raw_tables": [], "pii_columns": [],
          "columns": None, "write_grants": [], "inherited_roles": [], "server_roles": [], "public_grants": [],
          "default_acl": [], "external_objects": [], "user": None, "user_type": None,
          "secondary_roles_all": None, "user_roles": [], "inputs_present": {}}
    if args.dialect == "snowflake":
        grants = parse_show_tables(args.grants)
        pi["inputs_present"]["grants"] = bool(grants) and sf_tables_ok("grants", grants)
        if pi["inputs_present"]["grants"]:
            dbs = set()
            for r in grants[0]:
                on, priv, name = r.get("granted_on", "").upper(), r.get("privilege", "").upper(), r.get("name", "")
                if on == "TABLE":
                    db, sch, tbl = _split_sf_name(name)
                    if db:
                        dbs.add(db)
                        entry = {"schema": sch, "table": tbl}
                        if priv == "SELECT" and entry not in pi["raw_tables"]:
                            pi["raw_tables"].append(entry)
                        if priv in WRITE_PRIVS_SF:
                            pi["write_grants"].append({"schema": sch, "table": tbl, "privilege": priv})
                elif on == "ROLE" and priv == "USAGE":
                    pi["inherited_roles"].append(name)
                elif on in ("STAGE", "INTEGRATION"):
                    pi["external_objects"].append({"kind": on, "name": name, "privilege": priv})
            pi["database"] = sorted(dbs)[0] if len(dbs) == 1 else None
        pii = parse_show_tables(args.pii)
        pi["inputs_present"]["pii_columns"] = bool(pii) and sf_tables_ok("pii_columns", pii)
        if pi["inputs_present"]["pii_columns"]:
            views = parse_show_tables(args.views)
            sf_views = views[1] if views and len(views) > 1 else None
            pseudo_set = pseudonymized_set("snowflake", pii[0], sf_views)
            pi["pii_columns"] = [{"schema": r.get("table_schema"), "table": r.get("table_name"),
                                  "column": r.get("column_name"), "type": r.get("data_type"),
                                  "tier": "Pseudonymized" if (r.get("table_schema"), r.get("table_name"), r.get("column_name")) in pseudo_set else r.get("tier_floor")}
                                 for r in pii[0]]
        ident = parse_show_tables(args.identity) if args.identity else None
        pi["inputs_present"]["identity"] = bool(ident) and sf_tables_ok("identity", ident)
        if pi["inputs_present"]["identity"]:
            props = _desc_user(ident[0])
            pi["user"] = props.get("NAME") or None
            pi["user_type"] = (props.get("TYPE") or "").upper() or None
            sec = props.get("DEFAULT_SECONDARY_ROLES")
            pi["secondary_roles_all"] = ("ALL" in sec.upper()) if sec is not None else None
            pi["user_roles"] = sorted({r.get("role", "") for r in ident[1] if r.get("role")}) if len(ident) > 1 else []
        pi["columns"] = None  # Snowflake views use SELECT * EXCLUDE; no column list needed
    else:
        grants, pii = read_csv(args.grants), read_csv(args.pii)
        pi["inputs_present"]["grants"] = grants is not None and (not grants or REQUIRED_COLUMNS["grants"].issubset(grants[0].keys()))
        if pi["inputs_present"]["grants"]:
            for g in grants:
                entry = {"schema": g["table_schema"], "table": g["table_name"]}
                if g["privilege_type"] == "SELECT" and g["object_kind"] == "base table" and entry not in pi["raw_tables"]:
                    pi["raw_tables"].append(entry)
                if g["privilege_type"] in WRITE_PRIVS:
                    pi["write_grants"].append({**entry, "privilege": g["privilege_type"]})
        pi["inputs_present"]["pii_columns"] = pii is not None and (not pii or REQUIRED_COLUMNS["pii_columns"].issubset(pii[0].keys()))
        if pi["inputs_present"]["pii_columns"]:
            pseudo_set = pseudonymized_set("postgres", pii, read_csv(args.views))
            pi["pii_columns"] = [{"schema": p["table_schema"], "table": p["table_name"], "column": p["column_name"],
                                  "type": p.get("data_type"),
                                  "tier": "Pseudonymized" if (p["table_schema"], p["table_name"], p["column_name"]) in pseudo_set else p["tier_floor"]}
                                 for p in pii]
        cols = read_csv(args.columns) if args.columns else None
        pi["inputs_present"]["columns"] = cols is not None and (not cols or REQUIRED_COLUMNS["columns"].issubset(cols[0].keys()))
        if pi["inputs_present"]["columns"]:
            pi["columns"] = [{"schema": c["table_schema"], "table": c["table_name"], "column": c["column_name"],
                              "type": c["data_type"], "position": int(c["ordinal_position"]) if str(c["ordinal_position"]).isdigit() else 0}
                             for c in cols]
        ident = read_csv(args.identity) if args.identity else None
        pi["inputs_present"]["identity"] = ident is not None and (not ident or REQUIRED_COLUMNS["identity"].issubset(ident[0].keys()))
        if pi["inputs_present"]["identity"]:
            pi["inherited_roles"] = sorted({r["name"] for r in ident if r["kind"] == "member_of" and r["name"] not in SERVER_ROLES_PG})
            pi["server_roles"] = sorted({r["name"] for r in ident if r["kind"] == "member_of" and r["name"] in SERVER_ROLES_PG})
            pi["public_grants"] = [{"object": o, "privilege": pv} for o, pv in
                                   sorted({(r["name"], r["detail"]) for r in ident if r["kind"] == "public_grant"})]
            acl = set()
            for r in ident:
                if r["kind"] != "default_acl":
                    continue
                scope, _, objtype = r["name"].partition(":")
                grantor, _, priv = r["detail"].rpartition(":")
                acl.add((None if scope == "<all schemas>" else scope, objtype, grantor or None, priv))
            pi["default_acl"] = [{"schema": s, "objtype": o, "grantor": g, "privilege": pv}
                                 for s, o, g, pv in sorted(acl, key=lambda x: (x[0] or "", x[1], x[2] or "", x[3]))]
        ext = read_csv(args.external) if args.external else None
        if ext is not None and (not ext or REQUIRED_COLUMNS["external_paths"].issubset(ext[0].keys())):
            pi["external_objects"] = [{"kind": r["kind"], "name": r["name"], "privilege": ""} for r in ext if r["kind"] in ("server_role", "foreign_server")]
    pi["raw_tables"].sort(key=lambda e: (e["schema"] or "", e["table"] or ""))
    pi["pii_columns"].sort(key=lambda e: (e["schema"] or "", e["table"] or "", e["column"] or ""))
    pi["write_grants"].sort(key=lambda e: (e["schema"] or "", e["table"] or "", e["privilege"]))
    pi["inherited_roles"] = sorted(set(pi["inherited_roles"]))
    return pi


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dialect", choices=["postgres", "snowflake"] + MODULE_DIALECTS, default="postgres")
    parser.add_argument("--grants")
    parser.add_argument("--pii")
    parser.add_argument("--views")
    parser.add_argument("--settings")
    parser.add_argument("--recorded", help="v0.7: directory of recorded <query>.csv outputs for a module dialect "
                        f"({', '.join(MODULE_DIALECTS)}); one file per pack query")
    parser.add_argument("--identity", help="v0.4: identity.sql output (pg CSV or sf recorded text)")
    parser.add_argument("--policies", help="v0.4: policy_attachment.csv (pg) or policy_references.txt (sf)")
    parser.add_argument("--external", help="v0.4: external_paths.csv (pg; sf uses grants)")
    parser.add_argument("--audit-quality", help="v0.4: audit_quality.sql output")
    parser.add_argument("--columns", help="v0.6 (postgres): columns.csv — full column lists for the planner")
    parser.add_argument("--role", required=True, help="the AI principal analyzed")
    parser.add_argument("--principal-confirmed", action="store_true",
                        help="user explicitly confirmed --role is the AI principal")
    parser.add_argument("--ignore-dir", help="directory holding a .ai-data-security-ignore to apply "
                        "(the audited project's root, or the --recorded dir)")
    parser.add_argument("--org-config", help="path to an org profile (.ai-data-security.yml); "
                        "defaults to the one next to --ignore-dir when present")
    parser.add_argument("--emit-json")
    args = parser.parse_args()

    confidence = "confirmed" if args.principal_confirmed else "possible"
    citations, checks = load_registry()
    findings, unknowns = [], []
    module_plan_inputs = None

    if args.dialect in MODULE_DIALECTS:
        if not args.recorded:
            parser.error(f"--dialect {args.dialect} needs --recorded <dir> (one <query>.csv per pack file)")
        findings, module_plan_inputs = run_module_dialect(args, confidence, unknowns)
    elif args.dialect == "snowflake":
        for flag in ("grants", "pii", "views", "settings"):
            if not getattr(args, flag):
                parser.error(f"--{flag} is required for --dialect snowflake")
        findings = snowflake_findings(args, confidence, unknowns)
    else:
        for flag in ("grants", "pii", "views", "settings"):
            if not getattr(args, flag):
                parser.error(f"--{flag} is required for --dialect postgres")
        grants = read_csv(args.grants)
        pii = read_csv(args.pii)
        views = read_csv(args.views)
        settings = read_csv(args.settings)

        tables = {"grants": grants, "pii_columns": pii,
                  "masked_views": views, "audit_logging": settings}
        for name in ("grants", "pii_columns", "masked_views", "audit_logging"):
            data = tables[name]
            if data is None:
                unknowns.append({
                    "check_id": "DB-06",
                    "reason": f"query output '{name}' missing — that part of the audit did not run.",
                    "action": "Re-run the pack query and re-evaluate; do not treat this as a pass.",
                })
            elif not REQUIRED_COLUMNS[name].issubset(csv_header(getattr(args, {"grants": "grants", "pii_columns": "pii", "masked_views": "views", "audit_logging": "settings"}[name]))):
                missing = ", ".join(sorted(REQUIRED_COLUMNS[name] - csv_header(getattr(args, {"grants": "grants", "pii_columns": "pii", "masked_views": "views", "audit_logging": "settings"}[name]))))
                unknowns.append({
                    "check_id": "DB-06",
                    "reason": f"query output '{name}' has an unexpected schema (missing column(s): "
                              f"{missing}) — that check did not run.",
                    "action": "Re-run the exact pack query; do not treat this as a pass.",
                })
                tables[name] = None  # fail closed: skip this table's checks rather than crash
        grants, pii, views, settings = (tables["grants"], tables["pii_columns"],
                                        tables["masked_views"], tables["audit_logging"])

        # DB-01 / DB-02 from grants
        if grants is not None:
            writes = sorted({
                f"{g['table_schema']}.{g['table_name']}:{g['privilege_type']}"
                for g in grants if g["privilege_type"] in WRITE_PRIVS
            })
            if writes:
                findings.append(finding(
                    "DB-01", f"AI principal '{args.role}' holds write privileges",
                    "CRITICAL", confidence, args.role,
                    f"Write grants held: {', '.join(writes)}. An AI principal with write access can "
                    "mutate or destroy data on a bad generation or injected instruction.",
                    [
                        f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA <schema> FROM {args.role};",
                        "Re-run this audit to verify only SELECT-on-views remains.",
                    ],
                ))
            base_selects = sorted({
                f"{g['table_schema']}.{g['table_name']}"
                for g in grants
                if g["privilege_type"] == "SELECT" and g["object_kind"] == "base table"
            })
            if base_selects:
                findings.append(finding(
                    "DB-02", f"AI principal '{args.role}' reads base tables directly",
                    "HIGH", confidence, args.role,
                    f"SELECT on base tables (not views): {', '.join(base_selects)}. Raw tables expose "
                    "every column, including sensitive ones, with no masking layer in between.",
                    [
                        "Create a curated schema of masked/governed views and grant SELECT on those views only.",
                        f"Then: REVOKE SELECT ON ALL TABLES IN SCHEMA <schema> FROM {args.role};",
                    ],
                ))

            # DB-03: PII columns on tables the principal can SELECT
            if pii is not None and grants is not None:
                readable = {
                    (g["table_schema"], g["table_name"])
                    for g in grants if g["privilege_type"] == "SELECT"
                }
                exposed = [p for p in pii if (p["table_schema"], p["table_name"]) in readable]
                pseudo_set = pseudonymized_set("postgres", exposed, views)
                pseudo_rows = [p for p in exposed if (p["table_schema"], p["table_name"], p["column_name"]) in pseudo_set]
                exposed = [p for p in exposed if (p["table_schema"], p["table_name"], p["column_name"]) not in pseudo_set]
                restricted = sorted(
                    f"{p['table_schema']}.{p['table_name']}.{p['column_name']}"
                    for p in exposed if p["tier_floor"] == "Restricted"
                )
                confidential = sorted(
                    f"{p['table_schema']}.{p['table_name']}.{p['column_name']}"
                    for p in exposed if p["tier_floor"] == "Confidential"
                )
                if restricted:
                    findings.append(finding(
                        "DB-03", f"Restricted-tier columns readable by '{args.role}'",
                        "HIGH", confidence, ";".join(restricted[:3]),
                        f"PII-named columns at Restricted floor readable unmasked: {', '.join(restricted)} "
                        "(column names only; no data sampled).",
                        [
                            "Serve these through masked views (omit SSN/PAN; keyed-hash the join keys).",
                            "Where joins are needed use keyed hashing (HMAC) or tokenization with the key outside the AI role's reach — not a salt table beside the data. /ai-data-security:safe-db-access renders this.",
                        ],
                    ))
                pseudonymized = sorted(
                    f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" for p in pseudo_rows
                )
                if pseudonymized:
                    findings.append(finding(
                        "DB-03", f"Pseudonymized PII-derived columns readable by '{args.role}' (still personal data)",
                        "INFO", confidence, ";".join(pseudonymized[:3]),
                        f"Pseudonymized columns readable (suffix _pseudo/_hash/_hmac/_token AND the object is a view whose definition hashes/masks): {', '.join(pseudonymized)}. "
                        "Hashed identifiers remain personal data "
                        "(NIST SP 800-188 §4.3.2); the key must stay outside the AI role's reach.",
                        ["Confirm the key vault schema is not readable by the AI role and that the hash is keyed."],
                    ))
                if confidential:
                    findings.append(finding(
                        "DB-03", f"Confidential-tier columns readable by '{args.role}'",
                        "MEDIUM", confidence, ";".join(confidential[:3]),
                        f"PII-named columns at Confidential floor readable unmasked: {', '.join(confidential)} "
                        "(column names only; no data sampled).",
                        ["Prefer masked or aggregated views for person-identifying columns."],
                    ))

        # DB-04: masked-view layer
        if views is not None:
            signals = [v for v in views if v.get("has_masking_signal") in ("t", "true", "True")]
            if not signals:
                n = len(views)
                findings.append(finding(
                    "DB-04", "No masked/governed view layer detected",
                    "MEDIUM", confidence, "views",
                    f"{n} non-system view(s) found; none shows masking signals (hashing, truncation, "
                    "mask functions). AI access appears to go straight at raw objects.",
                    [
                        "Stand up a curated schema of masked views as the only surface the AI role can read.",
                        "The ai-data-security v2 safe-db-access recipe implements this end-to-end.",
                    ],
                ))

        # DB-05: audit logging
        if settings is not None:
            kv = {s["name"]: s["setting"] for s in settings}
            pgaudit = "pgaudit" in (kv.get("shared_preload_libraries") or "")
            stmt_logging = (kv.get("log_statement") or "none") != "none"
            if not pgaudit and not stmt_logging:
                findings.append(finding(
                    "DB-05", "No audit trail of the AI principal's queries",
                    "MEDIUM", confidence, "pg_settings",
                    f"pgaudit not in shared_preload_libraries ('{kv.get('shared_preload_libraries', '')}') "
                    f"and log_statement='{kv.get('log_statement', '')}'. Nothing records what the AI "
                    "role queried.",
                    [
                        "Enable pgaudit for the AI role (or at minimum log_statement=all scoped via ALTER ROLE).",
                        f"ALTER ROLE {args.role} SET log_statement = 'all';",
                    ],
                ))

        findings += postgres_v04_findings(args, confidence, unknowns, grants, pii)

    if not args.principal_confirmed:
        unknowns.append({
            "check_id": "DB-06",
            "reason": f"Role '{args.role}' was not confirmed as the AI principal by the user.",
            "action": "Confirm which principal your AI tooling connects as; findings above are "
                      "capped at MEDIUM/possible until then.",
        })

    for f in findings:
        f["citations"] = [citations[k]["display"] for k in checks[f["check_id"]]["citations"]]

    # Org profile: may APPEND org citations to findings — never removes or reweights one.
    org_path = args.org_config
    if not org_path and args.ignore_dir:
        candidate = os.path.join(args.ignore_dir, ".ai-data-security.yml")
        org_path = candidate if os.path.exists(candidate) else None
    org, org_err = load_org_config(org_path)
    if org_err:
        unknowns.append({
            "check_id": "DB-06",
            "reason": f"org profile '{org_path}' present but unparseable ({org_err}) — "
                      "org extensions were NOT applied.",
            "action": "Fix the file (JSON-formatted; see reference/org-config.md) and re-run.",
        })
    if org:
        for entry in org.get("citations", []):
            if not isinstance(entry, dict) or not entry.get("display"):
                continue
            applies = entry.get("checks")
            for f in findings:
                if applies is None or f["check_id"] in applies:
                    f["citations"].append(str(entry["display"]))

    suppressions = load_suppressions(args.ignore_dir) if args.ignore_dir else {}
    active, suppressed = [], []
    for f in findings:
        entry = suppressions.get(f["fingerprint"])
        if entry and not entry["expired"]:
            suppressed.append({
                "fingerprint": f["fingerprint"],
                "title": f["title"],
                "severity": f["severity"],
                "reason": entry["reason"],
                "expires": entry["expires"],
            })
        else:
            if entry and entry["expired"]:
                f["evidence"] += " (A suppression for this finding expired.)"
            active.append(f)

    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "db-access-audit",
        "target": args.role,
        "tools": {"eval_grants": "4", "dialect": args.dialect},
        "findings": active,
        "unknowns": unknowns,
        "suppressed": suppressed,
        "plan_inputs": module_plan_inputs if module_plan_inputs is not None else build_plan_inputs(args),
    }
    output = json.dumps(result, indent=2)
    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
