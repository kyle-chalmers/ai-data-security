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
    "masked_views": {"has_masking_signal"},
    "audit_logging": {"name", "setting"},
}


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
            tables.append([])
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
        if tables is None or len(tables) < expected_tables[name]:
            got = "missing" if tables is None else f"only {len(tables)} table(s) parsed"
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
                    "Serve these through masked views (hash email, last-4 account, omit SSN/PAN).",
                    "Apply per-row salted hashing where joins are needed; keep the salt out of the AI role's reach.",
                ],
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

    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dialect", choices=["postgres", "snowflake"], default="postgres")
    parser.add_argument("--grants", required=True)
    parser.add_argument("--pii", required=True)
    parser.add_argument("--views", required=True)
    parser.add_argument("--settings", required=True)
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

    if args.dialect == "snowflake":
        findings = snowflake_findings(args, confidence, unknowns)
    else:
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
            elif data and not REQUIRED_COLUMNS[name].issubset(data[0].keys()):
                missing = ", ".join(sorted(REQUIRED_COLUMNS[name] - set(data[0].keys())))
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
                            "Serve these through masked views (hash email, last-4 account, omit SSN/PAN).",
                            "Apply per-row salted hashing where joins are needed; keep the salt out of the AI role's reach.",
                        ],
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
        "tools": {"eval_grants": "2", "dialect": args.dialect},
        "findings": active,
        "unknowns": unknowns,
        "suppressed": suppressed,
    }
    output = json.dumps(result, indent=2)
    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
