#!/usr/bin/env python3
"""safe-db-access planner (ai-data-security v0.6, approved SPEC amendment 2026-09-11).

Renders the least-privilege recipe for an AI principal as TEXT, from the db-access-audit JSON and
a few validated parameters, and prints it to stdout. It never connects to a database, never
executes SQL, and never writes a file. Templates under ../templates/<dialect>/ are fixed; the only
things substituted into them are identifiers that passed `IDENT` below, so the model never
composes privilege-changing DDL and neither does this script.

Sections (all dialects): 1 service identity, 2 key vault for pseudonymization, 3 curated schema of
masked views, 4 grants (revoke raw, grant curated), 5 audit trail, 6 validation script run AS the
AI role, 7 rollback. A human reviews and executes; the audit is re-run afterwards.

Fail-closed rules: any parameter that is not a plain identifier -> exit 2, nothing rendered. Any
object name captured by the audit that is not a plain identifier -> excluded and listed under
"NOT RENDERED". Missing plan inputs -> the affected section says so and the plan header says
INCOMPLETE. Unfilled template slots -> exit 3 (a template bug must never ship half a statement).
Stdlib only. Deterministic: same inputs, byte-identical output.
"""

import argparse
import hashlib
import json
import os
import re
import sys

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TEMPLATES = os.path.join(PLUGIN_ROOT, "skills", "safe-db-access", "templates")
TOOL_VERSION = "1"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
SLOT = re.compile(r"\{\{([a-z_]+)\}\}")
CITATIONS = ["nist-sp800-188", "snowflake-agent-identity", "snowflake-access-control",
             "postgres-predefined-roles", "owasp-asi03", "nist-sp800-122"]
SECTIONS = ("header", "identity", "vault", "curated", "grants", "audit", "validate", "rollback")
CHECK_ID = re.compile(r"^[A-Z]{2,4}(-[A-Z0-9]+)+$")
RESERVED_SCHEMAS = {"public", "pg_catalog", "information_schema", "pg_toast", "snowflake", "account_usage"}
SF_STRING_TYPES = {"TEXT", "STRING", "VARCHAR", "CHAR", "CHARACTER", "NVARCHAR", "NVARCHAR2", "CHAR VARYING", "NCHAR", "NCHAR VARYING"}


def view_names(tables):
    """Deterministic, collision-free curated view names: <table> when the basename is unique across
    the readable tables, else <schema>_<table>."""
    counts = {}
    for _, n in tables:
        counts[n] = counts.get(n, 0) + 1
    return {(s, n): (n if counts[n] == 1 else f"{s}_{n}") for s, n in tables}


class PlanError(Exception):
    pass


def load_template(dialect, name):
    path = os.path.join(TEMPLATES, dialect, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def render(_dialect, _name, **slots):
    text = load_template(_dialect, _name)
    for key, value in slots.items():
        text = text.replace("{{" + key + "}}", value)
    left = SLOT.findall(text)
    if left:
        raise PlanError(f"template {_dialect}/{_name} has unfilled slot(s): {', '.join(sorted(set(left)))}")
    return text


def safe(value):
    """A value fit to print: the identifier itself when valid, otherwise a hash handle. Refused
    values are never echoed (a name with a newline or '--' could break out of a SQL comment)."""
    if isinstance(value, str) and IDENT.match(value):
        return value
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:12]
    return f"<refused:{digest}>"


def ident(value, what, refused):
    """Validated identifier or None (and a NOT RENDERED note that never repeats the value)."""
    if isinstance(value, str) and IDENT.match(value):
        return value
    refused.append(f"{what} {safe(value)}: {len(str(value))}-char name is not a plain identifier "
                   "(letters, digits, underscore); find it by hashing the name (sha256, first 12 hex)")
    return None


def load_citations():
    with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
        cites = json.load(f)["citations"]
    return [cites[k]["display"] for k in CITATIONS if k in cites]


def plan_postgres(pi, p, refused):
    d = "postgres"
    role = p["ai_role"]
    cur, vault, owner = p["curated_schema"], p["vault_schema"], p["owner_role"]
    tables = []
    for t in pi.get("raw_tables") or []:
        s, n = ident(t.get("schema"), "table schema", refused), ident(t.get("table"), f"table in schema {safe(t.get('schema'))}", refused)
        if s and n:
            tables.append((s, n))
    tables = sorted(set(tables))
    schemas = sorted({s for s, _ in tables})
    pii = {}
    for c in pi.get("pii_columns") or []:
        s, n, col = c.get("schema"), c.get("table"), c.get("column")
        if (s, n) not in tables:
            continue
        col_ok = ident(col, f"column in {safe(s)}.{safe(n)}", refused)
        if col_ok:
            if c.get("tier") == "Pseudonymized":
                continue  # already a keyed hash / token: pass through as an ordinary column
            pii.setdefault((s, n), {})[col_ok] = "Restricted" if c.get("tier") == "Restricted" else "Confidential"
    columns = {}
    if pi.get("columns") is not None:
        for c in sorted(pi["columns"], key=lambda x: (x.get("schema") or "", x.get("table") or "", x.get("position") or 0)):
            key = (c.get("schema"), c.get("table"))
            if key not in tables:
                continue
            col_ok = ident(c.get("column"), f"column in {safe(key[0])}.{safe(key[1])}", refused)
            if col_ok:
                columns.setdefault(key, []).append(col_ok)
    incomplete = []

    # 1 identity
    memberships = "".join(render(d, "frag_revoke_membership.sql", role=role, member=r)
                          for r in sorted(pi.get("inherited_roles") or []) if ident(r, "inherited role", refused))
    server_roles = "".join(render(d, "frag_revoke_membership.sql", role=role, member=r)
                           for r in sorted(pi.get("server_roles") or []) if ident(r, "server role", refused))
    identity = render(d, "10_identity.sql", ai_role=role, connection_limit=str(p["connection_limit"]),
                      revoke_memberships=memberships or "-- (the audit recorded no inherited role memberships)\n",
                      revoke_server_roles=server_roles or "-- (the audit recorded no server file/program role memberships)\n")
    # 2 vault
    vault_sql = render(d, "20_vault.sql", vault=vault, owner_role=owner)
    # 3 curated views
    views = []
    validate_views = []
    vnames = view_names(tables)
    for s, n in tables:
        view = vnames[(s, n)]
        cols = columns.get((s, n))
        tpii = pii.get((s, n), {})
        if cols is None and tpii:
            incomplete.append(f"{s}.{n}: PII-bearing table without a captured column list (columns.sql); view body not rendered")
            views.append(render(d, "frag_view_incomplete.sql", curated=cur, view=view, schema=s, table=n))
            continue
        if cols is None:
            body = "    *"
        else:
            kept, omitted = [], []
            for col in cols:
                tier = tpii.get(col)
                if tier == "Restricted":
                    omitted.append(f"    -- {col}: Restricted tier, omitted from the curated view")
                elif tier == "Confidential":
                    kept.append(f"    {vault}.hash_pii({col}::text) AS {col}_pseudo")
                else:
                    kept.append(f"    {col}")
            if not kept:
                incomplete.append(f"{s}.{n}: every captured column is Restricted; nothing can be projected, view not rendered")
                views.append(render(d, "frag_view_incomplete.sql", curated=cur, view=view, schema=s, table=n))
                continue
            body = ",\n".join(kept)
            if omitted:
                body = "\n".join(omitted) + "\n" + body
        views.append(render(d, "frag_view.sql", curated=cur, view=view, schema=s, table=n, body=body, owner_role=owner))
        validate_views.append(render(d, "frag_validate_view.sql", curated=cur, view=view))
    curated = render(d, "30_curated.sql", curated=cur, vault=vault, owner_role=owner, ai_role=role,
                     grant_owner_reads="".join(render(d, "frag_grant_owner_read.sql", owner_role=owner, schema=s) for s in schemas)
                     or "-- (no readable base tables recorded)\n",
                     views="".join(views) or "-- (no readable base tables recorded; nothing to curate)\n")
    # 4 grants
    revoke_raw = "".join(render(d, "frag_revoke_raw_schema.sql", ai_role=role, schema=s) for s in schemas)
    public_rows = []
    for g in (pi.get("public_grants") or []):
        obj, priv = str(g.get("object", "")), str(g.get("privilege", ""))
        if "." not in obj:
            continue
        s, n = obj.split(".", 1)
        if ident(s, "PUBLIC-granted schema", refused) and ident(n, "PUBLIC-granted table", refused) and re.fullmatch(r"[A-Z ]+", priv):
            public_rows.append((s, n, priv))
    public_rows = sorted(set(public_rows))
    prefix = "" if p["include_public"] else "-- REVIEW, then remove this comment marker to run: "
    revoke_public = "".join(prefix + render(d, "frag_revoke_public.sql", schema=s, table=n, privilege=pv) for s, n, pv in public_rows)
    acl_rows = []
    for a in (pi.get("default_acl") or []):
        objtype, priv = str(a.get("objtype", "")), str(a.get("privilege", ""))
        if objtype not in ("tables", "sequences", "functions", "types", "schemas") or not re.fullmatch(r"[A-Z ]+", priv):
            continue
        grantor = ident(a.get("grantor"), "default-privilege grantor", refused) if a.get("grantor") else None
        if not grantor:
            incomplete.append(f"default privileges on {objtype}: grantor not captured; the ALTER DEFAULT PRIVILEGES statement needs FOR ROLE <grantor> and was not rendered")
            continue
        schema = a.get("schema")
        if schema is not None and not ident(schema, "default-privilege schema", refused):
            continue
        acl_rows.append((grantor, schema, objtype, priv))
    acl_rows = sorted(set(acl_rows), key=lambda x: (x[0], x[1] or "", x[2], x[3]))
    default_acl = "".join(
        render(d, "frag_revoke_default_acl.sql", ai_role=role, grantor=g, schema=s, objtype=o.upper()) if s
        else render(d, "frag_revoke_default_acl_global.sql", ai_role=role, grantor=g, objtype=o.upper())
        for g, s, o, _ in acl_rows)
    grants = render(d, "40_grants.sql", ai_role=role, curated=cur,
                    revoke_raw=revoke_raw or "-- (no raw schema grants recorded)\n",
                    revoke_public=revoke_public or "-- (the audit recorded no PUBLIC grants on tables the AI role reads)\n",
                    revoke_default_acl=default_acl or "-- (the audit recorded no default privileges for the AI role)\n")
    # 5 audit
    audit = render(d, "50_audit.sql", ai_role=role)
    # 6 validate
    raw_checks = "".join(render(d, "frag_validate_raw.sql", schema=s, table=n) for s, n in tables)
    member_checks = "".join(render(d, "frag_validate_membership.sql", member=r)
                            for r in sorted(set(pi.get("inherited_roles") or []) | set(pi.get("server_roles") or [])) if IDENT.match(r))
    validate = render(d, "60_validate.sql", ai_role=role, curated=cur, vault=vault,
                      view_checks="".join(validate_views) or "",
                      raw_checks=raw_checks or "", membership_checks=member_checks or "")
    # 7 rollback
    regrant = "".join(render(d, "frag_rollback_membership.sql", role=role, member=r)
                      for r in sorted(set(pi.get("inherited_roles") or []) | set(pi.get("server_roles") or [])) if IDENT.match(r))
    writes = "".join(render(d, "frag_rollback_write.sql", ai_role=role, schema=w["schema"], table=w["table"], privilege=w["privilege"])
                     for w in (pi.get("write_grants") or [])
                     if IDENT.match(str(w.get("schema"))) and IDENT.match(str(w.get("table"))) and re.fullmatch(r"[A-Z]+", str(w.get("privilege"))))
    reselect = "".join(render(d, "frag_rollback_schema_usage.sql", ai_role=role, schema=s) for s in schemas) + \
               "".join(render(d, "frag_rollback_select.sql", ai_role=role, schema=s, table=n) for s, n in tables)
    re_acl = "".join(
        render(d, "frag_rollback_default_acl.sql", ai_role=role, grantor=g, schema=s, objtype=o.upper(), privilege=pv) if s
        else render(d, "frag_rollback_default_acl_global.sql", ai_role=role, grantor=g, objtype=o.upper(), privilege=pv)
        for g, s, o, pv in acl_rows)
    re_public = "".join(prefix + render(d, "frag_rollback_public.sql", schema=s, table=n, privilege=pv) for s, n, pv in public_rows)
    rollback = render(d, "70_rollback.sql", ai_role=role, curated=cur, vault=vault, owner_role=owner,
                      revoke_owner_reads="".join(render(d, "frag_rollback_owner_read.sql", owner_role=owner, schema=s) for s in schemas),
                      regrant_memberships=regrant or "", regrant_writes=writes or "", regrant_selects=reselect or "",
                      regrant_default_acl=re_acl or "", regrant_public=re_public or "")
    return {"identity": identity, "vault": vault_sql, "curated": curated, "grants": grants, "audit": audit,
            "validate": validate, "rollback": rollback}, incomplete, tables, pii


def plan_snowflake(pi, p, refused):
    d = "snowflake"
    role, user = p["ai_role"], p["ai_user"]
    db = p["database"]
    cur, vault, owner, auditor = p["curated_schema"], p["vault_schema"], p["owner_role"], p["auditor_role"]
    tables = []
    for t in pi.get("raw_tables") or []:
        s, n = ident(t.get("schema"), "table schema", refused), ident(t.get("table"), f"table in schema {safe(t.get('schema'))}", refused)
        if s and n:
            tables.append((s, n))
    tables = sorted(set(tables))
    schemas = sorted({s for s, _ in tables})
    pii = {}
    for c in pi.get("pii_columns") or []:
        s, n, col = c.get("schema"), c.get("table"), c.get("column")
        if (s, n) not in tables:
            continue
        col_ok = ident(col, f"column in {safe(s)}.{safe(n)}", refused)
        if col_ok:
            if c.get("tier") == "Pseudonymized":
                continue
            pii.setdefault((s, n), {})[col_ok] = "Restricted" if c.get("tier") == "Restricted" else "Confidential"
    incomplete = []
    if pi.get("user_type") is None:
        incomplete.append("identity.sql was not captured: the current user TYPE and secondary-role setting are unknown; section 1 still renders the target state")

    user_roles = [r for r in (pi.get("user_roles") or []) if r != role and ident(r, "user role", refused)]
    inherited = [r for r in (pi.get("inherited_roles") or []) if ident(r, "inherited role", refused)]
    identity = render(d, "10_identity.sql", ai_user=user, ai_role=role, user_type=p["user_type"],
                      revoke_user_roles="".join(render(d, "frag_revoke_user_role.sql", ai_user=user, member=r) for r in sorted(user_roles))
                      or "-- (the audit recorded no extra roles granted to the user)\n",
                      revoke_role_roles="".join(render(d, "frag_revoke_role_role.sql", ai_role=role, member=r) for r in sorted(inherited))
                      or "-- (the audit recorded no roles inherited by the AI role)\n")
    vault_sql = render(d, "20_vault.sql", db=db, vault=vault, owner_role=owner)
    views = []
    vnames = view_names(tables)
    for s, n in tables:
        tpii = pii.get((s, n), {})
        excl = sorted(tpii)
        hashed = "".join(f",\n    {db}.{vault}.HASH_PII({c}::STRING) AS {c}_PSEUDO" for c in excl if tpii[c] == "Confidential")
        exclude = f" EXCLUDE ({', '.join(excl)})" if excl else ""
        omitted = "".join(f"    -- {c}: Restricted tier, omitted\n" for c in excl if tpii[c] == "Restricted")
        views.append(render(d, "frag_view.sql", db=db, curated=cur, view=vnames[(s, n)], schema=s, table=n, exclude=exclude, hashed=hashed, omitted=omitted))
    types = {(c.get("schema"), c.get("table"), c.get("column")): str(c.get("type") or "").upper() for c in (pi.get("pii_columns") or [])}
    restricted_cols, untyped = [], []
    for (s, n), cols in sorted(pii.items()):
        for c, tier in sorted(cols.items()):
            if tier != "Restricted":
                continue
            ctype = types.get((s, n, c), "")
            base = ctype.split("(")[0].strip()
            if base in SF_STRING_TYPES:
                restricted_cols.append((s, n, c))
            else:
                untyped.append((s, n, c, base or "unknown type"))
    for s, n, c, ctype in untyped:
        incomplete.append(f"{s}.{n}.{c} is {ctype}: the STRING masking policy cannot attach to it; a type-matched policy is needed (not rendered)")
    policy_attach = "".join(render(d, "frag_attach_policy.sql", db=db, curated=cur, schema=s, table=n, column=c) for s, n, c in restricted_cols)
    masking = render(d, "35_masking_policy.sql", db=db, curated=cur, ai_role=role, owner_role=owner,
                     edition_note={"enterprise": "-- Edition: Enterprise or higher confirmed by the operator; masking policies are available.",
                                   "standard": "-- Edition: Standard. Masking policies are NOT available; this block is kept for reference only. Do not run it.",
                                   "unknown": "-- Edition: not stated. Masking policies need Enterprise or higher; if CREATE MASKING POLICY is refused, rely on section 3's secure views alone."}[p["edition"]],
                     attach=policy_attach or "-- (no Restricted-tier columns on readable tables were recorded)\n")
    curated = render(d, "30_curated.sql", db=db, curated=cur, owner_role=owner,
                     views="".join(views) or "-- (no readable base tables recorded; nothing to curate)\n") + masking
    ext = [(e.get("kind"), e.get("name")) for e in (pi.get("external_objects") or [])]
    revoke_ext = "".join(render(d, "frag_revoke_external.sql", kind=k, name=n, ai_role=role)
                         for k, n in sorted(ext) if k in ("STAGE", "INTEGRATION") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,300}", str(n)))
    grants = render(d, "40_grants.sql", db=db, curated=cur, ai_role=role,
                    revoke_raw="".join(render(d, "frag_revoke_raw_schema.sql", db=db, schema=s, ai_role=role) for s in schemas)
                    or "-- (no raw schema grants recorded)\n",
                    revoke_external=revoke_ext or "-- (the audit recorded no stage or integration grants)\n")
    audit = render(d, "50_audit.sql", ai_user=user, auditor_role=auditor)
    validate = render(d, "60_validate.sql", db=db, curated=cur, vault=vault, ai_role=role, ai_user=user,
                      view_checks="".join(render(d, "frag_validate_view.sql", db=db, curated=cur, view=vnames[(s, n)]) for s, n in tables),
                      schema_checks="".join(render(d, "frag_validate_schema.sql", db=db, schema=s, ai_role=role) for s in schemas),
                      raw_checks="".join(render(d, "frag_validate_raw.sql", db=db, schema=s, table=n) for s, n in tables))
    writes = "".join(render(d, "frag_rollback_write.sql", db=db, schema=w["schema"], table=w["table"], privilege=w["privilege"], ai_role=role)
                     for w in (pi.get("write_grants") or [])
                     if IDENT.match(str(w.get("schema"))) and IDENT.match(str(w.get("table"))) and re.fullmatch(r"[A-Z]+", str(w.get("privilege"))))
    ext_ok = [(e.get("kind"), e.get("name"), e.get("privilege")) for e in (pi.get("external_objects") or [])
              if e.get("kind") in ("STAGE", "INTEGRATION") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,300}", str(e.get("name")))
              and re.fullmatch(r"[A-Z ]+", str(e.get("privilege") or ""))]
    rollback = render(d, "70_rollback.sql", db=db, curated=cur, vault=vault, ai_role=role, ai_user=user, owner_role=owner,
                      regrant_role_roles="".join(render(d, "frag_rollback_role_role.sql", ai_role=role, member=r) for r in sorted(inherited)),
                      regrant_user_roles="".join(render(d, "frag_rollback_user_role.sql", ai_user=user, member=r) for r in sorted(user_roles)),
                      regrant_writes=writes,
                      regrant_external="".join(render(d, "frag_rollback_external.sql", kind=k, name=n, privilege=pv, ai_role=role) for k, n, pv in sorted(ext_ok)),
                      regrant_selects="".join(render(d, "frag_rollback_schema_usage.sql", db=db, schema=s, ai_role=role) for s in schemas)
                      + "".join(render(d, "frag_rollback_select.sql", db=db, schema=s, table=n, ai_role=role) for s, n in tables),
                      detach_policies="".join(render(d, "frag_detach_policy.sql", db=db, schema=s, table=n, column=c) for s, n, c in restricted_cols))
    return {"identity": identity, "vault": vault_sql, "curated": curated, "grants": grants, "audit": audit,
            "validate": validate, "rollback": rollback}, incomplete, tables, pii


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", required=True, help="db-access-audit JSON (eval_grants --emit-json output)")
    ap.add_argument("--dialect", choices=["postgres", "snowflake"], help="default: the audit's dialect")
    ap.add_argument("--ai-role", help="default: the audit's target role")
    ap.add_argument("--ai-user", help="Snowflake: the USER the agent authenticates as (default: audit identity, else --ai-role)")
    ap.add_argument("--database", help="Snowflake: database holding the raw schema (default: the audit's single database)")
    ap.add_argument("--curated-schema", help="default: curated (postgres) / CURATED (snowflake)")
    ap.add_argument("--vault-schema", help="default: vault (postgres) / VAULT (snowflake)")
    ap.add_argument("--owner-role", help="role that owns the curated views (default: curated_owner / SYSADMIN)")
    ap.add_argument("--auditor-role", default="GOVERNANCE_AUDITOR", help="Snowflake: role that receives GOVERNANCE_VIEWER")
    ap.add_argument("--user-type", choices=["SERVICE_AGENT", "SERVICE"], default="SERVICE_AGENT",
                    help="Snowflake user TYPE for the agent identity")
    ap.add_argument("--edition", choices=["enterprise", "standard", "unknown"], default="unknown",
                    help="Snowflake edition (masking policies need Enterprise or higher)")
    ap.add_argument("--connection-limit", type=int, default=5)
    ap.add_argument("--include-public-revokes", action="store_true",
                    help="render PUBLIC revocations as live statements (they affect every role); default renders them commented out for review")
    ap.add_argument("--section", choices=("all",) + SECTIONS, default="all",
                    help="print one section only (the test harness feeds apply/validate/rollback separately)")
    args = ap.parse_args()

    try:
        with open(args.audit, encoding="utf-8") as f:
            audit = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"REFUSED: audit JSON could not be read ({exc.__class__.__name__}). Nothing rendered.", file=sys.stderr)
        return 2
    pi = audit.get("plan_inputs") if isinstance(audit, dict) else None
    if not isinstance(pi, dict):
        print("REFUSED: the audit JSON has no plan_inputs block (eval_grants tool version 4+ writes it). "
              "Re-run db-access-audit with the current plugin. Nothing rendered.", file=sys.stderr)
        return 2
    dialect = args.dialect or pi.get("dialect") or (audit.get("tools") or {}).get("dialect")
    if dialect not in ("postgres", "snowflake"):
        print("REFUSED: dialect unknown. Nothing rendered.", file=sys.stderr)
        return 2

    params = {
        "ai_role": args.ai_role or pi.get("role") or audit.get("target"),
        "ai_user": args.ai_user or pi.get("user") or args.ai_role or pi.get("role") or audit.get("target"),
        "database": args.database or pi.get("database"),
        "curated_schema": args.curated_schema or ("curated" if dialect == "postgres" else "CURATED"),
        "vault_schema": args.vault_schema or ("vault" if dialect == "postgres" else "VAULT"),
        "owner_role": args.owner_role or ("curated_owner" if dialect == "postgres" else "SYSADMIN"),
        "auditor_role": args.auditor_role, "user_type": args.user_type, "edition": args.edition,
        "connection_limit": args.connection_limit, "include_public": args.include_public_revokes,
    }
    required = ["ai_role", "curated_schema", "vault_schema", "owner_role"] + (["ai_user", "database", "auditor_role"] if dialect == "snowflake" else [])
    bad = []
    for key in required:
        value = params.get(key)
        if not isinstance(value, str) or not IDENT.match(value):
            bad.append(f"--{key.replace('_', '-')}={value!r}")
    if not (1 <= args.connection_limit <= 1000):
        bad.append(f"--connection-limit={args.connection_limit}")
    if len({params["curated_schema"], params["vault_schema"]}) < 2:
        bad.append("--curated-schema and --vault-schema must differ")
    raw_schemas = {str(tt.get("schema")) for tt in (pi.get("raw_tables") or []) if isinstance(tt, dict)}
    raw_schemas |= {str(c.get("schema")) for c in (pi.get("pii_columns") or []) if isinstance(c, dict)}
    for key in ("curated_schema", "vault_schema"):
        value = str(params[key])
        if value in raw_schemas or value.lower() in RESERVED_SCHEMAS or value.upper() in {r.upper() for r in raw_schemas}:
            bad.append(f"--{key.replace('_', '-')}={value!r} is a raw/reserved schema the plan would DROP on rollback; choose a new namespace")
    if params["owner_role"].upper() == str(params["ai_role"]).upper():
        bad.append("--owner-role must not be the AI role (the owner reads raw tables)")
    if dialect == "snowflake" and params["auditor_role"].upper() in {str(params["ai_role"]).upper(), params["owner_role"].upper()}:
        bad.append("--auditor-role must differ from the AI role and the owner role")
    if bad:
        print("REFUSED: parameter(s) are not plain identifiers (letters, digits, underscore, max 128; the planner never "
              "quotes or escapes): " + ", ".join(bad) + ". Nothing rendered.", file=sys.stderr)
        return 2

    refused = []
    try:
        if dialect == "postgres":
            sections, incomplete, tables, pii = plan_postgres(pi, params, refused)
        else:
            sections, incomplete, tables, pii = plan_snowflake(pi, params, refused)
        findings = sorted({str(f.get("check_id")) for f in audit.get("findings", []) if isinstance(f, dict)
                           and isinstance(f.get("check_id"), str) and CHECK_ID.match(f["check_id"])})
        n_restricted = sum(1 for cols in pii.values() for t in cols.values() if t == "Restricted")
        n_conf = sum(1 for cols in pii.values() for t in cols.values() if t == "Confidential")
        header = render(dialect, "00_header.txt",
                        dialect=dialect, ai_role=params["ai_role"], ai_user=params["ai_user"],
                        database=params["database"] or "-", curated=params["curated_schema"], vault=params["vault_schema"],
                        owner_role=params["owner_role"], tool_version=TOOL_VERSION,
                        status="INCOMPLETE" if incomplete else "COMPLETE",
                        findings=", ".join(findings) or "none in the audit JSON",
                        n_tables=str(len(tables)), n_restricted=str(n_restricted), n_confidential=str(n_conf),
                        incomplete="".join(f"--   * {x}\n" for x in incomplete) or "--   (none)\n",
                        not_rendered="".join(f"--   * {x}\n" for x in sorted(set(refused))) or "--   (none)\n",
                        citations="".join(f"--   - {c}\n" for c in load_citations()))
    except PlanError as exc:
        print(f"REFUSED: {exc}. Nothing rendered.", file=sys.stderr)
        return 3
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(f"REFUSED: plan inputs malformed ({exc.__class__.__name__}: {exc}). Nothing rendered.", file=sys.stderr)
        return 3
    sections["header"] = header
    order = SECTIONS if args.section == "all" else (args.section,)
    sys.stdout.write("".join(sections[s] for s in order))
    return 0


if __name__ == "__main__":
    sys.exit(main())
