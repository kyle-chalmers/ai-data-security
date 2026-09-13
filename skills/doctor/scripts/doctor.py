#!/usr/bin/env python3
"""ai-data-security doctor: what can this machine audit, and what will be UNKNOWN?

Detects the external tools the skills depend on, checks the plugin's own citation/check
registry for consistency, and prints a capability matrix. Read-only; never installs anything;
always exits 0 (the matrix is the answer, not the exit code). Stdlib only.

Betterleaks (the gitleaks maintainers' successor project) is reported as INFORMATION only:
SPEC design rule 6 names gitleaks as the primary scanner, and an adapter requires its own
amendment with fixture parity.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCHEMA_VERSION = 1
TOOL_VERSION = "1"

TOOLS = [
    # (binary, version argv, role, skills that need it, info-only)
    ("gitleaks", ["gitleaks", "version"], "secrets scan (required by secrets-scanner, quick-check)",
     ["secrets-scanner", "quick-check", "security-audit"], False),
    ("betterleaks", ["betterleaks", "version"],
     "successor to gitleaks; reported for information, not used (SPEC rule 6)", [], True),
    ("psql", ["psql", "--version"], "live Postgres audit", ["db-access-audit (postgres)"], False),
    ("snow", ["snow", "--version"], "live Snowflake audit", ["db-access-audit (snowflake)"], False),
    ("dbsqlcli", ["dbsqlcli", "--version"], "live Databricks audit", ["db-access-audit (databricks)"], False),
    ("docker", ["docker", "--version"], "test suite only (Postgres golden fixtures)", [], True),
    ("claude", ["claude", "--version"], "plugin runtime / plugin validate", [], True),
    ("jq", ["jq", "--version"], "dev/validate.sh registry checks", [], True),
]


_VERSION_TOKEN = re.compile(r"\bv?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]{1,20})?)\b")


def probe(binary, argv):
    """Presence plus a narrowly validated version token. Child output is never rendered:
    a PATH-shadowed binary could print anything, so only a `major.minor[.patch]` token that
    matches _VERSION_TOKEN is retained."""
    path = shutil.which(binary)
    if not path:
        return {"present": False, "path": None, "version": None}
    version = None
    try:
        out = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=20)
        m = _VERSION_TOKEN.search((out.stdout or "") + " " + (out.stderr or ""))
        version = m.group(1) if m else None
    except (OSError, subprocess.SubprocessError, ValueError):
        version = None
    return {"present": True, "path": path, "version": version}


def registry_health():
    """Same invariants CI enforces, computed here so a user sees them before a run."""
    problems = []
    try:
        with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
            citations = json.load(f)["citations"]
        with open(os.path.join(PLUGIN_ROOT, "reference", "checks.yml"), encoding="utf-8") as f:
            checks = json.load(f)["checks"]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {"ok": False, "problems": ["registry unreadable or malformed"], "checks": 0, "citations": 0}
    if not isinstance(citations, dict) or not isinstance(checks, dict):
        return {"ok": False, "problems": ["registry has an unexpected shape"], "checks": 0, "citations": 0}
    for key, entry in citations.items():
        if not isinstance(entry, dict):
            problems.append(f"citation {key} is not an object")
            continue
        for field in ("published", "accessed", "status"):
            if not isinstance(entry.get(field), str) or not entry.get(field):
                problems.append(f"citation {key} missing {field}")
        if entry.get("status") not in ("current", "superseded", "withdrawn"):
            problems.append(f"citation {key} has invalid status")
    for check_id, spec in checks.items():
        if not isinstance(spec, dict):
            problems.append(f"check {check_id} is not an object")
            continue
        cites = spec.get("citations") if isinstance(spec.get("citations"), list) else []
        for c in cites:
            if c not in citations:
                problems.append(f"check {check_id} cites unknown {c}")
            elif isinstance(citations[c], dict) and citations[c].get("status") == "withdrawn":
                problems.append(f"check {check_id} cites withdrawn {c}")
        if not spec.get("fixtures"):
            problems.append(f"check {check_id} has no fixture")
    return {"ok": not problems, "problems": problems, "checks": len(checks), "citations": len(citations)}


def evaluators_compile():
    """Every deterministic evaluator must at least byte-compile on this interpreter.
    Compiles in memory (no .pyc is written anywhere)."""
    results = {}
    for rel in (
        "skills/secrets-scanner/scripts/eval_secrets.py",
        "skills/ai-config-audit/scripts/permeval.py",
        "skills/data-classification/scripts/classify_hints.py",
        "skills/db-access-audit/scripts/eval_grants.py",
        "skills/dbt-governance-audit/scripts/dbt_audit.py",
        "skills/safe-db-access/scripts/plan.py",
        "skills/db-access-audit/scripts/dialects/databricks.py",
        "skills/quick-check/scripts/quick_check.py",
        "scripts/to_sarif.py",
        "scripts/yaml_subset.py",
    ):
        path = os.path.join(PLUGIN_ROOT, rel)
        try:
            with open(path, encoding="utf-8") as f:
                compile(f.read(), path, "exec")
            results[rel] = "ok"
        except (SyntaxError, OSError, ValueError):
            results[rel] = "error: does not compile or cannot be read"
    return results


def sandbox_posture(home):
    """INFO: mirrors AC-07 so the doctor can say up front whether the OS boundary is on."""
    path = os.path.join(home, ".claude", "settings.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):  # ValueError covers JSONDecodeError and UnicodeDecodeError
        return {"user_settings_found": False, "sandbox_enabled": False}
    sandbox = data.get("sandbox") if isinstance(data, dict) else None
    return {
        "user_settings_found": True,
        "sandbox_enabled": isinstance(sandbox, dict) and sandbox.get("enabled") is True,
    }


def capability_matrix(tools):
    rows = []
    rows.append(("secrets-scanner", "ready" if tools["gitleaks"]["present"] else "UNKNOWN",
                 "gitleaks present" if tools["gitleaks"]["present"]
                 else "gitleaks missing → SS-05 UNKNOWN (brew install gitleaks)"))
    rows.append(("ai-config-audit", "ready", "stdlib only"))
    rows.append(("data-classification", "ready", "stdlib only"))
    rows.append(("dbt-governance-audit", "ready", "stdlib only; YAML declarations, no connection"))
    rows.append(("safe-db-access (planner)", "ready", "stdlib only; renders SQL text from a db-access-audit JSON, never connects"))
    rows.append(("db-access-audit (postgres)", "ready" if tools["psql"]["present"] else "UNKNOWN",
                 "psql present" if tools["psql"]["present"] else "psql missing → live Postgres audit unavailable; --recorded <dir> still works"))
    rows.append(("db-access-audit (databricks)", "ready" if tools["dbsqlcli"]["present"] else "UNKNOWN",
                 "dbsqlcli present" if tools["dbsqlcli"]["present"] else "dbsqlcli missing → live Databricks audit unavailable; --recorded <dir> still works"))
    rows.append(("db-access-audit (snowflake)", "ready" if tools["snow"]["present"] else "UNKNOWN",
                 ("snow present; DB-08/DB-09 additionally need GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER on the auditing role"
                  if tools["snow"]["present"] else "snow CLI missing → live Snowflake audit unavailable; --recorded <dir> still works")))
    rows.append(("quick-check", "ready" if tools["gitleaks"]["present"] else "partial",
                 "all three lanes" if tools["gitleaks"]["present"] else "secrets lane will be UNKNOWN without gitleaks"))
    rows.append(("security-audit", "ready" if tools["gitleaks"]["present"] else "partial",
                 "phases 1–3 local; phase 4 needs --db and a CLI"))
    return [{"skill": s, "status": st, "reason": r} for s, st, r in rows]


def render_text(result):
    lines = [f"ai-data-security doctor (plugin {result['plugin_version']}, python {result['python']}, {result['platform']})", ""]
    lines.append("Tools")
    for name, info in result["tools"].items():
        mark = "present" if info["present"] else "missing"
        extra = f" — {info['version']}" if info.get("version") else ""
        tag = " [info only]" if info.get("info_only") else ""
        lines.append(f"  {name:12} {mark}{extra}{tag}")
    lines.append("")
    lines.append("Capability matrix")
    for row in result["capabilities"]:
        lines.append(f"  {row['skill']:30} {row['status']:8} {row['reason']}")
    lines.append("")
    reg = result["registry"]
    lines.append(f"Registry: {'OK' if reg['ok'] else 'PROBLEMS'} ({reg['checks']} checks, {reg['citations']} citations)")
    for p in reg["problems"]:
        lines.append(f"  ! {p}")
    bad = {k: v for k, v in result["evaluators"].items() if v != "ok"}
    lines.append(f"Evaluators: {'all compile' if not bad else 'PROBLEMS'}")
    for k, v in bad.items():
        lines.append(f"  ! {k}: {v}")
    sb = result["sandbox"]
    lines.append("Sandbox (AC-07): " + ("enabled in user settings" if sb["sandbox_enabled"]
                 else "not enabled — deny rules are the only file boundary for Bash"))
    lines.append("")
    lines.append("Always UNKNOWN by design: AC-06 (consumer retention tier is an account setting, not a file).")
    lines.append("Next: /ai-data-security:quick-check <path>  or  /ai-data-security:security-audit <path>")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", default=os.path.expanduser("~"))
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--emit-json", help="also write the JSON here (same contract as the evaluators' --emit-json)")
    args = parser.parse_args()
    try:
        return _run(args)
    except Exception:  # noqa: BLE001 — the matrix must always render; a degraded result beats a traceback
        degraded = {"schema_version": SCHEMA_VERSION, "skill": "doctor", "degraded": True,
                    "reason": "doctor hit an unexpected error; treat every capability as UNKNOWN"}
        print(json.dumps(degraded, indent=2) if args.format == "json" else
              "ai-data-security doctor: unexpected error — treat every capability as UNKNOWN and run dev/validate.sh")
        return 0


def _run(args):

    tools = {}
    for binary, argv, role, needed_by, info_only in TOOLS:
        info = probe(binary, argv)
        info.update({"role": role, "needed_by": needed_by, "info_only": info_only})
        tools[binary] = info

    try:
        with open(os.path.join(PLUGIN_ROOT, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
            plugin_version = json.load(f).get("version", "unknown")
    except (OSError, json.JSONDecodeError):
        plugin_version = "unknown"

    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "doctor",
        "tools_version": {"doctor": TOOL_VERSION},
        "plugin_version": plugin_version,
        "python": platform.python_version(),
        "platform": platform.platform(terse=True),
        "tools": tools,
        "capabilities": capability_matrix(tools),
        "registry": registry_health(),
        "evaluators": evaluators_compile(),
        "sandbox": sandbox_posture(os.path.abspath(args.home)),
        "always_unknown": ["AC-06"],
    }
    if args.emit_json:
        try:
            with open(args.emit_json, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
                fh.write("\n")
        except OSError:
            result["emit_json_error"] = "could not write --emit-json path"
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
