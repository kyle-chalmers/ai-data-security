#!/usr/bin/env python3
"""Deterministic verdicts for the ai-data-security ai-config-audit skill.

Audits AI coding-tool configuration for data-safety risks:

  AC-01  missing recommended secret deny rules (project Claude settings)
  AC-02  dangerous allow rules (env-runners that grant arbitrary execution)
  AC-03  credential-shaped literal values in MCP server configs (name-based; values never echoed)
  AC-04  Gemini per-server trust:true (silently bypasses tool-call confirmations)
  AC-05  plaintext session transcripts on disk (INFO)
  AC-06  consumer retention/training tier — NOT locally auditable, always UNKNOWN (fail closed)

The model narrates this output; it does not change these verdicts.
Stdlib only. Read-only except the optional --emit-json path. Never prints config values —
only file paths, server names, and setting-key names.
"""

import argparse
import datetime
import json
import os
import re

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCHEMA_VERSION = 1

RECOMMENDED_DENY = ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]

# Allow-rule prefixes that delegate arbitrary command execution to an inner runner:
# Bash(npx *) effectively allows anything npx can fetch and run.
ENV_RUNNERS = [
    "npx", "uvx", "pipx", "npm exec", "pnpm dlx", "yarn dlx", "bunx",
    "devbox run", "docker run", "docker exec", "nix run", "nix-shell",
    "bash", "sh", "zsh", "eval", "env", "xargs",
]

SECRETY_KEY = re.compile(r"(?i)(token|secret|password|passwd|pwd|credential|api[-_]?key|private[-_]?key)")

SUBPROCESS_CAVEAT = (
    "Note: deny rules are enforced by Claude Code, not the OS — subprocesses (scripts the agent "
    "runs) can still read denied files. Only sandboxing enforces at the OS level."
)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def load_citation_registry():
    with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
        citations = json.load(f)["citations"]
    with open(os.path.join(PLUGIN_ROOT, "reference", "checks.yml"), encoding="utf-8") as f:
        checks = json.load(f)["checks"]
    return citations, checks


def finding(check_id, title, severity, confidence, obj, evidence, remediation, qualifier):
    caps = {"possible": "MEDIUM", "probable": "HIGH", "confirmed": "CRITICAL"}
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    cap = caps[confidence]
    if order.index(severity) > order.index(cap):
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
        "fingerprint": f"{check_id}:{obj}:{qualifier}",
    }


def check_deny_rules(target, findings):
    """AC-01: recommended secret deny rules present in project-scope Claude settings?"""
    deny = []
    sources = []
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        settings = read_json(os.path.join(target, rel))
        if isinstance(settings, dict):
            sources.append(rel)
            perms = settings.get("permissions")
            if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
                deny += perms["deny"]
    missing = [r for r in RECOMMENDED_DENY if r not in deny]
    if missing:
        src = " and ".join(sources) if sources else "no .claude/settings*.json found"
        findings.append(finding(
            "AC-01",
            f"Missing {len(missing)} recommended secret deny rule(s) in project settings",
            "HIGH", "confirmed", ".claude/settings.json",
            f"Recommended deny rules absent from project permissions ({src}): {', '.join(missing)}. "
            "Without them, the agent can read secret files in this project.",
            [
                'Add to .claude/settings.json: {"permissions": {"deny": '
                + json.dumps(missing) + "}}",
                SUBPROCESS_CAVEAT,
            ],
            "missing-deny",
        ))


def check_allow_rules(target, findings):
    """AC-02: allow rules that delegate arbitrary execution."""
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        settings = read_json(os.path.join(target, rel))
        if not isinstance(settings, dict):
            continue
        perms = settings.get("permissions")
        allow = perms.get("allow") if isinstance(perms, dict) else None
        for rule in allow if isinstance(allow, list) else []:
            if not isinstance(rule, str):
                continue
            m = re.fullmatch(r"Bash\((.+)\)", rule.strip())
            if not m:
                continue
            body = m.group(1).strip()
            # Both wildcard spellings delegate the inner command: "npx *" and "npx:*".
            has_wildcard = "*" in body
            core = re.sub(r"(:\*|\s+\*.*)$", "", body).strip()
            for runner in ENV_RUNNERS:
                if has_wildcard and (core == runner or core.startswith(runner + " ")):
                    findings.append(finding(
                        "AC-02",
                        f"Allow rule grants arbitrary execution via env-runner: {rule}",
                        "HIGH", "confirmed", rel,
                        f"'{rule}' pre-approves '{runner}' with a wildcard — the inner command is "
                        "unconstrained, so this is effectively an allow-everything rule.",
                        [
                            f"Replace {rule} with allow rules for the specific commands actually needed.",
                            "Wildcard argument constraints are documented as fragile; prefer exact "
                            "commands plus PreToolUse hooks for anything broader.",
                        ],
                        runner.replace(" ", "-"),
                    ))
                    break


def _scan_mcp_servers(servers, source_label, findings):
    """AC-03 over a parsed mcpServers-style dict; values are never echoed."""
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        env = spec.get("env")
        if not isinstance(env, dict):
            env = {}
        suspects = [
            k for k, v in env.items()
            if isinstance(v, str) and v.strip()
            and not re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", v.strip())
            and SECRETY_KEY.search(k)
        ]
        for k, v in (("url", spec.get("url")), ("command", spec.get("command"))):
            # credential-shaped literals embedded in URLs (user:pass@ or ?token=)
            if isinstance(v, str) and re.search(r"://[^/\s]+:[^/\s@]+@|[?&](token|key|secret)=", v):
                suspects.append(k)
        if suspects:
            findings.append(finding(
                "AC-03",
                f"MCP server '{name}' has credential-shaped literal value(s) in {source_label}",
                "HIGH", "probable", source_label,
                f"Server '{name}' defines literal value(s) for: {', '.join(sorted(suspects))} "
                "(values not shown). Plaintext credentials in MCP configs are readable by any "
                "process and often end up committed or synced.",
                [
                    "Move the credential to the OS keychain or an env var the MCP client resolves "
                    "at launch (e.g. \"${VAR}\" references), not a literal in the config file.",
                    "Scope the credential to the narrowest role the server needs.",
                ],
                name,
            ))
        if spec.get("trust") is True:
            findings.append(finding(
                "AC-04",
                f"MCP server '{name}' sets trust:true in {source_label}",
                "HIGH", "confirmed", source_label,
                f"'trust': true silently bypasses per-call tool confirmations for server '{name}' — "
                "every tool it exposes runs without user consent.",
                [
                    "Remove trust:true; approve tools per call or allowlist specific tools instead.",
                ],
                name,
            ))


def check_mcp_configs(target, home, findings):
    """AC-03/AC-04 across the known MCP config locations (project scope + home scope)."""
    candidates = [
        (os.path.join(target, ".mcp.json"), ".mcp.json", "mcpServers"),
        (os.path.join(target, ".cursor", "mcp.json"), ".cursor/mcp.json", "mcpServers"),
        (os.path.join(target, ".gemini", "settings.json"), ".gemini/settings.json", "mcpServers"),
        (os.path.join(home, ".claude.json"), "~/.claude.json", "mcpServers"),
        (os.path.join(home, ".cursor", "mcp.json"), "~/.cursor/mcp.json", "mcpServers"),
        (os.path.join(home, ".gemini", "settings.json"), "~/.gemini/settings.json", "mcpServers"),
        (
            os.path.join(home, "Library", "Application Support", "Claude",
                         "claude_desktop_config.json"),
            "claude_desktop_config.json", "mcpServers",
        ),
    ]
    for path, label, key in candidates:
        data = read_json(path)
        # A config whose top-level JSON is an array/scalar (not an object) has no mcpServers
        # to scan — skip it rather than crash on .get().
        if isinstance(data, dict):
            _scan_mcp_servers(data.get(key, {}), label, findings)

    # Codex uses TOML ([mcp_servers.<name>] tables). Parse with tomllib when available
    # (py3.11+); otherwise a line-based approximation that only reads key names. A codex
    # path that is a directory or holds invalid UTF-8 must be skipped, not crash the audit.
    codex = os.path.join(home, ".codex", "config.toml")
    if os.path.isfile(codex):
        servers = {}
        try:
            import tomllib
            with open(codex, "rb") as f:
                servers = {
                    name: {"env": (spec.get("env") if isinstance(spec, dict) else {}) or {}, **spec}
                    for name, spec in tomllib.load(f).get("mcp_servers", {}).items()
                    if isinstance(spec, dict)
                }
        except Exception:
            servers = {}
            current = None
            try:
                with open(codex, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        m = re.match(r"\s*\[mcp_servers\.([^\].]+)", line)
                        if m:
                            current = m.group(1)
                            servers.setdefault(current, {"env": {}})
                            continue
                        kv = re.match(r"\s*([A-Za-z0-9_-]+)\s*=\s*\"(.+)\"\s*$", line)
                        if current and kv and SECRETY_KEY.search(kv.group(1)):
                            servers[current]["env"][kv.group(1)] = kv.group(2)
            except OSError:
                servers = {}
        _scan_mcp_servers(servers, "~/.codex/config.toml", findings)


def check_transcripts(home, findings):
    """AC-05: plaintext transcripts under ~/.claude/projects (INFO)."""
    projects = os.path.join(home, ".claude", "projects")
    if os.path.isdir(projects) and any(os.scandir(projects)):
        settings = read_json(os.path.join(home, ".claude", "settings.json")) or {}
        cleanup = settings.get("cleanupPeriodDays", "unset (default 30)")
        findings.append(finding(
            "AC-05",
            "Claude Code session transcripts are stored on disk in plaintext",
            "INFO", "confirmed", "~/.claude/projects/",
            f"Transcript directory exists. Everything pasted or read into sessions persists here "
            f"in plaintext until cleanup (cleanupPeriodDays: {cleanup}).",
            [
                "If sessions touch sensitive data, lower cleanupPeriodDays in ~/.claude/settings.json.",
                "Ensure disk encryption (FileVault) is on for this machine.",
            ],
            "transcripts",
        ))


def load_suppressions(target):
    """Parse .ai-data-security-ignore (same contract as reference/finding-format.md):
    '<fingerprint> [expires=YYYY-MM-DD] [reason=...]' — duplicated from
    secrets-scanner's evaluator on purpose; each skill's script stays standalone."""
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
                    # Fail closed: an unparseable expiry must not suppress forever.
                    expired = True
            entries[fingerprint] = {"expires": expires, "reason": reason, "expired": expired}
    return entries


def unknown_retention():
    """AC-06: consumer training/retention tier cannot be audited from disk — fail closed."""
    return {
        "check_id": "AC-06",
        "reason": "The consumer 'Help improve Claude' training toggle and retention tier are "
                  "account settings, not local files — they cannot be audited from this machine.",
        "action": "Check https://claude.ai/settings/data-privacy-controls now. Consumer plans: "
                  "training ON means 5-year retention (30-day when off; the Aug 2025 rollout "
                  "pre-set it ON). Team/Enterprise/API accounts are not trained on by default and "
                  "retain for 30 days; Zero Data Retention is a qualified-Enterprise option. "
                  "If you handle Confidential/Restricted data with AI tools, verify the tier "
                  "in writing.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="project root to audit")
    parser.add_argument("--home", default=os.path.expanduser("~"),
                        help="home dir for user-scope configs (fixtures override this)")
    parser.add_argument("--emit-json", help="write JSON here instead of stdout")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    home = os.path.abspath(args.home)
    citations, checks = load_citation_registry()

    findings = []
    check_deny_rules(target, findings)
    check_allow_rules(target, findings)
    check_mcp_configs(target, home, findings)
    check_transcripts(home, findings)

    for f in findings:
        f["citations"] = [citations[k]["display"] for k in checks[f["check_id"]]["citations"]]

    suppressions = load_suppressions(target)
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
        "skill": "ai-config-audit",
        "target": target,
        "tools": {"permeval": "1"},
        "findings": active,
        "unknowns": [unknown_retention()],
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
