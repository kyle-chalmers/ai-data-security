#!/usr/bin/env python3
"""Deterministic verdicts for the ai-data-security ai-config-audit skill.

Audits AI coding-tool configuration for data-safety risks:

  AC-01  missing recommended secret deny rules (project Claude settings)
  AC-02  dangerous allow rules (env-runners that grant arbitrary execution)
  AC-03  credential-shaped literal values in MCP server configs (name-based; values never echoed)
  AC-04  Gemini per-server trust:true (silently bypasses tool-call confirmations)
  AC-05  plaintext session transcripts on disk (INFO)
  AC-06  consumer retention/training tier — NOT locally auditable, always UNKNOWN (fail closed)
  AC-07  Bash sandbox filesystem isolation not enabled (deny rules bind the tool layer; only the
         sandbox is OS-enforced); INFO when enabled without failIfUnavailable
  AC-08  capability inventory (INFO): private-data sources x external channels present together
         in static config — a composition note, not a prompt-injection detector
  AC-09  MCP server provenance: unpinned npx/uvx/pnpm dlx/bunx packages, @latest, mutable git refs
  AC-10  write-capable warehouse MCP server: Snowflake sql_statement_permissions, Postgres MCP Pro
         --access-mode, Toolbox tools.yaml statements; config not found -> UNKNOWN
  AC-11  local sensitive sinks: DuckDB persistent secrets, credential-shaped literals in warehouse
         CLI config files (key names only), shell history readable without a deny rule

The model narrates this output; it does not change these verdicts.
Stdlib only. Read-only except the optional --emit-json path. Never prints config values —
only file paths, server names, and setting-key names.
"""

import argparse
import datetime
import json
import os
import re
import sys

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "scripts"))
from yaml_subset import yaml_subset_load  # noqa: E402  (stdlib-only, shipped with the plugin)
SCHEMA_VERSION = 1
TOOL_VERSION = "3"  # 2: AC-01 by meaning + AC-07; 3: AC-08..AC-11, six more agent-tool config paths

# AC-01 targets, expressed as the path each recommended rule must cover. Per the Claude Code
# permissions docs (code.claude.com/docs/en/permissions, "Read and Edit"), a bare filename in a
# deny rule matches at any depth (`Read(.env)` == `Read(**/.env)`), `//**/x` matches anywhere on the
# filesystem, and `./x` or `/x` anchor at the project root. All of those satisfy the requirement;
# the any-depth spelling is what we recommend, because `./.env` leaves `app/.env` readable.
RECOMMENDED_DENY_TARGETS = [".env", ".env.*", "secrets/**"]
RECOMMENDED_DENY = [f"Read({t})" for t in RECOMMENDED_DENY_TARGETS]
_DENY_PREFIXES = ("//**/", "**/", "./", "//", "/")
# Representative paths each target must protect. A rule satisfies a target when its normalized
# glob matches every probe (so a stronger glob such as `.env*` covers both `.env` and `.env.*`,
# and `*` covers everything — which is true, if unwise).
_TARGET_PROBES = {
    ".env": [".env"],
    ".env.*": [".env.local", ".env.production"],
    "secrets/**": ["secrets/a.pem", "secrets/nested/b.key"],
}


def deny_rule_target(rule):
    """Normalize a `Read(<pattern>)` deny rule to the path it protects, stripping the documented
    anchor prefixes. Whitespace inside the parentheses is NOT trimmed: `Read( .env )` names a
    path with spaces and protects nothing useful. Returns None for anything that is not a Read
    rule."""
    if not isinstance(rule, str):
        return None
    m = re.fullmatch(r"Read\((.+)\)", rule.strip())
    if not m:
        return None
    pattern = m.group(1)
    if pattern != pattern.strip() or not pattern:
        return None
    for prefix in _DENY_PREFIXES:
        if pattern.startswith(prefix):
            pattern = pattern[len(prefix):]
            break
    return pattern or None


def _glob_covers(glob, relpath):
    """gitignore-flavoured coverage: `**` spans directories, `*` a single segment."""
    if glob == relpath:
        return True
    regex = re.escape(glob).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(regex, relpath) is not None


def deny_target_satisfied(target, deny_rules):
    """True when some deny rule covers every representative path of `target`."""
    probes = _TARGET_PROBES.get(target, [target])
    for rule in deny_rules:
        glob = deny_rule_target(rule)
        if glob and all(_glob_covers(glob, probe) for probe in probes):
            return True
    return False


# Allow-rule prefixes that delegate arbitrary command execution to an inner runner:
# Bash(npx *) effectively allows anything npx can fetch and run.
ENV_RUNNERS = [
    "npx", "uvx", "pipx", "npm exec", "pnpm dlx", "yarn dlx", "bunx",
    "devbox run", "docker run", "docker exec", "nix run", "nix-shell",
    "bash", "sh", "zsh", "eval", "env", "xargs",
]

SECRETY_KEY = re.compile(r"(?i)(token|secret|password|passwd|pwd|credential|api[-_]?key|private[-_]?key)")

SUBPROCESS_CAVEAT = (
    "Note: Read deny rules bind Claude Code's file tools and the Bash file commands it recognizes "
    "(cat, head, tail, sed, redirections), not `grep -r` or scripts that open files themselves. "
    "Only the Bash sandbox enforces the same paths at the OS level (see AC-07)."
)


def command_tokens(spec):
    """Flatten an MCP server's command + args (string or list forms) into tokens."""
    tokens = []
    cmd = spec.get("command")
    if isinstance(cmd, str):
        tokens += cmd.split()
    elif isinstance(cmd, list):
        tokens += [str(c) for c in cmd if isinstance(c, (str, int, float))]
    args = spec.get("args")
    if isinstance(args, list):
        tokens += [str(a) for a in args if isinstance(a, (str, int, float))]
    return tokens


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
    missing = [f"Read({t})" for t in RECOMMENDED_DENY_TARGETS
               if not deny_target_satisfied(t, deny)]
    if missing:
        src = " and ".join(sources) if sources else "no .claude/settings*.json found"
        findings.append(finding(
            "AC-01",
            f"Missing {len(missing)} recommended secret deny rule(s) in project settings",
            "HIGH", "confirmed", ".claude/settings.json",
            f"No deny rule covers {', '.join(missing)} in project permissions ({src}) under any "
            "documented spelling (bare name, **/, ./, //**/). Without them, the agent can read "
            "secret files in this project.",
            [
                'Add to .claude/settings.json: {"permissions": {"deny": '
                + json.dumps(missing) + "}} — bare names match at any depth; `./.env` would "
                "cover only the project root.",
                SUBPROCESS_CAVEAT,
            ],
            "missing-deny",
        ))


def check_sandbox(target, home, findings):
    """AC-07: is the Bash sandbox enabled anywhere Claude Code would honor it?

    `sandbox.enabled` is a user- or managed-settings key (the /sandbox panel also writes the mode
    to the project's settings.local.json). Project .claude/settings.json cannot turn it on, so a
    repo cannot fix this finding for its users; the remediation targets ~/.claude/settings.json.
    """
    checked = []
    enabled = False
    fs_disabled = False
    hard_gate = False
    for path, label in (
        (os.path.join(home, ".claude", "settings.json"), "~/.claude/settings.json"),
        (os.path.join(target, ".claude", "settings.local.json"), ".claude/settings.local.json"),
        (os.path.join(target, ".claude", "settings.json"), ".claude/settings.json"),
    ):
        data = read_json(path)
        if isinstance(data, dict):
            checked.append(label)
            sandbox = data.get("sandbox")
            if isinstance(sandbox, dict):
                if sandbox.get("enabled") is True:
                    enabled = True
                if sandbox.get("failIfUnavailable") is True:
                    hard_gate = True
                fs = sandbox.get("filesystem")
                if isinstance(fs, dict) and fs.get("disabled") is True:
                    fs_disabled = True
    if enabled and not fs_disabled:
        if not hard_gate:
            findings.append(finding(
                "AC-07",
                "Bash sandbox is on, but may silently fall back to unsandboxed when it cannot start",
                "INFO", "confirmed", "~/.claude/settings.json",
                "`sandbox.enabled` is true but `sandbox.failIfUnavailable` is not; if the sandbox "
                "dependencies are missing Claude Code warns and runs commands unsandboxed.",
                ['Add "failIfUnavailable": true under "sandbox" in ~/.claude/settings.json to make '
                 "a missing sandbox a hard stop."],
                "sandbox-soft",
            ))
        return
    src = ", ".join(checked) if checked else "no Claude settings files found"
    why = ("`sandbox.filesystem.disabled` is true, which removes the OS-level file boundary even "
           "though the sandbox is enabled" if enabled and fs_disabled
           else f"`sandbox.enabled` is not true in any settings file checked ({src})")
    findings.append(finding(
        "AC-07",
        "Bash sandbox filesystem isolation is not enabled — deny rules are the only file boundary for Bash",
        "MEDIUM", "confirmed", "~/.claude/settings.json",
        f"{why}. Without filesystem isolation, Read deny rules apply to Claude's file tools and "
        "recognized Bash file commands only; a script or `grep -r` run through Bash reads denied "
        "files with the agent's OS permissions.",
        [
            'Enable it in user settings: ~/.claude/settings.json → {"sandbox": {"enabled": true}} '
            "and do not set filesystem.disabled (macOS, Linux, WSL2; project settings cannot set "
            "these keys).",
            'Add "failIfUnavailable": true so Claude Code refuses to run unsandboxed when the '
            "sandbox cannot start.",
        ],
        "sandbox-disabled",
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
        headers = spec.get("headers")
        if isinstance(headers, dict):
            suspects += [
                f"headers.{k}" for k, v in headers.items()
                if isinstance(v, str) and v.strip()
                and not re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", v)
                and (SECRETY_KEY.search(k) or k.lower() == "authorization")
            ]
        cmd_text = " ".join(command_tokens(spec))
        for k, v in (("url", spec.get("url")), ("command", cmd_text)):
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


def _servers_at(data, keypaths):
    """First non-empty mapping found at any of the dotted key paths (e.g. 'mcp.servers', 'mcp')."""
    for kp in keypaths:
        node = data
        for part in kp.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict) and node:
            return node
    return {}


def _yaml_server_list(path, label, unknowns):
    """Continue-style YAML: `mcpServers:` is a LIST of {name, command, args, env}. Returns a
    name->spec dict; an unreadable or unsupported file becomes an AC-03 UNKNOWN, never a skip."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = yaml_subset_load(f.read())
    except (OSError, ValueError) as exc:
        unknowns.append({"check_id": "AC-03",
                         "reason": f"{label} could not be read by the stdlib YAML-subset reader ({exc.__class__.__name__}); "
                                   "its MCP servers were not assessed.",
                         "action": "Review the file by hand for credential literals and unpinned servers, or simplify its YAML."})
        return {}
    items = data.get("mcpServers") if isinstance(data, dict) else None
    if isinstance(items, dict):
        return items
    out = {}
    for i, item in enumerate(items if isinstance(items, list) else []):
        if isinstance(item, dict):
            out[str(item.get("name") or f"server{i}")] = item
    return out


def check_mcp_configs(target, home, findings, unknowns):
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
        # v0.5: more agent tools (paths as each tool documents them, 2026-09)
        (os.path.join(target, ".vscode", "mcp.json"), ".vscode/mcp.json", "servers"),
        (os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), "~/.codeium/windsurf/mcp_config.json", "mcpServers"),
        (os.path.join(home, "Library", "Application Support", "Code", "User", "globalStorage",
                      "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
         "cline_mcp_settings.json", "mcpServers"),
        (os.path.join(home, "Library", "Application Support", "Code", "User", "globalStorage",
                      "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
         "roo mcp_settings.json", "mcpServers"),
        (os.path.join(home, ".continue", "config.json"), "~/.continue/config.json", "mcpServers"),  # legacy JSON
        (os.path.join(home, ".copilot", "mcp-config.json"), "~/.copilot/mcp-config.json", "mcpServers"),
        # OpenCode: current schema nests servers at mcp.servers; older configs used a flat `mcp` map
        (os.path.join(target, "opencode.json"), "opencode.json", "mcp.servers|mcp"),
        (os.path.join(home, ".config", "opencode", "opencode.json"), "~/.config/opencode/opencode.json", "mcp.servers|mcp"),
    ]
    inventory = []  # (label, name, spec) for AC-08 / AC-09 / AC-10
    for path, label, key in candidates:
        data = read_json(path)
        # A config whose top-level JSON is an array/scalar (not an object) has no mcpServers
        # to scan — skip it rather than crash on .get().
        if isinstance(data, dict):
            servers = _servers_at(data, key.split("|"))
            _scan_mcp_servers(servers, label, findings)
            inventory += [(label, n, s) for n, s in servers.items() if isinstance(s, dict)]

    # Continue (current): ~/.continue/config.yaml plus one YAML/JSON file per server under
    # .continue/mcpServers/ (workspace and home).
    yaml_sources = [(os.path.join(home, ".continue", "config.yaml"), "~/.continue/config.yaml")]
    for base, lab in ((os.path.join(target, ".continue", "mcpServers"), ".continue/mcpServers"),
                      (os.path.join(home, ".continue", "mcpServers"), "~/.continue/mcpServers")):
        if os.path.isdir(base):
            for fn in sorted(os.listdir(base)):
                if fn.endswith((".yaml", ".yml", ".json")):
                    yaml_sources.append((os.path.join(base, fn), f"{lab}/{fn}"))
    for path, label in yaml_sources:
        if not os.path.isfile(path):
            continue
        if path.endswith(".json"):
            data = read_json(path)
            servers = _servers_at(data, ["mcpServers"]) if isinstance(data, dict) else {}
            if not servers and isinstance(data, dict) and isinstance(data.get("mcpServers"), list):
                servers = {str(s.get("name") or f"server{i}"): s for i, s in enumerate(data["mcpServers"]) if isinstance(s, dict)}
        else:
            servers = _yaml_server_list(path, label, unknowns)
        _scan_mcp_servers(servers, label, findings)
        inventory += [(label, n, s) for n, s in servers.items() if isinstance(s, dict)]

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
        inventory += [("~/.codex/config.toml", n, s) for n, s in servers.items() if isinstance(s, dict)]
    return inventory


# ---------------------------------------------------------------------------------------------
# v0.5 checks
# ---------------------------------------------------------------------------------------------
PIN_RUNNERS = {"npx", "uvx", "bunx", "pipx"}
WAREHOUSE_TOKENS = ("snowflake", "postgres", "databricks", "bigquery", "redshift", "duckdb", "motherduck",
                    "toolbox", "mysql", "clickhouse", "trino")
NETWORK_ALLOW = re.compile(r"^(WebFetch|WebSearch)\b|^Bash\((curl|wget|gh|aws|gcloud|az|ssh|scp|rsync|nc|ncat)\b")
# "Unknown: True" lets through any statement the server's mapper does not recognize, so it is a
# write path too (Snowflake-Labs/mcp README, SQL execution section).
SF_WRITE_TYPES = {"insert", "update", "delete", "drop", "create", "alter", "merge", "copy",
                  "truncatetable", "command", "all", "unknown"}
SQL_WRITE_HEAD = re.compile(r"(?is)^\s*(insert|update|delete|drop|create|alter|truncate|merge|copy|grant|revoke|call|exec|execute|replace|upsert|vacuum|refresh)\b")
SQL_WRITE_ANY = re.compile(r"(?is)\b(insert|update|delete|drop|create|alter|truncate|merge|copy|grant|revoke|call|exec|execute|replace|upsert)\b")
SQL_READ_HEAD = re.compile(r"(?is)^\s*(select|show|describe|desc|explain|values|table)\b")
SQL_COMMENT = re.compile(r"(?s)(--[^\n]*|/\*.*?\*/)")


def classify_statement(sql):
    """'write' | 'read' | 'unclassified' for one Toolbox tool statement. Leading comments are
    stripped; a `WITH ... (DELETE ... RETURNING) SELECT` data-modifying CTE counts as a write;
    anything the head matcher cannot place is 'unclassified' (the caller reports UNKNOWN)."""
    body = SQL_COMMENT.sub(" ", sql or "").strip()
    if not body:
        return "unclassified"
    if SQL_WRITE_HEAD.match(body):
        return "write"
    if re.match(r"(?is)^\s*with\b", body):
        return "write" if SQL_WRITE_ANY.search(body) else "read"
    if SQL_READ_HEAD.match(body):
        return "write" if re.search(r"(?is)\binto\b", body) and SQL_WRITE_ANY.search(body) else "read"
    return "unclassified"


def _unpinned(tokens):
    """Return (reason) when an npx/uvx/bunx/pipx/pnpm dlx invocation has no exact version pin.
    Understands `pkg@1.2.3`, `pkg==1.2.3` (pipx/uvx), `pipx run pkg`, `uvx --from pkg cmd`, and
    git/URL sources pinned with a full commit SHA (`#<40 hex>` or `@<40 hex>`)."""
    if not tokens:
        return None
    runner = tokens[0]
    rest = tokens[1:]
    if runner in ("pnpm", "yarn", "npm") and rest[:1] in (["dlx"], ["exec"]):
        rest = rest[1:]
    elif runner == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]
    elif runner not in PIN_RUNNERS:
        return None
    pkg = None
    for i, tk in enumerate(rest):
        if tk == "--from" and i + 1 < len(rest):
            pkg = rest[i + 1]
            break
        if not tk.startswith("-"):
            pkg = tk
            break
    if not pkg:
        return None
    if pkg.endswith("@latest") or pkg.endswith("==latest"):
        return f"{runner} {pkg}: '@latest' resolves to whatever is published at launch"
    if pkg.startswith(("git+", "http://", "https://", "ssh://", "git@")):
        frag = pkg.rsplit("#", 1)[1] if "#" in pkg else (pkg.split("/")[-1].rsplit("@", 1)[1] if "@" in pkg.split("/")[-1] else "")
        if re.fullmatch(r"[0-9a-f]{40}", frag):
            return None
        return f"{runner} {pkg}: git/URL source without an immutable commit pin (branch, tag, or none)"
    if "==" in pkg:
        version = pkg.split("==", 1)[1]
    else:
        name_part = pkg[1:] if pkg.startswith("@") else pkg
        if "@" not in name_part:
            return f"{runner} {pkg}: no version pin (the package is fetched at launch)"
        version = name_part.rsplit("@", 1)[1]
    if not re.fullmatch(r"\d+\.\d+\.\d+([-+][0-9A-Za-z.]+)?", version):
        return f"{runner} {pkg}: version '{version}' is a range, not an exact pin"
    return None


def check_provenance(inventory, findings):
    """AC-09: MCP servers that fetch and run whatever is published at launch."""
    for label, name, spec in inventory:
        reason = _unpinned(command_tokens(spec))
        if reason:
            findings.append(finding(
                "AC-09", f"MCP server '{name}' runs an unpinned package ({label})",
                "MEDIUM", "probable", label,
                f"{reason}. A server started this way changes without review; a tool description "
                "or dependency swapped upstream reaches the agent on the next launch.",
                [
                    "Pin an exact version (name@x.y.z) or install the server locally and point `command` at it.",
                    "Keep a lockfile or checksum for stdio servers; review changes before re-approving.",
                ],
                f"{name}-unpinned",
            ))


def _classify_warehouse(tokens, name):
    text = " ".join(tokens).lower() + " " + name.lower()
    if "snowflake" in text:
        return "snowflake"
    if "postgres-mcp" in text or "crystaldba" in text:
        return "postgres-mcp"
    if "toolbox" in text:
        return "toolbox"
    if "databricks" in text:
        return "databricks"
    return None


def _arg_value(tokens, flag):
    for i, tk in enumerate(tokens):
        if tk == flag and i + 1 < len(tokens):
            return tokens[i + 1]
        if tk.startswith(flag + "="):
            return tk.split("=", 1)[1]
    return None


def check_warehouse_mcp(inventory, target, findings, unknowns):
    """AC-10: is a warehouse MCP server write-capable by its own configuration?"""
    for label, name, spec in inventory:
        tokens = command_tokens(spec)
        kind = _classify_warehouse(tokens, name)
        if not kind:
            continue
        if kind == "snowflake":
            cfg = _arg_value(tokens, "--service-config-file")
            path = os.path.join(target, cfg) if cfg and not os.path.isabs(cfg) else cfg
            data = None
            if path and os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        data = yaml_subset_load(f.read())
                except (OSError, ValueError):
                    data = None
            perms = data.get("sql_statement_permissions") if isinstance(data, dict) else None
            if not isinstance(perms, list):
                unknowns.append({
                    "check_id": "AC-10",
                    "reason": f"Snowflake MCP server '{name}' ({label}): service config "
                              f"{'not found' if not path or not os.path.isfile(path) else 'unparseable or without sql_statement_permissions'}"
                              f" ({cfg or 'no --service-config-file argument'}). Write capability unknown.",
                    "action": "Point --service-config-file at the YAML and set every write statement type to False "
                              "(Insert, Update, Delete, Drop, Create, Alter, Merge, Copy, TruncateTable, Command, All, Unknown).",
                })
                continue
            enabled = sorted({
                k for item in perms if isinstance(item, dict)
                for k, v in item.items() if v is True and k.lower() in SF_WRITE_TYPES
            })
            if enabled:
                findings.append(finding(
                    "AC-10", f"Snowflake MCP server '{name}' is write-capable by config",
                    "HIGH", "confirmed", label,
                    f"sql_statement_permissions enables {', '.join(enabled)} in {cfg}. The server honors the "
                    "connected role's RBAC, so with a write-capable role this is a write path for the agent.",
                    ["Set the write statement types to False in the service config; keep Select/Describe/Use only.",
                     "Connect the server as a service identity whose role has no write grants (see db-access-audit DB-01)."],
                    f"{name}-write",
                ))
        elif kind == "postgres-mcp":
            if not tokens or (isinstance(spec.get("url"), str) and spec["url"]):
                unknowns.append({
                    "check_id": "AC-10",
                    "reason": f"Postgres MCP server '{name}' ({label}) is remote (URL/SSE) or has no local launch command; "
                              "its --access-mode is set on the server side and cannot be read here.",
                    "action": "Confirm the server runs with --access-mode=restricted where it is launched.",
                })
                continue
            mode = _arg_value(tokens, "--access-mode")
            if mode != "restricted":
                findings.append(finding(
                    "AC-10", f"Postgres MCP server '{name}' is not in restricted mode",
                    "HIGH", "confirmed", label,
                    f"--access-mode is {mode or 'absent (defaults to unrestricted in the documented examples)'}; "
                    "restricted mode wraps queries in read-only transactions and rejects COMMIT/ROLLBACK.",
                    ["Add --access-mode=restricted to the server's args."],
                    f"{name}-write",
                ))
        elif kind == "toolbox":
            cfg = _arg_value(tokens, "--tools-file") or _arg_value(tokens, "--tools_file") or "tools.yaml"
            path = os.path.join(target, cfg) if not os.path.isabs(cfg) else cfg
            data = None
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        data = yaml_subset_load(f.read())
                except (OSError, ValueError):
                    data = None
            tools = data.get("tools") if isinstance(data, dict) else None
            if not isinstance(tools, dict):
                unknowns.append({
                    "check_id": "AC-10",
                    "reason": f"Toolbox MCP server '{name}' ({label}): tools file {cfg} not found or unparseable; "
                              "statement capability unknown.",
                    "action": "Review every `statement:` in tools.yaml; only SELECT statements belong in an agent's toolbox.",
                })
                continue
            classes = {tn: classify_statement(tspec["statement"]) for tn, tspec in tools.items()
                       if isinstance(tspec, dict) and isinstance(tspec.get("statement"), str)}
            writers = sorted(tn for tn, c in classes.items() if c == "write")
            unclassified = sorted(tn for tn, c in classes.items() if c == "unclassified")
            if unclassified:
                unknowns.append({
                    "check_id": "AC-10",
                    "reason": f"Toolbox MCP server '{name}' ({label}): {len(unclassified)} tool statement(s) could not be "
                              f"classified as read or write by the static matcher ({', '.join(unclassified)}).",
                    "action": "Review those statements by hand; only SELECT statements belong in an agent's toolbox.",
                })
            if writers:
                findings.append(finding(
                    "AC-10", f"Toolbox MCP server '{name}' exposes writing tool(s)",
                    "HIGH", "confirmed", label,
                    f"Tool(s) whose statement writes: {', '.join(writers)} (statement text not shown). Toolbox has no "
                    "global read-only switch; each tool is exactly its SQL.",
                    ["Remove or rewrite the writing tools; keep the toolbox to SELECT statements."],
                    f"{name}-write",
                ))
        elif kind == "databricks":
            findings.append(finding(
                "AC-10", f"Databricks MCP server '{name}' has no write control in its config",
                "INFO", "confirmed", label,
                "The Databricks MCP server exposes whatever the authenticated identity's Unity Catalog grants allow; "
                "there is nothing in the config to make it read-only.",
                ["Audit the identity's grants with db-access-audit; use a service principal with SELECT on curated objects only."],
                f"{name}-nocontrol",
            ))


def check_capabilities(target, home, inventory, findings):
    """AC-08: an INFO composition note when private-data sources and external channels coexist."""
    private, external, shell = [], [], []
    for label, name, spec in inventory:
        tokens = command_tokens(spec)
        if _classify_warehouse(tokens, name) or any(w in (name + " " + " ".join(tokens)).lower() for w in WAREHOUSE_TOKENS):
            private.append(f"{name} ({label})")
        if isinstance(spec.get("url"), str) and spec["url"].startswith(("http://", "https://")):
            external.append(f"{name} ({label}, remote MCP)")
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        settings = read_json(os.path.join(target, rel))
        perms = settings.get("permissions") if isinstance(settings, dict) else None
        allow = perms.get("allow") if isinstance(perms, dict) else None
        for rule in allow if isinstance(allow, list) else []:
            if isinstance(rule, str) and NETWORK_ALLOW.search(rule.strip()):
                external.append(f"{rule} ({rel})")
            if isinstance(rule, str) and rule.startswith("Bash("):
                shell.append(rule)
    if private and external:
        findings.append(finding(
            "AC-08", "Private data sources and external channels are both configured for this agent",
            "INFO", "confirmed", ".claude/settings.json",
            f"Data sources: {', '.join(private)}. External channels: {', '.join(external)}. "
            f"{len(shell)} Bash allow rule(s). Together these are the composition OWASP ASI02 and the agent cheat "
            "sheet warn about: data the agent can read, and a place it can send it. This is an inventory, not a "
            "detection of any attack.",
            [
                "Scope each channel: remove network allow rules the agent does not need; prefer read-only warehouse identities.",
                "Treat every retrieved document and query result as untrusted input (OWASP AI Agent Security Cheat Sheet).",
            ],
            "composition",
        ))


CRED_FILES = [
    (".snowflake/connections.toml", "Snowflake CLI connections"),
    (".snowflake/config.toml", "Snowflake CLI config"),
    (".databrickscfg", "Databricks CLI profiles"),
    (".dbt/profiles.yml", "dbt profiles"),
    (".aws/credentials", "AWS CLI credentials"),
    (".pgpass", "libpq password file"),
]
KV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(\S.*)$")


def check_local_sinks(target, home, findings):
    """AC-11: places sensitive material sits on this machine outside the repo. Key names only."""
    duck = os.path.join(home, ".duckdb", "stored_secrets")
    try:
        n_duck = sum(1 for e in os.scandir(duck) if e.is_file()) if os.path.isdir(duck) else 0
    except OSError:
        n_duck = 0
    if n_duck:
        findings.append(finding(
            "AC-11", f"DuckDB persistent secrets on disk ({n_duck} file(s))",
            "HIGH", "probable", "~/.duckdb/stored_secrets/",
            f"{n_duck} persistent secret file(s) in ~/.duckdb/stored_secrets; DuckDB stores them unencrypted, and any "
            "DuckDB session the agent runs can use them to reach the external stores they unlock.",
            ["Prefer temporary secrets (CREATE SECRET without PERSISTENT) or a credential provider; delete stale persistent secrets.",
             "Deny the agent's file tools this directory: Read(~/.duckdb/**)."],
            "duckdb-secrets",
        ))
    for rel, label in CRED_FILES:
        path = os.path.join(home, rel)
        if not os.path.isfile(path):
            continue
        keys = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = KV_LINE.match(line)
                    if not m:
                        continue
                    key, value = m.group(1), m.group(2).strip().strip('"').strip("'")
                    if SECRETY_KEY.search(key) and value and not value.startswith(("${", "$")):
                        keys.append(key)
        except OSError:
            continue
        if rel == ".pgpass":
            keys = ["pgpass-entries"]
        if keys:
            findings.append(finding(
                "AC-11", f"{label} file holds credential-shaped literal(s): ~/{rel}",
                "HIGH", "probable", f"~/{rel}",
                f"Keys with literal values: {', '.join(sorted(set(keys)))} (values not shown). This file is readable "
                "by any process the agent runs unless a deny rule or the sandbox covers it.",
                [f"Move the value to the OS keychain, a token provider, or an env var the tool resolves; add Read(~/{rel}) to deny rules.",
                 "Rotate the credential if the file was ever synced or committed."],
                rel.replace("/", "-"),
            ))
    histories = [h for h in (".zsh_history", ".bash_history", ".psql_history", ".snowsql_history")
                 if os.path.isfile(os.path.join(home, h))]
    if histories:
        deny = []
        for rel in (".claude/settings.json", ".claude/settings.local.json"):
            settings = read_json(os.path.join(target, rel))
            perms = settings.get("permissions") if isinstance(settings, dict) else None
            if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
                deny += [d for d in perms["deny"] if isinstance(d, str)]
        user_settings = read_json(os.path.join(home, ".claude", "settings.json"))
        perms = user_settings.get("permissions") if isinstance(user_settings, dict) else None
        if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
            deny += [d for d in perms["deny"] if isinstance(d, str)]
        covered = any("_history" in d for d in deny)
        if not covered:
            findings.append(finding(
                "AC-11", f"Shell history readable by the agent ({', '.join(histories)})",
                "LOW", "confirmed", "~/.*_history",
                f"{len(histories)} history file(s) present and no deny rule mentions *_history. Pasted tokens and "
                "connection strings live there.",
                ["Add Read(~/.*_history) to ~/.claude/settings.json deny rules; clear history after pasting secrets."],
                "shell-history",
            ))


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
    unknowns = [unknown_retention()]
    check_deny_rules(target, findings)
    check_allow_rules(target, findings)
    inventory = check_mcp_configs(target, home, findings, unknowns)
    check_transcripts(home, findings)
    check_sandbox(target, home, findings)
    check_provenance(inventory, findings)
    check_warehouse_mcp(inventory, target, findings, unknowns)
    check_capabilities(target, home, inventory, findings)
    check_local_sinks(target, home, findings)

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
        "tools": {"permeval": TOOL_VERSION},
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
