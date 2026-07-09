#!/usr/bin/env python3
"""Deterministic verdicts for the ai-data-security secrets-scanner skill.

Consumes two gitleaks JSON reports (history scan: `gitleaks git`; working-tree scan:
`gitleaks dir`) and computes the exposure matrix gitleaks lacks:

    on_disk x in_history x agent_readable x vcs_remote

then assigns check ids, severity, confidence, and remediation per reference/finding-format.md.
The model narrates this output; it does not change these verdicts.

Stdlib only. Read-only except for the optional --emit-json output path.
Never prints secret values: run gitleaks with --redact, and this script never reads
match content — only file paths, rule ids, and commit SHAs.
"""

import argparse
import datetime
import json
import os
import re
import subprocess

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

SCHEMA_VERSION = 1

# Structured, format-specific detector rules -> confidence "confirmed".
# Entropy/generic detections stay "probable" (capped at HIGH by finding-format.md).
CONFIRMED_RULES = {
    "aws-access-key-id",
    "aws-secret-access-key",
    "anthropic-api-key",
    "gcp-api-key",
    "github-app-token",
    "github-fine-grained-pat",
    "github-oauth",
    "github-pat",
    "openai-api-key",
    "private-key",
    "slack-bot-token",
    "slack-user-token",
    "stripe-access-token",
}

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_CAP = {"possible": "MEDIUM", "probable": "HIGH", "confirmed": "CRITICAL"}

SUBPROCESS_CAVEAT = (
    "Note: permission deny rules are enforced by Claude Code, not the OS — a subprocess "
    "(e.g. a Python script the agent runs) can still read the file. Only sandboxing "
    "enforces at the OS level."
)


def load_report(path):
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read().strip()
        return json.loads(content) if content else []
    except (json.JSONDecodeError, OSError) as e:
        raise SystemExit(f"eval_secrets: unreadable gitleaks report {path}: {e}")


def load_citations():
    path = os.path.join(PLUGIN_ROOT, "reference", "citations.yml")
    with open(path, encoding="utf-8") as f:
        return json.load(f)["citations"]


def load_checks():
    path = os.path.join(PLUGIN_ROOT, "reference", "checks.yml")
    with open(path, encoding="utf-8") as f:
        return json.load(f)["checks"]


def deny_patterns(target):
    """Collect Read(...) deny patterns from the target's Claude settings files."""
    patterns = []
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        path = os.path.join(target, rel)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                settings = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for rule in settings.get("permissions", {}).get("deny", []):
            m = re.fullmatch(r"Read\((.+)\)", rule.strip())
            if m:
                patterns.append(m.group(1))
    return patterns


def _glob_to_regex(glob):
    """Translate a Claude Code path glob (supports ** across separators, * within a
    segment, ? single char) into a regex string. '**/' means zero or more WHOLE path
    segments — '(?:.*/)?' — so '**/.env' matches 'a/b/.env' but never 'prod.env'."""
    out = []
    i = 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if glob[i : i + 2] == "**":
                if glob[i + 2 : i + 3] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                else:
                    out.append(".*")
                    i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def deny_covers(pattern, relpath):
    """Approximation of Claude Code's documented Read-rule path matching:
    './foo' anchors at the project root; a bare name with no '/' matches at any depth
    (Read(.env) == Read(**/.env)); '//' prefixes are filesystem-absolute (not supported
    here — treated as not matching the repo-relative path, fail-closed toward reporting)."""
    p = pattern.strip()
    if p.startswith("//"):
        return False
    if p.startswith("./"):
        regex = _glob_to_regex(p[2:])
    elif "/" not in p:
        regex = "(.*/)?" + _glob_to_regex(p)
    else:
        regex = _glob_to_regex(p)
    return re.fullmatch(regex, relpath) is not None


def commit_pushed(target, commit):
    """True when the commit is reachable from any remote-tracking branch."""
    if not commit:
        return False
    try:
        remotes = subprocess.run(
            ["git", "-C", target, "remote"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if not remotes.stdout.strip():
            return False
        contains = subprocess.run(
            ["git", "-C", target, "branch", "-r", "--contains", commit],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return bool(contains.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def load_suppressions(target):
    """Parse .ai-data-security-ignore: '<fingerprint> [expires=YYYY-MM-DD] [reason=...]'."""
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
            expires = None
            reason = ""
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


def _relpath(file, target):
    """Normalize a gitleaks File field to target-relative: `gitleaks git` emits repo-relative
    paths, but `gitleaks dir <path>` emits absolute paths (verified against 8.30.1)."""
    if os.path.isabs(file):
        # realpath both sides so a symlinked root (e.g. macOS /tmp -> /private/tmp) and the
        # absolute paths gitleaks emits reconcile to one repo-relative key.
        return os.path.relpath(os.path.realpath(file), os.path.realpath(target))
    return file


def build_findings(history, worktree, target):
    """One finding per secret per location class: a disk finding (SS-02/SS-03) and/or a
    history finding (SS-01/SS-04). The exposure matrix is attached to each."""
    denies = deny_patterns(target)
    keys = {}
    for item in history:
        keys.setdefault(
            (_relpath(item.get("File", ""), target), item.get("RuleID", "")),
            {"history": [], "disk": []},
        )["history"].append(item)
    for item in worktree:
        keys.setdefault(
            (_relpath(item.get("File", ""), target), item.get("RuleID", "")),
            {"history": [], "disk": []},
        )["disk"].append(item)

    findings = []
    for (file, rule), sources in sorted(keys.items()):
        in_history = bool(sources["history"])
        on_disk = bool(sources["disk"])
        agent_readable = on_disk and not any(deny_covers(p, file) for p in denies)
        pushed = in_history and any(
            commit_pushed(target, item.get("Commit")) for item in sources["history"]
        )
        confidence = "confirmed" if rule in CONFIRMED_RULES else "probable"
        exposure = {
            "on_disk": on_disk,
            "in_history": in_history,
            "agent_readable": agent_readable,
            "vcs_remote": pushed,
        }

        if on_disk:
            check_id = "SS-03" if agent_readable else "SS-02"
            severity = "CRITICAL" if agent_readable else "HIGH"
            title = (
                f"Secret on disk and agent-readable: {file} ({rule})"
                if agent_readable
                else f"Secret on disk (deny rule covers it): {file} ({rule})"
            )
            gitignored = not in_history
            evidence = (
                f"gitleaks dir detected rule '{rule}' in {file} (value redacted). "
                + ("File is not in git history — .gitignore does not protect files on disk. " if gitignored else "")
                + ("No permissions.deny Read rule covers this path." if agent_readable
                   else "A permissions.deny Read rule covers this path.")
            )
            remediation = (
                [
                    f"Add a deny rule for this path in .claude/settings.json: \"Read({'./' + file})\"",
                    "Move the secret out of the repo (secret manager, or env config outside the project).",
                    SUBPROCESS_CAVEAT,
                ]
                if agent_readable
                else [
                    "Deny rule present — keep it.",
                    "Consider moving the secret out of the repo entirely. " + SUBPROCESS_CAVEAT,
                ]
            )
            findings.append(
                _finding(check_id, title, severity, confidence, file, rule, evidence, exposure,
                         remediation, rotate_first=False)
            )

        if in_history:
            check_id = "SS-04" if pushed else "SS-01"
            severity = "CRITICAL" if pushed else "HIGH"
            commits = sorted({(item.get("Commit") or "")[:8] for item in sources["history"]})
            title = (
                f"Secret pushed to a git remote: {file} ({rule})"
                if pushed
                else f"Secret in local git history: {file} ({rule})"
            )
            evidence = (
                f"gitleaks git detected rule '{rule}' in {file} at commit(s) "
                f"{', '.join(c for c in commits if c)} (value redacted)."
                + (" Commit is reachable from a remote-tracking branch." if pushed else
                   " Commit is not on any remote-tracking branch (local only).")
            )
            remediation = (
                [
                    "ROTATE this credential now — it has left this machine and must be treated as compromised.",
                    "Then rewrite history (git filter-repo) or accept the exposure as rotated-and-dead.",
                    "Add a deny rule and .gitignore entry to prevent recurrence.",
                ]
                if pushed
                else [
                    "Rewrite local history (git filter-repo) before this repo is pushed or shared.",
                    "Rotate the credential if there is any doubt about prior exposure.",
                ]
            )
            findings.append(
                _finding(check_id, title, severity, confidence, file, rule, evidence, exposure,
                         remediation, rotate_first=pushed)
            )
    return findings


def _finding(check_id, title, severity, confidence, file, rule, evidence, exposure,
             remediation, rotate_first):
    cap = CONFIDENCE_CAP[confidence]
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(cap):
        severity = cap
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file": file,
        "rule_id": rule,
        "evidence": evidence,
        "exposure": exposure,
        "remediation": remediation,
        "rotate_first": rotate_first,
        "fingerprint": f"{check_id}:{file}:{rule}",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-report", help="gitleaks git JSON report path")
    parser.add_argument("--dir-report", help="gitleaks dir JSON report path")
    parser.add_argument("--target", required=True, help="audited repo root")
    parser.add_argument("--gitleaks-version", default="unknown")
    parser.add_argument("--emit-json", help="write JSON here instead of stdout")
    args = parser.parse_args()

    target = os.path.realpath(os.path.abspath(args.target))
    checks = load_checks()
    citations = load_citations()

    findings = build_findings(
        load_report(args.history_report), load_report(args.dir_report), target
    )

    for finding in findings:
        keys = checks[finding["check_id"]]["citations"]
        finding["citations"] = [citations[k]["display"] for k in keys]

    suppressions = load_suppressions(target)
    active, suppressed = [], []
    for finding in findings:
        entry = suppressions.get(finding["fingerprint"])
        if entry and not entry["expired"]:
            suppressed.append(
                {
                    "fingerprint": finding["fingerprint"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "reason": entry["reason"],
                    "expires": entry["expires"],
                }
            )
        else:
            if entry and entry["expired"]:
                finding["evidence"] += " (A suppression for this finding expired.)"
            active.append(finding)

    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "secrets-scanner",
        "target": target,
        "tools": {"gitleaks": args.gitleaks_version},
        "findings": active,
        "unknowns": [],
        "suppressed": suppressed,
    }
    output = json.dumps(result, indent=2)
    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as f:
            f.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
