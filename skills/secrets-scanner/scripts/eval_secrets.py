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


def load_report(path, scan, unknowns):
    """Return the findings list from one gitleaks JSON report, or None when there is none to use.

    A report that was asked for but is missing, empty, or not a JSON list of objects means the
    scan did not finish. gitleaks exits 1 both when it finds leaks and when it dies (an unreadable
    path, an unwritable report path, a missing --config file), and only a scan
    that finishes writes the file, so "no report" must never read as "no secrets". Each unusable
    report becomes an SS-05 UNKNOWN. No path at all means the caller chose not to run that scan
    (history on a non-git target), which is not a failure."""
    if not path:
        return None
    name = os.path.basename(path)
    why = None
    data = None
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read().strip()
        data = json.loads(content) if content else None
        if data is None:
            why = "is empty"
        elif not isinstance(data, list) or not all(isinstance(i, dict) for i in data):
            why = "is not a gitleaks JSON findings list"
    except FileNotFoundError:
        why = "was not written"
    except (ValueError, OSError) as e:
        why = f"could not be read ({e.__class__.__name__})"
    if why is None:
        return data
    unknowns.append({
        "check_id": "SS-05",
        "scan_failed": True,
        "reason": f"gitleaks {scan} report '{name}' {why}, so that scan did not finish. gitleaks "
                  "exits 1 for a fatal error as well as for leaks found; this is not a clean result.",
        "action": f"Re-run `gitleaks {scan}` by hand and read its stderr (an unreadable path or an "
                  "unwritable report path are common causes), then re-run the audit.",
    })
    return None


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


def load_target_gitleaksignore(target, unknowns):
    """List every entry in the target's .gitleaksignore as a skipped finding.

    gitleaks always loads <source>/.gitleaksignore and has no flag to turn that off (verified
    against 8.30.1, cmd/root.go), so the scanned repo can still drop findings this way even though
    the plugin passes its own --config. The plugin cannot see what was dropped, so each entry is
    listed in the Suppressed appendix and one SS-05 UNKNOWN says those locations were not verified."""
    path = os.path.join(target, ".gitleaksignore")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            entries = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        entries = None
    if entries is None:
        unknowns.append({
            "check_id": "SS-05",
            "scan_failed": False,
            "reason": "the scanned repo has a .gitleaksignore that could not be read; gitleaks loads "
                      "it anyway, so findings it names were skipped without being listed.",
            "action": "Make .gitleaksignore readable, or move intentional skips to "
                      ".ai-data-security-ignore, then re-run.",
        })
        return []
    if not entries:
        return []
    unknowns.append({
        "check_id": "SS-05",
        "scan_failed": False,
        "reason": f"the scanned repo's .gitleaksignore lists {len(entries)} finding(s) that gitleaks "
                  "skipped; gitleaks cannot be told to ignore that file, so those locations were "
                  "not verified (each is listed in the Suppressed appendix).",
        "action": "Move intentional skips to .ai-data-security-ignore (fingerprint plus reason) and "
                  "delete .gitleaksignore, then re-run so every location is scanned.",
    })
    return [
        {
            "check_id": "SS-05",
            "fingerprint": entry,
            "file": ".gitleaksignore",
            "title": "Skipped by the scanned repo's .gitleaksignore (not verified)",
            "severity": "UNKNOWN",
            "source": ".gitleaksignore",
            "reason": "gitleaks skipped this at the scanned repo's request; the plugin cannot see "
                      "what it was.",
            "expires": None,
        }
        for entry in entries
    ]


def _relpath(file, target):
    """Normalize a gitleaks File field to target-relative: `gitleaks git` emits repo-relative
    paths, but `gitleaks dir <path>` emits absolute paths (verified against 8.30.1)."""
    if os.path.isabs(file):
        # realpath both sides so a symlinked root (e.g. macOS /tmp -> /private/tmp) and the
        # absolute paths gitleaks emits reconcile to one repo-relative key.
        return os.path.relpath(os.path.realpath(file), os.path.realpath(target))
    return file


def build_findings(history, worktree, target, history_scanned=True):
    """One finding per secret per location class: a disk finding (SS-02/SS-03) and/or a
    history finding (SS-01/SS-04). The exposure matrix is attached to each. When history was
    not scanned (quick-check, a non-git target, or a failed history scan), the evidence does not
    claim that a file is absent from history."""
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
            gitignored = history_scanned and not in_history
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

    unknowns = []
    history = load_report(args.history_report, "git", unknowns)
    if args.dir_report:
        worktree = load_report(args.dir_report, "dir", unknowns)
    else:
        # The working-tree scan is the one that sees gitignored files on disk; every caller runs
        # it, so its absence means the disk lane never ran.
        worktree = None
        unknowns.append({
            "check_id": "SS-05",
            "scan_failed": True,
            "reason": "no gitleaks dir report was supplied, so secrets on disk were not scanned.",
            "action": "Run the `gitleaks dir` command from the secrets-scanner skill (it passes the "
                      "plugin's --config) and pass its report as --dir-report.",
        })
    findings = build_findings(history or [], worktree or [], target,
                              history_scanned=history is not None)

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
                    "source": ".ai-data-security-ignore",
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
    suppressed.extend(load_target_gitleaksignore(target, unknowns))

    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "secrets-scanner",
        "target": target,
        "tools": {"gitleaks": args.gitleaks_version},
        # Callers run gitleaks with the plugin's --config and --ignore-gitleaks-allow, so the
        # target's .gitleaks.toml is never read and inline gitleaks:allow comments do not hide
        # findings. Recorded here so the report can say whose rules were used.
        "scan_config": {
            "rules": "plugin",
            "target_gitleaks_toml_ignored": os.path.isfile(os.path.join(target, ".gitleaks.toml")),
            "inline_allow_comments": "reported",
        },
        "findings": active,
        "unknowns": unknowns,
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
