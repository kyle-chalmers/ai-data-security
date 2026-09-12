#!/usr/bin/env python3
"""ai-data-security quick-check: three verdict lines in about a minute.

Runs the existing deterministic evaluators over a target and condenses them:

  1. Secrets   — agent-readable secrets on disk (gitleaks dir scan + eval_secrets.py; SS-02/SS-03).
                 Git history is NOT scanned here (that is the full secrets-scanner); said out loud.
  2. Agent     — deny-rule coverage (AC-01), sandbox posture (AC-07), other AC findings (permeval.py).
  3. Data      — Restricted / Confidential file counts (classify_hints.py; DC-01/DC-02).

Everything unverifiable is listed as UNKNOWN (gitleaks missing → SS-05; AC-06 always; DC-03
unreadable paths; and the two things quick-check does not do: history and warehouse). No new
verdict logic lives here: findings pass through from the evaluators with their citations and
fingerprints intact. Stdlib only. Read-only. Never prints secret or data values.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCHEMA_VERSION = 1
TOOL_VERSION = "1"
LANE_TIMEOUT = 35  # seconds per evaluator (3 lanes < 120 s total); a timeout becomes an UNKNOWN, never a pass

EVAL_SECRETS = os.path.join(PLUGIN_ROOT, "skills", "secrets-scanner", "scripts", "eval_secrets.py")
PERMEVAL = os.path.join(PLUGIN_ROOT, "skills", "ai-config-audit", "scripts", "permeval.py")
CLASSIFY = os.path.join(PLUGIN_ROOT, "skills", "data-classification", "scripts", "classify_hints.py")


def _valid_blob(data):
    """Shape check for evaluator output: an object whose findings/unknowns/suppressed are lists of
    objects. Anything else is treated as unusable (lane UNKNOWN), never as a pass."""
    if not isinstance(data, dict):
        return False
    for key in ("findings", "unknowns", "suppressed"):
        items = data.get(key, [])
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            return False
    return True


def run_json(argv, out_path, timeout=LANE_TIMEOUT):
    """Run an evaluator that writes JSON to out_path; return (data, error_category).
    Child stdout/stderr are never surfaced: the evaluators are the redaction boundary and a
    failing child could print anything."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"evaluator timed out after {timeout}s"
    except OSError:
        return None, "evaluator could not be started"
    if proc.returncode != 0:
        return None, f"evaluator exited {proc.returncode}"
    try:
        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None, "evaluator output was not readable JSON"
    if not _valid_blob(data):
        return None, "evaluator output had an unexpected shape"
    return data, None


def secrets_lane(target, tmp, unknowns):
    # History is never scanned by quick-check, whatever happens below — say so first.
    unknowns.append({
        "check_id": "SS-01",
        "reason": "quick-check scans the working tree only; git history was not scanned.",
        "action": "Run /ai-data-security:secrets-scanner to cover history and pushed remotes (SS-01/SS-04).",
    })
    gitleaks = shutil.which("gitleaks")
    if not gitleaks:
        unknowns.append({
            "check_id": "SS-05",
            "reason": "gitleaks is not installed; quick-check does not substitute a weaker scanner.",
            "action": "brew install gitleaks (or https://github.com/gitleaks/gitleaks/releases), then re-run.",
        })
        return None, "UNKNOWN"
    report = os.path.join(tmp, "dir.json")
    try:
        proc = subprocess.run(
            [gitleaks, "dir", "--no-banner", "--redact", "--report-format", "json",
             "--report-path", report, target],
            capture_output=True, text=True, errors="replace", timeout=LANE_TIMEOUT,
        )
        vout = subprocess.run([gitleaks, "version"], capture_output=True, text=True, errors="replace", timeout=10)
        m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", (vout.stdout or "") + (vout.stderr or ""))
        version = m.group(1) if m else "unknown"
    except (subprocess.TimeoutExpired, OSError, ValueError):
        unknowns.append({"check_id": "SS-05", "reason": "gitleaks dir scan did not complete (timeout or launch error)",
                         "action": "Run /ai-data-security:secrets-scanner for the full, retried scan."})
        return None, "UNKNOWN"
    if proc.returncode not in (0, 1):
        unknowns.append({"check_id": "SS-05", "reason": f"gitleaks exited {proc.returncode}",
                         "action": "Run /ai-data-security:secrets-scanner for the full, retried scan."})
        return None, "UNKNOWN"
    out = os.path.join(tmp, "secrets.json")
    data, err = run_json([sys.executable, EVAL_SECRETS, "--dir-report", report, "--target", target,
                          "--gitleaks-version", version, "--emit-json", out], out)
    if err:
        unknowns.append({"check_id": "SS-05", "reason": f"eval_secrets: {err}",
                         "action": "Run /ai-data-security:secrets-scanner."})
        return None, "UNKNOWN"
    return data, "ran"


def agent_lane(target, home, tmp, unknowns):
    out = os.path.join(tmp, "config.json")
    argv = [sys.executable, PERMEVAL, "--target", target, "--emit-json", out]
    if home:
        argv += ["--home", home]
    data, err = run_json(argv, out)
    if err:
        unknowns.append({"check_id": "AC-01", "reason": f"permeval: {err}",
                         "action": "Run /ai-data-security:ai-config-audit."})
        return None, "UNKNOWN"
    return data, "ran"


def data_lane(target, tmp, unknowns):
    out = os.path.join(tmp, "classify.json")
    data, err = run_json([sys.executable, CLASSIFY, "--target", target, "--emit-json", out], out)
    if err:
        unknowns.append({"check_id": "DC-03", "reason": f"classify_hints: {err}",
                         "action": "Run /ai-data-security:data-classification (large trees may need the full skill)."})
        return None, "UNKNOWN"
    return data, "ran"


def count(findings, check_id):
    return sum(1 for f in findings if f.get("check_id") == check_id)


def suppressed_ids(blob):
    """Check ids of suppressed findings (fingerprint prefix before the first ':')."""
    ids = []
    for s in blob.get("suppressed", []) if blob else []:
        fp = s.get("fingerprint")
        if isinstance(fp, str) and fp:
            ids.append(fp.split(":", 1)[0])
    return ids


def verdict_lines(secrets, agent, data):
    """Condense, never conclude: a suppressed finding is reported as suppressed, not as a pass."""
    lines = []
    if secrets is None:
        lines.append("1. Secrets: UNKNOWN — gitleaks unavailable or the scan failed (see UNKNOWN list).")
    else:
        f = secrets.get("findings", [])
        sup = suppressed_ids(secrets)
        readable = count(f, "SS-03")
        denied = count(f, "SS-02")
        sup_n = sum(1 for s in sup if s in ("SS-02", "SS-03"))
        tail = f" {sup_n} secret finding(s) suppressed via .ai-data-security-ignore." if sup_n else ""
        if readable:
            lines.append(f"1. Secrets: {readable} agent-readable secret(s) on disk (SS-03, CRITICAL)"
                         + (f"; {denied} more covered by a deny rule (SS-02)" if denied else "")
                         + ". History not scanned." + tail)
        elif denied:
            lines.append(f"1. Secrets: {denied} secret(s) on disk, all covered by deny rules (SS-02, HIGH). History not scanned." + tail)
        elif sup_n:
            lines.append("1. Secrets: no active findings, but" + tail + " History not scanned.")
        else:
            lines.append("1. Secrets: no secrets found on disk by gitleaks. History not scanned.")
    if agent is None:
        lines.append("2. Agent config: UNKNOWN — permeval failed (see UNKNOWN list).")
    else:
        f = agent.get("findings", [])
        sup = suppressed_ids(agent)
        deny_missing = count(f, "AC-01")
        sandbox = [x for x in f if x.get("check_id") == "AC-07"]
        sandbox_off = any(x.get("severity") != "INFO" for x in sandbox)
        others = len(f) - deny_missing - len(sandbox) - count(f, "AC-05")
        parts = []
        if deny_missing:
            parts.append("deny rules missing (AC-01)")
        elif "AC-01" in sup:
            parts.append("deny-rule finding suppressed (AC-01)")
        else:
            parts.append("deny rules present")
        if sandbox_off:
            parts.append("sandbox filesystem isolation off (AC-07)")
        elif "AC-07" in sup:
            parts.append("sandbox finding suppressed (AC-07)")
        elif sandbox:
            parts.append("sandbox on, no hard gate (AC-07 INFO)")
        else:
            parts.append("sandbox on")
        if others:
            parts.append(f"{others} other finding(s)")
        other_sup = sum(1 for s in sup if s not in ("AC-01", "AC-07"))
        if other_sup:
            parts.append(f"{other_sup} suppressed")
        lines.append("2. Agent config: " + "; ".join(parts) + ". Retention tier always UNKNOWN (AC-06).")
    if data is None:
        lines.append("3. Data: UNKNOWN — classification failed (see UNKNOWN list).")
    else:
        f = data.get("findings", [])
        sup = suppressed_ids(data)
        restricted = count(f, "DC-01")
        confidential = count(f, "DC-02")
        unreadable = len(data.get("unknowns", []))
        sup_n = sum(1 for s in sup if s in ("DC-01", "DC-02"))
        lines.append(f"3. Data: {restricted} Restricted-tier file(s) (DC-01), {confidential} Confidential-tier (DC-02)"
                     + (f"; {unreadable} path(s) unreadable (DC-03)" if unreadable else "")
                     + (f"; {sup_n} classification finding(s) suppressed" if sup_n else "")
                     + ". Counts only, never values.")
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--home", help="home dir for user-scope configs (fixtures override this)")
    parser.add_argument("--emit-json", help="write the merged JSON here (text verdicts still print)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    started = time.monotonic()
    unknowns = []
    tmp = tempfile.mkdtemp(prefix="ads-quick-")
    try:
        secrets, s_status = secrets_lane(target, tmp, unknowns)
        agent, a_status = agent_lane(target, args.home, tmp, unknowns)
        data, d_status = data_lane(target, tmp, unknowns)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    findings, suppressed = [], []
    for skill, blob in (("secrets-scanner", secrets), ("ai-config-audit", agent), ("data-classification", data)):
        if not blob:
            continue
        for f in blob.get("findings", []):
            f = dict(f)
            f["skill"] = skill
            findings.append(f)
        for u in blob.get("unknowns", []):
            u = dict(u)
            u["skill"] = skill
            unknowns.append(u)
        suppressed.extend(blob.get("suppressed", []))
    unknowns.append({
        "check_id": "DB-06",
        "reason": "quick-check does not connect to a warehouse.",
        "action": "Run /ai-data-security:db-access-audit (or security-audit --db) for grants, PII columns, masking, audit logging.",
    })

    lines = verdict_lines(secrets, agent, data)
    elapsed = round(time.monotonic() - started, 1)
    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "quick-check",
        "target": target,
        "tools": {"quick_check": TOOL_VERSION, "lanes": {"secrets": s_status, "agent": a_status, "data": d_status}},
        "elapsed_seconds": elapsed,
        "verdicts": lines,
        "findings": findings,
        "unknowns": unknowns,
        "suppressed": suppressed,
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
        return 0
    print(f"ai-data-security quick-check — {target} ({elapsed}s)")
    print()
    for line in lines:
        print(line)
    print()
    print(f"UNKNOWN ({len(unknowns)}):")
    for u in unknowns:
        print(f"  - {u['check_id']}: {u['reason']} → {u['action']}")
    if suppressed:
        print(f"Suppressed (appendix): {len(suppressed)} finding(s) via .ai-data-security-ignore")
    print()
    print("Findings above pass through from the evaluators with citations and fingerprints; run the"
          " full skills for the rendered report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
