#!/usr/bin/env bash
# Deterministic fixture assertions for ai-data-security. No LLM calls.
# Bidirectional: a missing expected finding is a false-negative regression;
# an unexpected finding on clean paths is a false-positive regression.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
step() { echo; echo "==> $1"; }

# Portable bounded run: timeout (GNU/Linux) -> gtimeout (macOS coreutils) -> pure-shell poll.
# Returns 124 if the command exceeds the deadline.
run_bounded() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"; return $?; fi
  if command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"; return $?; fi
  "$@" & local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 1; i=$((i + 1))
    if [ "$i" -ge "$secs" ]; then kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124; fi
  done
  wait "$pid"
}

step "reference consistency: checks.yml -> citations.yml + fixtures"
if ! jq -e --slurpfile cites reference/citations.yml '
    [.checks | to_entries[]
     | select((.value.citations - ($cites[0].citations | keys)) != [] or (.value.fixtures | length) == 0)
     | .key] == []' reference/checks.yml >/dev/null; then
  echo "FAIL: a check in checks.yml cites an unknown citation key or has no fixture"
  jq -r --slurpfile cites reference/citations.yml '
    .checks | to_entries[]
    | select((.value.citations - ($cites[0].citations | keys)) != [] or (.value.fixtures | length) == 0)
    | "  offending check: \(.key)"' reference/checks.yml
  fail=1
else
  echo "OK: every check cites known citations and names at least one fixture"
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "SKIP: gitleaks not installed — secrets fixture assertions skipped (install: brew install gitleaks)"
  exit "$fail"
fi

EVAL="skills/secrets-scanner/scripts/eval_secrets.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run_gitleaks() { # $1 subcommand, $2 report path, $3 repo — exit 0/1 are normal; >1 retried once, then loud
  local sub="$1" report="$2" repo="$3" rc=0
  gitleaks "$sub" --no-banner --redact --report-format json --report-path "$report" "$repo" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "WARN: gitleaks $sub exited $rc for $repo; retrying once"
    rc=0
    gitleaks "$sub" --no-banner --redact --report-format json --report-path "$report" "$repo" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -gt 1 ]; then
      echo "FAIL: gitleaks $sub errored twice (exit $rc) for $repo"
      fail=1
    fi
  fi
}

run_eval() { # $1 repo path -> writes $TMP/out.json; reports are always fresh (no stale reuse)
  local repo="$1"
  rm -f "$TMP/hist.json" "$TMP/dir.json" "$TMP/out.json"
  run_gitleaks git "$TMP/hist.json" "$repo"
  run_gitleaks dir "$TMP/dir.json" "$repo"
  python3 "$EVAL" --history-report "$TMP/hist.json" --dir-report "$TMP/dir.json" \
    --target "$repo" --gitleaks-version "test" --emit-json "$TMP/out.json"
}

assert() { # $1 description, $2 jq expression that must be true against $TMP/out.json
  if jq -e "$2" "$TMP/out.json" >/dev/null; then
    echo "OK: $1"
  else
    echo "FAIL: $1"
    echo "     (expression: $2)"
    fail=1
  fi
}

step "fixture secrets-generated: SS-01 history HIGH + SS-03 disk CRITICAL"
REPO="$(tests/fixtures/make-secrets-repo.sh | tail -1)"
run_eval "$REPO"
# gitleaks rule multiplicity on the same planted secret varies by random draw, so assert
# semantics (findings confined to planted files, correct check per file), not exact counts.
assert "findings confined to the two planted files" \
  '[.findings[].file] | unique | sort == [".env", "deploy-creds.txt"]'
assert "every deploy-creds.txt finding is history-only SS-01" \
  '[.findings[] | select(.file == "deploy-creds.txt") | .check_id] | (length > 0) and (unique == ["SS-01"])'
assert "SS-01 present, severity HIGH, history-only exposure" \
  '.findings | any(.check_id == "SS-01" and .severity == "HIGH" and .exposure.in_history and (.exposure.on_disk | not) and (.exposure.vcs_remote | not))'
assert "SS-03 present on .env, severity CRITICAL, confirmed, agent-readable" \
  '.findings | any(.check_id == "SS-03" and .file == ".env" and .severity == "CRITICAL" and .confidence == "confirmed" and .exposure.agent_readable)'
assert "no secret values leak into the report (no ghp_ or AKIA strings)" \
  '[tostring | test("ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")] == [false]'
assert "every finding carries at least one citation" \
  '[.findings[] | .citations | length > 0] | all'
assert "every finding carries a fingerprint" \
  '[.findings[] | .fingerprint | length > 0] | all'

step "fixture secrets-generated-denied: deny rule flips SS-03 to SS-02 HIGH"
REPO="$(tests/fixtures/make-secrets-repo.sh --with-deny-rule | tail -1)"
run_eval "$REPO"
assert "SS-02 present on .env, severity HIGH, not agent-readable" \
  '.findings | any(.check_id == "SS-02" and .file == ".env" and .severity == "HIGH" and (.exposure.agent_readable | not))'
assert "no SS-03 finding (false-positive guard)" \
  '[.findings[] | select(.check_id == "SS-03")] | length == 0'

step "fixture secrets-generated-remote: pushed history flips SS-01 to SS-04 rotate-first"
REPO="$(tests/fixtures/make-secrets-repo.sh --with-remote | tail -1)"
run_eval "$REPO"
assert "SS-04 present with rotate_first and vcs_remote exposure" \
  '.findings | any(.check_id == "SS-04" and .rotate_first and .exposure.vcs_remote)'
assert "no SS-01 finding (exposure upgraded, not duplicated)" \
  '[.findings[] | select(.check_id == "SS-01")] | length == 0'

step "false-positive guard: clean repo yields zero findings"
CLEAN="$(dirname "$(tests/fixtures/make-secrets-repo.sh | tail -1)")/clean-repo"
rm -rf "$CLEAN" && mkdir -p "$CLEAN"
git -C "$CLEAN" init -q -b main
git -C "$CLEAN" -c user.name=fixture -c user.email=f@example.invalid commit -q --allow-empty -m "empty"
echo "README" > "$CLEAN/README.md"
run_eval "$CLEAN"
assert "clean repo: zero findings" '.findings | length == 0'

step "suppression: .ai-data-security-ignore moves a finding to the appendix"
REPO="$(tests/fixtures/make-secrets-repo.sh | tail -1)"
FP="$(run_eval "$REPO"; jq -r '[.findings[] | select(.check_id == "SS-03")][0].fingerprint' "$TMP/out.json")"
printf '%s reason=fixture test\n' "$FP" > "$REPO/.ai-data-security-ignore"
run_eval "$REPO"
assert "suppressed finding is in the appendix, not findings" \
  '(.findings | map(.check_id) | index("SS-03")) == null and (.suppressed | length == 1)'

PERMEVAL="skills/ai-config-audit/scripts/permeval.py"

step "fixture ai-config: AC-01..AC-05 findings + AC-06 unknown"
python3 "$PERMEVAL" --target tests/fixtures/ai-config \
  --home tests/fixtures/ai-config/home --emit-json "$TMP/out.json"
assert "AC-01: all 3 recommended deny rules reported missing" \
  '.findings | any(.check_id == "AC-01" and (.title | test("Missing 3")) and .severity == "HIGH")'
assert "AC-02: Bash(npx *) flagged as env-runner allow" \
  '.findings | any(.check_id == "AC-02" and (.title | test("npx")) and .severity == "HIGH")'
assert "AC-02: colon-wildcard spelling Bash(uvx:*) also flagged" \
  '.findings | any(.check_id == "AC-02" and (.title | test("uvx")))'
assert "AC-03: credential-shaped MCP env key flagged by name" \
  '.findings | any(.check_id == "AC-03" and (.evidence | test("WAREHOUSE_PASSWORD")))'
assert "AC-03: the placeholder value itself never appears in output" \
  '[tostring | test("placeholder-not-a-real-value")] == [false]'
assert "AC-04: gemini trust:true flagged" \
  '.findings | any(.check_id == "AC-04" and (.file | test("gemini")))'
assert "AC-05: transcript INFO present" \
  '.findings | any(.check_id == "AC-05" and .severity == "INFO")'
assert "AC-06: retention always reported UNKNOWN with manual-check action" \
  '.unknowns | any(.check_id == "AC-06" and (.action | test("data-privacy-controls")))'
assert "every ai-config finding carries a citation and fingerprint" \
  '[.findings[] | (.citations | length > 0) and (.fingerprint | length > 0)] | all'

step "fixture ai-config-hardened: false-positive guard"
HARDHOME="$TMP/empty-home"
mkdir -p "$HARDHOME"
python3 "$PERMEVAL" --target tests/fixtures/ai-config-hardened \
  --home "$HARDHOME" --emit-json "$TMP/out.json"
assert "hardened config: zero findings" '.findings | length == 0'
assert "hardened config: AC-06 unknown still present (never a clean bill)" \
  '.unknowns | any(.check_id == "AC-06")'

CLASSIFY="skills/data-classification/scripts/classify_hints.py"

step "matcher unit tests (permission globs + fail-closed expiry)"
if ! python3 tests/test_matchers.py; then fail=1; fi

step "fixture classify-repo: deterministic floors, validators, no values in output"
python3 "$CLASSIFY" --target tests/fixtures/classify-repo --emit-json "$TMP/out.json"
assert "accounts.csv floors to Restricted, confirmed, via SSN + Luhn validators" \
  '.files | any(.path == "accounts.csv" and .floor == "Restricted" and .confidence == "confirmed" and .indicators.ssn_valid == 2 and .indicators.pan_luhn_valid >= 2)'
assert "customers.csv floors to Confidential via validated emails + PII columns" \
  '.files | any(.path == "customers.csv" and .floor == "Confidential" and .indicators.emails == 2 and (.pii_columns | length >= 2))'
assert "README.md and runbook.md floor to Internal (never auto-Public)" \
  '[.files[] | select(.path == "README.md" or .path == "runbook.md") | .floor == "Internal"] == [true, true]'
assert "no data values leak into hint output (no SSN/PAN/email strings)" \
  '[tostring | test("078-05-1120|4111111111111111|jane\\.doe@example\\.com")] == [false]'
assert "nothing is ever floored to Public" \
  '[.files[] | .floor != "Public"] | all'
assert "DC-01 finding emitted for accounts.csv (HIGH, confirmed, cited)" \
  '.findings | any(.check_id == "DC-01" and .file == "accounts.csv" and .severity == "HIGH" and .confidence == "confirmed" and (.citations | length > 0))'
assert "DC-02 finding emitted for customers.csv (MEDIUM)" \
  '.findings | any(.check_id == "DC-02" and .file == "customers.csv" and .severity == "MEDIUM")'

step "classification DC-03: unreadable file becomes an UNKNOWN, never a silent skip"
DCDIR="$TMP/dc-unreadable"
mkdir -p "$DCDIR"
echo "readable" > "$DCDIR/ok.txt"
echo "hidden" > "$DCDIR/locked.txt"
chmod 000 "$DCDIR/locked.txt"
if [ -r "$DCDIR/locked.txt" ]; then
  echo "SKIP: running as root (chmod 000 still readable) — DC-03 check skipped"
else
  python3 "$CLASSIFY" --target "$DCDIR" --emit-json "$TMP/out.json"
  assert "DC-03 unknown names the unreadable file" \
    '.unknowns | any(.check_id == "DC-03" and (.reason | test("locked.txt")))'
  assert "unreadable file absent from the classification table" \
    '[.files[] | .path] | index("locked.txt") == null'
fi
chmod 644 "$DCDIR/locked.txt" 2>/dev/null || true

step "classification suppression: .ai-data-security-ignore moves DC finding to appendix"
DCSUP="$TMP/dc-suppress"
mkdir -p "$DCSUP"
cp tests/fixtures/classify-repo/accounts.csv "$DCSUP/"
printf 'DC-01:accounts.csv:Restricted reason=fixture test\n' > "$DCSUP/.ai-data-security-ignore"
python3 "$CLASSIFY" --target "$DCSUP" --emit-json "$TMP/out.json"
assert "DC-01 suppressed into appendix" \
  '(.findings | map(.check_id) | index("DC-01")) == null and (.suppressed | length == 1)'

step "db-access-audit suppression via --ignore-dir (recorded CSVs, no docker)"
DBSUP="$TMP/db-suppress"
mkdir -p "$DBSUP"
printf 'DB-04:views:db reason=fixture test\n' > "$DBSUP/.ai-data-security-ignore"
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants tests/fixtures/postgres/expected/grants.csv \
  --pii tests/fixtures/postgres/expected/pii_columns.csv \
  --views tests/fixtures/postgres/expected/masked_views.csv \
  --settings tests/fixtures/postgres/expected/audit_logging.csv \
  --role ai_agent --principal-confirmed --ignore-dir "$DBSUP" --emit-json "$TMP/out.json"
assert "DB-04 suppressed into appendix; other findings intact" \
  '(.findings | map(.check_id) | index("DB-04")) == null and (.suppressed | length == 1) and (.findings | length >= 3)'

step "edge hardening: crash-resistance + value-leak regressions (from the bug hunt)"
CLASSIFY_S="skills/data-classification/scripts/classify_hints.py"
PERMEVAL_S="skills/ai-config-audit/scripts/permeval.py"
GRANTS_S="skills/db-access-audit/scripts/eval_grants.py"

# classify_hints: untraversable subdirectory -> DC-03 unknown, never a silent skip (blocker)
EH="$TMP/eh-walkerr"; mkdir -p "$EH/secretsub"
printf 'ssn,email\n123-45-6789,a@example.com\n' > "$EH/secretsub/hidden.csv"
printf 'id\n1\n' > "$EH/ok.csv"
chmod 000 "$EH/secretsub"
python3 "$CLASSIFY_S" --target "$EH" --emit-json "$TMP/out.json"
chmod 755 "$EH/secretsub"
assert "unreadable subdir emits a DC-03 unknown (fail-closed, not a silent skip)" \
  '.unknowns | any(.check_id == "DC-03" and (.reason | test("secretsub")))'

# classify_hints: no raw field text leaks into pii_columns / evidence (blocker: value leak)
EH2="$TMP/eh-leak"; mkdir -p "$EH2"
printf 'row_id,medical note: patient Jane Q Public HIV+ policy#A1234567\n1,ok\n' > "$EH2/dump.csv"
python3 "$CLASSIFY_S" --target "$EH2" --emit-json "$TMP/out.json"
assert "free-text header field never captured as a column (no value leak)" \
  '[tostring | test("Jane Q Public|HIV")] == [false]'

# classify_hints: FIFO does not hang the scan (bounded by a short timeout here)
EH3="$TMP/eh-fifo"; mkdir -p "$EH3"; mkfifo "$EH3/pipe" 2>/dev/null || true
if [ -p "$EH3/pipe" ]; then
  if run_bounded 15 python3 "$CLASSIFY_S" --target "$EH3" --emit-json "$TMP/out.json"; then
    assert "FIFO surfaced as DC-03, scan did not hang" '.unknowns | any(.check_id == "DC-03")'
  else
    echo "FAIL: classify_hints hung or errored on a FIFO (exit $?)"; fail=1
  fi
fi

# classify_hints: BOM UTF-16 text with a valid SSN is scanned, not filed Internal-binary
EH4="$TMP/eh-utf16"; mkdir -p "$EH4"
python3 - "$EH4/wide.txt" <<'PY'
import sys
open(sys.argv[1], "wb").write("account\nssn 078-05-1120\n".encode("utf-16"))
PY
python3 "$CLASSIFY_S" --target "$EH4" --emit-json "$TMP/out.json"
assert "UTF-16 file with a valid SSN yields a Restricted DC-01 (not silent Internal)" \
  '.findings | any(.check_id == "DC-01" and (.file | test("wide.txt")))'

# permeval: malformed / hostile config shapes must not crash the audit (fail-open -> crash)
EHP="$TMP/eh-perm"; mkdir -p "$EHP/.claude"
printf '{"permissions": null}\n' > "$EHP/.claude/settings.json"
printf '{"mcpServers": {"s": {"command": "x", "env": null}}}\n' > "$EHP/.mcp.json"
mkdir -p "$EHP/.cursor"; printf '["not-an-object"]\n' > "$EHP/.cursor/mcp.json"
EHHOME="$TMP/eh-perm-home"; mkdir -p "$EHHOME/.codex"
mkdir -p "$EHHOME/.codex/config.toml"  # a DIRECTORY where a file is expected
if python3 "$PERMEVAL_S" --target "$EHP" --home "$EHHOME" --emit-json "$TMP/out.json" 2>"$TMP/err"; then
  assert "hostile configs still yield a well-formed run with the AC-06 unknown" \
    '.unknowns | any(.check_id == "AC-06")'
  assert "permissions:null still produces the AC-01 finding (did not crash out)" \
    '.findings | any(.check_id == "AC-01")'
else
  echo "FAIL: permeval crashed on hostile config shapes:"; cat "$TMP/err"; fail=1
fi

# eval_grants: a present-but-malformed CSV fails closed to DB-06, does not KeyError-crash
EHG="$TMP/eh-grants"; mkdir -p "$EHG/expected"
printf 'wrong,header\na,b\n' > "$EHG/grants.csv"
cp tests/fixtures/postgres/expected/pii_columns.csv "$EHG/pii.csv"
cp tests/fixtures/postgres/expected/masked_views.csv "$EHG/views.csv"
cp tests/fixtures/postgres/expected/audit_logging.csv "$EHG/settings.csv"
if python3 "$GRANTS_S" --grants "$EHG/grants.csv" --pii "$EHG/pii.csv" \
     --views "$EHG/views.csv" --settings "$EHG/settings.csv" \
     --role ai_agent --principal-confirmed --emit-json "$TMP/out.json" 2>"$TMP/err"; then
  assert "malformed grants.csv -> DB-06 unknown (fail closed, no crash)" \
    '.unknowns | any(.check_id == "DB-06" and (.reason | test("grants")))'
else
  echo "FAIL: eval_grants crashed on a malformed CSV:"; cat "$TMP/err"; fail=1
fi

step "postgres pack (docker; self-skips when unavailable)"
if ! tests/postgres-fixture-check.sh; then
  echo "FAIL: postgres pack checks"
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then echo "FIXTURES: PASS"; else echo "FIXTURES: FAIL"; exit 1; fi
