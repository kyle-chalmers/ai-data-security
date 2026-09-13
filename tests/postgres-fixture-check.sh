#!/usr/bin/env bash
# Postgres pack verification for db-access-audit. Spins up a throwaway pinned Postgres in
# docker, loads the misconfigured fixture, runs every read-only pack query THROUGH a
# read-only transaction (PGOPTIONS), diffs outputs against the committed golden CSVs, and
# asserts eval_grants.py verdicts — including the unconfirmed-principal confidence cap.
#
# Usage: tests/postgres-fixture-check.sh [--record]   (--record rewrites expected/ CSVs)
# Skips (exit 0) when docker is unavailable.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

RECORD=0
[ "${1:-}" = "--record" ] && RECORD=1

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker unavailable — postgres pack checks skipped"
  exit 0
fi

IMAGE="postgres:16-alpine"
NAME="ai-data-security-pg-fixture"
PACK="skills/db-access-audit/sql/postgres"
EXPECTED="tests/fixtures/postgres/expected"
OUT="tests/fixtures/generated/postgres-out"
fail=0

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=fixture-placeholder "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

# Wait for the REAL server, not the init-phase one. On a fresh container the alpine image runs
# initdb behind a TEMPORARY server (to set the password), logs "ready to accept connections",
# shuts it down, then starts the real server and logs "ready to accept connections" a SECOND
# time. A plain `SELECT 1` (or pg_isready) can succeed against the temp server, after which the
# restart yanks the socket out from under the next command. So the gate requires BOTH: that
# "ready to accept connections" has appeared at least twice (proves we are past the init
# restart) AND that a live query succeeds. The count only reaches 2 once the real server is up,
# so this cannot pass early regardless of CI timing.
echo "waiting for postgres real server (past init restart)..."
ready=0
for _ in $(seq 1 120); do
  n_ready="$(docker logs "$NAME" 2>&1 | grep -c 'ready to accept connections' || true)"
  if [ "${n_ready:-0}" -ge 2 ] && docker exec "$NAME" psql -U postgres -d postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL: postgres real server never came up; container logs follow"
  docker logs --tail 40 "$NAME" 2>&1 || true
  exit 1
fi

echo "loading fixture schema..."
docker exec -i "$NAME" psql -U postgres -d postgres -q -v ON_ERROR_STOP=1 \
  < tests/fixtures/postgres/init.sql

rm -rf "$OUT"; mkdir -p "$OUT"
for f in "$PACK"/*.sql; do
  name="$(basename "$f" .sql)"
  # default_transaction_read_only=on enforces the pack's read-only promise at the session level.
  # org_* are the no-op defaults; an org profile (reference/org-config.md) swaps in real tokens.
  docker exec -i -e PGOPTIONS="-c default_transaction_read_only=on" "$NAME" \
    psql -U postgres -d postgres --csv -q -v ON_ERROR_STOP=1 -v ai_role='ai_agent' \
    -v org_restricted='(^|_)(__none__)(_|$)' -v org_confidential='(^|_)(__none__)(_|$)' -f - \
    < "$f" > "$OUT/$name.csv"
  echo "ran $name.sql -> $(wc -l < "$OUT/$name.csv") lines"
done

if [ "$RECORD" -eq 1 ]; then
  mkdir -p "$EXPECTED"
  cp "$OUT"/*.csv "$EXPECTED/"
  echo "RECORDED golden outputs into $EXPECTED/"
else
  for f in "$OUT"/*.csv; do
    name="$(basename "$f")"
    if diff -u "$EXPECTED/$name" "$f"; then
      echo "OK: $name matches golden output"
    else
      echo "FAIL: $name diverges from golden output"
      fail=1
    fi
  done
fi

echo "evaluating verdicts (principal confirmed)..."
EVAL_OUT="$OUT/eval.json"
V04_ARGS=(--identity "$OUT/identity.csv" --policies "$OUT/policy_attachment.csv"
          --external "$OUT/external_paths.csv" --audit-quality "$OUT/audit_quality.csv")
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" "${V04_ARGS[@]}" \
  --role ai_agent --principal-confirmed --emit-json "$EVAL_OUT"

assert() {
  if jq -e "$2" "$EVAL_OUT" >/dev/null; then echo "OK: $1"; else
    echo "FAIL: $1"; echo "     (expression: $2)"; fail=1; fi
}
assert "DB-01 CRITICAL: write privileges on app tables" \
  '.findings | any(.check_id == "DB-01" and .severity == "CRITICAL" and (.evidence | test("app.customers:INSERT")))'
assert "DB-02 HIGH: SELECT on base tables app.customers + app.orders" \
  '.findings | any(.check_id == "DB-02" and .severity == "HIGH" and (.evidence | test("app.customers")) and (.evidence | test("app.orders")))'
assert "DB-03 HIGH: restricted columns ssn + card_number exposed" \
  '.findings | any(.check_id == "DB-03" and .severity == "HIGH" and (.evidence | test("ssn")) and (.evidence | test("card_number")))'
assert "DB-03 MEDIUM: confidential columns (email, full_name) exposed" \
  '.findings | any(.check_id == "DB-03" and .severity == "MEDIUM" and (.evidence | test("email")))'
assert "token-boundary patterns: prefixed member_ssn caught, emailed_at not" \
  '(.findings | any(.check_id == "DB-03" and (.evidence | test("member_ssn")))) and ([tostring | test("emailed_at")] == [false])'
assert "DB-04: no masked-view layer" '.findings | any(.check_id == "DB-04")'
assert "DB-05: no audit logging" '.findings | any(.check_id == "DB-05")'
assert "no row data in output (fixture has no data, and no SELECT * anywhere)" \
  '[tostring | test("fixture-placeholder")] == [false]'
assert "DB-ID-01 HIGH: ai_agent inherits analyst_group (INHERIT), not super/bypassrls" \
  '.findings | any(.check_id == "DB-ID-01" and .severity == "HIGH" and (.evidence | test("analyst_group")) and (.evidence | test("rolsuper") | not))'
assert "DB-07 HIGH: indirect paths — inherited SELECT on app.customers + default privileges" \
  '.findings | any(.check_id == "DB-07" and .severity == "HIGH" and (.evidence | test("inherited_grant app.customers via analyst_group:SELECT")) and (.evidence | test("default privileges")))'
assert "DB-08 HIGH: readable PII columns carry no masking label; anon not installed" \
  '.findings | any(.check_id == "DB-08" and .severity == "HIGH" and (.evidence | test("ssn")) and (.evidence | test("no masking mechanism")))'
assert "DB-09 MEDIUM: pgaudit not loaded, no per-role logging, collector off" \
  '.findings | any(.check_id == "DB-09" and .severity == "MEDIUM" and (.evidence | test("pgaudit is not loaded")) and (.evidence | test("logging_collector=off")))'
assert "DB-10 CRITICAL: pg_write_server_files membership" \
  '.findings | any(.check_id == "DB-10" and .severity == "CRITICAL" and (.evidence | test("pg_write_server_files")))'
assert "v0.4 inputs present: no DB-06 'not captured' unknowns" \
  '[.unknowns[] | select(.reason | test("not captured"))] | length == 0'
assert "every finding (incl. v0.4) carries citations and a fingerprint" \
  '[.findings[] | (.citations | length > 0) and (.fingerprint | length > 0)] | all'

echo "evaluating verdicts (principal NOT confirmed -> capped)..."
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" "${V04_ARGS[@]}" \
  --role ai_agent --emit-json "$EVAL_OUT"
assert "unconfirmed principal: every severity capped at MEDIUM" \
  '[.findings[] | .severity == "MEDIUM" or .severity == "LOW" or .severity == "INFO"] | all'
assert "unconfirmed principal: DB-06 unknown present" \
  '.unknowns | any(.check_id == "DB-06")'

# ---------------------------------------------------------------------------------------------
# v0.6 safe-db-access planner: render from the audit JSON, apply as the DBA (the harness plays the
# human), validate AS the AI role, re-audit (findings gone), roll back, re-audit (findings back).
# The planner itself only ever printed text.
# ---------------------------------------------------------------------------------------------
echo "planner: rendering the plan from the fixture audit..."
PLAN="skills/safe-db-access/scripts/plan.py"
PO="$OUT/planner"; mkdir -p "$PO"
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" "${V04_ARGS[@]}" \
  --columns "$OUT/columns.csv" --role ai_agent --principal-confirmed --emit-json "$EVAL_OUT"
# --include-public-revokes: the harness plays the human who reviewed the PUBLIC revocations.
python3 "$PLAN" --audit "$EVAL_OUT" --include-public-revokes > "$PO/plan.sql"
for sec in identity vault curated grants audit; do python3 "$PLAN" --audit "$EVAL_OUT" --include-public-revokes --section "$sec"; done > "$PO/plan-apply.sql"
python3 "$PLAN" --audit "$EVAL_OUT" --include-public-revokes --section validate > "$PO/plan-validate.sql"
python3 "$PLAN" --audit "$EVAL_OUT" --include-public-revokes --section rollback > "$PO/plan-rollback.sql"
if grep -q 'Status: INCOMPLETE' "$PO/plan.sql"; then echo "FAIL: plan is INCOMPLETE with every input present"; fail=1; fi
if grep -q '{{' "$PO/plan.sql"; then echo "FAIL: unfilled template slot in plan"; fail=1; fi
if grep -q 'fixture-placeholder' "$PO/plan.sql"; then echo "FAIL: a value leaked into the plan"; fail=1; fi
echo "OK: plan rendered ($(wc -l < "$PO/plan.sql") lines), complete, no unfilled slots"

echo "planner: applying sections 1-5 as the DBA (harness acts as the human)..."
if docker exec -i "$NAME" psql -U postgres -d postgres -q -v ON_ERROR_STOP=1 < "$PO/plan-apply.sql" > "$PO/plan-apply.log" 2>&1; then
  echo "OK: plan applied without error"
else
  echo "FAIL: plan apply errored"; cat "$PO/plan-apply.log"; fail=1
fi

echo "planner: validation AS ai_agent..."
docker exec -i "$NAME" psql -U ai_agent -d postgres --csv -q -v ON_ERROR_STOP=1 < "$PO/plan-validate.sql" > "$PO/plan-validate.csv" 2>&1 || { echo "FAIL: validation script errored"; cat "$PO/plan-validate.csv"; fail=1; }
n_checks="$(tail -n +2 "$PO/plan-validate.csv" | grep -c . || true)"
n_bad="$(tail -n +2 "$PO/plan-validate.csv" | grep -vc ',t$' || true)"
if [ "${n_checks:-0}" -ge 15 ] && [ "${n_bad:-0}" -eq 0 ]; then
  echo "OK: validation — $n_checks checks, all ok = t"
else
  echo "FAIL: validation — $n_checks checks, $n_bad not ok"; cat "$PO/plan-validate.csv"; fail=1
fi
if docker exec "$NAME" psql -U ai_agent -d postgres -tAc 'SELECT ssn FROM app.customers LIMIT 1' >/dev/null 2>&1; then
  echo "FAIL: ai_agent can still read the raw table"; fail=1
else
  echo "OK: raw read as ai_agent is refused"
fi
if docker exec "$NAME" psql -U ai_agent -d postgres -tAc 'SELECT count(*) FROM curated.customers' >/dev/null 2>&1; then
  echo "OK: analytics query on the curated view succeeds as ai_agent"
else
  echo "FAIL: curated view not readable by ai_agent"; fail=1
fi

echo "planner: re-auditing AFTER apply..."
AFTER="$PO/after"; mkdir -p "$AFTER"
for f in "$PACK"/*.sql; do
  name="$(basename "$f" .sql)"
  docker exec -i -e PGOPTIONS="-c default_transaction_read_only=on" "$NAME" \
    psql -U postgres -d postgres --csv -q -v ON_ERROR_STOP=1 -v ai_role='ai_agent' \
    -v org_restricted='(^|_)(__none__)(_|$)' -v org_confidential='(^|_)(__none__)(_|$)' -f - \
    < "$f" > "$AFTER/$name.csv"
done
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$AFTER/grants.csv" --pii "$AFTER/pii_columns.csv" \
  --views "$AFTER/masked_views.csv" --settings "$AFTER/audit_logging.csv" \
  --identity "$AFTER/identity.csv" --policies "$AFTER/policy_attachment.csv" \
  --external "$AFTER/external_paths.csv" --audit-quality "$AFTER/audit_quality.csv" \
  --columns "$AFTER/columns.csv" --role ai_agent --principal-confirmed --emit-json "$AFTER/eval.json"
EVAL_OUT="$AFTER/eval.json"
assert "after apply: DB-01 (writes), DB-02 (base tables), DB-03 (raw PII), DB-07 (indirect), DB-08 (unattached PII), DB-10 (server roles), DB-ID-01 are gone" \
  '[.findings[] | select(.check_id == "DB-01" or .check_id == "DB-02" or (.check_id == "DB-03" and .severity != "INFO") or .check_id == "DB-07" or .check_id == "DB-08" or .check_id == "DB-10" or .check_id == "DB-ID-01")] | length == 0'
assert "after apply: the hashed columns surface as DB-03 INFO (pseudonymized, still personal data), by name" \
  '.findings | any(.check_id == "DB-03" and .severity == "INFO" and (.evidence | test("email_pseudo")) and (.evidence | test("personal data")))'
assert "after apply: the AI role reads only curated views (grants show no base table)" \
  '[.findings[] | select(.check_id == "DB-02")] | length == 0'
assert "after apply: DB-04 gone (curated views show a hashing signal)" \
  '[.findings[] | select(.check_id == "DB-04")] | length == 0'
assert "after apply: DB-09 no longer reports a missing per-role log_statement" \
  '[.findings[] | select(.check_id == "DB-09" and (.evidence | test("no per-role log_statement")))] | length == 0'
assert "after apply: no DB-06 unknowns (every input captured)" \
  '[.unknowns[] | select(.check_id == "DB-06")] | length == 0'

echo "planner: rolling back (section 7) and re-auditing..."
if docker exec -i "$NAME" psql -U postgres -d postgres -q -v ON_ERROR_STOP=1 < "$PO/plan-rollback.sql" > "$PO/plan-rollback.log" 2>&1; then
  echo "OK: rollback applied without error"
else
  echo "FAIL: rollback errored"; cat "$PO/plan-rollback.log"; fail=1
fi
ROLL="$PO/rollback"; mkdir -p "$ROLL"
for f in "$PACK"/*.sql; do
  name="$(basename "$f" .sql)"
  docker exec -i -e PGOPTIONS="-c default_transaction_read_only=on" "$NAME" \
    psql -U postgres -d postgres --csv -q -v ON_ERROR_STOP=1 -v ai_role='ai_agent' \
    -v org_restricted='(^|_)(__none__)(_|$)' -v org_confidential='(^|_)(__none__)(_|$)' -f - \
    < "$f" > "$ROLL/$name.csv"
done
for name in grants pii_columns identity external_paths columns; do
  if diff -q "$EXPECTED/$name.csv" "$ROLL/$name.csv" >/dev/null; then
    echo "OK: rollback restored $name.csv to the original golden"
  else
    echo "FAIL: after rollback $name.csv differs from the golden"; diff -u "$EXPECTED/$name.csv" "$ROLL/$name.csv" || true; fail=1
  fi
done

echo
if [ "$fail" -eq 0 ]; then echo "POSTGRES PACK: PASS"; else echo "POSTGRES PACK: FAIL"; exit 1; fi
