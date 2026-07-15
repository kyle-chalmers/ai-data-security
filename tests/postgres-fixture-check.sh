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

mkdir -p "$OUT"
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
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" \
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

echo "evaluating verdicts (principal NOT confirmed -> capped)..."
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" \
  --role ai_agent --emit-json "$EVAL_OUT"
assert "unconfirmed principal: every severity capped at MEDIUM" \
  '[.findings[] | .severity == "MEDIUM" or .severity == "LOW" or .severity == "INFO"] | all'
assert "unconfirmed principal: DB-06 unknown present" \
  '.unknowns | any(.check_id == "DB-06")'

echo
if [ "$fail" -eq 0 ]; then echo "POSTGRES PACK: PASS"; else echo "POSTGRES PACK: FAIL"; exit 1; fi
