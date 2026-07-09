#!/usr/bin/env bash
# Generate a throwaway git repo with planted secret exposures for testing secrets-scanner.
#
# SAFETY DOCTRINE: every secret-shaped string here is RANDOMLY GENERATED AT RUN TIME into the
# gitignored tests/fixtures/generated/ directory. Nothing secret-shaped is ever committed to the
# datawarden repo. (The canonical AWS documented example key is NOT used because gitleaks'
# default config allowlists it — verified empirically 2026-07-07.)
#
# Modes (fixture ids in reference/checks.yml):
#   (no flag)        secrets-generated         -> expects SS-01 (history-only) + SS-03 (.env, agent-readable)
#   --with-deny-rule secrets-generated-denied  -> adds .claude/settings.json deny rule; SS-03 becomes SS-02
#   --with-remote    secrets-generated-remote  -> pushes history to a local bare "origin"; SS-01 becomes SS-04
#
# Prints the generated repo path on the last line of stdout.
set -euo pipefail

# tr reads /dev/urandom forever; head closing the pipe sends tr SIGPIPE, which pipefail
# would turn into exit 141 — hence the || true. GNU tr also prints "write error: Broken
# pipe" on that signal, hence the 2>/dev/null.
rand() { # $1 charset, $2 length
  { LC_ALL=C tr -dc "$1" 2>/dev/null </dev/urandom | head -c "$2"; } || true
}

MODE="base"
case "${1:-}" in
  --with-deny-rule) MODE="denied" ;;
  --with-remote)    MODE="remote" ;;
  "") ;;
  *) echo "usage: $0 [--with-deny-rule|--with-remote]" >&2; exit 2 ;;
esac

FIXTURES_DIR="$(cd "$(dirname "$0")" && pwd)"
GENERATED="$FIXTURES_DIR/generated"
REPO="$GENERATED/secrets-repo-$MODE"
rm -rf "$REPO"
mkdir -p "$REPO"

cd "$REPO"
git init -q -b main
git config --local user.name "fixture"
git config --local user.email "fixture@example.invalid"

# --- history exposure: a format-detected token, committed then deleted -----------------------
# Uses a ghp_-shaped token: gitleaks' github-pat rule is FORMAT-based (deterministic). A random
# AWS secret was detected only via the entropy-based generic-api-key rule, which missed ~8% of
# random draws and intermittently reddened CI (no history finding -> no SS-04).
DEPLOY_TOKEN="ghp_$(rand 'A-Za-z0-9' 36)"
printf 'GITHUB_DEPLOY_TOKEN=%s\n' "$DEPLOY_TOKEN" > deploy-creds.txt
git add deploy-creds.txt
git commit -qm "add deploy credentials"
git rm -q deploy-creds.txt
git commit -qm "remove deploy credentials"

# --- disk exposure: GitHub-PAT-shaped token in a gitignored .env -----------------------------
TOKEN="ghp_$(rand 'A-Za-z0-9' 36)"
printf 'GITHUB_TOKEN=%s\n' "$TOKEN" > .env
echo ".env" > .gitignore
git add .gitignore
git commit -qm "ignore env files"

if [ "$MODE" = "denied" ]; then
  mkdir -p .claude
  cat > .claude/settings.json <<'EOF'
{
  "permissions": {
    "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]
  }
}
EOF
fi

if [ "$MODE" = "remote" ]; then
  BARE="$GENERATED/secrets-origin-$MODE.git"
  rm -rf "$BARE"
  git init -q --bare "$BARE"
  git remote add origin "$BARE"
  git push -qu origin main
fi

echo "$REPO"
