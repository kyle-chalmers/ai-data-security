#!/usr/bin/env bash
# Session-start orientation for the ai-data-security long-running build harness.
# Read SPEC.md first if this is your first session.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== ai-data-security build harness ==="
echo
echo "--- last 5 commits ---"
git log --oneline -5 2>/dev/null || echo "(no commits yet)"
echo
echo "--- unfinished features (dev/feature_list.json) ---"
jq -r '.features[] | select(.passes == false) | "[ ] \(.id): \(.description)"' dev/feature_list.json
echo
echo "--- progress log (last 10 lines) ---"
tail -10 dev/progress.txt
echo
echo "Next: run dev/validate.sh (baseline must pass before new work), then do ONE feature,"
echo "demonstrate its check, flip only its 'passes' field, append to dev/progress.txt, commit."
