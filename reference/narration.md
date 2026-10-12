# Narration contract

Every skill follows this when it talks to the person running it. The scripts decide the verdicts;
narration makes sure the person knows what is happening, why, and what to do next. People trust
an audit when it says plainly what it is about to do and why.

## While running

- **Before each step that runs a tool or reads files, one line of what and why.** For example:
  "Scanning git history with gitleaks, because a secret deleted from disk can still sit in an
  old commit."
- **After it, one line of result.** For example: "History scan done: 2 secrets, both in commits
  that were pushed."
- **Keep it to those two lines.** No progress chatter between them, and no verdicts the script
  did not produce.

## Asking a question

- **Say what the answer decides and what each choice changes** before you ask: which checks will
  run, what becomes UNKNOWN, what it costs (warehouse credits, auditor rights), and whether it
  touches a live system.
- **A detected value is a recommendation, not an answer.** If you found a likely AI role or
  connection, offer it as the first option and let the person confirm it. Detection never counts
  as confirmation.
- **Ask everything you need in one round** where you can, so the person is not interrupted
  again later.

## Explaining results

- **Give the plain title with a check ID on first mention**, e.g. "AC-07 (Bash sandbox not
  enabled)". The titles come from [checks.yml](checks.yml); the full list is in
  [docs/glossary.md](../docs/glossary.md).
- **For every UNKNOWN, say why it could not be checked and what would make it checkable.**
- **State the counts in chat** (findings, UNKNOWNs, suppressed), so nobody has to open a file to
  know where they stand.

## Finishing

End with three short parts: what ran, what did not run and why, and the one command to run next
(a line starting `Next:`).

## When another skill runs you

A worker skill invoked by `security-audit` skips the step-by-step lines and returns its report
and JSON; the orchestrator narrates the phases instead, one what-and-why line per phase.
