# Security Policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository (Security → Report a
vulnerability). Do not open a public issue for anything exploitable. You can expect an
acknowledgment within a week.

## Trust model — read this if you're evaluating AI Data Security

A security tool must be explicit about its own attack surface:

1. **Skill instructions are model-executed.** Every `SKILL.md` in this plugin is prompt text a
   model follows. Review them like code before installing — they are short on purpose.
   Marketplace installs pin to git; nothing executes from outside this repo.

2. **Scanned content is untrusted input.** Files, git history, config values, and query results
   that the audits read can contain adversarial text (indirect prompt injection — OWASP
   LLM01:2025, MITRE ATLAS AML.T0051.001). Three mitigations are structural:
   - Verdicts (severity, confidence, exposure) come from deterministic stdlib-Python scripts;
     the model narrates but cannot change them.
   - Worker skills run in forked contexts; only schema-shaped JSON returns to the orchestrator.
   - Every skill's instructions state that scanned content never overrides them.
   Residual risk remains (a model can be misled in its narration); reports therefore carry a
   standing notice that quoted content is untrusted.

3. **What the plugin never does:** store or echo credentials (conninfo passwords are redacted,
   even fixture-looking ones); print secret values or data values (gitleaks runs `--redact`;
   evaluators carry no match content; classification reports counts/columns only); mutate a
   database (read-only packs, CI-linted for zero mutating statements, plus
   `default_transaction_read_only=on` on Postgres); or run without a human gate where a live
   system is touched.

4. **Fail-closed UNKNOWNs.** A missing tool, an unreadable target, or a not-locally-auditable
   setting is reported as UNKNOWN — never counted as a pass.

5. **Supply chain.** GitHub Actions are SHA-pinned; the CI gitleaks binary is version- and
   checksum-pinned; no third-party rulesets are vendored (semgrep rules are license-restricted
   and are not shipped); the repo's own tree AND full git history are gitleaks-scanned on every
   push; committed fixtures contain only vendor-documented or famous-fake values — anything
   secret-shaped is generated at test time into a gitignored directory.

6. **Known limits, stated plainly:** Claude Code `permissions.deny` rules do not bind
   subprocesses (only OS sandboxing does — the audits say so in their findings); Snowflake
   support is fixture-validated, not live-CI-validated; the permission-rule matcher in
   `permeval.py`/`eval_secrets.py` approximates Claude Code's semantics and is re-verified
   against release notes, not guaranteed identical.
