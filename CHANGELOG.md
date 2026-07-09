# Changelog

All notable changes to DataWarden are documented here. This project follows
[Semantic Versioning](https://semver.org). Dates are ISO-8601.

## [0.1.0] — 2026-07-09

First public release. Feature-complete v1: audit-only, read-only, every finding cites a standard.

### Skills

- **secrets-scanner** — gitleaks history + working-tree scans, plus the exposure matrix gitleaks
  does not compute (on-disk × in-history × agent-readable × pushed-to-remote); a pushed secret is
  always a rotate-first CRITICAL. Fails closed to UNKNOWN if gitleaks is absent.
- **ai-config-audit** — permission deny/allow rules (flags env-runner wildcard grants), MCP configs
  across Claude/Cursor/Gemini/Codex, plaintext transcripts, and a fail-closed UNKNOWN for the
  consumer retention/training tier (not locally auditable).
- **data-classification** — the 4-tier framework (Public/Internal/Confidential/Restricted, based on
  NIST SP 800-122), deterministic floors (never auto-Public), content validators (Luhn, SSN format);
  reports carry counts and column names, never data values.
- **db-access-audit** — read-only Postgres and Snowflake packs; audits AI-principal write grants,
  raw base-table reads, unmasked PII columns, missing masked views, and missing audit logging.
  Human-gated; supports an air-gapped `--recorded` mode.
- **security-audit** — the ~30-minute orchestrator that merges all of the above into one
  deduplicated, cited report with a severity-ranked Top-5 (rotate-first override).

### Design

- Deterministic stdlib-Python evaluators own every verdict; the model narrates but cannot change
  severity, confidence, or exposure. Severity is capped by confidence; unverifiable checks are
  first-class UNKNOWN (fail-closed). Suppressions (`.datawarden-ignore`) always appear in an appendix.
- Verified-only citation registry (OWASP LLM Top 10 2025, MITRE ATLAS, MCP Security Best Practices,
  NIST SP 800-122, NIST AI 600-1).

### Quality

- CI (deterministic, no LLM calls): plugin validation, shellcheck, SQL read-only lint, gitleaks
  self-scan of tree and full history, dockerized Postgres fixture diffs; all GitHub Actions
  SHA-pinned. Fixtures use only vendor-documented or famous-fake values; secret-shaped test data is
  generated at test time, never committed.
- Hardened against two internal adversarial passes (a fresh-context review and an edge-case bug
  hunt): permission-glob precision, uniform fail-closed suppression, a value-leak in classification
  evidence, crash-resistance on hostile inputs, and a regex ReDoS were all fixed and regression-locked.

[0.1.0]: https://github.com/kyle-chalmers/datawarden/releases/tag/v0.1.0
