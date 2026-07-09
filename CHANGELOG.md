# Changelog

All notable changes to AI Data Security are documented here. This project follows
[Semantic Versioning](https://semver.org). Dates are ISO-8601.

## [0.1.2] — 2026-07-09

### Changed
- **Renamed the plugin `datawarden` → `ai-data-security`** to match the AI Data Security series.
  This changes the repository, the command prefix (`/ai-data-security:<skill>`), the marketplace
  install id (`ai-data-security@ai-data-security`), and the suppression-file convention
  (`.datawarden-ignore` → `.ai-data-security-ignore`). No functional change to any skill. GitHub
  redirects the old repo URL, but existing installs should be reinstalled under the new name:
  ```bash
  claude plugin marketplace remove datawarden 2>/dev/null; claude plugin uninstall datawarden 2>/dev/null
  claude plugin marketplace add kyle-chalmers/ai-data-security
  claude plugin install ai-data-security@ai-data-security
  ```

## [0.1.1] — 2026-07-09

### Fixed
- **data-classification filename precision** — a source-code or docs filename that merely contains
  a sensitive word (`eval_secrets.py`, `payment_service.go`, `security.md`) no longer floors the
  file by name alone; classification of source/doc files is now content-driven. Data/config files
  (`.env`, `credentials.json`, `secrets.yaml`, `.csv`, `.pem`) still floor on their name, and real
  secrets hardcoded inside source are still caught by content scanning.

### Added
- AI Data Security now passes its own `ai-config-audit` — a `.claude/settings.json` ships the secret
  deny-rules AC-01 recommends.
- A repository `.ai-data-security-ignore` triages AI Data Security's own example/fake PII (docs, tests,
  fixtures) so a self-audit returns clean-with-appendix; every entry is visible and reasoned.

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
  first-class UNKNOWN (fail-closed). Suppressions (`.ai-data-security-ignore`) always appear in an appendix.
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

[0.1.2]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.2
[0.1.1]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.1
[0.1.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.0
