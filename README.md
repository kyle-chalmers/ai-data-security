# AI Data Security

**Data + AI security audits for data professionals, as a Claude Code plugin.**

AI agents read your filesystem, not your `.gitignore`. They connect to your warehouse with
whatever privileges you gave them. AI Data Security audits both sides of that relationship — the AI
tooling's configuration and the data stack it touches — and reports **cited, severity-ranked
findings** with concrete fixes. Read-only by design; nothing mutates anything.

The flagship flow is the **~30-minute security audit**:

```
/ai-data-security:security-audit <path> [--db '--dialect postgres --connection <conninfo> --role <ai-role>']
```

…which runs every skill below and merges the results into one prioritized report.

## Skills

| Skill | What it audits |
|---|---|
| `/ai-data-security:secrets-scanner <path>` | Secrets on disk **and** in git history (gitleaks), plus the exposure matrix gitleaks doesn't compute: on-disk × in-history × agent-readable × pushed-to-remote |
| `/ai-data-security:ai-config-audit <path>` | Permission deny/allow rules, MCP configs across Claude/Cursor/Gemini/Codex, plaintext transcripts, retention-tier guidance |
| `/ai-data-security:data-classification <path>` | Every file against the 4-tier sensitivity framework, with validated-content evidence (Luhn, SSN format rules) — counts and column names only, never values |
| `/ai-data-security:db-access-audit --dialect … --connection … --role …` | What your AI principal can actually do in Postgres/Snowflake: write grants, raw base-table reads, unmasked PII columns, missing masked-view layer, missing audit logging. Human-gated; `--recorded <dir>` air-gapped mode |
| `/ai-data-security:security-audit <path>` | All of the above, merged, deduplicated, Top-5 actions first |

Every finding cites a standard — OWASP LLM Top 10 2025, MITRE ATLAS, MCP Security Best
Practices, NIST SP 800-122, NIST AI 600-1 — from a verified-only registry
([reference/citations.yml](reference/citations.yml)).

## Install

```bash
claude plugin marketplace add kyle-chalmers/ai-data-security
claude plugin install ai-data-security@ai-data-security
```

For development: `git clone` this repo, then `claude --plugin-dir ./ai-data-security`.

**Requirements:** [gitleaks](https://github.com/gitleaks/gitleaks) (`brew install gitleaks`) for
the secrets scan — the skill fails closed (UNKNOWN, with instructions) rather than substituting a
weaker scanner. `python3` (stdlib only). Optional: `psql` / [Snowflake CLI](https://docs.snowflake.com/en/developer-guide/snowflake-cli)
for live DB audits; docker only if you run the test suite.

## The 4-tier framework

**Public / Internal / Confidential / Restricted** — based on NIST SP 800-122's PII
confidentiality impact levels, with explicit AI-tool guidance per tier (Restricted data never
enters an AI context; Confidential requires verified commercial-tier retention; …). Full
definitions, detection heuristics, and operating rules:
[reference/four-tier-framework.md](reference/four-tier-framework.md). Two rules do most of the
work: **the floor is Internal** (nothing is auto-classified Public), and **reports never contain
data values** — a AI Data Security report is itself Public-tier shareable.

## How verdicts are made (and why you can trust a report)

Deterministic Python scripts (stdlib-only, bundled) compute every verdict — exposure matrices,
severity, confidence. The model narrates and renders; it cannot change a script's verdict.
Severity is **capped by confidence** (`possible ≤ MEDIUM`, `probable ≤ HIGH`, only `confirmed`
reaches CRITICAL), and anything unverifiable is a first-class **UNKNOWN** — stated next to the
finding count, never silently counted as a pass. Suppressions (`.ai-data-security-ignore`) always
appear in an appendix; nothing disappears.

## What AI Data Security is not (use these too)

*Last reviewed: 2026-07.*

| Tool | Covers | Relation |
|---|---|---|
| Anthropic `security-guidance` plugin | Vulnerabilities in **Claude-generated code** | Complementary — run both |
| `claude-privacy-guard`, prompt redactors | Masking PII **in prompts** before they leave | Complementary; AI Data Security audits what's on disk and in the warehouse |
| `mcp-scan` / Snyk agent-scan | Deep MCP server analysis (tool poisoning, rug pulls) | Recommended for MCP internals; AI Data Security's AC checks cover config hygiene only |
| NB Defense | Jupyter notebook scanning | Recommended for notebook-heavy repos |
| garak / promptfoo | Red-teaming models and LLM apps | Out of scope here |

What none of them do — and AI Data Security does — is audit **the data professional's stack**:
warehouse grants for AI principals, unmasked PII columns, classification, and the exposure
matrix around secrets.

## Roadmap

- **v2 — safe-db-access (IMPLEMENT)**: generate the fix the DB audit points at — dedicated
  read-only AI role → curated schema of masked views → per-row salted hashing (salt out of the
  AI role's reach) → audit logging → a validation script proving analytics still work **and**
  raw access is refused at the database layer.
- **v2 — enforcement hooks**: PreToolUse gates (e.g., block pushes while a rotate-first finding
  is open).
- Presidio deep tier for classification; notebook and MCP deep audits stay delegated to the
  tools above.

## Learn more

AI Data Security productizes the "AI Data Security" series by
[Kyle Chalmers | Data + AI](https://www.youtube.com/@kylechalmersdataai) ([kclabs.ai](https://kclabs.ai)) —
see also the companion content repo [ai-data-security](https://github.com/kyle-chalmers/ai-data-security).
The videos cite the plugin; the plugin never depends on the videos.

## Disclaimer

AI Data Security assists a professional's judgment. It is not a compliance certification, a guarantee
of security, or legal advice. Audit reports may quote paths and names from scanned content —
treat scanned content as untrusted input (see [SECURITY.md](SECURITY.md)).

## License

[MIT](LICENSE) © Kyle Chalmers
