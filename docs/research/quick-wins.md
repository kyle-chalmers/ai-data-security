# Quick wins found during the 2026-09-11 research pass (not applied)

Hygiene and credibility fixes surfaced while reading the repo, its GitHub metadata, and the
knowledge base. None of these change plugin behavior. Each is small enough for one commit and is
listed here so the implementation session can pick them up without re-deriving them. Nothing on
this list has been applied in this pass.

| # | Fix | Where | Why it matters | Size |
|---|---|---|---|---|
| 1 | Companion-repo link points at the plugin repo itself | `README.md` "Learn more" (`README.md:96`): `[ai-data-security](https://github.com/kyle-chalmers/ai-data-security)` should be `[ai-data-security-demo](https://github.com/kyle-chalmers/ai-data-security-demo)` | The demo repo holds the SQL the thesis video promises; the plugin README currently links to itself | S |
| 2 | GitHub repo description still says "Private during v1 development" | GitHub → Settings → description (API: `gh repo edit --description`) | The repo has been public since 2026-07-09; the first thing a visitor reads contradicts the README | S |
| 3 | v0.2.0 was merged 2026-07-15 but never tagged or released | `git tag v0.2.0 <merge sha> && git push origin v0.2.0`, then a GitHub release with the CHANGELOG 0.2.0 section | Latest release shows v0.1.2; the marketplace and CHANGELOG disagree with GitHub Releases. Consider tagging v0.3.0 after the roadmap's first slice instead of back-tagging | S |
| 4 | No GitHub topics | `gh repo edit --add-topic claude-code,claude-code-plugin,ai-security,data-security,pii,snowflake,postgres,mcp,secrets-detection` | Topics are the main discovery surface for plugins on GitHub; the repo has zero | S |
| 5 | README "What AI Data Security is not" table (dated 2026-07) has no entry for Anthropic's official **Claude Security** plugin (beta 2026-07-22) | `README.md` comparison table | A reader who knows the official plugin exists will assume this one is unaware of it. The research report's positioning table (by category) supersedes this table | S |
| 6 | Citation registry lacks the two 2026 OWASP publications | `reference/citations.yml` (+ `reference/checks.yml` mappings; CI enforces registry consistency) | OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10, published 2025-12-09) and OWASP GenAI LLM Top 10 2026 exist; the plugin cites LLM Top 10 **2025** only. Verify exact IDs against the primary pages before adding (see `docs/research/sources.md`) | M |
| 7 | `dev/validate.sh` hardening (from the 2026-09-08 review recorded in the knowledge base) | `dev/validate.sh`, `.github/workflows/ci.yml` | (a) CI guard `[ -n "${CI:-}" ]` is spoofable; (b) cleanup is not signal-safe (`trap`); (c) the negative control corrupts only the lexically-first skill; (d) CI installs `@anthropic-ai/claude-code` unpinned — a supply-chain gap in a security-focused repo | M |
| 8 | `.ai-data-security.yml` org profile pending in `data-intelligence-tickets` and the 497 Restricted-floor / 879 PII-finding dogfood triage | Work repo, not this one (`knowledge/work-ideas.md`) | The dogfood result is the strongest real-world evidence the plugin works; triaging it produces the "one real finding walked to its fix" the video needs | M |
| 9 | Skill-trigger evals | none yet (`CHANGELOG.md` 0.2.0 "Deferred") | No test proves Claude picks `secrets-scanner` over `security-audit` from their descriptions; the `skill-creator` eval harness exists for this | M |
| 10 | Plugin README has no Mission/Vision block | `README.md` top | Sibling `ticketwright/README.md` sets the pattern (Mission, Vision, ✅/❌ fit list). Proposed patch in `docs/research/mission-vision-options.md` | S |

## Not quick wins (tracked in `ROADMAP.md` instead)

`/doctor` and `/quick-check` skills, SARIF export, new DB checks, platform packs, the safe-db-access
planner/IMPLEMENT recipe, enforcement hooks, and `claude-plugins-community` submission all change
behavior or scope and are sequenced in the roadmap.
