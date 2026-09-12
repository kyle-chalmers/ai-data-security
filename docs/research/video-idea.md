# Video idea: what the researchers agree on, and the plugin that checks it

_One page for recording on another machine. Everything referenced here is in this repo
(`docs/research/2026-09-landscape.md`, `docs/research/sources.md`, `ROADMAP.md`). Series slot: the
"20d" position after 20a (video 21, provider retention), 20b (video 22, the PII build), and 20c
(video 39 draft, secrets). Full brief, script, and packaging happen later in `kc-content-workspace`._

## Thesis sentence

Four months after I showed you how to stop an AI agent from reading raw customer data, I read what
the standards bodies, the researchers, and the warehouse vendors published since. They agree on
about ten things you can actually check; in CSA's 2026 survey 74% of organizations said their agents
get more access than they need (S75); and I turned the checks into a plugin so you can see where you
stand.

## Title candidates (query-question shape; video 22's 19% search share is a hypothesis, n=134)

1. What Does Your AI Agent Actually Have Access To? (10 Checks From the Research)
2. What the 2026 AI Agent Security Standards Say Data Teams Should Check
3. Your AI Coding Agent Is a Privileged User. Prove It Isn't.
4. Is Your Snowflake Safe From Claude Code? Run This Audit.
5. The Least-Privilege Number Nobody Quotes Correctly (17% vs 76%)

## Cold open (first 20 seconds, no caveat, no stat recitation)

**Gate: record this only after ROADMAP v0.3 ships `/quick-check`; until then, open on the current
`/ai-data-security:security-audit` and quote its real runtime.** Screen: the audit running on the
combined fixture repo (`tests/fixtures/make-combined-repo.sh`). Three findings appear: a secret an
agent can read, a personal warehouse user with every role active (needs v0.4 DB-ID-01; otherwise
show the current DB-01 write-grant finding), a Restricted-tier CSV in the working tree. Voice:
"This fixture exposes three things the research says to check first. Here's where the list came
from, and how to clear each one."

## Beats (target 10–14 minutes)

| # | Minutes | Beat | On screen | Card or repo link |
|---|---|---|---|---|
| 1 | 0:00–0:50 | Cold open: the 50-second audit | Terminal, three findings | — |
| 2 | 0:50–2:30 | The access-path diagram: your identity → the agent → the warehouse role → the raw customer table. Named-concept-with-authority beat: Willison's lethal trifecta (S7) and OWASP's new **ASI03 Identity & Privilege Abuse** (S46) | One diagram, one OWASP page | Card: "OWASP Agentic Top 10, Dec 2025" |
| 3 | 2:30–5:00 | What the research agrees on: least privilege and scope minimization are now in the MCP spec itself (S48); the incident numbers (Teleport 17% vs 76%, S45; IBM 97% lacked access controls, S72; CSA 74% over-provisioned agents, S75) | Three source cards, each tied to one control | Card per number, with attribution (Teleport, not Zscaler) |
| 4 | 5:00–7:30 | What I got wrong in the last video: hashing is pseudonymization, not anonymization (NIST SP 800-188 §4.3.2, S10); the salt table in the same schema; secondary roles are a per-user setting (S19); and Snowflake now ships **agent identity** and a `SERVICE_AGENT` user type that does the identity-selection principle natively (S77, S78) | Doc excerpts, the `CREATE USER … TYPE = SERVICE_AGENT` line | Card: "What changed since May" |
| 5 | 7:30–11:00 | The plugin runs the checks: `/ai-data-security:security-audit` on the same project; walk **one** finding to its fix. The fix is SQL **you** write and run (the plugin is read-only and does not generate it until the v0.6 planner is approved): a personal user with `DEFAULT_SECONDARY_ROLES = ('ALL')` → a `SERVICE_AGENT` user with `()`. Then the before/after proof: the analytics query still works through the governed view, the raw-table read is refused, and the audit re-run shows the finding cleared | Terminal + one SQL diff, labelled "human-applied" | Card + repo link for install; setup steps never live |
| 6 | 11:00–12:30 | What it still does not solve: prompt injection (Rehberger's CVE-2025-55284, S63), provider retention, masking side channels, aggregate inference. The plugin says UNKNOWN out loud when it cannot verify | One slide | Card: "Read-only by design" |
| 7 | 12:30–13:30 | Close: install command, the roadmap in one line (planner next, never an auto-applier), ask for the dogfood stories | Terminal | Repo link |

## Plugin moments worth showing

- The UNKNOWN list rendered next to the finding count. It is the honesty spine on screen.
- A suppression appearing in the appendix instead of disappearing.
- The `/doctor` capability matrix if v0.3 has shipped by record time; otherwise the current
  install one-liner plus gitleaks requirement.

## Sources to name on screen (decision anchors, not a montage)

- **Least privilege**: MCP spec Security Best Practices, 2026-07-28, "Scope Minimization" (S48);
  OWASP Agentic Top 10 2026 ASI03 (S46).
- **Data minimization**: NIST SP 800-188 §4.3.2 on hashing direct identifiers (S10).
- **Auditability**: OWASP AI Agent Security Cheat Sheet, "Log all agent decisions, tool calls, and
  outcomes" (S12).
- **The numbers**: Teleport 2026 (S45), IBM 2025 press release (S72), CSA March and April 2026
  (S75, S76). Say "survey" when it is a survey.

## The honest close

This audits a boundary. It does not make an agent safe, it does not stop prompt injection, and
hashed data is still personal data. What it does is tell you, with citations, what your agent can
reach today and what to shrink first.

## Funnel note

The May video's description links "companion repo" to `github.com/kyle-chalmers/ai-data-security`,
which is now the **plugin** repo. Viewers who follow that link land on the plugin README, so the
README should carry the mission block and the install one-liner before this video goes live
(`docs/research/quick-wins.md` #1, #10). The demo SQL lives in `ai-data-security-demo`.

## Checklist against the video-22 retrospective and the Codex review

- [x] No caveat or stat recitation right after the hook; the caveat is a lower-third in beat 6
- [x] Named concept with authority inside the first 90 seconds (beat 2)
- [x] Account and role setup is a card and a repo link, never live (beats 4–5)
- [x] No off-screen steps; anything that ran off camera becomes a result card
- [x] Runtime 10–14 minutes with a compression lever (beat 3 can drop to one number)
- [x] Depth over reach is the deliberate bet; do not judge it on views
- [x] Opens on the concrete access-path diagram (Codex)
- [x] Before/after permissions proof, with "audits the boundary, fix stays human-reviewed" said aloud (Codex)
- [x] Every plugin capability shown is scoped to a shipped release; unshipped items are gated (Codex deliverable review #7, #8)
