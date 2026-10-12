# Contributing to AI Data Security

## Ground rules (non-negotiable for a security repo)

1. **Never commit a secret-shaped string** — not even an obviously fake one. Fixture material
   that must look like a secret is *generated at test time* (`tests/fixtures/make-*.sh`) into
   the gitignored `tests/fixtures/generated/`. Committed fixtures may only contain
   vendor-documented examples, famous fakes (078-05-1120), or inert placeholders. CI gitleaks
   self-scans tree + full history on every push; a hit fails the build and, once pushed, lives
   in history forever.
2. **Citations are verified-only.** [reference/citations.yml](reference/citations.yml) is the
   single source of citation IDs; add an entry only after checking the live source, and never
   cite from memory. Every check in [reference/checks.yml](reference/checks.yml) must map to
   existing citation keys and at least one fixture id — CI enforces this.
3. **The model narrates; scripts decide.** Anything that determines severity, confidence, or
   exposure belongs in a deterministic stdlib-Python script with fixture assertions — not in
   SKILL.md prose.
4. **Read-only.** SQL packs must contain zero mutating statements (CI-linted). Skills never
   store credentials or print data values.

## Dev loop

```bash
claude --plugin-dir .        # load the plugin locally
./dev/validate.sh            # the deterministic baseline — must pass before every commit
./tests/postgres-fixture-check.sh   # docker-based DB pack check (self-skips without docker)
```

Python is stdlib-only by design (no requirements.txt to rot). Shell scripts must pass
shellcheck. JSON-in-`.yml` files under `reference/` are deliberate — jq validates them with
zero dependencies.

## Build discipline

`dev/feature_list.json` is the immutable feature list: sessions flip only `passes` (after
demonstrating the check, never asserting it) and append evidence to `dev/progress.txt`.
New work = new thin vertical slice with a runnable check, one atomic commit per feature.

## Releases

The version lives in one place: the semver `version` field in `.claude-plugin/plugin.json`
(required since 0.1.0). The marketplace entry must not set one, because plugin.json would
silently win; `dev/validate.sh` fails the build if it does. Tagging a release or submitting to
any marketplace needs the maintainer's explicit approval. Each release:

1. Bump `version` in plugin.json and add the matching `CHANGELOG.md` entry.
2. Run `dev/validate.sh`. It validates both manifests by name. Do not switch it to
   `claude plugin validate . --strict`: a root target resolves to `marketplace.json` in
   preference to `plugin.json` and never reads skills, so that form passes even with a garbage
   `SKILL.md`. There is no flag to force plugin mode.
3. Run the gitleaks tree and full-history self-scan, and a clean-machine install test for any
   release that changes install steps or `doctor`.
4. Update the README skills table, `docs/getting-started.md`, and `docs/glossary.md` (regenerate
   with `python3 dev/gen_glossary.py`) when a skill, check, or pack is added.
