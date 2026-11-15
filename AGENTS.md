# AGENTS.md

Rules for AI assistants and maintainers working in `Pigbibi/PrGovernance`.

## What this repository is

`Pigbibi/PrGovernance` is the owner-controlled pull request governance hub for two
tracks:
- `pr-governance/` — reusable GitHub Action, policy schema, and caller templates
  shared across public repositories.
- `local/` — canonical Git hooks, private-repo merge gate (`merge_gate.py`), and
  repository hygiene checker (`check_hygiene.py`) for Pigbibi private
  repositories.

## Critical twin rule

**NEVER modify any file under `pr-governance/` or `VERSION` without syncing the
identical byte-for-byte change to both twin repositories: `GdeiAssistant/.github`
and `QuantStrategyLab/.github`.**

- `pr-governance/` and `VERSION` MUST remain 100% byte-identical across
  `Pigbibi/PrGovernance`, `GdeiAssistant/.github`, and `QuantStrategyLab/.github`.
- `.github/workflows/governance-drift.yml` runs `pr-governance/scripts/check-twin-drift.sh`
  to fail on any drift between the three repositories.
- `local/` is Pigbibi-only. Private-track governance changes belong under `local/`
  (or root `AGENTS.md`/`CLAUDE.md`) and must leave `git diff pr-governance/ VERSION`
  completely empty unless a coordinated three-twin update is explicitly authorized.

## Stack and layout

- `pr-governance/` — Node.js (`gate.cjs`, `runner.cjs`, `main.cjs`, `nudge.cjs`),
  Python (`secret_scan.py`), shell scripts, and tests (`test-*.cjs`, `test_secret_scan.py`).
- `local/` — Python 3 (`governance.py`, `merge_gate.py`, `check_hygiene.py`) and
  unittest suites (`test_governance.py`, `test_check_hygiene.py`,
  `test_merge_gate*.py`), plus hook shims.
- `VERSION` — shared twin revision integer.
- `docs/` — rollout and design notes.
- `.github/workflows/` — `pr-governance-tests.yml` and `governance-drift.yml`.

## Local checks

Run all relevant tests before opening or updating a pull request:

```sh
python3 -m unittest discover -s local -p "test_*.py"
for t in pr-governance/scripts/test-*.cjs; do node "$t"; done
python3 -m unittest discover -s pr-governance/scripts -p "test_*.py"
```

When working on Pigbibi-only private governance changes, verify twin files are
untouched:

```sh
git diff pr-governance/ VERSION
```

## Code Review Rules

1. Flag any diff under `pr-governance/` or `VERSION` that is not part of an
   explicitly coordinated sync across `Pigbibi/PrGovernance`, `GdeiAssistant/.github`,
   and `QuantStrategyLab/.github`.
2. Preserve fail-closed behavior in `local/governance.py` and `local/merge_gate.py`:
   reject symlinks, missing files, stale heads, incomplete diffs, and partial
   review coverage instead of silently passing.
3. Keep `local/merge_gate.py` and `local/check_hygiene.py` free of
   single-repository hardcoded names or real credentials.

## Do not

- Do not edit `pr-governance/` or `VERSION` casually or opportunistically; keep
  them byte-identical to `GdeiAssistant/.github` and `QuantStrategyLab/.github`.
- Do not add or remove `owner-approved`; only the repository owner may set it.
  Coding agents may add `agent-approved` on high-risk PRs only after their own
  verification passes.
- Do not push directly to `main` or `v1`, and do not force-push a reviewed branch.
- Do not weaken tests, secret rules, or assertions to make a check pass.

<!-- content-boundary:begin -->
- Public material carries no real resource names, tokens, or private account ids:
  use synthetic values (`<owner>`, `<repo>`, synthetic token fixtures) and
  read sensitive configuration from repository variables or environment.
- Judge whether a change is clean using `git diff` and `git ls-files`.
<!-- content-boundary:end -->

## Commits and pull requests

- Use English Conventional Commits (`feat`, `fix`, `docs`, `refactor`, `test`,
  `chore`, `perf`, `ci`) with headers at most 72 characters.
- Branch from `origin/main` using `<type>/<topic>`.
- Fill in `AI assistance`, `What changed`, and `How verified` in pull request
  descriptions.
