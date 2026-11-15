# AGENTS.md

Rules for AI assistants and maintainers working in `Pigbibi/PrGovernance`.

## What this repository is

`Pigbibi/PrGovernance` is the single canonical PR and repository governance hub
shared across `Pigbibi`, `GdeiAssistant`, and `QuantStrategyLab`.

## Stack

- Node.js (`pr-governance/scripts/*.cjs` and `test-*.cjs`)
- Python 3 (`local/governance.py`, `local/merge_gate.py`, `local/check_hygiene.py`, `pr-governance/scripts/secret_scan.py`)
- GitHub Actions composite action and workflow templates

## Layout

- `pr-governance/` — canonical GitHub Action, policy schema, Gitleaks config, and caller templates
- `local/` — local Git hooks, private-repo `merge_gate.py`, `check_hygiene.py`, and test suites (`test_governance.py`, `test_check_hygiene.py`, `test_merge_gate*.py`)
- `.github/workflows/` — action and repository hygiene CI checks

## Local checks

Run before opening or updating any pull request:

```sh
python3 -m unittest discover -s local -p "test_*.py"
for t in pr-governance/scripts/test-*.cjs; do node "$t"; done
python3 -m unittest discover -s pr-governance/scripts -p "test_*.py"
python3 local/check_hygiene.py --root .
```

## Do not

- Do not add or remove `owner-approved`. Agents may apply `agent-approved` on R2
  PRs only after local checks, CI checks, and `ai-review` pass on the exact head SHA.
- Do not push directly to `main`, pass `--admin` to merge, or force-push a reviewed branch.
- Do not weaken fail-closed checks in `gate.cjs`, `merge_gate.py`, `check_hygiene.py`, or tests.
- Do not commit `docs/plans/`, `docs/audits/`, `docs/changes/`, or `docs/acceptance-policy.md`.
- Update `README.md` only for user-visible workflow, configuration, CLI, or public API
  changes; record internal invariants in tests and the PR description, never as
  `remains unchanged` prose or sections after `## License`.

<!-- content-boundary:begin -->
- Public material carries no real resource names, tokens, or private account ids:
  use synthetic values (`<owner>`, `<repo>`, synthetic token fixtures) and read
  sensitive configuration from repository variables or environment.
- Judge whether a change is clean using `git diff` and `git ls-files`; `.gitignore`
  only affects untracked files.
<!-- content-boundary:end -->

## Commits and pull requests

- Use English Conventional Commits (`feat`, `fix`, `docs`, `refactor`, `test`,
  `chore`, `perf`, `ci`) with commit headers ≤ 72 characters.
- Branch from `origin/main` using `<type>/<topic>`.
- Fill in `AI assistance`, `What changed`, `How verified`, `Why`, and `Risk`.
