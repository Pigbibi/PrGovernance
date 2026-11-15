# Contributing

Thanks for contributing to `Pigbibi/PrGovernance`.

## Workflow

1. Branch from `origin/main` using a short prefix such as `feat/`, `fix/`,
   `docs/`, `refactor/`, `test/`, or `chore/`.
2. Keep pull requests focused. Changes to `pr-governance/` affect downstream
   repositories across `Pigbibi`, `GdeiAssistant`, and `QuantStrategyLab` on
   their next pin update; preserve fail-closed behavior and keep changes backwards
   compatible unless migration notes are included.
3. Run the local test suites before pushing:

```sh
python3 -m unittest discover -s local -p "test_*.py"
for t in pr-governance/scripts/test-*.cjs; do node "$t"; done
python3 -m unittest discover -s pr-governance/scripts -p "test_*.py"
python3 local/check_hygiene.py --root .
```

## Pull Request Standards

- Use English Conventional Commits (`feat`, `fix`, `docs`, `refactor`, `test`,
  `chore`, `perf`, `ci`) with commit headers at most 72 characters.
- Complete every section in `.github/pull_request_template.md`, listing the
  exact commands run and observed results.
- Never include real credentials, personal paths, or internal notes.
