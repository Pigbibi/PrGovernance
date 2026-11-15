# PrGovernance

Canonical pull request and repository governance shared across `Pigbibi`,
`GdeiAssistant`, and `QuantStrategyLab`. It publishes verifiable check statuses;
branch protection, not this repository, enforces merges.

## Layout

| Path | Purpose |
| --- | --- |
| `pr-governance/` | Canonical GitHub Action, policy schema, and caller templates. |
| `pr-governance/templates/` | Caller workflows consumed via `Pigbibi/PrGovernance/pr-governance@<sha>`. |
| `local/` | Git hooks, private-repo merge gate, and `check_hygiene.py`. |
| `.github/workflows/` | Action and local-governance regression checks. |

## Two tracks

Public repositories consume the canonical GitHub Action to publish `pr-template`,
`ai-review`, `risk-gate`, and `Gitleaks` statuses bound to the current pull
request head SHA.

Private repositories without protected branches run `local/` Git hooks and
`merge_gate.py` locally with identical receipt, commit, and secret rules.

## Consuming the canonical action

Pin downstream caller workflows across `Pigbibi`, `GdeiAssistant`, and
`QuantStrategyLab` to a reviewed commit SHA of `Pigbibi/PrGovernance`:

```yaml
uses: Pigbibi/PrGovernance/pr-governance@<40-char-sha>
```

The action always reads `.github/governance/policy.json` from the repository's
default branch so pull requests cannot weaken their own gate.

A private repository installs hooks from a clean checkout:

```sh
git clone https://github.com/Pigbibi/PrGovernance
python3 PrGovernance/local/governance.py install --root <repository> \
  --source PrGovernance/local
```

## Boundaries

The action never checks out pull request code, pushes commits, modifies labels,
or merges pull requests. Screenshots and prose claims are not evidence; a
signed-off reviewer receipt bound to the current head SHA is required.

See [pr-governance/README.md](pr-governance/README.md) for risk tiers and
[local/README.md](local/README.md) for local hook enforcement.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).
