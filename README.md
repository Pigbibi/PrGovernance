# PrGovernance

Owner-controlled pull request governance shared by the Pigbibi, GdeiAssistant
and QuantStrategyLab repositories. It publishes evidence; branch protection, not
this repository, is the merge constraint.

## Layout

| Path | Purpose |
| --- | --- |
| `pr-governance/` | The reusable action, the policy schema and the caller workflow templates. |
| `pr-governance/templates/` | Callers to copy into `.github/workflows/` with `__GOVERNANCE_REPO__` and `__GOVERNANCE_SHA__` replaced. |
| `local/` | The Git hook track for private repositories: pre-commit, commit-msg, pre-push and a tracked-tree audit. |
| `VERSION` | The shared revision. It changes whenever `pr-governance/` changes. |
| `.github/workflows/` | The drift check across the twin repositories and the action's own tests. |

## Two tracks

Public repositories get the action: `pr-template`, `ai-review`, `risk-gate` and
`Gitleaks` statuses, with the reviewer receipt bound to the current head. Private
repositories are on a plan without protected branches or secret scanning, so the
same intent runs as local Git hooks instead. Nothing in either track identifies
the agent that wrote a pull request.

## Twin repositories

`pr-governance/` is byte-identical in `Pigbibi/PrGovernance`, `GdeiAssistant/.github`
and `QuantStrategyLab/.github`; `VERSION` names the shared revision. Each
repository runs `scripts/check-twin-drift.sh` weekly and on demand, so a change
to any shared file is applied to all three before the check can pass.

`local/` is Pigbibi-only: the other two are public organizations that do not keep
private repositories on this track.

## Consuming it

A public repository copies the templates it needs, replaces `__GOVERNANCE_REPO__`
with the slug of its own governance repository and pins `__GOVERNANCE_SHA__` to a
full commit SHA of the reviewed revision. The policy is read from the default
branch head, so a pull request cannot change the rules that judge it.

A private repository installs the hooks from a trusted checkout:

```sh
git clone https://github.com/Pigbibi/PrGovernance
python3 PrGovernance/local/governance.py install --root <repository> \
  --source PrGovernance/local
```

## Boundaries

The action cannot merge, label or write repository contents. It never checks out
or executes pull request code. Screenshots, prose and labels are not evidence; a
marker comment from the configured reviewer identity is.

See `pr-governance/README.md` for the enforced checks, risk tiers and the trust
model, and `local/README.md` for what each hook refuses.
