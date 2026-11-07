# Organization PR governance

One action and four caller workflows shared by every public repository in the
organization. The reviewer is Codex; the coding agent may be anything. No
workflow identifies or depends on the agent that wrote a pull request.

## What is enforced

A pull request may merge when all of these hold:

- `pr-template` — the body fills the AI assistance, what changed and how
  verified sections.
- `ai-review` — the newest Codex receipt names the current head, reports a
  completed review, has no unresolved finding, and the head contains the
  current base head.
- `risk-gate` — the resolved risk tier allows the path. Low risk passes on the
  reviewer receipt. High risk also needs one clearing label that was recorded
  on this exact head.
- `Gitleaks` — no credential in the commits the pull request adds.
- Repository-specific checks (`test`, `Documentation check`, `Repository
  hygiene`, `Commit message convention`, …) stay in each repository.

Branch protection, not this action, is the merge constraint. The action only
publishes evidence; it cannot merge, label, or write repository contents.

The gate applies to repositories that build, deploy or run code. A repository
that only publishes a static site through a `pages` workflow keeps that
deployment workflow and is exempt from the gate.

## Risk tiers

| Tier | Typical paths | Requirement |
| --- | --- | --- |
| R0 | prose, docs | template and reviewer receipt |
| R1 | ordinary source | template and reviewer receipt |
| R2 | auth, secrets, deploy, runtime, strategy, config, manifests | one clearing label bound to the head |

The tiers come from the engine's path rules plus the repository's `r2_paths`.
`r0_paths` can only lower a path that has no sensitive token.

Clearing labels: `owner-approved` (owner only) and `agent-approved` (any actor
with write permission). A label added by a coding agent is evidence that the
agent judged the change, not a substitute for the reviewer receipt. Only the
owner may add or remove `owner-approved`; agents must never touch it.

## Files

Everything below lives under `pr-governance/` so it can share a repository with
organization community-health files.

| Path | Purpose |
| --- | --- |
| `action.yml` | `mode: gate`, `nudge` or `scan` |
| `scripts/gate.cjs` | classification, evidence and verdict |
| `scripts/runner.cjs` | collection, status publication, label recording |
| `scripts/main.cjs` | trusted policy loading and mode dispatch |
| `scripts/nudge.cjs` | one review request per head |
| `scripts/secret_scan.py` | range, history baseline and artifact scans |
| `scripts/install-gitleaks.sh` | checksum-verified Gitleaks 8.30.1 |
| `.gitleaks.toml` | organization rules and narrow synthetic allowlists |
| `policy.schema.json` | `pr-governance/v3` schema |
| `policy.default.json` | starting policy |
| `templates/` | caller workflows to copy into a repository |

## Wiring a repository

1. Copy `.github/governance/policy.json` from `policy.default.json` and set
   `reviewer` and repository-specific `r2_paths`. Leave `owner` out: account
   identities belong in protected configuration, so the action reads
   `RISK_GATE_OWNER_ID` and `RISK_GATE_OWNER` from repository or organization
   variables and replaces `owner` when they are set. A repository whose content
   rules keep accounts out of public source may also leave `reviewer` out and
   set `RISK_GATE_REVIEWER_APP_ID`, `RISK_GATE_REVIEWER_USER_ID` and
   `RISK_GATE_REVIEWER_LOGIN` instead; a partial set fails closed.
2. Copy `templates/risk-gate.yml`, `templates/codex-nudge.yml`,
   `templates/gitleaks.yml` and `templates/weekly-secret-scan.yml` into
   `.github/workflows/`, replacing `__GOVERNANCE_REPO__` with the
   `owner/repository` of this governance repository and `__GOVERNANCE_SHA__`
   with the full commit SHA at the head of `v1`. Copy
   `templates/pr-review-signal.yml` unchanged as well: review events on fork
   and Dependabot pull requests get a read-only token, so the gate is started
   by that workflow's completion instead.
3. Add the required contexts to branch protection on the default branch:
   `pr-template`, `ai-review`, `risk-gate`, `Gitleaks`, and the repository's
   own checks. Keep `strict` (require branches to be up to date) and
   `enforce_admins` on.
4. Add the `SECRET_SCAN_BASELINE_B64` secret before enabling the weekly scan.
   The scan refuses to run without it.

The owner identity comes from the `RISK_GATE_OWNER_ID` and `RISK_GATE_OWNER`
variables. A policy that still carries `owner` keeps working until the
variables are set, but no account identity is required in the file. The
reviewer follows the same rule through the `RISK_GATE_REVIEWER_*` variables.

## Trust model

- Workflows never check out or execute pull request code.
- The action is pinned to a full commit SHA of this repository, not by the
  repository under judgement. Update the pins after `v1` moves.
- The policy is read from the default branch head, so a pull request cannot
  change the rules that judge it.
- Reviewer evidence is a marker comment written by the configured reviewer
  identity. Screenshots, prose and labels are not evidence.
- A label only counts for the head the `labeled` event named. Revoking and
  re-adding it does not replay an older record.
- Status writes stop before GitHub's 1000-per-context limit; the last slot is
  reserved for a blocking state, so a head that runs out of slots stays blocked
  instead of silently passing.

## Modes

`policy.json` `mode` controls the outcome:

- `enforce` (default) — publish statuses and fail the run when any pull request
  fails.
- `report-only` — publish advisory statuses, warn instead of failing. Use for
  the first week of a migration.
- `local` — publish nothing. Used by the private-repository track, where branch
  protection is unavailable.

## Changing the shared action

Open a pull request against `v1`. The `test` check must pass. Merging changes
the behavior of every consumer at its next run, so the digest of the policy is
part of every receipt: a policy change invalidates older receipts and asks for
a fresh review instead of silently reusing one.

## Private repositories

GitHub Free does not provide branch protection or secret scanning for private
repositories, and hosted Actions may be billing-blocked. Private repositories
use a local enforcement track instead: Git hooks that reject staged credentials,
unconventional commit headers, direct pushes to a protected branch, and
non-fast-forward pushes, plus an audit over the tracked tree.


## Twin repositories

`pr-governance/` is byte-identical in `Pigbibi/governance`, `GdeiAssistant/.github`
and `QuantStrategyLab/.github`; `VERSION` names the shared revision. Each
repository runs `scripts/check-twin-drift.sh` weekly and on demand. A change to
any shared file is applied to all three before the drift check can pass.
