# Organization PR governance

One action and four caller workflows shared by every public repository in the
organization. AI review asks for Codex, Claude, or both, according to
`CODEX_REVIEW_ENABLED` and `CLAUDE_REVIEW_ENABLED`.

An empty value leaves Codex on and Claude off. When both are false, or an
enabled reviewer reports a quota limit on this head and no other subscription
reviewer is on, the workflow posts `GOVERNANCE_API_REVIEW_MENTION` so the
DeepSeek reviewer starts. Cursor and Bugbot are not requested. No workflow
identifies or depends on the agent that wrote a pull request.

## What is enforced

A pull request may merge when all of these hold:

- `pr-template` — the body fills the AI assistance, what changed and how
  verified sections.
- `ai-review` — the newest receipt from a configured reviewer bot names the
  current head, reports a completed review, has no unresolved finding, and the
  head contains the current base head. Supported markers:
  `ai-review-receipt:v1`, `codex-review-receipt:v1`, `codex-review-state:v1`.
- `risk-gate` — the resolved risk tier allows the path. Low risk passes on the
  reviewer receipt. Under `pr-governance/v4`, R2 requires the configured number
  of independent reviewer providers plus a clearing label, while R3 requires
  independent reviewers and `owner-approved` recorded on this exact head.
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
| R2 | workflows, deploy, runtime, strategy and protected config | configured independent reviews and one clearing label bound to the head |
| R3 | IAM, credentials, production state, live trading and destructive migration | configured independent reviews and owner-approved bound to the head |

The tiers come from the engine's path rules plus the repository's `r2_paths`.
A v4 policy also supplies `r3_paths` and monotonic reviewer counts for R0–R3.
When `distinct_providers` is true, multiple receipts from one provider never
satisfy the threshold. `r0_paths` can only lower a path that has no sensitive
token.

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
| `policy.schema.json` | backward-compatible `pr-governance/v3` schema |
| `policy.default.json` | v3 starting policy |
| `policy.v4.schema.json` | independent-review and owner-only R3 schema |
| `policy.v4.default.json` | report-only v4 pilot policy |
| `templates/` | caller workflows to copy into a repository |

## Wiring a repository

1. For existing repositories, copy `.github/governance/policy.json` from
   `policy.default.json`. For a v4 pilot, start from `policy.v4.default.json`,
   keep `mode: report-only`, configure two distinct reviewer identities, and set
   repository-specific `r3_paths`. After observed evidence is complete, switch
   that repository to `enforce`. Set
   `reviewer` and repository-specific `r2_paths`. Leave `owner` out: account
   identities belong in protected configuration, so the action reads
   `RISK_GATE_OWNER_ID` and `RISK_GATE_OWNER` from repository or organization
   variables and replaces `owner` when they are set. A repository whose content
   rules keep accounts out of public source may also leave `reviewer` out and
   set `RISK_GATE_REVIEWER_APP_ID`, `RISK_GATE_REVIEWER_USER_ID` and
   `RISK_GATE_REVIEWER_LOGIN` instead; or set organization variable
   `GOVERNANCE_REVIEWERS_JSON` to the full ordered chain (see
   `reviewers.example.json`). A partial set fails closed.
2. Copy `templates/risk-gate.yml`, `templates/codex-nudge.yml`,
   `templates/gitleaks.yml` and `templates/weekly-secret-scan.yml` into
   `.github/workflows/`, replacing `__GOVERNANCE_REPO__` with
   `Pigbibi/PrGovernance` and `__GOVERNANCE_SHA__` with the full 40-character
   commit SHA from `Pigbibi/PrGovernance` `main`. Keep `codex-nudge.yml`'s
   `pull-requests: write` and `issues: write`: posting the review request
   comment on a pull request needs both. Copy `templates/pr-review-signal.yml`
   unchanged as well: review events on fork and Dependabot pull requests get a
   read-only token, so the gate is started by that workflow's completion instead.
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
- The action is pinned to a full commit SHA of `Pigbibi/PrGovernance`, not
  selected by the pull request under review. Update downstream SHA pins after
  changes merge to `main`.
- The policy is read from the default branch head, so a pull request cannot
  change the rules that judge it.
- Reviewer evidence is a marker comment written by the configured reviewer
  identity. Screenshots, prose and labels are not evidence.
- A label only counts for the head the `labeled` event named. Revoking and
  re-adding it does not replay an older record.
- Status writes stop before GitHub's 1000-per-context limit; the last slot is
  reserved for a blocking state, so a head that runs out of slots stays blocked
  instead of silently passing.

## Incomplete diff evidence

GitHub's files endpoint can omit or truncate patches for large text files. The
collector recovers those patches from the diff media type of an immutable
`base...head` comparison. It matches each file header and verifies the exact
addition and deletion counts before evaluating, then repeats collection for
the normal evidence readback. No pull request code is checked out or executed.

Deleting a regular non-executable binary file requires a matching deletion in
the immutable comparison and a matching binary blob at the base commit. The
path must be absent at the head commit. Other binary changes, unreadable
responses, unrecognised quoted paths, inconsistent counts and diffs over 16 MiB
block evaluation.

Evaluation errors publish a fixed reason code in all three required statuses,
a warning and the job summary. Arbitrary exception text and API response bodies
are never included. A rerun cannot repair missing evidence or change a pinned
action: the consumer must first adopt the reviewed fixed action revision.

## Modes

`policy.json` `mode` controls the outcome:

- `enforce` (default) — publish statuses for every open pull request, fail
  pull-request evaluations and evaluation errors, and keep `schedule` /
  base-`push` sweeps green when all evaluations complete cleanly.
- `report-only` — publish advisory statuses, warn instead of failing. Use for
  the first week of a migration.
- `local` — publish nothing. Used by the private-repository track, where branch
  protection is unavailable.

## Changing the shared action

Open a pull request against `main` in `Pigbibi/PrGovernance`. All CI tests must
pass before merging. Merging updates the canonical action; downstream
repositories adopt changes explicitly by bumping their pinned SHA.

## Private repositories

GitHub Free does not provide branch protection or secret scanning for private
repositories, and hosted Actions may be billing-blocked. Private repositories
use the local enforcement track instead: Git hooks that reject staged
credentials, unconventional commit headers, direct pushes to a protected branch,
and non-fast-forward pushes, plus an audit over the tracked tree.
