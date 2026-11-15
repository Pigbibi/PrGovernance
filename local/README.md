# Local governance for private repositories

The private repositories are on a plan without protected branches or secret
scanning for private code, and hosted Actions are billing-blocked. The checks
that public repositories get from Actions and branch protection run here as Git
hooks instead.

Nothing in this directory identifies an agent. Any agent or person with a clone
gets the same rules.

## What is checked

| Hook | Refuses |
| --- | --- |
| `pre-commit` | staged credentials, tracked `.env`/key/keystore files |
| `commit-msg` | headers that are not conventional, or longer than 72 characters |
| `pre-push` | direct pushes to `main`/`master`, non-fast-forward pushes, moving or deleting an existing tag |

`audit` runs the same secret and sensitive-file scan over the whole tracked tree.
Use it before publishing a repository or after importing history.

Secret rules: PEM private keys (including encrypted PKCS#8), GitHub tokens
(classic and fine-grained), AWS access keys, Slack tokens, and quoted credential
assignments of 16 characters or more. Quoted values may contain spaces and
punctuation, so a word-only passphrase is reported. Placeholder values
(`example`, `sample`, `synthetic`, `dummy`, `changeme`, `change-me`, `redacted`,
`your_token`, `<token>`), environment references (`os.environ`, `getenv`,
`process.env`, `secrets.`, shell `${NAME:-}` and `${NAME-word}`), shell fallbacks
that are themselves placeholders, and `${NAME:?message}` guards are allowed. The
exemption applies to the matched value, not to the whole line, so a hard-coded
fallback beside `getenv` or inside a shell parameter expansion is still
reported. Test fixtures that spell a credential generically are not exempt;
list the test file in `ignore_paths` instead. Documentation that must quote a
full literal lists that exact value in `allow_values`. UTF-16 text is decoded.
A stray NUL byte does not hide a text file; dense binary content is still
skipped.

`audit` reads the committed tree (`HEAD`); `audit --staged` reads the index.
That keeps a staged deletion from hiding a credential that is still committed.

## Install in a repository

Install from a trusted checkout of this repository, not from the branch being
reviewed:

```sh
git clone https://github.com/Pigbibi/PrGovernance
python3 PrGovernance/local/governance.py install --root <repository> \
  --source PrGovernance/local
```

To also install or update the canonical private-repository merge entry and
hygiene checker (`merge_gate.py`, `test_merge_gate.py`, and `check_hygiene.py`)
into `.git/governance/` (outside the repository worktree), pass `--include-merge-gate`:

```sh
python3 PrGovernance/local/governance.py install --root <repository> \
  --source PrGovernance/local --include-merge-gate
```

Keeping the merge gate inside `.git/governance/` ensures that checking out a
contributor branch cannot overwrite `merge_gate.py` before you invoke it.
`--include-merge-gate` refuses before making changes if any canonical source file
is missing or if a destination inside `.git/governance/` is a symlink or
non-regular file.

When a repository tracks vendored copies (`governance/merge_gate.py`,
`governance/tests/test_merge_gate.py`, and `scripts/check_hygiene.py`), update
them explicitly from a clean default-branch checkout with `vendor`:

```sh
python3 PrGovernance/local/governance.py vendor --root <repository> \
  --source PrGovernance/local
```

`vendor` leaves `.git/governance/` untouched and refuses before writing if any
canonical source file is missing or any worktree destination is a symlink or
non-regular file.

A repository that vendors `.githooks/` can instead run
`python3 .githooks/governance.py install` once from the reviewed default branch.

`install` copies the runner, the shims and a snapshot of `governance.json` into
the common git directory (`.git/governance/`, shared by linked worktrees), makes
them executable, and sets `core.hooksPath` to that directory for this clone.
Hooks already configured through `core.hooksPath`, and executable hooks in the
default hooks directory, keep running: `install` adds forwarding shims for every
hook it does not provide itself, such as a global `prepare-commit-msg`. Only
files named after a hook git actually runs are forwarded, so helpers kept beside
a hook (for example `json.py`) are not copied into the hook directory, where they
would shadow the runner's imports. Every
linked worktree contributes its own configured hooks; if two worktrees resolve
the same hook name to different files, `install` stops and asks for a single
hook directory instead of dropping one. Nothing inside a worktree is forwarded,
including symlinks that resolve there, because a contributor branch could
replace those scripts. When `extensions.worktreeConfig` sets a per-worktree
`core.hooksPath`, `install` updates that value too. Checking out a branch cannot
replace an installed hook or its policy. Commit `.githooks/` so every clone has
the source, and re-run `install` from a trusted copy whenever the policy or the
runner changes. Each developer and each agent installs once per clone; CI cannot
do it for them.

## Commands

Use the installed copy, so an untrusted branch cannot substitute its own runner:

```sh
hooks=$(git rev-parse --path-format=absolute --git-common-dir)/governance
python3 "$hooks/governance.py" audit              # committed tree
python3 "$hooks/governance.py" audit --staged     # whole index
python3 "$hooks/governance.py" pre-commit
python3 "$hooks/governance.py" commit-msg FILE
python3 "$hooks/governance.py" pre-push           # reads ref updates on stdin
python3 "$hooks/governance.py" verify             # installed copy matches .githooks
python3 "$hooks/governance.py" verify --source PrGovernance/local --include-merge-gate
python3 "$hooks/merge_gate.py" --pr <number> --dry-run
python3 PrGovernance/local/governance.py vendor --root <repository> \
  --source PrGovernance/local                     # copy merge-gate files into worktree
python3 PrGovernance/local/governance.py check-drift --root <repository> \
  --source PrGovernance/local                     # repository copies match canonical local/
```

Every command exits non-zero and prints `governance: <finding>` on failure.

`verify` compares the installed copy in the common git directory with the
committed `.githooks/` source (or `--source` when given), checks that the hook
scripts are executable, and checks that every worktree still resolves
`core.hooksPath` there. When merge-gate files are installed in
`.git/governance/` (or `--include-merge-gate` is passed), `verify` also checks
that those files are regular non-symlink files and match `--source` (or the
vendored repository copies if present). A source without `governance.json`
compares against the default policy `install` writes, so an optional policy file
never makes a clone unverifiable. Run it after pulling a change to the vendored
hooks, and before trusting a clone that was installed by someone else; a
non-empty result means `install` must run again from a trusted copy.

`check-drift` compares the SHA-256 digest of `.githooks/governance.py`,
`governance/merge_gate.py`, `governance/tests/test_merge_gate.py`, and
`scripts/check_hygiene.py` in `--root` against the canonical files in
`--source` (defaulting to the directory containing `governance.py`). If any
file is missing, symlinked, or differs, it prints the SHA-256 mismatch and a
diff summary to stderr and exits non-zero.

## Configuration

The installed snapshot of `.githooks/governance.json` overrides the defaults:

```json
{
  "protected_branches": ["main"],
  "max_header": 72,
  "commit_types": ["feat", "fix", "docs", "refactor", "test", "chore",
                   "perf", "ci", "build", "revert"],
  "ignore_paths": ["tests/fixtures/"],
  "allow_values": ["Brave Web Search discovery"]
}
```

`ignore_paths` skips a path in both the hook scan and the publication audit. An
entry ending in `/` names a directory; anything else must match the whole path,
so ignoring `governance.json` cannot also hide `governance.json.bak`. The
vendored hook files need no entry because the runner and shims contain no
credentials; ignoring all of `.githooks/` would hide a secret added beside them.
Add a test directory only when the suite intentionally contains synthetic key
material that cannot be spelled as a placeholder. `allow_values` exempts a
scanned value only when the quoted literal matches it in full; it is meant for
documentation that describes a setting, not for passphrases. Editing
`governance.json` on a branch has no effect until someone re-installs from a
trusted copy.

## Limits

- Hooks are local. `git commit --no-verify` and `git push --no-verify` skip
  them, and a clone that never ran `install` has no hooks. The control is
  discipline plus the publication audit, not enforcement.
- The audit scans the current tree, not history. A credential removed from a
  file is still in the objects; rotate it if it ever appears in a finding.
- Review before merge still applies: open a pull request, run `audit` from the
  installed copy on the branch, and merge through `"$hooks/merge_gate.py"`
  only after it passes. By default (`"codex_required": true`), `merge_gate.py`
  strictly requires a Codex receipt (`codex-review-receipt:v1`,
  `codex-review-state:v1`, or `ai-review-receipt:v1` authored by
  `chatgpt-codex-connector[bot]`). Setting `"codex_required": false` with
  `"ai_review_providers": ["codex", "claude", "cursor"]` in
  `governance/policy.json` opts into single-AI-receipt review across the listed
  providers (`chatgpt-codex-connector[bot]`, `claude[bot]`, or `cursor[bot]`)
  with author-matched `ai-review-receipt:v1`, explicit complete coverage on
  receipt markers, and no unresolved findings on the current head.
- If `governance/policy.json` is not on the repository default branch yet,
  `merge_gate.py --pr <number>` refuses instead of falling back to the pull
  request head. Pass an out-of-band trusted `--policy-file <path>` (outside the
  pull request worktree) for first-time bootstrap, or merge after committing the
  policy to the default branch.
- On T2 pull requests, `owner-approved` requires `owner_login`. Optional
  `"agent_logins"` in the base `governance/policy.json` allowlists trusted
  non-owner agent GitHub logins allowed to apply `agent-approved`; when
  omitted, only `owner_login` is accepted (fail closed for arbitrary
  collaborators or triage users). `merge_gate.py` also refuses Git symlink
  (`120000`) tree entries on pull requests.
- `merge_gate.py --audit` accepts `--policy-ref <ref>` or `--policy-file <path>`
  to evaluate against a trusted policy revision instead of the audited branch;
  passing `--strict-direct` without a trusted policy ignores self-exemptions
  (`audit_since`, `audit_ignore_prs`, `audit_acknowledged_direct`) and clamps
  `audit_direct_commits` to at least 40.
