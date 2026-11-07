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
| `pre-push` | direct pushes to `main`/`master`, non-fast-forward pushes |

`audit` runs the same secret and sensitive-file scan over the whole tracked tree.
Use it before publishing a repository or after importing history.

Secret rules: PEM private keys (including encrypted PKCS#8), GitHub tokens
(classic and fine-grained), AWS access keys, Slack tokens, and quoted credential
assignments of 16 characters or more. Placeholder and fixture values (`example`,
`sample`, `synthetic`, `dummy`, `test`, `fake`, `mock`, `fixture`, `changeme`,
`change-me`, `redacted`, `your_token`, `<token>`), environment references
(`os.environ`, `getenv`, `process.env`, `secrets.`, shell `${NAME:-}`), and
all-caps names such as `CONTACT_PHONE_LIST_JSON` are allowed. The exemption
applies to the matched value, not to the whole line, so a hard-coded fallback
beside `getenv` or inside `${NAME:-...}` is still reported. UTF-16 text is
decoded, not treated as binary.

`audit` reads the committed tree (`HEAD`); `audit --staged` reads the index.
That keeps a staged deletion from hiding a credential that is still committed.

## Install in a repository

Install from a trusted checkout of this repository, not from the branch being
reviewed:

```sh
git clone https://github.com/Pigbibi/governance
python3 governance/local/governance.py install --root <repository> \
  --source governance/local
```

A repository that vendors `.githooks/` can instead run
`python3 .githooks/governance.py install` once from the reviewed default branch.

`install` copies the runner, the shims and a snapshot of `governance.json` into
the common git directory (`.git/governance/`, shared by linked worktrees), makes
them executable, and sets `core.hooksPath` to that directory for this clone.
Hooks already configured through `core.hooksPath` keep running: `install` adds
forwarding shims for every hook it does not provide itself, such as a global
`prepare-commit-msg`. Checking out a branch cannot replace an installed hook or
its policy. Commit `.githooks/` so every clone has the source, and re-run
`install` from a trusted copy whenever the policy or the runner changes. Each
developer and each agent installs once per clone; CI cannot do it for them.

## Commands

Use the installed copy, so an untrusted branch cannot substitute its own runner:

```sh
hooks=$(git rev-parse --path-format=absolute --git-common-dir)/governance
python3 "$hooks/governance.py" audit              # committed tree
python3 "$hooks/governance.py" audit --staged     # whole index
python3 "$hooks/governance.py" pre-commit
python3 "$hooks/governance.py" commit-msg FILE
python3 "$hooks/governance.py" pre-push           # reads ref updates on stdin
```

Every command exits non-zero and prints `governance: <finding>` on failure.

## Configuration

The installed snapshot of `.githooks/governance.json` overrides the defaults:

```json
{
  "protected_branches": ["main"],
  "max_header": 72,
  "commit_types": ["feat", "fix", "docs", "refactor", "test", "chore",
                   "perf", "ci", "build", "revert"],
  "ignore_paths": ["tests/fixtures/"]
}
```

`ignore_paths` skips a path in both the hook scan and the publication audit. An
entry ending in `/` names a directory; anything else must match the whole path,
so ignoring `governance.json` cannot also hide `governance.json.bak`. The
vendored hook files need no entry because the runner and shims contain no
credentials; ignoring all of `.githooks/` would hide a secret added beside them.
Add a test directory only when the suite intentionally contains synthetic key
material that cannot be spelled as a placeholder. Editing `governance.json` on a
branch has no effect until someone re-installs from a trusted copy.

## Limits

- Hooks are local. `git commit --no-verify` and `git push --no-verify` skip
  them, and a clone that never ran `install` has no hooks. The control is
  discipline plus the publication audit, not enforcement.
- The audit scans the current tree, not history. A credential removed from a
  file is still in the objects; rotate it if it ever appears in a finding.
- Review before merge still applies: open a pull request, run `audit` from the
  installed copy on the branch, and merge only after it passes. The reviewer
  identity rules of the public track apply unchanged; only the enforcement point
  is local.
