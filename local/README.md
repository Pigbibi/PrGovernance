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

Secret rules: PEM private keys, GitHub tokens, AWS access keys, Slack tokens,
and quoted credential assignments. Placeholder values (`example`, `sample`,
`synthetic`, `dummy`, `changeme`, `redacted`, `your_token`, `<token>`) and
environment references (`os.environ`, `getenv`, `process.env`, `secrets.`) are
allowed. The exemption applies to the matched value, not to the whole line, so a
hard-coded fallback beside `getenv` is still reported.

`audit` reads the committed tree (`HEAD`); `audit --staged` reads the index.
That keeps a staged deletion from hiding a credential that is still committed.

## Install in a repository

```sh
mkdir -p .githooks
cp <governance-repo>/local/governance.py .githooks/
cp <governance-repo>/local/pre-commit <governance-repo>/local/commit-msg \
   <governance-repo>/local/pre-push .githooks/
cp <governance-repo>/local/governance.example.json .githooks/governance.json
python3 .githooks/governance.py install
```

`install` makes the shims executable and sets `core.hooksPath=.githooks` for this
clone. Commit `.githooks/` so every clone can install the same rules. Each
developer and each agent runs `install` once per clone; CI cannot do it for them.

## Commands

```sh
python3 .githooks/governance.py audit              # tracked tree
python3 .githooks/governance.py audit --staged     # index only
python3 .githooks/governance.py pre-commit
python3 .githooks/governance.py commit-msg FILE
python3 .githooks/governance.py pre-push           # reads ref updates on stdin
python3 .githooks/governance.py install
```

Every command exits non-zero and prints `governance: <finding>` on failure.

## Configuration

`.githooks/governance.json` overrides the defaults:

```json
{
  "protected_branches": ["main"],
  "max_header": 72,
  "commit_types": ["feat", "fix", "docs", "refactor", "test", "chore",
                   "perf", "ci", "build", "revert"],
  "ignore_paths": [".githooks/", "tests/"]
}
```

`ignore_paths` skips a path in both the hook scan and the publication audit.
Add `tests/` only when the suite intentionally contains synthetic key material
that cannot be spelled as a placeholder.

## Limits

- Hooks are local. `git commit --no-verify` and `git push --no-verify` skip
  them, and a clone that never ran `install` has no hooks. The control is
  discipline plus the publication audit, not enforcement.
- The audit scans the current tree, not history. A credential removed from a
  file is still in the objects; rotate it if it ever appears in a finding.
- Review before merge still applies: open a pull request, run `audit` on the
  branch, and merge only after it passes. The reviewer identity rules of the
  public track apply unchanged; only the enforcement point is local.
