#!/usr/bin/env bash
# Add ai-review to required status checks on public repos for one account.
# Does not rewrite pull-request reviews or push restrictions.
# Usage: ALIGN_OWNER=Pigbibi ./align-branch-protection.sh
#    or: ./align-branch-protection.sh Pigbibi
set -euo pipefail

OWNER="${ALIGN_OWNER:-${1:-}}"
if [[ -z "$OWNER" ]]; then
  echo "Set ALIGN_OWNER or pass the account login as argv[1]" >&2
  exit 1
fi
HUB_REPOS="${ALIGN_SKIP_REPOS:-PrGovernance}"

BASE_CONTEXTS='Repository hygiene
risk-gate
pr-template
Gitleaks
ai-review'

repos=$(gh api "users/${OWNER}/repos?per_page=100&type=owner" \
  --jq '.[] | select(.private==false and .archived==false) | .name')

skip_hub() {
  case " ${HUB_REPOS} " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

for name in $repos; do
  if skip_hub "$name"; then
    echo "skip (hub): ${OWNER}/$name"
    continue
  fi
  full="${OWNER}/$name"
  default=$(gh api "repos/$full" --jq .default_branch)
  if ! gh api "repos/$full/branches/$default/protection" &>/dev/null; then
    echo "skip (no protection): $full"
    continue
  fi
  existing=$(gh api "repos/$full/branches/$default/protection/required_status_checks" \
    --jq '.contexts[]?' || true)
  if printf '%s\n' "$existing" | grep -qx 'ai-review'; then
    echo "ok: $full already has ai-review"
    continue
  fi
  merged=$(printf '%s\n%s\n' "$existing" "$BASE_CONTEXTS" | awk 'NF && !seen[$0]++')
  contexts_json=$(printf '%s\n' "$merged" | jq -R . | jq -s .)
  strict=$(gh api "repos/$full/branches/$default/protection/required_status_checks" \
    --jq 'if .strict == null then true else .strict end')
  payload=$(jq -nc --argjson contexts "$contexts_json" --argjson strict "$strict" \
    '{strict:$strict, contexts:$contexts}')
  # Status-checks endpoint only: leave required reviews and restrictions untouched.
  gh api -X PATCH "repos/$full/branches/$default/protection/required_status_checks" --input - <<<"$payload"
  echo "updated: $full (+ai-review)"
done
