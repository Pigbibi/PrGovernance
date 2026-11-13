#!/usr/bin/env bash
# Add ai-review to Pigbibi public repos that lack it. Requires gh + admin:org or repo admin.
set -euo pipefail

BASE_CONTEXTS=(
  'Repository hygiene'
  'risk-gate'
  'pr-template'
  'Gitleaks'
  'ai-review'
)

repos=$(gh api 'users/Pigbibi/repos?per_page=100&type=owner' --jq '.[] | select(.private==false and .archived==false) | .name')

for name in $repos; do
  full="Pigbibi/$name"
  default=$(gh api "repos/$full" --jq .default_branch)
  if ! gh api "repos/$full/branches/$default/protection" &>/dev/null; then
    echo "skip (no protection): $full"
    continue
  fi
  mapfile -t existing < <(gh api "repos/$full/branches/$default/protection" \
    --jq '.required_status_checks.contexts[]?')
  declare -A seen=()
  merged=()
  for c in "${existing[@]}" "${BASE_CONTEXTS[@]}"; do
    [[ -z "${c:-}" ]] && continue
    [[ -n "${seen[$c]+x}" ]] && continue
    seen[$c]=1
    merged+=("$c")
  done
  if printf '%s\n' "${existing[@]}" | grep -qx 'ai-review'; then
    echo "ok: $full already has ai-review"
    continue
  fi
  payload=$(jq -nc --argjson contexts "$(printf '%s\n' "${merged[@]}" | jq -R . | jq -s .)" \
    '{required_status_checks:{strict:true,contexts:$contexts},enforce_admins:true,required_pull_request_reviews:{dismiss_stale_reviews:true,required_approving_review_count:0},restrictions:null}')
  gh api -X PUT "repos/$full/branches/$default/protection" --input - <<<"$payload"
  echo "updated: $full (+ai-review)"
done
