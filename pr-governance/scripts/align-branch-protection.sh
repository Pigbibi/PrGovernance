#!/usr/bin/env bash
# Add ai-review to Pigbibi public repos that lack it. Requires gh + repo admin.
set -euo pipefail

BASE_CONTEXTS='Repository hygiene
risk-gate
pr-template
Gitleaks
ai-review'

repos=$(gh api 'users/Pigbibi/repos?per_page=100&type=owner' --jq '.[] | select(.private==false and .archived==false) | .name')

for name in $repos; do
  # Hub repos only publish governance unit tests, not consumer risk-gate statuses.
  if [ "$name" = "PrGovernance" ]; then
    echo "skip (hub): Pigbibi/$name"
    continue
  fi
  full="Pigbibi/$name"
  default=$(gh api "repos/$full" --jq .default_branch)
  if ! gh api "repos/$full/branches/$default/protection" &>/dev/null; then
    echo "skip (no protection): $full"
    continue
  fi
  existing=$(gh api "repos/$full/branches/$default/protection" \
    --jq '.required_status_checks.contexts[]?' || true)
  if printf '%s\n' "$existing" | grep -qx 'ai-review'; then
    echo "ok: $full already has ai-review"
    continue
  fi
  merged=$(printf '%s\n%s\n' "$existing" "$BASE_CONTEXTS" | awk 'NF && !seen[$0]++')
  contexts_json=$(printf '%s\n' "$merged" | jq -R . | jq -s .)
  payload=$(jq -nc --argjson contexts "$contexts_json" \
    '{required_status_checks:{strict:true,contexts:$contexts},enforce_admins:true,required_pull_request_reviews:null,restrictions:null}')
  # Preserve existing PR review / restrictions if present
  current=$(gh api "repos/$full/branches/$default/protection")
  payload=$(jq -nc --argjson contexts "$contexts_json" --argjson cur "$current" '
    {
      required_status_checks: {
        strict: (($cur.required_status_checks.strict) // true),
        contexts: $contexts
      },
      enforce_admins: (($cur.enforce_admins.enabled) // true),
      required_pull_request_reviews: (
        if $cur.required_pull_request_reviews == null then null
        else {
          dismiss_stale_reviews: ($cur.required_pull_request_reviews.dismiss_stale_reviews // false),
          require_code_owner_reviews: ($cur.required_pull_request_reviews.require_code_owner_reviews // false),
          required_approving_review_count: ($cur.required_pull_request_reviews.required_approving_review_count // 0)
        }
        end
      ),
      restrictions: null
    }')
  gh api -X PUT "repos/$full/branches/$default/protection" --input - <<<"$payload"
  echo "updated: $full (+ai-review)"
done
