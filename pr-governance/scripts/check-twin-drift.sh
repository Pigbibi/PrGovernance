#!/bin/sh
# Compare the shared governance content across the three twin repositories.
set -eu

REPOS="Pigbibi/PrGovernance GdeiAssistant/.github QuantStrategyLab/.github"
base=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0

for repo in $REPOS; do
  slug=$(printf '%s' "$repo" | tr '/' '_')
  mkdir -p "$tmp/$slug"
  archive="$tmp/$slug.tar.gz"
  if ! curl --fail --silent --show-error --location --retry 2 \
      "https://codeload.github.com/$repo/tar.gz/refs/heads/main" --output "$archive"; then
    echo "cannot download $repo" >&2
    status=1
    continue
  fi
  if ! tar -xzf "$archive" -C "$tmp/$slug" --strip-components=1; then
    echo "cannot extract $repo" >&2
    status=1
    continue
  fi
  for path in pr-governance VERSION; do
    if ! diff -ru -x '__pycache__' "$base/$path" "$tmp/$slug/$path"; then
      echo "drift: $path differs from $repo" >&2
      status=1
    fi
  done
done

exit $status
