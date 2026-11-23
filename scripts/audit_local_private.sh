#!/usr/bin/env bash
set -euo pipefail

PRIVATE_DIR="${1:-${PRIVATE_REPOS_DIR:-$HOME/code/private-repos}}"
CANONICAL_SHA="${CANONICAL_SHA:-$(git -C "$(dirname "$0")/.." rev-parse HEAD)}"

python3 "$(dirname "$0")/org_audit.py" \
  --owners \
  --canonical-sha "$CANONICAL_SHA" \
  --private-dir "$PRIVATE_DIR" \
  --run-tools
