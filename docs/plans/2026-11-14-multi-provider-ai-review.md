# Multi-provider AI review rollout

**Goal:** Keep `ai-review` / `risk-gate` semantics; accept Codex → Claude → Cursor receipts; nudge in dispatch order.

**Source of truth:** `GdeiAssistant-dotgithub/pr-governance` → publish to `Pigbibi/PrGovernance` → org templates pin SHA.

**Rollout order**

1. Merge pr-governance changes; tag or record SHA for `__GOVERNANCE_SHA__`.
2. Set org variable `GOVERNANCE_REVIEWERS_JSON` (see `reviewers.example.json`).
3. Sync `risk-gate.yml` / `codex-nudge.yml` pins on QSL + Gdei + Pigbibi public repos.
4. Add `ai-review` to Pigbibi public branch protection (script `scripts/align-branch-protection.sh`).
5. Private repos: sync `governance/merge_gate.py` + `policy.json` reviewer chain.

**Provider order (dispatch):** Codex → Claude → Cursor. **Gate:** newest valid marker from any configured reviewer on the head.

**Product notes (public docs):** Claude check never fails; Bugbot ignores bot-posted `cursor review`/`bugbot run`. Codex Security Review is optional and not merge-blocking. See `2026-11-14-ai-review-best-practices.md`.
