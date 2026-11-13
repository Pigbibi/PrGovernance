# ai-review-receipt:v1 (fallback adapter)

When a provider does not emit native markers, a trusted bot may post:

```html
<!-- ai-review-receipt:v1 {"review":{"provider":"cursor","commit_sha":"<40-char-head>","coverage":"complete","unresolved_findings":false,"status":"completed"}} -->

## AI review summary
Brief human-readable summary here.
```

Rules match `codex-review-receipt:v1`: exact head, completed coverage, no unresolved findings, comment author must be a configured reviewer identity.
