import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
GATE_PATH = next(
    (path for path in (HERE / "merge_gate.py", HERE.parent / "merge_gate.py") if path.is_file()),
    HERE / "merge_gate.py",
)
SPEC = importlib.util.spec_from_file_location("merge_gate", GATE_PATH)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

class RevalidateTests(unittest.TestCase):
    HEAD = "a" * 40

    def verdict(self, **overrides):
        verdict = {
            "repo": "o/r",
            "pr": 7,
            "head_sha": self.HEAD,
            "base_ref": "main",
            "policy_ref": "main",
            "base_sha": "c" * 40,
            "tier": "T2",
            "codex": "success",
            "label": "agent-approved",
            "checks": "failure",
            "required_checks": ["test"],
            "bootstrap": True,
            "body_sha256": gate.hashlib.sha256(b"").hexdigest(),
            "policy_sha256": "d",
        }
        verdict.update(overrides)
        return verdict

    def run_revalidate(self, verdict, checks_fail, policy=None):
        pull = {"state": "open", "head": {"sha": self.HEAD}, "base": {"ref": "main"}, "body": ""}
        calls = {}

        def fake_checks(repo, sha, required):
            calls["required"] = required
            return checks_fail

        with mock.patch.object(gate, "request", lambda *a, **k: pull), \
             mock.patch.object(gate, "load_policy",
                               lambda *a, **k: policy or {"require_checks": True, "_sha256": "d"}), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             mock.patch.object(gate, "head_contains_base", lambda *a, **k: (True, "c" * 40)), \
             mock.patch.object(gate, "shared_head", lambda *a, **k: False), \
             mock.patch.object(gate, "live_label", lambda *a, **k: "agent-approved"), \
             mock.patch.object(gate, "codex_verdict", lambda *a, **k: ("success", "")), \
             mock.patch.object(gate, "check_results", fake_checks):
            gate.revalidate("o/r", verdict)
        return calls

    def test_bootstrap_verdict_still_needs_the_ci_contexts(self):
        with self.assertRaises(gate.Refusal):
            self.run_revalidate(self.verdict(), ([], [], [], ["test"]))

    def test_bootstrap_verdict_passes_when_the_contexts_still_pass(self):
        calls = self.run_revalidate(self.verdict(), ([], [], [], []))
        self.assertEqual(calls["required"], ["test"])

    def test_a_policy_that_skips_ci_does_not_wait_for_contexts(self):
        calls = self.run_revalidate(self.verdict(), ([], [], [], []), {"require_checks": False, "_sha256": "d"})
        self.assertEqual(calls, {})


class CodexReceiptTests(unittest.TestCase):
    """A Codex summary carries several marker comments in one comment body."""

    HEAD = "a" * 40

    def test_receipt_stays_inside_its_own_comment(self):
        receipt = json.dumps({
            "code_review": {
                "commit_sha": self.HEAD,
                "has_unresolved_findings": False,
                "status": "completed",
            },
            "security_review": {"status": "completed"},
        })
        body = (
            "<!-- codex-pull-request-review-summary -->\n"
            f"<!-- codex-review-state:v1 {receipt} -->\n"
            '<!-- codex-security-review:v1 {"status":"completed"} -->\n'
            "<details>Codex Review Summary</details>"
        )
        comment = {
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "body": body,
            "updated_at": "2026-11-08T08:29:18Z",
        }
        with mock.patch.object(gate, "paginate", return_value=[comment]):
            verdict = gate.codex_verdict("o/r", 7, self.HEAD)
        self.assertEqual(verdict[0], "success")

    def test_bare_codex_prose_receipt_marker_does_not_mask_state_comment(self):
        state_comment = {
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "body": "<!-- codex-review-state:v1 "
            + json.dumps(
                {
                    "code_review": {
                        "commit_sha": self.HEAD,
                        "status": "completed",
                        "has_unresolved_findings": False,
                    }
                }
            )
            + " -->",
            "updated_at": "2026-11-15T06:10:00Z",
        }
        bare_prose_comment = {
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "body": "<!-- codex-review-receipt:v1 -->\n\nCodex Review: Didn't find any major issues!",
            "updated_at": "2026-11-15T06:15:00Z",
        }
        with mock.patch.object(gate, "paginate", return_value=[state_comment, bare_prose_comment]):
            self.assertEqual(gate.codex_verdict("o/r", 7, self.HEAD)[0], "success")

        for bad_marker in (
            "<!-- codex-review-receipt:v1 ",
            "<!-- codex-review-receipt:v1 not-json -->",
            "<!-- codex-review-state:v1 -->",
        ):
            with self.subTest(bad_marker=bad_marker):
                bad_comment = {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": bad_marker,
                    "updated_at": "2026-11-15T06:16:00Z",
                }
                with mock.patch.object(gate, "paginate", return_value=[state_comment, bad_comment]):
                    self.assertEqual(gate.codex_verdict("o/r", 7, self.HEAD)[0], "error")


class AiReviewReceiptTests(unittest.TestCase):
    """Multi-provider receipt parsing across Codex, Claude, and Cursor."""

    HEAD = "a" * 40

    def comment(self, login, marker, payload, updated_at="2026-11-14T08:00:00Z"):
        body = f"<!-- {marker} {json.dumps(payload)} -->" if isinstance(payload, dict) else f"<!-- {marker} {payload} -->"
        return {
            "user": {"login": login},
            "body": body,
            "updated_at": updated_at,
        }

    def verdict(self, comments):
        with mock.patch.object(gate, "paginate", return_value=comments):
            return gate.ai_review_verdict("o/r", 7, self.HEAD)

    def test_claude_receipt_approves_head(self):
        comment = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        state, note = self.verdict([comment])
        self.assertEqual(state, "success")
        self.assertIn("claude", note)

    def test_cursor_receipt_with_completed_status_and_valid_coverages_passes(self):
        for coverage in ("complete", "completed", "full", "reported_complete", "all", " Full "):
            with self.subTest(coverage=coverage):
                comment = self.comment(
                    "cursor[bot]",
                    "ai-review-receipt:v1",
                    {
                        "review": {
                            "provider": "cursor",
                            "commit_sha": self.HEAD,
                            "status": "completed",
                            "unresolved_findings": False,
                            "coverage": coverage,
                        }
                    },
                )
                state, note = self.verdict([comment])
                self.assertEqual(state, "success")
                self.assertIn("cursor", note)

    def test_all_receipt_formats_require_explicit_completed_status(self):
        cases = (
            ("claude[bot]", "ai-review-receipt:v1", "review", {"provider": "claude", "unresolved_findings": 0, "coverage": "complete"}),
            ("chatgpt-codex-connector[bot]", "codex-review-receipt:v1", "review", {"provider": "codex", "unresolved_findings": 0, "coverage": "complete"}),
            ("chatgpt-codex-connector[bot]", "codex-review-state:v1", "code_review", {"has_unresolved_findings": False}),
        )
        for login, marker, key, fields in cases:
            for bad_status in ("__ABSENT__", None, "", "   "):
                with self.subTest(marker=marker, status=bad_status):
                    body_obj = {"commit_sha": self.HEAD, **fields}
                    if bad_status != "__ABSENT__":
                        body_obj["status"] = bad_status
                    comment = self.comment(login, marker, {key: body_obj})
                    state, note = self.verdict([comment])
                    self.assertEqual(state, "pending")
                    self.assertIn("not finished", note)

    def test_unrecognized_author_is_ignored(self):
        comment = self.comment(
            "impostor[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        self.assertEqual(self.verdict([comment])[0], "pending")

    def test_in_progress_receipt_stays_pending(self):
        comment = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "in_progress",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        state, note = self.verdict([comment])
        self.assertEqual(state, "pending")
        self.assertIn("in_progress", note)

    def test_stale_commit_sha_is_rejected(self):
        comment = self.comment(
            "cursor[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "cursor",
                    "commit_sha": "b" * 40,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        state, note = self.verdict([comment])
        self.assertEqual(state, "failure")
        self.assertIn("another commit", note)

    def test_missing_or_invalid_commit_sha_returns_error(self):
        for marker, login, provider in (
            ("ai-review-receipt:v1", "claude[bot]", "claude"),
            ("codex-review-receipt:v1", "chatgpt-codex-connector[bot]", "codex"),
        ):
            for bad_sha in ("__ABSENT__", None, "", "   ", 123, "abc123", "z" * 40):
                with self.subTest(marker=marker, commit_sha=bad_sha):
                    review = {
                        "provider": provider,
                        "status": "completed",
                        "unresolved_findings": 0,
                        "coverage": "complete",
                    }
                    if bad_sha != "__ABSENT__":
                        review["commit_sha"] = bad_sha
                    comment = self.comment(login, marker, {"review": review})
                    state, note = self.verdict([comment])
                    self.assertEqual(state, "error")
                    self.assertIn("commit_sha", note)

            with self.subTest(marker=marker, uppercase_head=True):
                comment = self.comment(
                    login,
                    marker,
                    {
                        "review": {
                            "provider": provider,
                            "commit_sha": self.HEAD.upper(),
                            "status": "completed",
                            "unresolved_findings": 0,
                            "coverage": "complete",
                        }
                    },
                )
                self.assertEqual(self.verdict([comment])[0], "success")

    def test_newer_receipt_missing_commit_sha_not_masked_by_older_clean_receipt(self):
        for marker, login, provider in (
            ("ai-review-receipt:v1", "claude[bot]", "claude"),
            ("codex-review-receipt:v1", "chatgpt-codex-connector[bot]", "codex"),
        ):
            older_clean = self.comment(
                login,
                marker,
                {
                    "review": {
                        "provider": provider,
                        "commit_sha": self.HEAD,
                        "status": "completed",
                        "unresolved_findings": 0,
                        "coverage": "complete",
                    }
                },
                updated_at="2026-11-14T08:00:00Z",
            )
            with self.subTest(marker=marker, case="completed_with_findings"):
                newer_findings = self.comment(
                    login,
                    marker,
                    {
                        "review": {
                            "provider": provider,
                            "status": "completed",
                            "unresolved_findings": 2,
                            "coverage": "complete",
                        }
                    },
                    updated_at="2026-11-14T09:00:00Z",
                )
                state, note = self.verdict([older_clean, newer_findings])
                self.assertEqual(state, "error")
                self.assertIn("commit_sha", note)

            with self.subTest(marker=marker, case="in_progress"):
                newer_pending = self.comment(
                    login,
                    marker,
                    {
                        "review": {
                            "provider": provider,
                            "status": "in_progress",
                        }
                    },
                    updated_at="2026-11-14T09:00:00Z",
                )
                state, note = self.verdict([older_clean, newer_pending])
                self.assertEqual(state, "pending")
                self.assertIn("in_progress", note)

    def test_unresolved_findings_variants_are_rejected(self):
        for payload in (
            {"unresolved_findings": 2},
            {"unresolved_findings": True},
            {"has_unresolved_findings": True},
        ):
            with self.subTest(payload=payload):
                review = {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "coverage": "complete",
                    **payload,
                }
                comment = self.comment("claude[bot]", "ai-review-receipt:v1", {"review": review})
                state, note = self.verdict([comment])
                self.assertEqual(state, "failure")
                self.assertIn("unresolved findings", note)

    def test_missing_or_invalid_findings_state_is_rejected(self):
        for payload in (
            {},
            {"has_unresolved_findings": None},
            {"unresolved_findings": -1},
            {"unresolved_findings": "0"},
        ):
            with self.subTest(payload=payload):
                review = {
                    "provider": "cursor",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "coverage": "complete",
                    **payload,
                }
                comment = self.comment("cursor[bot]", "ai-review-receipt:v1", {"review": review})
                state, note = self.verdict([comment])
                self.assertEqual(state, "failure")
                self.assertIn("findings state", note)

    def test_incomplete_coverage_is_rejected(self):
        for coverage in ("partial", "sampled", "none"):
            with self.subTest(coverage=coverage):
                comment = self.comment(
                    "claude[bot]",
                    "ai-review-receipt:v1",
                    {
                        "review": {
                            "provider": "claude",
                            "commit_sha": self.HEAD,
                            "status": "completed",
                            "unresolved_findings": 0,
                            "coverage": coverage,
                        }
                    },
                )
                state, note = self.verdict([comment])
                self.assertEqual(state, "failure")
                self.assertIn("coverage", note)

    def test_malformed_json_returns_error(self):
        for bad_payload in ("{not valid json}", {}):
            with self.subTest(bad_payload=bad_payload):
                comment = self.comment("claude[bot]", "ai-review-receipt:v1", bad_payload)
                state, note = self.verdict([comment])
                self.assertEqual(state, "error")
                self.assertIn("valid JSON", note)

    def test_newest_receipt_wins_across_providers(self):
        older_bad = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": "f" * 40,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        newer_good = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T09:00:00Z",
        )
        self.assertEqual(self.verdict([older_bad, newer_good])[0], "success")

        newer_bad = self.comment(
            "cursor[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "cursor",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 1,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T10:00:00Z",
        )
        self.assertEqual(self.verdict([newer_good, newer_bad])[0], "failure")

    def test_receipt_markers_require_explicit_complete_coverage(self):
        for marker, login, provider in (
            ("ai-review-receipt:v1", "claude[bot]", "claude"),
            ("codex-review-receipt:v1", "chatgpt-codex-connector[bot]", "codex"),
        ):
            for bad_cov in ("__ABSENT__", None, "", "   ", 123, True, "partial"):
                with self.subTest(marker=marker, coverage=bad_cov):
                    review = {
                        "provider": provider,
                        "commit_sha": self.HEAD,
                        "status": "completed",
                        "unresolved_findings": 0,
                    }
                    if bad_cov != "__ABSENT__":
                        review["coverage"] = bad_cov
                    comment = self.comment(login, marker, {"review": review})
                    state, note = self.verdict([comment])
                    self.assertEqual(state, "failure")
                    self.assertIn("coverage", note)

    def test_legacy_codex_state_v1_defaults_missing_or_null_coverage_only(self):
        for cov in ("__ABSENT__", None, "complete"):
            with self.subTest(cov=cov):
                code_review = {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
                if cov != "__ABSENT__":
                    code_review["coverage"] = cov
                comment = self.comment(
                    "chatgpt-codex-connector[bot]",
                    "codex-review-state:v1",
                    {"code_review": code_review},
                )
                self.assertEqual(self.verdict([comment])[0], "success")
        for bad_cov in ("", "partial", 1):
            with self.subTest(bad_cov=bad_cov):
                comment = self.comment(
                    "chatgpt-codex-connector[bot]",
                    "codex-review-state:v1",
                    {
                        "code_review": {
                            "commit_sha": self.HEAD,
                            "status": "completed",
                            "has_unresolved_findings": False,
                            "coverage": bad_cov,
                        }
                    },
                )
                self.assertEqual(self.verdict([comment])[0], "failure")

    def test_unresolved_rejects_malformed_booleans_and_disagreements(self):
        for bad_review in (
            {"has_unresolved_findings": "false"},
            {"has_unresolved_findings": 0},
            {"has_unresolved_findings": 1},
            {"unresolved_findings": 1.5},
            {"has_unresolved_findings": False, "unresolved_findings": 1},
            {"has_unresolved_findings": True, "unresolved_findings": 0},
            {"has_unresolved_findings": False, "unresolved_findings": "0"},
        ):
            with self.subTest(bad_review=bad_review):
                self.assertIsNone(gate._receipt_unresolved(bad_review))
                comment = self.comment(
                    "claude[bot]",
                    "ai-review-receipt:v1",
                    {
                        "review": {
                            "provider": "claude",
                            "commit_sha": self.HEAD,
                            "status": "completed",
                            "coverage": "complete",
                            **bad_review,
                        }
                    },
                )
                state, note = self.verdict([comment])
                self.assertEqual(state, "failure")
                self.assertIn("findings state", note)
        self.assertFalse(gate._receipt_unresolved({"has_unresolved_findings": False, "unresolved_findings": 0}))
        self.assertTrue(gate._receipt_unresolved({"has_unresolved_findings": True, "unresolved_findings": 2}))

    def test_provider_login_and_marker_binding(self):
        wrong_marker = self.comment(
            "claude[bot]",
            "codex-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        state, note = self.verdict([wrong_marker])
        self.assertEqual(state, "failure")
        self.assertIn("Ambiguous or disallowed", note)

        mismatched_provider = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "codex",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        state, note = self.verdict([mismatched_provider])
        self.assertEqual(state, "failure")
        self.assertIn("match", note)

        codex_user_login = self.comment(
            "chatgpt-codex-connector",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            },
        )
        with mock.patch.object(gate, "paginate", return_value=[codex_user_login]):
            self.assertEqual(gate.codex_verdict("o/r", 7, self.HEAD)[0], "success")

    def test_codex_verdict_enforces_codex_only_when_other_providers_approve(self):
        claude_only = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        with mock.patch.object(gate, "paginate", return_value=[claude_only]):
            self.assertEqual(gate.codex_verdict("o/r", 7, self.HEAD)[0], "pending")
            self.assertEqual(
                gate.ai_review_verdict("o/r", 7, self.HEAD, allowed_providers={"codex", "claude"})[0],
                "success",
            )

    def test_unresolved_finding_on_head_cannot_be_masked_by_newer_clean_provider(self):
        codex_bad = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": True,
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        claude_good = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T09:00:00Z",
        )
        with mock.patch.object(gate, "paginate", return_value=[codex_bad, claude_good]):
            state, note = gate.ai_review_verdict(
                "o/r", 7, self.HEAD, allowed_providers={"codex", "claude", "cursor"}
            )
        self.assertEqual(state, "failure")
        self.assertIn("unresolved findings", note)

        cursor_malformed = self.comment(
            "cursor[bot]",
            "ai-review-receipt:v1",
            "{not valid json}",
            updated_at="2026-11-14T10:00:00Z",
        )
        with mock.patch.object(gate, "paginate", return_value=[claude_good, cursor_malformed]):
            self.assertEqual(
                gate.ai_review_verdict(
                    "o/r", 7, self.HEAD, allowed_providers={"codex", "claude", "cursor"}
                )[0],
                "error",
            )

        older_malformed = self.comment(
            "cursor[bot]",
            "ai-review-receipt:v1",
            "{not valid json}",
            updated_at="2026-11-14T07:00:00Z",
        )
        with mock.patch.object(gate, "paginate", return_value=[older_malformed, claude_good]):
            self.assertEqual(
                gate.ai_review_verdict(
                    "o/r", 7, self.HEAD, allowed_providers={"codex", "claude", "cursor"}
                )[0],
                "success",
            )

    def test_old_commit_incomplete_receipt_does_not_block_newer_clean_head_receipt(self):
        old_pending = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": "e" * 40,
                    "status": "in_progress",
                    "has_unresolved_findings": False,
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        claude_good = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T09:00:00Z",
        )
        with mock.patch.object(gate, "paginate", return_value=[old_pending, claude_good]):
            self.assertEqual(
                gate.ai_review_verdict(
                    "o/r", 7, self.HEAD, allowed_providers={"codex", "claude"}
                )[0],
                "success",
            )

    def test_policy_review_providers_preserves_codex_required_contract(self):
        self.assertEqual(gate.policy_review_providers({}), {"codex"})
        self.assertEqual(
            gate.policy_review_providers({"codex_required": True, "ai_review_providers": ["claude"]}),
            {"codex"},
        )
        self.assertEqual(gate.policy_review_providers({"codex_required": False}), set())
        self.assertEqual(
            gate.policy_review_providers(
                {"codex_required": False, "ai_review_providers": ["codex", "Claude", "cursor", "unknown"]}
            ),
            {"codex", "claude", "cursor"},
        )

    def test_ambiguous_or_multiple_markers_fail_closed(self):
        clean_claude = json.dumps(
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            }
        )
        dirty_claude = json.dumps(
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 2,
                    "coverage": "complete",
                }
            }
        )
        codex_state = json.dumps(
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            }
        )
        cursor_good = self.comment(
            "cursor[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "cursor",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T10:00:00Z",
        )
        for body in (
            f"<!-- ai-review-receipt:v1 {clean_claude} -->\n<!-- ai-review-receipt:v1 {dirty_claude} -->",
            f"<!-- ai-review-receipt:v1 {clean_claude} -->\n<!-- ai-review-receipt:v1 {clean_claude} -->",
            f"<!-- ai-review-receipt:v1 {clean_claude} -->\n<!-- codex-review-state:v1 {codex_state} -->",
        ):
            with self.subTest(body=body):
                ambiguous = {
                    "user": {"login": "claude[bot]"},
                    "body": body,
                    "updated_at": "2026-11-14T08:00:00Z",
                }
                state, note = self.verdict([ambiguous])
                self.assertEqual(state, "failure")
                self.assertIn("Ambiguous or disallowed", note)

                state_with_cursor, _ = self.verdict([ambiguous, cursor_good])
                self.assertEqual(state_with_cursor, "failure")

    def test_delayed_stale_receipt_does_not_replace_current_head_finding(self):
        codex_head_bad = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": True,
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        claude_head_good = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T09:00:00Z",
        )
        codex_delayed_stale_clean = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": "e" * 40,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            },
            updated_at="2026-11-14T10:00:00Z",
        )
        with mock.patch.object(
            gate, "paginate", return_value=[codex_head_bad, claude_head_good, codex_delayed_stale_clean]
        ):
            state, note = gate.ai_review_verdict(
                "o/r", 7, self.HEAD, allowed_providers={"codex", "claude"}
            )
        self.assertEqual(state, "failure")
        self.assertIn("unresolved findings", note)

        codex_head_resolved = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            },
            updated_at="2026-11-14T11:00:00Z",
        )
        with mock.patch.object(
            gate,
            "paginate",
            return_value=[codex_head_bad, claude_head_good, codex_delayed_stale_clean, codex_head_resolved],
        ):
            state, _ = gate.ai_review_verdict(
                "o/r", 7, self.HEAD, allowed_providers={"codex", "claude"}
            )
        self.assertEqual(state, "success")

    def test_newer_unterminated_receipt_rejects_prior_clean_receipt(self):
        claude_clean = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        codex_clean = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            },
            updated_at="2026-11-14T08:30:00Z",
        )
        findings_json = json.dumps(
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 2,
                    "coverage": "complete",
                }
            }
        )
        for bad_body in (
            f"<!-- ai-review-receipt:v1 {findings_json}",
            "<!-- ai-review-receipt:v1",
            '<!-- ai-review-receipt:v1 {"review":{"note":"a-->b"}} -->',
        ):
            with self.subTest(bad_body=bad_body):
                newer_bad = {
                    "user": {"login": "claude[bot]"},
                    "body": bad_body,
                    "updated_at": "2026-11-14T09:00:00Z",
                }
                with mock.patch.object(gate, "paginate", return_value=[claude_clean, newer_bad]):
                    state, _ = gate.ai_review_verdict("o/r", 7, self.HEAD, allowed_providers={"claude"})
                self.assertEqual(state, "error")

                with mock.patch.object(gate, "paginate", return_value=[claude_clean, codex_clean, newer_bad]):
                    multi_state, _ = gate.ai_review_verdict(
                        "o/r", 7, self.HEAD, allowed_providers={"codex", "claude"}
                    )
                self.assertEqual(multi_state, "error")

    def test_mixed_closed_receipt_and_unterminated_second_marker_fails_closed(self):
        claude_clean = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        clean_json = json.dumps(
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            }
        )
        mixed = {
            "user": {"login": "claude[bot]"},
            "body": f"<!-- ai-review-receipt:v1 {clean_json} -->\n<!-- ai-review-receipt:v1 {clean_json}",
            "updated_at": "2026-11-14T09:00:00Z",
        }
        with mock.patch.object(gate, "paginate", return_value=[claude_clean, mixed]):
            state, note = gate.ai_review_verdict("o/r", 7, self.HEAD, allowed_providers={"claude"})
        self.assertEqual(state, "failure")
        self.assertIn("Ambiguous or disallowed", note)

    def test_base_changed_at_invalidates_older_receipt_until_rereviewed(self):
        cutoff = gate.dt.datetime(2026, 11, 14, 8, 30, 0, tzinfo=gate.dt.timezone.utc)
        old_codex = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "has_unresolved_findings": False,
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        old_claude = self.comment(
            "claude[bot]",
            "ai-review-receipt:v1",
            {
                "review": {
                    "provider": "claude",
                    "commit_sha": self.HEAD,
                    "status": "completed",
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
            updated_at="2026-11-14T08:00:00Z",
        )
        untimed_claude = {
            "user": old_claude["user"],
            "body": old_claude["body"],
            "updated_at": "",
            "created_at": "",
        }
        with mock.patch.object(gate, "paginate", return_value=[old_codex, old_claude, untimed_claude]):
            state_c, note_c = gate.codex_verdict("o/r", 7, self.HEAD, base_changed_at=cutoff)
            state_m, note_m = gate.ai_review_verdict(
                "o/r", 7, self.HEAD, allowed_providers={"codex", "claude"}, base_changed_at=cutoff
            )
        self.assertEqual(state_c, "pending")
        self.assertIn("base change", note_c)
        self.assertEqual(state_m, "pending")
        self.assertIn("base change", note_m)

        fresh_claude = {
            "user": old_claude["user"],
            "body": old_claude["body"],
            "created_at": "2026-11-14T09:00:00Z",
        }
        with mock.patch.object(gate, "paginate", return_value=[old_codex, old_claude, fresh_claude]):
            state_after, _ = gate.ai_review_verdict(
                "o/r", 7, self.HEAD, allowed_providers={"codex", "claude"}, base_changed_at=cutoff
            )
        self.assertEqual(state_after, "success")


class ClearingLabelTests(unittest.TestCase):
    HEAD = "a" * 40

    def pull(self, labels, head_repo="o/r"):
        return {
            "number": 7,
            "labels": [{"name": name} for name in labels],
            "head": {"sha": self.HEAD, "ref": "feat/test", "repo": {"full_name": head_repo}},
        }

    def test_legacy_three_arg_live_label_enforces_owner_and_agent_logins(self):
        events = [
            {"event": "labeled", "label": {"name": "owner-approved"}, "actor": {"login": "intruder"}},
            {"event": "labeled", "label": {"name": "agent-approved"}, "actor": {"login": "codex-bot"}},
        ]
        with mock.patch.object(gate, "paginate", return_value=events):
            self.assertIsNone(gate.live_label("o/r", 7, "owner-login"))
            self.assertEqual(
                gate.live_label("o/r", 7, "owner-login", agent_logins={"codex-bot"}),
                "agent-approved",
            )

        owner_as_agent = [
            {"event": "labeled", "label": {"name": "agent-approved"}, "actor": {"login": "owner-login"}},
        ]
        with mock.patch.object(gate, "paginate", return_value=owner_as_agent):
            self.assertEqual(gate.live_label("o/r", 7, "owner-login"), "agent-approved")

        both_valid = [
            {"event": "labeled", "label": {"name": "agent-approved"}, "actor": {"login": "codex-bot"}},
            {"event": "labeled", "label": {"name": "owner-approved"}, "actor": {"login": "owner-login"}},
        ]
        with mock.patch.object(gate, "paginate", return_value=both_valid):
            self.assertEqual(
                gate.live_label("o/r", 7, "owner-login", agent_logins={"codex-bot"}),
                "owner-approved",
            )

    def test_timeline_commit_or_push_clears_earlier_clearing_labels(self):
        pull = self.pull(["owner-approved"])
        timeline = [
            {
                "id": 101,
                "event": "labeled",
                "label": {"name": "owner-approved"},
                "actor": {"login": "owner-login"},
                "created_at": "2026-11-14T08:00:00Z",
            },
            {"event": "committed", "created_at": "2026-11-14T08:05:00Z"},
        ]
        with mock.patch.object(gate, "paginate", return_value=timeline):
            self.assertIsNone(gate.live_label("o/r", 7, "owner-login", pull=pull))

    def test_clearing_label_status_accepts_owner_or_configured_agent_on_exact_head(self):
        pull = self.pull(["agent-approved"])
        timeline = [
            {
                "id": 202,
                "event": "labeled",
                "label": {"name": "agent-approved"},
                "actor": {"login": "review-agent"},
                "created_at": "2026-11-14T08:10:00Z",
            }
        ]
        statuses = [
            {
                "context": "clearing-label",
                "state": "success",
                "creator": {"login": gate.ACTIONS_BOT},
                "description": "agent-approved for PR 7 at event 202 on this head",
            }
        ]

        def fake_paginate(path, params=None):
            if path.endswith("/timeline"):
                return timeline
            if path.endswith("/statuses"):
                return statuses
            raise AssertionError(f"Unexpected paginate call: {path}")

        with mock.patch.object(gate, "paginate", fake_paginate):
            self.assertIsNone(gate.live_label("o/r", 7, "owner-login", pull=pull))
            self.assertEqual(
                gate.live_label(
                    "o/r", 7, "owner-login", pull=pull, agent_logins={"review-agent"}
                ),
                "agent-approved",
            )

        bad_owner_pull = self.pull(["owner-approved"])
        bad_owner_timeline = [
            {
                "id": 203,
                "event": "labeled",
                "label": {"name": "owner-approved"},
                "actor": {"login": "review-agent"},
                "created_at": "2026-11-14T08:10:00Z",
            }
        ]
        with mock.patch.object(gate, "paginate", return_value=bad_owner_timeline):
            self.assertIsNone(
                gate.live_label(
                    "o/r", 7, "owner-login", pull=bad_owner_pull, agent_logins={"review-agent"}
                )
            )

    def test_activity_fallback_cursor_pagination_and_fork_prs(self):
        pull = self.pull(["agent-approved"])
        timeline = [
            {
                "id": 303,
                "event": "labeled",
                "label": {"name": "agent-approved"},
                "actor": {"login": "review-agent"},
                "created_at": "2026-11-14T08:10:00Z",
            }
        ]

        def run_with_raw(raw_handler, test_pull=pull, agent_logins=frozenset({"review-agent"})):
            def fake_paginate(path, params=None):
                if path.endswith("/timeline"):
                    return timeline
                if path.endswith("/statuses"):
                    return []
                raise AssertionError(f"Unexpected paginate call: {path}")

            with mock.patch.object(gate, "paginate", fake_paginate), \
                 mock.patch.object(gate, "_raw_request", raw_handler):
                return gate.live_label("o/r", 7, "owner-login", pull=test_pull, agent_logins=set(agent_logins))

        seen_params = []

        def paged_handler(method, path, body=None, params=None, allow=()):
            self.assertEqual(path, "/repos/o/r/activity")
            self.assertNotIn("page", params or {})
            seen_params.append(dict(params or {}))
            if "after" not in (params or {}):
                return (
                    [{"activity_type": "push", "after": "b" * 40, "timestamp": "2026-11-14T07:55:00Z"}],
                    {"link": '<https://api.github.com/repos/o/r/activity?ref=refs%2Fheads%2Ffeat%2Ftest&per_page=100&after=c2>; rel="next"'},
                )
            self.assertEqual(params["after"], "c2")
            return (
                [{"activity_type": "push", "after": self.HEAD, "timestamp": "2026-11-14T08:05:00+00:00"}],
                {},
            )

        self.assertEqual(run_with_raw(paged_handler), "agent-approved")
        self.assertEqual(len(seen_params), 2)

        def repeating_cursor_handler(method, path, body=None, params=None, allow=()):
            return (
                [{"activity_type": "push", "after": self.HEAD, "timestamp": "2026-11-14T08:05:00Z"}],
                {"link": '<https://api.github.com/repos/o/r/activity?after=c2>; rel="next"'},
            )

        self.assertIsNone(run_with_raw(repeating_cursor_handler))

        for bad_entries in (
            [{"activity_type": "force_push", "after": self.HEAD, "timestamp": "2026-11-14T08:12:00Z"}],
            [{"activity_type": "pr_merge", "after": "d" * 40, "timestamp": "2026-11-14T08:12:00Z"}],
            [{"activity_type": "branch_deletion", "after": self.HEAD, "timestamp": "2026-11-14T08:05:00Z"}],
            [{"activity_type": "push", "after": "b" * 40, "timestamp": "2026-11-14T08:05:00Z"}],
            [{"activity_type": "push", "after": self.HEAD}],
            [],
        ):
            with self.subTest(bad_entries=bad_entries):
                self.assertIsNone(run_with_raw(lambda *a, entries=bad_entries, **k: (entries, {})))

        def fork_ok(method, path, body=None, params=None, allow=()):
            self.assertEqual(path, "/repos/fork/r/activity")
            return ([{"activity_type": "push", "after": self.HEAD, "timestamp": "2026-11-14T08:05:00Z"}], {})

        self.assertEqual(
            run_with_raw(fork_ok, test_pull=self.pull(["agent-approved"], head_repo="fork/r")),
            "agent-approved",
        )
        self.assertIsNone(
            run_with_raw(
                lambda *a, **k: (None, {}),
                test_pull=self.pull(["agent-approved"], head_repo="fork/r"),
            )
        )

    def test_timeline_base_ref_changed_clears_earlier_label_and_pre_retarget_status(self):
        pull = self.pull(["owner-approved", "agent-approved"])
        pre_retarget_status = {
            "context": "clearing-label",
            "state": "success",
            "creator": {"login": gate.ACTIONS_BOT},
            "description": "owner-approved for PR 7 at event 201 on this head",
            "updated_at": "2026-11-14T08:00:05Z",
        }
        stale_timeline = [
            {
                "id": 201,
                "event": "labeled",
                "label": {"name": "owner-approved"},
                "actor": {"login": "owner-login"},
                "created_at": "2026-11-14T08:00:00Z",
            },
            {
                "id": 202,
                "event": "labeled",
                "label": {"name": "agent-approved"},
                "actor": {"login": "review-agent"},
                "created_at": "2026-11-14T08:01:00Z",
            },
            {"event": "base_ref_changed", "created_at": "2026-11-14T08:05:00Z"},
        ]

        def run(timeline, statuses):
            def fake_paginate(path, params=None):
                if path.endswith("/timeline"):
                    return timeline
                if path.endswith("/statuses"):
                    return statuses
                raise AssertionError(f"Unexpected paginate call: {path}")

            with mock.patch.object(gate, "paginate", fake_paginate), \
                 mock.patch.object(gate, "branch_activities", return_value=[]):
                return gate.live_label(
                    "o/r", 7, "owner-login", pull=pull, agent_logins={"review-agent"}
                )

        self.assertIsNone(run(stale_timeline, [pre_retarget_status]))

        # Even if re-labeled after base_ref_changed, an untimed or pre-retarget status never passes.
        relabeled_timeline = stale_timeline + [
            {
                "id": 203,
                "event": "labeled",
                "label": {"name": "owner-approved"},
                "actor": {"login": "owner-login"},
                "created_at": "2026-11-14T08:10:00Z",
            }
        ]
        for bad_status in (
            {
                "context": "clearing-label",
                "state": "success",
                "creator": {"login": gate.ACTIONS_BOT},
                "description": "owner-approved for PR 7 at event 203 on this head",
            },
            {
                "context": "clearing-label",
                "state": "success",
                "creator": {"login": gate.ACTIONS_BOT},
                "description": "owner-approved for PR 7 at event 203 on this head",
                "updated_at": "2026-11-14T08:04:00Z",
            },
        ):
            with self.subTest(bad_status=bad_status):
                self.assertIsNone(run(relabeled_timeline, [pre_retarget_status, bad_status]))

        fresh_status = {
            "context": "clearing-label",
            "state": "success",
            "creator": {"login": gate.ACTIONS_BOT},
            "description": "owner-approved for PR 7 at event 203 on this head",
            "updated_at": "2026-11-14T08:10:05Z",
        }
        self.assertEqual(run(relabeled_timeline, [pre_retarget_status, fresh_status]), "owner-approved")

    def test_accepts_pigbibi_local_ai_reviewer_receipt(self):
        head = "a" * 40
        comments = [
            {
                "id": 901,
                "user": {"login": "pigbibi-local-ai-reviewer[bot]"},
                "body": '<!-- ai-review-receipt:v1 {"review":{"provider":"opencode","model":"gemini","commit_sha":"%s","status":"completed","coverage":"complete","unresolved_findings":false}} -->'
                % head,
                "updated_at": "2026-11-14T08:11:00Z",
            }
        ]
        latest = gate._collect_latest_provider_receipts(comments, head, {"opencode"}, None)
        self.assertIn("opencode", latest)
        self.assertEqual(latest["opencode"].state, "success")


if __name__ == "__main__":
    unittest.main()
