import contextlib
import importlib.util
import io
import json
import tempfile
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

class AuditTests(unittest.TestCase):
    HEAD = "a" * 40
    MERGE = "b" * 40

    def run_audit(self, comments):
        policy = {"owner_login": "synthetic-owner", "audit_since": "", "audit_ignore_prs": []}
        pull = {
            "number": 7,
            "merged_at": "2026-01-02T00:00:00Z",
            "head": {"sha": self.HEAD},
            "merge_commit_sha": self.MERGE,
        }

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pull] if params.get("page") == 1 else []
            return []

        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: comments), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: policy), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None):
            return gate.audit("o/r", 20, False)

    def verdict(self, **overrides):
        verdict = {
            "repo": "o/r",
            "pr": 7,
            "head_sha": self.HEAD,
            "merge_sha": self.MERGE,
            "verdict": "pass",
            "merged": True,
        }
        verdict.update(overrides)
        body = "<!-- governance-verdict:v1 " + json.dumps(verdict) + " -->"
        return {"user": {"login": "synthetic-owner"}, "body": body}

    def test_authenticated_verdict_passes(self):
        self.assertEqual(self.run_audit([self.verdict()]), 0)

    def test_foreign_author_is_not_evidence(self):
        comment = self.verdict()
        comment["user"] = {"login": "intruder"}
        self.assertEqual(self.run_audit([comment]), 2)

    def test_merge_sha_must_match(self):
        self.assertEqual(self.run_audit([self.verdict(merge_sha="c" * 40)]), 2)

    def test_pr_number_must_match(self):
        self.assertEqual(self.run_audit([self.verdict(pr=8)]), 2)

    def test_stale_update_does_not_use_the_audit_window(self):
        policy = {
            "owner_login": "synthetic-owner",
            "audit_since": "2026-01-02T00:00:00Z",
            "audit_ignore_prs": [],
        }
        old = {
            "number": 6,
            "merged_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z",
            "head": {"sha": "c" * 40},
            "merge_commit_sha": "d" * 40,
        }
        recent = {
            "number": 7,
            "merged_at": "2026-01-02T12:00:00Z",
            "updated_at": "2026-01-02T12:00:00Z",
            "head": {"sha": self.HEAD},
            "merge_commit_sha": self.MERGE,
        }

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [old, recent] if params.get("page") == 1 else []
            return []

        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: []), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: policy), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None):
            self.assertEqual(gate.audit("o/r", 1, False, policy_ref="refs/tags/trusted"), 2)

    def test_future_or_invalid_audit_since_fails(self):
        for bad_since in ("2099-01-01T00:00:00Z", "not-a-timestamp"):
            with self.subTest(bad_since=bad_since):
                policy = {"owner_login": "synthetic-owner", "audit_since": bad_since, "audit_ignore_prs": []}

                def fake_request(method, path, body=None, params=None, allow=()):
                    if path == "/repos/o/r":
                        return {"default_branch": "main"}
                    if path == "/repos/o/r/pulls":
                        return []
                    if path == "/repos/o/r/commits":
                        return []
                    return []

                captured = io.StringIO()
                with mock.patch.object(gate, "request", fake_request), \
                     mock.patch.object(gate, "paginate", lambda path, params=None: []), \
                     mock.patch.object(gate, "branch_activities", return_value=[]), \
                     mock.patch.object(gate, "load_policy", lambda *a, **k: policy), \
                     mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
                     contextlib.redirect_stdout(captured):
                    code = gate.audit("o/r", 20, False)
                self.assertEqual(code, 2)
                self.assertIn("audit_since in policy is invalid or in the future", captured.getvalue())

    def test_strict_direct_ignores_untrusted_branch_exemptions(self):
        direct = "d" * 40
        untrusted_policy = {
            "owner_login": "synthetic-owner",
            "audit_since": "2026-01-01T00:00:00Z",
            "audit_baseline_sha": direct,
            "audit_ignore_prs": [7],
            "audit_acknowledged_direct": {direct: "self-excused"},
            "audit_direct_commits": 1,
            "audit_strict_direct": False,
        }
        pull = {
            "number": 7,
            "merged_at": "2025-12-01T00:00:00Z",
            "head": {"sha": self.HEAD},
            "merge_commit_sha": self.MERGE,
        }
        commit = {
            "sha": direct,
            "parents": [],
            "commit": {"message": "direct change", "committer": {"date": "2025-12-02T00:00:00Z"}},
        }
        seen_limit = {}

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pull] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return [commit]
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                return []
            return []

        orig_scan = gate.scan_direct_pushes

        def wrap_scan(
            repo, default, merge_shas, acknowledged, strict, direct_limit, baseline_sha="", listing=None, **kwargs
        ):
            seen_limit["baseline_sha"] = baseline_sha
            seen_limit["acknowledged"] = acknowledged
            seen_limit["strict"] = strict
            seen_limit["direct_limit"] = direct_limit
            return orig_scan(
                repo,
                default,
                merge_shas,
                acknowledged,
                strict,
                direct_limit,
                baseline_sha=baseline_sha,
                listing=listing,
                **kwargs,
            )

        captured = io.StringIO()
        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [self.verdict()]), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: untrusted_policy), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             mock.patch.object(gate, "scan_direct_pushes", wrap_scan), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True)
        self.assertEqual(code, 2)
        self.assertEqual(seen_limit, {"baseline_sha": "", "acknowledged": {}, "strict": True, "direct_limit": 40})
        self.assertIn(f"violation: {direct[:7]} on main is not associated", captured.getvalue())

    def test_policy_driven_strict_audit_ignores_untrusted_branch_exemptions(self):
        direct = "d" * 40
        force_event = {
            "id": 9001,
            "activity_type": "force_push",
            "ref": "refs/heads/main",
            "before": "e" * 40,
            "after": direct,
            "timestamp": "2025-11-15T00:00:00Z",
        }
        pull = {
            "number": 7,
            "merged_at": "2025-12-01T00:00:00Z",
            "head": {"sha": self.HEAD},
            "merge_commit_sha": self.MERGE,
        }
        commit = {
            "sha": direct,
            "parents": [],
            "commit": {"message": "direct change", "committer": {"date": "2025-12-02T00:00:00Z"}},
        }

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pull] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return [commit]
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                return []
            return []

        for extra_policy in ({}, {"audit_strict_direct": True}):
            with self.subTest(extra_policy=extra_policy):
                untrusted_policy = {
                    "owner_login": "synthetic-owner",
                    "audit_since": "2026-01-01T00:00:00Z",
                    "audit_baseline_sha": direct,
                    "audit_ignore_prs": [7],
                    "audit_acknowledged_direct": {
                        direct: "self-excused",
                        "9001": "self-excused-force",
                    },
                    "audit_direct_commits": 1,
                    **extra_policy,
                }
                seen_limit = {}
                orig_scan = gate.scan_direct_pushes

                def wrap_scan(
                    repo, default, merge_shas, acknowledged, strict, direct_limit, baseline_sha="", listing=None, **kwargs
                ):
                    seen_limit["baseline_sha"] = baseline_sha
                    seen_limit["acknowledged"] = acknowledged
                    seen_limit["strict"] = strict
                    seen_limit["direct_limit"] = direct_limit
                    return orig_scan(
                        repo,
                        default,
                        merge_shas,
                        acknowledged,
                        strict,
                        direct_limit,
                        baseline_sha=baseline_sha,
                        listing=listing,
                        **kwargs,
                    )

                captured = io.StringIO()
                with mock.patch.object(gate, "request", fake_request), \
                     mock.patch.object(gate, "paginate", lambda path, params=None: []), \
                     mock.patch.object(gate, "branch_activities", return_value=[force_event]), \
                     mock.patch.object(gate, "load_policy", lambda *a, **k: untrusted_policy), \
                     mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
                     mock.patch.object(gate, "scan_direct_pushes", wrap_scan), \
                     contextlib.redirect_stdout(captured):
                    code = gate.audit("o/r", 20, False)
                out = captured.getvalue()
                self.assertEqual(code, 2)
                self.assertEqual(seen_limit, {"baseline_sha": "", "acknowledged": {}, "strict": True, "direct_limit": 40})
                self.assertIn("#7 merged at aaaaaaa without an authenticated passing verdict", out)
                self.assertIn(f"violation: {direct[:7]} on main is not associated", out)
                self.assertIn("force push on main (activity 9001", out)

        trusted_policy = {
            "owner_login": "synthetic-owner",
            "audit_since": "2026-01-01T00:00:00Z",
            "audit_baseline_sha": direct,
            "audit_ignore_prs": [7],
            "audit_acknowledged_direct": {direct: "approved", "9001": "approved-reset"},
            "audit_strict_direct": True,
        }
        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: []), \
             mock.patch.object(gate, "branch_activities", return_value=[force_event]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: trusted_policy), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.audit("o/r", 20, False, policy_ref="refs/tags/trusted"), 0)

    def test_audit_honors_explicit_policy_ref_and_policy_file(self):
        direct = "d" * 40
        trusted_policy = {
            "owner_login": "synthetic-owner",
            "audit_ignore_prs": [7],
            "audit_acknowledged_direct": {direct: "approved emergency hotfix"},
            "audit_direct_commits": 5,
        }
        commit = {
            "sha": direct,
            "parents": [],
            "commit": {"message": "hotfix", "committer": {"date": "2026-01-02T00:00:00Z"}},
        }
        refs_seen = []

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return []
            if path == "/repos/o/r/commits":
                return [commit]
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                return []
            return []

        def fake_load_policy(repo, ref, fallback=None):
            refs_seen.append(("load", ref))
            return trusted_policy

        def fake_verify_script(repo, ref):
            refs_seen.append(("verify", ref))

        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: []), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", fake_load_policy), \
             mock.patch.object(gate, "verify_script", fake_verify_script):
            code = gate.audit("o/r", 20, True, policy_ref="refs/tags/trusted-policy")
        self.assertEqual(code, 0)
        self.assertEqual(refs_seen, [("load", "refs/tags/trusted-policy"), ("verify", "refs/tags/trusted-policy")])

        refs_seen.clear()
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            policy_path.write_text(json.dumps(trusted_policy), encoding="utf-8")
            with mock.patch.object(gate, "request", fake_request), \
                 mock.patch.object(gate, "paginate", lambda path, params=None: []), \
                 mock.patch.object(gate, "branch_activities", return_value=[]), \
                 mock.patch.object(gate, "verify_script", fake_verify_script):
                code = gate.audit("o/r", 20, True, policy_file=str(policy_path))
        self.assertEqual(code, 0)
        self.assertEqual(refs_seen, [("verify", "main")])


class DirectPushAuditTests(unittest.TestCase):
    TIP = "a" * 40
    DIRECT = "d" * 40
    SIDE = "s" * 40
    PREV = "p" * 40
    DATE = "2026-01-05T00:00:00Z"

    def commit(self, sha, parents=(), subject="commit", date=None):
        return {
            "sha": sha,
            "parents": [{"sha": parent} for parent in parents],
            "commit": {"message": subject, "committer": {"date": date or self.DATE}},
        }

    def verdict_comment(self):
        verdict = {
            "repo": "o/r",
            "pr": 7,
            "head_sha": "h" * 40,
            "merge_sha": self.TIP,
            "verdict": "pass",
            "merged": True,
        }
        return {"user": {"login": "synthetic-owner"},
                "body": "<!-- governance-verdict:v1 " + json.dumps(verdict) + " -->"}

    def run_audit(
        self,
        chain,
        policy=None,
        strict_direct=False,
        details=None,
        attributed=(),
        related_pulls=None,
        pull_base="main",
        policy_ref=None,
        activities=(),
    ):
        base = {"owner_login": "synthetic-owner", "audit_since": "", "audit_ignore_prs": []}
        base.update(policy or {})
        pull = {
            "number": 7,
            "merged_at": self.DATE,
            "base": {"ref": pull_base},
            "head": {"sha": "h" * 40},
            "merge_commit_sha": self.TIP,
        }
        details = details or {}
        attributed = set(attributed)
        related_pulls = related_pulls or {}
        parents_of = {
            commit["sha"]: [parent.get("sha") for parent in (commit.get("parents") or [])]
            for commit in list(chain) + list(details.values())
        }

        def ancestors_of(start):
            seen = set()
            stack = [start] if start in parents_of else []
            while stack:
                node = stack.pop()
                if node in seen:
                    continue
                seen.add(node)
                for parent in parents_of.get(node, []):
                    if parent in parents_of:
                        stack.append(parent)
            return seen

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pull] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return chain
            if path.startswith("/repos/o/r/compare/") and "..." in path:
                left, right = path.rsplit("/", 1)[-1].split("...", 1)
                if left not in parents_of or right not in parents_of:
                    return None
                right_ancestors = ancestors_of(right)
                if left in right_ancestors:
                    return {
                        "status": "identical" if left == right else "ahead",
                        "merge_base_commit": {"sha": left},
                    }
                left_ancestors = ancestors_of(left)
                return {
                    "status": "behind" if right in left_ancestors else "diverged",
                    "merge_base_commit": {"sha": right if right in left_ancestors else ""},
                }
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                sha = path.rsplit("/", 2)[-2]
                if sha in related_pulls:
                    return related_pulls[sha]
                # Only the shas named here have a merged pull request attached;
                # everything else asks the entry and gets nothing back.
                return (
                    [{"merged_at": self.DATE, "base": {"ref": "main"}, "merge_commit_sha": sha}]
                    if sha in attributed
                    else []
                )
            if path.startswith("/repos/o/r/commits/"):
                return details.get(path.rsplit("/", 1)[-1])
            return []

        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [self.verdict_comment()]), \
             mock.patch.object(gate, "branch_activities", return_value=list(activities)), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: base), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None):
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = gate.audit("o/r", 20, strict_direct, policy_ref=policy_ref)
        return code, captured.getvalue()

    def test_chain_direct_push_is_a_violation_by_default(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.DIRECT, (), "governance: loosen a check")]
        code, output = self.run_audit(chain)
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.DIRECT[:7]} on main is not associated", output)

    def test_pull_merge_commits_on_the_chain_are_not_direct_pushes(self):
        chain = [self.commit(self.TIP, (self.PREV,), "feat: via pull request"),
                 self.commit(self.PREV, (), "docs: earlier merged pull request")]
        code, _ = self.run_audit(chain, attributed={self.PREV})
        self.assertEqual(code, 0)

    def test_pull_merged_to_non_default_branch_does_not_exempt_direct_push(self):
        chain = [self.commit(self.TIP, (self.PREV,), "feat: via pull request"),
                 self.commit(self.PREV, (), "docs: merged onto release branch only")]
        related = {self.PREV: [{"merged_at": self.DATE, "base": {"ref": "release"}, "merge_commit_sha": self.PREV}]}
        code, output = self.run_audit(chain, related_pulls=related)
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.PREV[:7]} on main is not associated", output)

    def test_fast_forwarded_merge_sha_from_non_default_branch_is_not_exempted(self):
        chain = [self.commit(self.TIP, (self.PREV,), "feat: release pr fast-forwarded to main"),
                 self.commit(self.PREV, (), "docs: earlier merged pull request")]
        related = {self.TIP: [{"merged_at": self.DATE, "base": {"ref": "release"}, "merge_commit_sha": self.TIP}]}
        code, output = self.run_audit(chain, attributed={self.PREV}, related_pulls=related, pull_base="release")
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.TIP[:7]} on main is not associated", output)

    def test_side_or_head_commit_of_merged_pr_does_not_exempt_direct_push(self):
        chain = [self.commit(self.TIP, (self.PREV,), "feat: via pull request"),
                 self.commit(self.PREV, (), "feat: side commit from a merge-commit PR")]
        related = {self.PREV: [{"merged_at": self.DATE, "base": {"ref": "main"}, "merge_commit_sha": "f" * 40}]}
        code, output = self.run_audit(chain, related_pulls=related)
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.PREV[:7]} on main is not associated", output)

    def test_commits_outside_the_first_parent_chain_are_not_audited(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.DIRECT, (), "governance: loosen a check"),
                 self.commit(self.SIDE, (self.DIRECT,), "wip: never reached main alone")]
        code, output = self.run_audit(chain)
        self.assertEqual(code, 2)
        self.assertNotIn(self.SIDE[:7], output)

    def test_acknowledged_direct_push_is_recorded_without_a_violation(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.DIRECT, (), "governance: suspend required CI")]
        policy = {"audit_acknowledged_direct": {self.DIRECT: "owner decision 2026-11-05"}}
        code, output = self.run_audit(chain, policy, policy_ref="refs/tags/trusted")
        self.assertEqual(code, 0)
        self.assertIn(f"note: acknowledged direct push {self.DIRECT[:7]}: owner decision", output)

    def test_policy_can_relax_the_direct_push_audit(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.DIRECT, (), "governance: loosen a check")]
        code, output = self.run_audit(chain, {"audit_strict_direct": False})
        self.assertEqual(code, 0)
        self.assertIn(f"warning: {self.DIRECT[:7]} on main is not associated", output)

    def test_backdated_direct_push_outside_audit_since_is_still_audited(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request",
                             date="2026-01-01T00:00:00Z"),
                 self.commit(self.DIRECT, (), "governance: loosen a check",
                             date="2026-01-01T00:00:00Z")]
        code, output = self.run_audit(
            chain,
            {"audit_since": "2026-01-06T00:00:00Z"},
            attributed={self.TIP},
            policy_ref="refs/tags/trusted",
        )
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.DIRECT[:7]} on main is not associated", output)

    def test_backdated_tip_does_not_hide_an_in_window_direct_push(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request",
                             date="2026-01-01T00:00:00Z"),
                 self.commit(self.DIRECT, (), "governance: loosen a check",
                             date="2026-01-05T00:00:00Z")]
        code, output = self.run_audit(
            chain,
            {"audit_since": "2026-01-02T00:00:00Z"},
            attributed={self.TIP},
            policy_ref="refs/tags/trusted",
        )
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.DIRECT[:7]} on main is not associated", output)

    def test_trusted_baseline_sha_bounds_direct_push_walk_without_relying_on_dates(self):
        baseline = "b" * 40
        chain = [self.commit(self.TIP, (baseline,), "feat: via pull request",
                             date="2026-01-01T00:00:00Z"),
                 self.commit(baseline, (), "chore: historical direct commit before adoption")]
        code, _ = self.run_audit(
            chain,
            {"audit_since": "2026-01-06T00:00:00Z", "audit_baseline_sha": baseline},
            attributed={self.TIP},
            policy_ref="refs/tags/trusted",
        )
        self.assertEqual(code, 0)

        bypass_chain = [
            self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
            self.commit(self.DIRECT, (baseline,), "direct push after baseline", date="2026-01-01T00:00:00Z"),
            self.commit(baseline, (), "chore: historical direct commit before adoption"),
        ]
        code, output = self.run_audit(
            bypass_chain,
            {"audit_since": "2026-01-06T00:00:00Z", "audit_baseline_sha": baseline},
            attributed={self.TIP},
            policy_ref="refs/tags/trusted",
        )
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.DIRECT[:7]} on main is not associated", output)

    def test_audit_detects_force_push_rollback_via_ancestry_and_activity(self):
        m1 = "1" * 40
        m2 = "2" * 40
        pr1 = {
            "number": 1,
            "merged_at": "2026-01-05T00:00:00Z",
            "base": {"ref": "main"},
            "head": {"sha": "a" * 40},
            "merge_commit_sha": m1,
        }
        pr2 = {
            "number": 2,
            "merged_at": "2026-01-06T00:00:00Z",
            "base": {"ref": "main"},
            "head": {"sha": "b" * 40},
            "merge_commit_sha": m2,
        }

        def make_verdict(number, head_sha, merge_sha):
            payload = {
                "repo": "o/r",
                "pr": number,
                "head_sha": head_sha,
                "merge_sha": merge_sha,
                "verdict": "pass",
                "merged": True,
            }
            return {"user": {"login": "synthetic-owner"}, "body": "<!-- governance-verdict:v1 " + json.dumps(payload) + " -->"}

        # 1. Main rolled back from PR #2 (m2) to older gate-approved PR #1 (m1), even with empty /activity.
        def rollback_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pr2, pr1] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return [self.commit(m1, (), "feat: pr 1")]
            if path == f"/repos/o/r/compare/{m2}...{m1}":
                return {"status": "behind", "merge_base_commit": {"sha": m1}}
            return []

        def rollback_paginate(path, params=None):
            if path == "/repos/o/r/issues/1/comments":
                return [make_verdict(1, pr1["head"]["sha"], m1)]
            if path == "/repos/o/r/issues/2/comments":
                return [make_verdict(2, pr2["head"]["sha"], m2)]
            return []

        def clean_raw(*a, **k):
            self.assertEqual(a[1], "/repos/o/r/activity")
            return ([], {})

        captured = io.StringIO()
        with mock.patch.object(gate, "request", rollback_request), \
             mock.patch.object(gate, "paginate", rollback_paginate), \
             mock.patch.object(gate, "_raw_request", clean_raw), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: {"owner_login": "synthetic-owner"}), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True, policy_ref="refs/tags/trusted")
        self.assertEqual(code, 2)
        self.assertIn(f"#2 merge commit {m2[:7]} is no longer an ancestor of main", captured.getvalue())
        self.assertNotIn("cannot verify force-push activity", captured.getvalue())

        # 2. Cursor-paginated /activity force_push is caught even when all listed PRs match current main tip.
        def single_pr_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pr1] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return [self.commit(m1, (), "feat: pr 1")]
            if path == f"/repos/o/r/commits/{m1}/pulls":
                return [pr1]
            return []

        def paged_activity_raw(method, path, body=None, params=None, allow=()):
            self.assertEqual(path, "/repos/o/r/activity")
            if "after" not in (params or {}):
                return (
                    [{"id": 5001, "activity_type": "pr_merge", "ref": "refs/heads/main", "before": "0" * 40, "after": m2, "timestamp": "2026-01-06T00:00:00Z"}],
                    {"link": '<https://api.github.com/repos/o/r/activity?ref=refs%2Fheads%2Fmain&per_page=100&after=cur2>; rel="next"'},
                )
            self.assertEqual(params["after"], "cur2")
            return (
                [{"id": 5002, "activity_type": "force_push", "ref": "refs/heads/main", "before": m2, "after": m1, "timestamp": "2026-01-07T00:00:00Z"}],
                {},
            )

        captured = io.StringIO()
        with mock.patch.object(gate, "request", single_pr_request), \
             mock.patch.object(gate, "paginate", rollback_paginate), \
             mock.patch.object(gate, "_raw_request", paged_activity_raw), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: {"owner_login": "synthetic-owner"}), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True, policy_ref="refs/tags/trusted")
        self.assertEqual(code, 2)
        self.assertIn(f"force push on main (activity 5002: {m2[:7]}..{m1[:7]})", captured.getvalue())

        # Trusted policy acknowledgment by activity ID or audit_since after the event clears it.
        for trusted_override in (
            {"audit_acknowledged_direct": {"5002": "approved rollback"}},
            {"audit_since": "2026-01-08T00:00:00Z"},
        ):
            with self.subTest(trusted_override=trusted_override):
                policy = {"owner_login": "synthetic-owner", **trusted_override}
                with mock.patch.object(gate, "request", single_pr_request), \
                     mock.patch.object(gate, "paginate", rollback_paginate), \
                     mock.patch.object(gate, "_raw_request", paged_activity_raw), \
                     mock.patch.object(gate, "load_policy", lambda *a, **k: policy), \
                     mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.audit("o/r", 20, True, policy_ref="refs/tags/trusted"), 0)

        # 3. Baseline SHA rewound past baseline is detected via ancestry check.
        baseline = "b" * 40
        older = "c" * 40
        baseline_chain = [self.commit(older, (), "old ancestor before baseline")]
        details = {baseline: self.commit(baseline, (older,), "baseline commit")}
        code, output = self.run_audit(
            baseline_chain,
            {"audit_baseline_sha": baseline},
            details=details,
            attributed={older},
            policy_ref="refs/tags/trusted",
        )
        self.assertEqual(code, 2)
        self.assertIn(f"baseline {baseline[:7]} is no longer an ancestor of main", output)

    def test_strict_audit_fails_closed_when_branch_activity_is_unavailable(self):
        m1 = "1" * 40
        pr1 = {
            "number": 1,
            "merged_at": "2026-01-05T00:00:00Z",
            "updated_at": "2026-01-05T00:00:00Z",
            "base": {"ref": "main"},
            "head": {"sha": "a" * 40},
            "merge_commit_sha": m1,
        }
        verdict = {
            "user": {"login": "synthetic-owner"},
            "body": "<!-- governance-verdict:v1 "
            + json.dumps({
                "repo": "o/r",
                "pr": 1,
                "head_sha": "a" * 40,
                "merge_sha": m1,
                "verdict": "pass",
                "merged": True,
            })
            + " -->",
        }

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pr1] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return [self.commit(m1, (), "feat: pr 1")]
            if path == f"/repos/o/r/commits/{m1}/pulls":
                return [pr1]
            return []

        def unavailable_raw(method, path, body=None, params=None, allow=()):
            self.assertEqual(path, "/repos/o/r/activity")
            return (None, {})

        for strict_arg in (False, True):
            with self.subTest(strict_arg=strict_arg):
                captured = io.StringIO()
                with mock.patch.object(gate, "request", fake_request), \
                     mock.patch.object(gate, "paginate", lambda path, params=None: [verdict]), \
                     mock.patch.object(gate, "_raw_request", unavailable_raw), \
                     mock.patch.object(gate, "load_policy", lambda *a, **k: {"owner_login": "synthetic-owner"}), \
                     mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
                     contextlib.redirect_stdout(captured):
                    code = gate.audit("o/r", 20, strict_arg)
                self.assertEqual(code, 2)
                self.assertIn(
                    "violation: cannot verify force-push activity on main; branch activity log is unavailable",
                    captured.getvalue(),
                )

        relaxed_out = io.StringIO()
        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [verdict]), \
             mock.patch.object(gate, "_raw_request", unavailable_raw), \
             mock.patch.object(
                 gate,
                 "load_policy",
                 lambda *a, **k: {"owner_login": "synthetic-owner", "audit_strict_direct": False},
             ), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(relaxed_out):
            code = gate.audit("o/r", 20, False, policy_ref="refs/tags/trusted")
        self.assertEqual(code, 0)
        self.assertIn(
            "warning: cannot verify force-push activity on main; branch activity log is unavailable",
            relaxed_out.getvalue(),
        )

    def test_invalid_audit_baseline_sha_fails(self):
        chain = [self.commit(self.TIP, (), "feat: via pull request")]
        code, output = self.run_audit(chain, {"audit_baseline_sha": "abc123"}, attributed={self.TIP})
        self.assertEqual(code, 2)
        self.assertIn("audit_baseline_sha in policy is invalid", output)

    def test_ancestor_missing_from_the_listing_is_fetched_directly(self):
        # A merge that pulled in a long branch fills the recent listing with
        # side-branch commits; the chain behind the tip is then absent from it.
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.SIDE, (self.DIRECT,), "wip: side branch commit")]
        details = {self.DIRECT: self.commit(self.DIRECT, (), "governance: loosen a check")}
        code, output = self.run_audit(chain, details=details)
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.DIRECT[:7]} on main is not associated", output)

    def test_unresolvable_ancestor_reports_an_incomplete_audit(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request")]
        code, output = self.run_audit(chain)
        self.assertEqual(code, 2)
        self.assertIn(f"{self.DIRECT[:7]} on main could not be resolved", output)

    def _rich_commit(
        self, sha, parents, message, email="dev@example.com", date="2026-01-05T00:00:00Z", tree_sha=None, files=None
    ):
        commit_obj = {
            "message": message,
            "author": {"email": email, "date": date},
            "committer": {"date": date},
        }
        if tree_sha is not None:
            commit_obj["tree"] = {"sha": tree_sha}
        entry = {
            "sha": sha,
            "parents": [{"sha": p} for p in parents],
            "commit": commit_obj,
        }
        if files is not None:
            entry["files"] = files
        return entry

    def test_multi_commit_rebase_merge_commits_are_not_direct_pushes(self):
        root = "0" * 40
        r_old_1 = "1" * 40
        r_old_2 = "2" * 40
        r1 = "3" * 40
        r2 = "4" * 40
        pre_base = "6" * 40
        orig_old_1 = "e" * 40
        orig_old_2 = "f" * 40
        orig_1 = "7" * 40
        orig_2 = "8" * 40
        orig_3 = "9" * 40
        t_old_1 = "a1" * 20
        t_old_2 = "a2" * 20

        chain = [
            self._rich_commit(self.TIP, (r2,), "feat: step 3", date="2026-01-05T03:00:00Z"),
            self._rich_commit(r2, (r1,), "feat: step 2", date="2026-01-05T02:00:00Z"),
            self._rich_commit(r1, (r_old_2,), "feat: step 1", date="2026-01-05T01:00:00Z"),
            self._rich_commit(r_old_2, (r_old_1,), "fix: old 2", date="2026-01-04T02:00:00Z", tree_sha=t_old_2),
            self._rich_commit(r_old_1, (root,), "fix: old 1", date="2026-01-04T01:00:00Z", tree_sha=t_old_1),
            self._rich_commit(root, (), "chore: root", date="2026-01-03T00:00:00Z"),
        ]
        pull_7 = {
            "number": 7,
            "merged_at": self.DATE,
            "base": {"ref": "main", "sha": r_old_2},
            "head": {"sha": orig_3},
            "merge_commit_sha": self.TIP,
            "commits": 3,
        }
        pull_6 = {
            "number": 6,
            "merged_at": "2026-01-04T03:00:00Z",
            "base": {"ref": "main", "sha": root},
            "head": {"sha": orig_old_2},
            "merge_commit_sha": r_old_2,
            "commits": 2,
        }
        pr_commits = {
            7: [
                self._rich_commit(orig_1, (pre_base,), "feat: step 1", date="2026-01-05T01:00:00Z"),
                self._rich_commit(orig_2, (orig_1,), "feat: step 2", date="2026-01-05T02:00:00Z"),
                self._rich_commit(orig_3, (orig_2,), "feat: step 3", date="2026-01-05T03:00:00Z"),
            ],
            6: [
                self._rich_commit(orig_old_1, (root,), "fix: old 1", date="2026-01-04T01:00:00Z", tree_sha=t_old_1),
                self._rich_commit(orig_old_2, (orig_old_1,), "fix: old 2", date="2026-01-04T02:00:00Z", tree_sha=t_old_2),
            ],
        }
        verdict_7 = {
            "user": {"login": "synthetic-owner"},
            "body": "<!-- governance-verdict:v1 "
            + json.dumps({
                "repo": "o/r",
                "pr": 7,
                "head_sha": orig_3,
                "merge_sha": self.TIP,
                "merge_method": "rebase",
                "verdict": "pass",
                "merged": True,
            })
            + " -->",
        }

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pull_7] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return chain
            if path == f"/repos/o/r/commits/{r_old_2}/pulls":
                return [pull_6]
            if path == f"/repos/o/r/commits/{root}/pulls":
                return [{"merged_at": "2026-01-03T00:00:00Z", "base": {"ref": "main"}, "merge_commit_sha": root}]
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                return []
            if path == "/repos/o/r/pulls/7/commits":
                return pr_commits[7] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/pulls/6/commits":
                return pr_commits[6] if params and params.get("page") == 1 else []
            return []

        captured = io.StringIO()
        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [verdict_7]), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: {"owner_login": "synthetic-owner"}), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True)
        self.assertEqual(code, 0, captured.getvalue())
        self.assertIn("no violations", captured.getvalue())

    def test_unknown_merge_method_requires_content_proof_and_rejects_squash_forgery(self):
        root = "0" * 40
        direct_forged = "1" * 40
        squash_forged = "2" * 40
        r1 = "3" * 40
        r2 = "4" * 40
        p0 = "7" * 40
        p1 = "8" * 40
        file_a = [{"filename": "a.py", "status": "modified", "additions": 1, "deletions": 0, "changes": 1, "patch": "+a"}]
        file_b = [{"filename": "b.py", "status": "modified", "additions": 1, "deletions": 0, "changes": 1, "patch": "+b"}]
        file_evil = [{"filename": "evil.py", "status": "added", "additions": 1, "deletions": 0, "changes": 1, "patch": "+x"}]

        # Case 1: outside-window PR discovered via /commits/{sha}/pulls (merge_method=None)
        # cannot exempt a direct push whose commit message/author metadata mimic P0.
        forged_chain = [
            self._rich_commit(squash_forged, (direct_forged,), "feat: step 2", date="2026-01-05T02:00:00Z"),
            self._rich_commit(direct_forged, (root,), "feat: step 1", date="2026-01-05T01:00:00Z"),
            self._rich_commit(root, (), "chore: root"),
        ]
        pull_outside = {
            "number": 9,
            "merged_at": self.DATE,
            "base": {"ref": "main", "sha": root},
            "head": {"sha": p1},
            "merge_commit_sha": squash_forged,
            "commits": 2,
        }
        pr9_commits = [
            self._rich_commit(p0, ("6" * 40,), "feat: step 1", date="2026-01-05T01:00:00Z"),
            self._rich_commit(p1, (p0,), "feat: step 2", date="2026-01-05T02:00:00Z"),
        ]
        details_forged = {
            squash_forged: self._rich_commit(squash_forged, (direct_forged,), "feat: step 2", date="2026-01-05T02:00:00Z", files=file_a + file_b),
            direct_forged: self._rich_commit(direct_forged, (root,), "feat: step 1", date="2026-01-05T01:00:00Z", files=file_evil),
            p0: self._rich_commit(p0, ("6" * 40,), "feat: step 1", date="2026-01-05T01:00:00Z", files=file_a),
            p1: self._rich_commit(p1, (p0,), "feat: step 2", date="2026-01-05T02:00:00Z", files=file_b),
        }

        def request_case1(method, path, body=None, params=None, allow=()):
            if path == f"/repos/o/r/commits/{squash_forged}/pulls":
                return [pull_outside]
            if path == f"/repos/o/r/commits/{root}/pulls":
                return [{"merged_at": self.DATE, "base": {"ref": "main"}, "merge_commit_sha": root}]
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                return []
            if path.startswith("/repos/o/r/commits/"):
                sha = path.rsplit("/", 1)[-1]
                return details_forged.get(sha)
            if path == "/repos/o/r/pulls/9/commits":
                return pr9_commits if params and params.get("page") == 1 else []
            return []

        with mock.patch.object(gate, "request", request_case1):
            findings = gate.scan_direct_pushes("o/r", "main", set(), {}, True, 20, listing=forged_chain)
        self.assertEqual(len(findings), 1)
        self.assertIn(direct_forged[:7], findings[0])

        # Case 2: outside-window PR with authenticated squash verdict is rejected immediately.
        p_base = "6" * 40
        t_root, t_r1, t_r2 = "a0" * 20, "a1" * 20, "a2" * 20
        t_p_base, t_p0, t_p1 = "b0" * 20, "b1" * 20, "b2" * 20
        blob_sha = "c" * 40
        valid_tree_chain = [
            self._rich_commit(r2, (r1,), "feat: step 2", date="2026-01-05T02:00:00Z", tree_sha=t_r2),
            self._rich_commit(r1, (root,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_r1),
            self._rich_commit(root, (), "chore: root", tree_sha=t_root),
        ]
        pr9_tree_commits = [
            self._rich_commit(p0, (p_base,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_p0),
            self._rich_commit(p1, (p0,), "feat: step 2", date="2026-01-05T02:00:00Z", tree_sha=t_p1),
        ]
        rebased_pull = {**pull_outside, "merge_commit_sha": r2}
        rebased_details = {
            root: valid_tree_chain[2],
            p_base: self._rich_commit(p_base, (), "chore: other base", tree_sha=t_p_base),
            r1: self._rich_commit(r1, (root,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_r1, files=file_a),
            r2: self._rich_commit(r2, (r1,), "feat: step 2", date="2026-01-05T02:00:00Z", tree_sha=t_r2, files=file_b),
            p0: self._rich_commit(p0, (p_base,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_p0, files=file_a),
            p1: self._rich_commit(p1, (p0,), "feat: step 2", date="2026-01-05T02:00:00Z", tree_sha=t_p1, files=file_b),
        }
        trees = {
            sha: {
                "truncated": False,
                "tree": [
                    {"path": "a.py", "type": "blob", "mode": "100644", "sha": blob_sha},
                    {"path": "b.py", "type": "blob", "mode": "100644", "sha": blob_sha},
                ],
            }
            for sha in (t_root, t_r1, t_r2, t_p_base, t_p0, t_p1)
        }

        def request_case2(method, path, body=None, params=None, allow=()):
            if path == f"/repos/o/r/commits/{r2}/pulls":
                return [rebased_pull]
            if path == f"/repos/o/r/commits/{root}/pulls":
                return [{"merged_at": self.DATE, "base": {"ref": "main"}, "merge_commit_sha": root}]
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                return []
            if path.startswith("/repos/o/r/commits/"):
                return rebased_details.get(path.rsplit("/", 1)[-1])
            if path.startswith("/repos/o/r/git/trees/"):
                return trees.get(path.rsplit("/", 1)[-1])
            if path == "/repos/o/r/pulls/9/commits":
                return pr9_tree_commits if params and params.get("page") == 1 else []
            return []

        squash_comment_for_rebased = {
            "user": {"login": "synthetic-owner"},
            "body": "<!-- governance-verdict:v1 "
            + json.dumps({
                "repo": "o/r",
                "pr": 9,
                "head_sha": p1,
                "merge_sha": r2,
                "merge_method": "squash",
                "verdict": "pass",
                "merged": True,
            })
            + " -->",
        }
        with mock.patch.object(gate, "request", request_case2), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [squash_comment_for_rebased]):
            findings = gate.scan_direct_pushes(
                "o/r", "main", set(), {}, True, 20, listing=valid_tree_chain, signers={"synthetic-owner"}
            )
        self.assertEqual(len(findings), 1)
        self.assertIn(r1[:7], findings[0])

        # Case 3: outside-window PR with unknown method passes when diffs and tree modes match.
        with mock.patch.object(gate, "request", request_case2), \
             mock.patch.object(gate, "paginate", lambda path, params=None: []):
            findings = gate.scan_direct_pushes(
                "o/r", "main", set(), {}, True, 20, listing=valid_tree_chain, signers={"synthetic-owner"}
            )
        self.assertEqual(findings, [])

        # Case 4: truncated/missing patches, mode changes (100644 -> 100755), or missing trees fail closed.
        truncated = [{"filename": "a.py", "status": "modified", "additions": 2, "deletions": 0, "changes": 2, "patch": "@@ -1 +1,2 @@\n+a"}]
        missing_patch = [{"filename": "a.py", "status": "modified", "additions": 1, "deletions": 0, "changes": 1, "patch": None}]
        for bad_files in (truncated, missing_patch):
            bad_details = {
                **rebased_details,
                r1: self._rich_commit(r1, (root,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_r1, files=bad_files),
                p0: self._rich_commit(p0, (p_base,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_p0, files=bad_files),
            }

            def bad_request(method, path, body=None, params=None, allow=(), _details=bad_details):
                if path.startswith("/repos/o/r/commits/") and not path.endswith("/pulls"):
                    return _details.get(path.rsplit("/", 1)[-1])
                return request_case2(method, path, body=body, params=params, allow=allow)

            with mock.patch.object(gate, "request", bad_request), \
                 mock.patch.object(gate, "paginate", lambda path, params=None: []):
                findings = gate.scan_direct_pushes(
                    "o/r", "main", set(), {}, True, 20, listing=valid_tree_chain, signers={"synthetic-owner"}
                )
            self.assertEqual(len(findings), 1)
            self.assertIn(r1[:7], findings[0])

        chmod_trees = {
            **trees,
            t_r1: {
                "truncated": False,
                "tree": [{"path": "a.py", "type": "blob", "mode": "100755", "sha": blob_sha}],
            },
        }
        missing_trees = {**trees, t_r1: None}
        for bad_trees in (chmod_trees, missing_trees):
            def tree_request(method, path, body=None, params=None, allow=(), _trees=bad_trees):
                if path.startswith("/repos/o/r/git/trees/"):
                    return _trees.get(path.rsplit("/", 1)[-1])
                return request_case2(method, path, body=body, params=params, allow=allow)

            with mock.patch.object(gate, "request", tree_request), \
                 mock.patch.object(gate, "paginate", lambda path, params=None: []):
                findings = gate.scan_direct_pushes(
                    "o/r", "main", set(), {}, True, 20, listing=valid_tree_chain, signers={"synthetic-owner"}
                )
            self.assertEqual(len(findings), 1)
            self.assertIn(r1[:7], findings[0])

        # Case 5: truncated recursive trees fall back cleanly to segment-by-segment lookup.
        sub_tree = "d1" * 20
        dir_file = [{"filename": "dir/a.py", "status": "modified", "additions": 1, "deletions": 0, "changes": 1, "patch": "+a"}]
        dir_details = {
            **rebased_details,
            r1: self._rich_commit(r1, (root,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_r1, files=dir_file),
            p0: self._rich_commit(p0, (p_base,), "feat: step 1", date="2026-01-05T01:00:00Z", tree_sha=t_p0, files=dir_file),
        }

        def trunc_request(method, path, body=None, params=None, allow=()):
            if path.startswith("/repos/o/r/commits/") and not path.endswith("/pulls"):
                return dir_details.get(path.rsplit("/", 1)[-1])
            if path == f"/repos/o/r/git/trees/{t_r1}" and params == {"recursive": "1"}:
                return {"truncated": True, "tree": []}
            if path == f"/repos/o/r/git/trees/{t_r1}" and not params:
                return {
                    "truncated": False,
                    "tree": [
                        {"path": "dir", "type": "tree", "mode": "040000", "sha": sub_tree},
                        {"path": "b.py", "type": "blob", "mode": "100644", "sha": blob_sha},
                    ],
                }
            if path == f"/repos/o/r/git/trees/{sub_tree}" and not params:
                return {"truncated": False, "tree": [{"path": "a.py", "type": "blob", "mode": "100644", "sha": blob_sha}]}
            if path.startswith("/repos/o/r/git/trees/"):
                return {
                    "truncated": False,
                    "tree": [{"path": "dir/a.py", "type": "blob", "mode": "100644", "sha": blob_sha}, {"path": "b.py", "type": "blob", "mode": "100644", "sha": blob_sha}],
                }
            return request_case2(method, path, body=body, params=params, allow=allow)

        with mock.patch.object(gate, "request", trunc_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: []):
            findings = gate.scan_direct_pushes(
                "o/r", "main", set(), {}, True, 20, listing=valid_tree_chain, signers={"synthetic-owner"}
            )
        self.assertEqual(findings, [])

        # Case 6: outside-window PR whose base.sha is a later first-parent commit than
        # base_parent fails closed even when audit populates the tip-wide first_parent set.
        later_base_pull = {**rebased_pull, "base": {"ref": "main", "sha": r2}}
        for unindexed_root in (False, True):
            chain_c6 = valid_tree_chain[:-1] if unindexed_root else valid_tree_chain

            def base_fwd_request(method, path, body=None, params=None, allow=(), _root=unindexed_root):
                if path == f"/repos/o/r/commits/{r2}/pulls":
                    return [later_base_pull]
                if _root and path == f"/repos/o/r/compare/{r2}...{root}":
                    return {"status": "behind", "merge_base_commit": {"sha": root}}
                if _root and path == f"/repos/o/r/commits/{root}":
                    return valid_tree_chain[2]
                return request_case2(method, path, body=body, params=params, allow=allow)

            with mock.patch.object(gate, "request", base_fwd_request), \
                 mock.patch.object(gate, "paginate", lambda path, params=None: []):
                fp = gate._first_parent_shas(valid_tree_chain)
                findings = gate.scan_direct_pushes(
                    "o/r", "main", set(), {}, True, 20,
                    listing=chain_c6, first_parent=fp, signers={"synthetic-owner"},
                )
            self.assertEqual(len(findings), 1)
            self.assertIn(r1[:7], findings[0])

    def test_squash_or_divergent_rebase_does_not_exempt_parent_commits(self):
        r1 = "3" * 40
        unrelated = "5" * 40
        chain = [
            self._rich_commit(self.TIP, (r1,), "feat: step 2", date="2026-01-05T02:00:00Z"),
            self._rich_commit(r1, (self.PREV,), "feat: step 1", date="2026-01-05T01:00:00Z"),
            self._rich_commit(self.PREV, (), "chore: prev"),
        ]
        pull_7 = {
            "number": 7,
            "merged_at": self.DATE,
            "base": {"ref": "main", "sha": self.PREV},
            "head": {"sha": "8" * 40},
            "merge_commit_sha": self.TIP,
            "commits": 2,
        }
        pr_commits = [
            self._rich_commit("7" * 40, (), "feat: step 1", date="2026-01-05T01:00:00Z"),
            self._rich_commit("8" * 40, ("7" * 40,), "feat: step 2", date="2026-01-05T02:00:00Z"),
        ]
        squash_verdict = {
            "user": {"login": "synthetic-owner"},
            "body": "<!-- governance-verdict:v1 "
            + json.dumps({
                "repo": "o/r",
                "pr": 7,
                "head_sha": "8" * 40,
                "merge_sha": self.TIP,
                "merge_method": "squash",
                "verdict": "pass",
                "merged": True,
            })
            + " -->",
        }

        def make_request(pull_obj):
            def fake_request(method, path, body=None, params=None, allow=()):
                if path == "/repos/o/r":
                    return {"default_branch": "main"}
                if path == "/repos/o/r/pulls":
                    return [pull_obj] if params and params.get("page") == 1 else []
                if path == "/repos/o/r/commits":
                    return chain
                if path == "/repos/o/r/pulls/7/commits":
                    return pr_commits if params and params.get("page") == 1 else []
                if path == f"/repos/o/r/commits/{self.PREV}/pulls":
                    return [{"merged_at": self.DATE, "base": {"ref": "main"}, "merge_commit_sha": self.PREV}]
                if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                    return []
                return []
            return fake_request

        captured = io.StringIO()
        with mock.patch.object(gate, "request", make_request(pull_7)), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [squash_verdict]), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: {"owner_login": "synthetic-owner"}), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True)
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {r1[:7]} on main is not associated", captured.getvalue())

        bad_base_pull = {**pull_7, "base": {"ref": "main", "sha": unrelated}}
        rebase_verdict = {
            "user": {"login": "synthetic-owner"},
            "body": "<!-- governance-verdict:v1 "
            + json.dumps({
                "repo": "o/r",
                "pr": 7,
                "head_sha": "8" * 40,
                "merge_sha": self.TIP,
                "merge_method": "rebase",
                "verdict": "pass",
                "merged": True,
            })
            + " -->",
        }
        captured = io.StringIO()
        with mock.patch.object(gate, "request", make_request(bad_base_pull)), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [rebase_verdict]), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: {"owner_login": "synthetic-owner"}), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True)
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {r1[:7]} on main is not associated", captured.getvalue())

    def test_post_baseline_rollback_followed_by_restore_is_caught(self):
        baseline = "b" * 40
        post = "1" * 40
        older = "c" * 40
        earliest = "e" * 40
        chain = [
            self.commit(self.TIP, (post,), "feat: restored tip"),
            self.commit(post, (baseline,), "feat: post-baseline commit"),
            self.commit(baseline, (older,), "chore: baseline"),
            self.commit(older, (earliest,), "chore: older"),
            self.commit(earliest, (), "chore: earliest"),
        ]
        post_baseline_rollback = {
            "id": 9002,
            "activity_type": "force_push",
            "ref": "refs/heads/main",
            "before": post,
            "after": older,
            "timestamp": "2026-01-07T00:00:00Z",
        }
        restore_push = {
            "id": 9003,
            "activity_type": "push",
            "ref": "refs/heads/main",
            "before": older,
            "after": self.TIP,
            "timestamp": "2026-01-08T00:00:00Z",
        }
        code, output = self.run_audit(
            chain,
            {"audit_baseline_sha": baseline},
            attributed={self.TIP, post},
            policy_ref="refs/tags/trusted",
            activities=[restore_push, post_baseline_rollback],
        )
        self.assertEqual(code, 2)
        self.assertIn(f"force push on main (activity 9002: {post[:7]}..{older[:7]})", output)

        pre_baseline_reset = {
            "id": 9004,
            "activity_type": "force_push",
            "ref": "refs/heads/main",
            "before": older,
            "after": earliest,
            "timestamp": "2026-01-02T00:00:00Z",
        }
        code_pre, output_pre = self.run_audit(
            chain,
            {"audit_baseline_sha": baseline},
            attributed={self.TIP, post},
            policy_ref="refs/tags/trusted",
            activities=[pre_baseline_reset],
        )
        self.assertEqual(code_pre, 0, output_pre)


class MergeSignerTests(unittest.TestCase):
    HEAD = "a" * 40
    BASE = "c" * 40
    MERGE = "b" * 40

    def _fixtures(self, policy):
        pull = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": self.HEAD, "ref": "feat/x", "repo": {"full_name": "o/r"}},
            "base": {"ref": "main"},
            "user": {"login": "contributor"},
            "changed_files": 1,
            "body": "",
            "labels": [],
        }
        app_file = {
            "filename": "app.py",
            "status": "modified",
            "additions": 1,
            "deletions": 0,
            "changes": 1,
            "patch": "@@ -1 +1 @@\n+one\n",
        }
        claude_comment = {
            "user": {"login": "claude[bot]"},
            "updated_at": "2026-11-14T09:00:00Z",
            "body": '<!-- ai-review-receipt:v1 {"review":{"provider":"claude","commit_sha":"'
            + self.HEAD
            + '","status":"completed","unresolved_findings":0,"coverage":"complete"}} -->',
        }
        tree_payload = {
            "truncated": False,
            "tree": [{"path": "app.py", "mode": "100644", "type": "blob"}],
        }
        verdict = {
            "repo": "o/r",
            "pr": 7,
            "head_sha": self.HEAD,
            "base_ref": "main",
            "policy_ref": "main",
            "base_sha": self.BASE,
            "tier": "T1",
            "codex": "success",
            "review_providers": ["claude"],
            "label": None,
            "confirmed_by_owner": False,
            "checks": "skipped",
            "required_checks": [],
            "checks_note": "not required by policy",
            "bootstrap": False,
            "body_sha256": gate.hashlib.sha256(b"").hexdigest(),
            "policy_sha256": policy["_sha256"],
            "verdict": "pass",
            "reasons": [],
            "unscanned": [],
            "merge_method": "squash",
        }
        return pull, app_file, claude_comment, tree_payload, verdict

    def test_merge_refuses_unauthorized_or_unidentified_caller_before_put(self):
        base_policy = {
            "owner_login": "owner",
            "codex_required": False,
            "ai_review_providers": ["claude"],
            "require_checks": False,
            "_source": "main",
            "_sha256": "p-signer",
        }
        pull, app_file, claude_comment, tree_payload, verdict = self._fixtures(base_policy)

        for label, user_response, policy_override in (
            ("collaborator", {"login": "collaborator"}, {}),
            ("missing_login", {}, {}),
            ("empty_login", {"login": "   "}, {}),
            ("non_dict", None, {}),
            ("api_error", gate.ApiError(403, "Resource not accessible by integration"), {}),
            ("no_policy_signer", {"login": "owner"}, {"owner_login": ""}),
        ):
            with self.subTest(case=label):
                calls = []
                active_policy = {**base_policy, **policy_override}

                def fake_request(method, path, body=None, params=None, allow=()):
                    calls.append((method, path))
                    if path == "/repos/o/r/pulls/7":
                        return pull
                    if path == "/user":
                        if isinstance(user_response, Exception):
                            raise user_response
                        return user_response
                    if path == "/repos/o/r/pulls/7/merge":
                        raise AssertionError("PUT merge must not be issued for invalid verdict signer")
                    return None

                def fake_paginate(path, params=None):
                    if path.endswith("/comments"):
                        return [claude_comment]
                    return []

                with mock.patch.object(gate, "request", side_effect=fake_request), \
                     mock.patch.object(gate, "load_policy", return_value=active_policy), \
                     mock.patch.object(gate, "verify_script", return_value=None), \
                     mock.patch.object(gate, "head_contains_base", return_value=(True, self.BASE)), \
                     mock.patch.object(gate, "shared_head", return_value=False), \
                     mock.patch.object(gate, "paginate", side_effect=fake_paginate):
                    with self.assertRaises(gate.Refusal):
                        gate.merge("o/r", dict(verdict))
                self.assertFalse(any(m == "PUT" and p.endswith("/merge") for m, p in calls))

        # CLI: --dry-run does not require /user, while non-dry-run refuses collaborator before PUT /merge.
        cli_calls = []

        def cli_request(method, path, body=None, params=None, allow=()):
            cli_calls.append((method, path))
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls/7":
                return pull
            if path == "/repos/o/r/branches/main":
                return {"commit": {"sha": self.BASE}}
            if path == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                return {"merge_base_commit": {"sha": self.BASE}, "files": [app_file]}
            if path == f"/repos/o/r/git/trees/{self.HEAD}":
                return tree_payload
            if path == "/user":
                return {"login": "collaborator"}
            if path == "/repos/o/r/pulls/7/merge":
                raise AssertionError("CLI merge must not execute PUT /merge for collaborator")
            return None

        def cli_paginate(path, params=None):
            if path.endswith("/comments"):
                return [claude_comment]
            return []

        with mock.patch.object(gate, "request", side_effect=cli_request), \
             mock.patch.object(gate, "load_policy", return_value=base_policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "paginate", side_effect=cli_paginate):
            dry_out = io.StringIO()
            with mock.patch.object(gate.sys, "argv", ["merge_gate.py", "--repo", "o/r", "--pr", "7", "--dry-run"]), \
                 contextlib.redirect_stdout(dry_out):
                self.assertEqual(gate.main(), 0)
            self.assertFalse(any(p == "/user" for _, p in cli_calls))

            err = io.StringIO()
            with mock.patch.object(gate.sys, "argv", ["merge_gate.py", "--repo", "o/r", "--pr", "7"]), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(gate.main(), 2)
            self.assertIn("not an audit-accepted verdict signer", err.getvalue())
            self.assertFalse(any(m == "PUT" and p.endswith("/merge") for m, p in cli_calls))

    def test_merge_and_audit_share_verdict_signers_policy(self):
        policy = {
            "owner_login": "owner",
            "verdict_signers": ["release-bot"],
            "codex_required": False,
            "ai_review_providers": ["claude"],
            "require_checks": False,
            "audit_since": "",
            "audit_ignore_prs": [],
            "_source": "main",
            "_sha256": "p-signer",
        }
        pull, _, claude_comment, _, verdict = self._fixtures(policy)

        for caller_login in ("owner", "release-bot"):
            with self.subTest(caller=caller_login):
                posted = []

                def merge_request(method, path, body=None, params=None, allow=()):
                    if path == "/repos/o/r/pulls/7":
                        return pull
                    if path == "/user":
                        return {"login": caller_login}
                    if method == "PUT" and path == "/repos/o/r/pulls/7/merge":
                        return {"merged": True, "sha": self.MERGE}
                    if method == "POST" and path == "/repos/o/r/issues/7/comments":
                        posted.append(body["body"])
                        return {"id": 1}
                    return None

                with mock.patch.object(gate, "request", side_effect=merge_request), \
                     mock.patch.object(gate, "load_policy", return_value=policy), \
                     mock.patch.object(gate, "verify_script", return_value=None), \
                     mock.patch.object(gate, "head_contains_base", return_value=(True, self.BASE)), \
                     mock.patch.object(gate, "shared_head", return_value=False), \
                     mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: [claude_comment] if p.endswith("/comments") else []):
                    result = gate.merge("o/r", dict(verdict))
                self.assertEqual(result["sha"], self.MERGE)
                self.assertEqual(len(posted), 1)

                merged_pull = {
                    "number": 7,
                    "merged_at": "2026-11-14T10:00:00Z",
                    "base": {"ref": "main"},
                    "head": {"sha": self.HEAD},
                    "merge_commit_sha": self.MERGE,
                }
                audit_comments = [{"user": {"login": caller_login}, "body": posted[0]}]

                def audit_request(method, path, body=None, params=None, allow=()):
                    if path == "/repos/o/r":
                        return {"default_branch": "main"}
                    if path == "/repos/o/r/pulls":
                        return [merged_pull] if params and params.get("page") == 1 else []
                    if path == "/repos/o/r/commits":
                        return [{"sha": self.MERGE, "parents": []}]
                    return []

                with mock.patch.object(gate, "request", side_effect=audit_request), \
                     mock.patch.object(gate, "paginate", lambda path, params=None: audit_comments if path.endswith("/comments") else []), \
                     mock.patch.object(gate, "branch_activities", return_value=[]), \
                     mock.patch.object(gate, "load_policy", return_value=policy), \
                     mock.patch.object(gate, "verify_script", return_value=None):
                    self.assertEqual(gate.audit("o/r", 20, False), 0)


if __name__ == "__main__":
    unittest.main()
