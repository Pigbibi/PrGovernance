import contextlib
import importlib.util
import io
import json
import tempfile
import threading
import time
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


def changed(name, patch=None, previous=None, status="modified"):
    entry = {"filename": name, "status": status}
    if patch is not None:
        entry["patch"] = patch
    if previous is not None:
        entry["previous_filename"] = previous
    return entry


REPIN = (
    "@@ -1 +1 @@\n"
    "-      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
    "+      uses: actions/checkout@4f1c2a8d0e9b7c6a5f4e3d2c1b0a9f8e7d6c5b4a\n"
)


class TierTests(unittest.TestCase):
    def test_docs_are_t0(self):
        files = [changed("docs/README.md"), changed("README.md")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T0", False))

    def test_docs_about_protected_topics_stay_t0(self):
        files = [changed("docs/security.md"), changed("docs/deploy-config.md")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T0", False))

    def test_behavioural_instructions_are_not_t0(self):
        for name in ("profiles/agents-portable.md", "skills/quant/SKILL.md", "docs/instructions.md"):
            with self.subTest(name=name):
                self.assertEqual(gate.classify([changed(name)], False, set(), ()), ("T2", False))

    def test_non_prose_files_under_docs_are_not_t0(self):
        for name, expected_tier in (
            ("docs/conf.py", "T1"),
            ("doc/tool.sh", "T1"),
            ("docs/requirements.txt", "T1"),
            ("src/auth/docs/handler.py", "T2"),
            ("docs/deploy.sh", "T2"),
            ("docs/config.yml", "T2"),
        ):
            with self.subTest(name=name):
                self.assertEqual(gate.classify([changed(name)], False, set(), ()), (expected_tier, False))
        renamed = [changed("docs/guide.md", previous="doc/tool.sh", status="renamed")]
        self.assertEqual(gate.classify(renamed, False, set(), ()), ("T1", False))

    def test_added_tests_are_t1(self):
        for name in ("tests/test_reader.py", "tests/reader_test.py", "examples/demo.py"):
            with self.subTest(name=name):
                files = [changed(name, status="added")]
                self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_modified_tests_are_t1(self):
        patch = "@@ -1,2 +1,3 @@\n one\n two\n+three\n"
        files = [changed("tests/test_reader.py", patch)]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_deleted_tests_are_t1(self):
        files = [changed("tests/test_redaction.py", status="removed")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_tests_losing_assertions_are_t1(self):
        patch = "@@ -1,2 +1 @@\n-    self.assertTrue(redacted)\n     pass\n"
        files = [changed("tests/test_redaction.py", patch)]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_renamed_tests_are_t1(self):
        files = [changed("tests/test_new.py", previous="tests/test_old.py", status="renamed")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_skip_test_added_to_an_existing_module_is_t1(self):
        patch = "@@ -1,2 +1,4 @@\n one\n two\n+import unittest\n+raise unittest.SkipTest('disabled')\n"
        files = [changed("tests/test_redaction.py", patch)]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_added_collection_hooks_are_t1(self):
        for name in ("tests/conftest.py", "tests/__init__.py", "tests/pytest.ini"):
            with self.subTest(name=name):
                files = [changed(name, status="added")]
                self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_added_import_shadowing_helpers_are_t1(self):
        for name in ("tests/scripts.py", "tests/helpers.py", "tests/support/util.py"):
            with self.subTest(name=name):
                files = [changed(name, status="added")]
                self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_ordinary_source_is_t1(self):
        files = [changed("sources/wechat/reader.py")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T1", False))

    def test_workflows_are_t2(self):
        files = [changed(".github/workflows/unit-tests.yml", REPIN)]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T2", False))

    def test_renamed_workflow_stays_t2(self):
        files = [changed(".github/workflows/other.yml", previous=".github/workflows/unit-tests.yml")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T2", False))

    def test_runtime_config_and_env_are_t2(self):
        for name in (
            "sources/wechat/config/settings.json",
            ".env.local",
            "deploy/service.yaml",
            "governance/policy.json",
            "app_config.py",
            "sources/job_platform/scripts/check_unattended_config.sh",
            "risk_model/train.py",
        ):
            with self.subTest(name=name):
                self.assertEqual(gate.classify([changed(name)], False, set(), ()), ("T2", False))

    def test_instruction_files_are_t2_in_any_case(self):
        for name in ("AGENTS.md", "CLAUDE.md", "packages/api/AGENTS.md"):
            with self.subTest(name=name):
                self.assertEqual(gate.classify([changed(name)], False, set(), ()), ("T2", False))

    def test_files_below_github_scripts_are_t2(self):
        files = [changed(".github/scripts/check_workflows.py")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T2", False))

    def test_verified_dependabot_repin_takes_fast_path(self):
        files = [changed(".github/workflows/unit-tests.yml", REPIN)]
        allowed = {".github/workflows/unit-tests.yml"}
        self.assertEqual(gate.classify(files, True, allowed, ()), ("T1", True))

    def test_repin_mixed_with_a_manifest_change_is_not_a_fast_path(self):
        files = [
            changed(".github/workflows/unit-tests.yml", REPIN),
            changed("requirements.txt", "@@ -1 +1 @@\n-a==1.0\n+a==1.1\n"),
        ]
        allowed = {".github/workflows/unit-tests.yml"}
        self.assertFalse(gate.classify(files, True, allowed, ())[1])

    def test_changed_action_is_not_a_repin(self):
        patch = (
            "@@ -1 +1 @@\n"
            "-      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "+      uses: actions/upload-artifact@4f1c2a8d0e9b7c6a5f4e3d2c1b0a9f8e7d6c5b4a\n"
        )
        files = [changed(".github/workflows/unit-tests.yml", patch)]
        allowed = {".github/workflows/unit-tests.yml"}
        self.assertEqual(gate.classify(files, True, allowed, ()), ("T2", False))

    def test_dependabot_repin_outside_the_policy_is_t2(self):
        files = [changed(".github/workflows/other.yml", REPIN)]
        allowed = {".github/workflows/unit-tests.yml"}
        self.assertEqual(gate.classify(files, True, allowed, ()), ("T2", False))

    def test_repin_to_a_tag_is_not_a_fast_path(self):
        patch = (
            "@@ -1 +1 @@\n"
            "-      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "+      uses: actions/checkout@v4\n"
        )
        files = [changed(".github/workflows/unit-tests.yml", patch)]
        allowed = {".github/workflows/unit-tests.yml"}
        self.assertEqual(gate.classify(files, True, allowed, ()), ("T2", False))

    def test_repin_with_a_version_comment_takes_the_fast_path(self):
        patch = (
            "@@ -1 +1 @@\n"
            "-      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v4.0.0\n"
            "+      uses: actions/checkout@4f1c2a8d0e9b7c6a5f4e3d2c1b0a9f8e7d6c5b4a # v4.1.0\n"
        )
        files = [changed(".github/workflows/unit-tests.yml", patch)]
        allowed = {".github/workflows/unit-tests.yml"}
        self.assertEqual(gate.classify(files, True, allowed, ()), ("T1", True))

    def test_extra_protected_paths_match_mixed_case_and_normalized_paths_consistently(self):
        extra = ("src/PaymentService/", "docs/RestrictedNote.md", "")
        for name in (
            "src/PaymentService/reader.py",
            "src/payment_service/reader.py",
            "docs/RestrictedNote.md",
        ):
            with self.subTest(protected=name):
                self.assertTrue(gate.is_protected(name, extra))
                self.assertEqual(gate.classify([changed(name)], False, set(), extra), ("T2", False))
        for name, expected_tier in (
            ("src/PaymentServiceExtra/reader.py", "T1"),
            ("docs/public.md", "T0"),
        ):
            with self.subTest(unprotected=name):
                self.assertFalse(gate.is_protected(name, extra))
                self.assertEqual(gate.classify([changed(name)], False, set(), extra), (expected_tier, False))


class SecretTests(unittest.TestCase):
    def test_high_signal_keys_are_found(self):
        files = [changed("app.py", '+key = "ghp_' + "a" * 36 + '"\n')]
        self.assertTrue(gate.scan_secrets(files))

    def test_removed_lines_are_not_scanned(self):
        files = [changed("app.py", '-key = "ghp_' + "a" * 36 + '"\n')]
        self.assertEqual(gate.scan_secrets(files), [])

    def test_placeholders_are_allowed(self):
        files = [changed("README.md", '+key = "ghp_placeholder_xxxx"\n')]
        self.assertEqual(gate.scan_secrets(files), [])

    def test_private_key_header_is_found(self):
        files = [changed("keys.py", "+-----BEGIN " + "RSA PRIVATE KEY-----\n")]
        self.assertTrue(gate.scan_secrets(files))

    def test_placeholder_on_the_same_line_hides_nothing_else(self):
        files = [
            changed(
                "app.py",
                '+placeholder = "example"\n+key = "ghp_' + "a" * 36 + '"\n',
            )
        ]
        self.assertTrue(gate.scan_secrets(files))

    def test_placeholder_value_inside_a_key_is_allowed(self):
        files = [changed("app.py", '+key = "ghp_' + "x" * 36 + '"\n')]
        self.assertEqual(gate.scan_secrets(files), [])

    def test_triple_plus_added_line_is_still_scanned(self):
        files = [changed("app.py", '+++key = "ghp_' + "a" * 36 + '"\n')]
        self.assertTrue(gate.scan_secrets(files))

    def test_unicode_and_control_line_separators_do_not_hide_secret(self):
        for sep in ("\u2028", "\u2029", "\x0b", "\x0c", "\r"):
            with self.subTest(sep=repr(sep)):
                files = [changed("app.py", '+' + sep + 'key = "ghp_' + "a" * 36 + '"\n')]
                self.assertTrue(gate.scan_secrets(files))


class DiffCompletenessTests(unittest.TestCase):
    def test_complete_patch_validates_line_counts_and_types(self):
        valid = {"filename": "a.py", "status": "modified", "additions": 1, "deletions": 0, "patch": "@@ -1 +1 @@\n+x\n"}
        self.assertTrue(gate.complete_patch(valid))
        renamed = {"filename": "b.py", "status": "renamed", "additions": 0, "deletions": 0, "patch": ""}
        self.assertTrue(gate.complete_patch(renamed))
        for bad in (
            {"filename": "a.py", "status": "modified", "additions": 2, "deletions": 0, "patch": "@@ -1 +1 @@\n+x\n"},
            {"filename": "a.py", "status": "modified", "additions": 0, "deletions": 0, "patch": ""},
            {"filename": "a.py", "status": "modified", "additions": True, "deletions": 0, "patch": "@@ -1 +1 @@\n"},
            {"filename": "a.py", "status": "modified", "additions": -1, "deletions": 0, "patch": "+x\n"},
        ):
            with self.subTest(bad=bad):
                self.assertFalse(gate.complete_patch(bad))
                self.assertEqual(gate.unscanned_text([bad]), ["a.py"])
    def test_text_change_without_a_patch_is_refused(self):
        files = [changed("sources/wechat/reader.py")]
        self.assertEqual(gate.unscanned_text(files), ["sources/wechat/reader.py"])

    def test_pure_rename_without_a_patch_is_fine(self):
        files = [dict(filename="sources/wechat/reader.py", previous_filename="sources/wechat/old.py",
                      status="renamed", changes=0)]
        self.assertEqual(gate.unscanned_text(files), [])

    def test_binary_change_without_a_patch_is_fine(self):
        files = [dict(filename="assets/logo.png", status="modified", changes=0)]
        self.assertEqual(gate.unscanned_text(files), [])

    def test_empty_text_file_without_a_patch_is_fine(self):
        files = [dict(filename="pkg/__init__.py", status="added", changes=0, _size=0)]
        self.assertEqual(gate.unscanned_text(files), [])

    def test_zero_change_file_with_data_is_unscanned(self):
        files = [dict(filename="notes.txt", status="added", changes=0, _size=12)]
        self.assertEqual(gate.unscanned_text(files), ["notes.txt"])

    def test_zero_change_file_without_a_readable_blob_is_unscanned(self):
        files = [dict(filename="notes.txt", status="modified", changes=0)]
        self.assertEqual(gate.unscanned_text(files), ["notes.txt"])


class TemplateTests(unittest.TestCase):
    def test_complete_template_passes(self):
        body = "## AI assistance\nNone\n\n## What changed\nFix the reader.\n\n## How verified\nRan the tests.\n"
        self.assertTrue(gate.complete_template(body))

    def test_placeholder_template_fails(self):
        body = "## AI assistance\nDescribe the change.\n\n## What changed\nTBD\n\n## How verified\nN/A\n"
        self.assertFalse(gate.complete_template(body))


class RequiredContextTests(unittest.TestCase):
    def test_default_contexts(self):
        policy = {"required_checks": ["test", "Repository hygiene"]}
        self.assertEqual(gate.required_contexts(policy, False), ["test", "Repository hygiene"])

    def test_dependabot_uses_its_own_contexts(self):
        policy = {
            "required_checks": ["test"],
            "dependabot_required_checks": ["test", "Safe dependency update"],
        }
        self.assertEqual(gate.required_contexts(policy, True), ["test", "Safe dependency update"])

    def test_dependabot_falls_back_to_the_shared_list(self):
        policy = {"required_checks": ["test"]}
        self.assertEqual(gate.required_contexts(policy, True), ["test"])

    def test_paths_ignored_by_ci_drop_the_skipped_context(self):
        policy = {
            "required_checks": ["test", "Repository hygiene"],
            "ci_skipped_checks": {"test": ["README.md", "AGENTS.md"]},
        }
        files = [changed("README.md")]
        self.assertEqual(gate.applicable_contexts(policy, False, files), ["Repository hygiene"])

    def test_one_source_file_keeps_the_skipped_context(self):
        policy = {
            "required_checks": ["test", "Repository hygiene"],
            "ci_skipped_checks": {"test": ["README.md", "AGENTS.md"]},
        }
        files = [changed("README.md"), changed("scanner/reader.py")]
        self.assertEqual(
            gate.applicable_contexts(policy, False, files), ["test", "Repository hygiene"]
        )


class CheckResultTests(unittest.TestCase):
    def run_checks(self, entries, required):
        # Two-tuples mean "reported by Actions"; a third item overrides the
        # issuer, which is how the untrusted-provider cases are expressed.
        entries = [entry if len(entry) == 3 else (*entry, gate.ACTIONS_APP_ID) for entry in entries]
        with mock.patch.object(gate, "checks_state", lambda repo, sha: entries):
            return gate.check_results("o/r", "a" * 40, required)

    def test_check_from_another_app_cannot_satisfy_a_required_context(self):
        missing, unsettled, pending, failing = self.run_checks(
            [("test", "success", None), ("Repository hygiene", "success")],
            ["test", "Repository hygiene"],
        )
        self.assertEqual((missing, unsettled, pending, failing), (["test"], [], [], []))

    def test_actions_report_satisfies_a_required_context(self):
        missing, _, _, _ = self.run_checks(
            [("test", "success", gate.ACTIONS_APP_ID)], ["test"]
        )
        self.assertEqual(missing, [])

    def test_pending_required_context_is_not_success(self):
        missing, unsettled, pending, failing = self.run_checks(
            [("test", "pending"), ("Repository hygiene", "success")],
            ["test", "Repository hygiene"],
        )
        self.assertEqual((missing, unsettled, pending, failing), ([], ["test"], ["test"], []))

    def test_skipped_required_context_is_not_success(self):
        missing, unsettled, pending, failing = self.run_checks(
            [("test", "success"), ("Safe dependency update", "skipped")],
            ["test", "Safe dependency update"],
        )
        self.assertEqual((missing, unsettled, pending, failing), ([], ["Safe dependency update"], [], []))

    def test_missing_required_context_is_reported(self):
        missing, unsettled, pending, failing = self.run_checks(
            [("Repository hygiene", "success")], ["test", "Repository hygiene"]
        )
        self.assertEqual((missing, unsettled, pending, failing), (["test"], [], [], []))

    def test_failure_outside_the_list_is_reported(self):
        missing, unsettled, pending, failing = self.run_checks(
            [
                ("test", "success"),
                ("Verify Dependabot metadata", "failure"),
                ("Safe dependency update", "success"),
            ],
            ["test", "Repository hygiene"],
        )
        self.assertEqual(failing, ["Verify Dependabot metadata"])

    def test_second_failing_run_of_the_same_context_is_not_hidden(self):
        missing, unsettled, pending, failing = self.run_checks(
            [("test", "success"), ("test", "failure"), ("Repository hygiene", "success")],
            ["test", "Repository hygiene"],
        )
        self.assertEqual(unsettled, ["test"])
        self.assertEqual(failing, ["test"])

    def test_pending_check_outside_the_list_is_reported(self):
        missing, unsettled, pending, failing = self.run_checks(
            [
                ("test", "success"),
                ("Repository hygiene", "success"),
                ("Verify Dependabot metadata", "pending"),
            ],
            ["test", "Repository hygiene"],
        )
        self.assertEqual(pending, ["Verify Dependabot metadata"])
        self.assertEqual((missing, unsettled, failing), ([], [], []))

    def test_check_runs_are_read_from_every_page(self):
        pages = {1: [{"name": f"run-{index}"} for index in range(100)], 2: [{"name": "last"}]}

        def fake_request(method, path, body=None, params=None, allow=()):
            return {"check_runs": pages[params["page"]]}

        with mock.patch.object(gate, "request", fake_request):
            runs = gate.check_runs("o/r", "a" * 40)
        self.assertEqual(len(runs), 101)
        self.assertEqual(runs[-1]["name"], "last")

    def read_state(self, statuses, combined):
        with mock.patch.object(gate, "check_runs", lambda repo, sha: []), mock.patch.object(
            gate, "paginate", lambda *args, **kwargs: statuses
        ), mock.patch.object(gate, "request", lambda *args, **kwargs: {"state": combined}):
            return gate.checks_state("o/r", "a" * 40)

    def test_combined_status_failure_is_reported_when_statuses_exist(self):
        entries = self.read_state(
            [{"context": "ci", "state": "success", "created_at": "2026-01-01T00:00:00Z"}],
            "failure",
        )
        self.assertEqual(entries, [("ci", "success", None), ("combined status", "failure", None)])

    def test_combined_status_pending_is_reported_when_statuses_exist(self):
        entries = self.read_state(
            [{"context": "ci", "state": "success", "created_at": "2026-01-01T00:00:00Z"}],
            "pending",
        )
        self.assertEqual(entries, [("ci", "success", None), ("combined status", "pending", None)])

    def test_actions_bot_status_is_trusted_and_a_user_status_is_not(self):
        entries = self.read_state(
            [
                {"context": "gitleaks", "state": "success", "creator": {"login": "github-actions[bot]"}},
                {"context": "test", "state": "success", "creator": {"login": "someone"}},
            ],
            "success",
        )
        self.assertEqual(
            entries,
            [("gitleaks", "success", gate.ACTIONS_APP_ID), ("test", "success", None)],
        )

    def test_check_runs_carry_their_app(self):
        runs = [{"name": "test", "status": "completed", "conclusion": "success",
                 "app": {"id": 1, "slug": "foreign"}}]
        with mock.patch.object(gate, "check_runs", lambda repo, sha: runs), mock.patch.object(
            gate, "paginate", lambda *args, **kwargs: []
        ), mock.patch.object(gate, "request", lambda *args, **kwargs: {"state": "success"}):
            entries = gate.checks_state("o/r", "a" * 40)
        self.assertEqual(entries, [("test", "success", 1)])

    def test_combined_pending_without_statuses_is_ignored(self):
        self.assertEqual(self.read_state([], "pending"), [])
        self.assertEqual(self.read_state([], "success"), [])

    def test_only_the_newest_legacy_status_per_context_counts(self):
        entries = self.read_state(
            [
                {"context": "legacy", "state": "success", "created_at": "2026-01-01T00:00:01Z"},
                {"context": "legacy", "state": "pending", "created_at": "2026-01-01T00:00:01Z"},
                {"context": "legacy", "state": "failure", "created_at": "2026-01-01T00:00:00Z"},
            ],
            "success",
        )
        self.assertEqual(entries, [("legacy", "success", None)])

    def test_skipped_check_outside_the_list_stays_allowed(self):
        missing, unsettled, pending, failing = self.run_checks(
            [
                ("test", "success"),
                ("Repository hygiene", "success"),
                ("Safe dependency update", "skipped"),
            ],
            ["test", "Repository hygiene"],
        )
        self.assertEqual((missing, unsettled, pending, failing), ([], [], [], []))


class MergeLockTests(unittest.TestCase):
    def test_a_second_merge_waits_for_the_critical_section(self):
        entered = threading.Event()

        def holder():
            with gate.merge_lock("o/r-lock", "main"):
                entered.set()
                time.sleep(0.3)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(entered.wait(2))
        started = time.monotonic()
        with gate.merge_lock("o/r-lock", "main"):
            pass
        waited = time.monotonic() - started
        thread.join(2)
        self.assertGreaterEqual(waited, 0.2)


class EvaluatePolicyTests(unittest.TestCase):
    HEAD = "a" * 40
    BASE = "c" * 40

    def test_evaluate_and_revalidate_respect_codex_required_and_ai_review_providers(self):
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
        truncated = {
            "filename": "app.py",
            "status": "modified",
            "additions": 2,
            "deletions": 0,
            "changes": 2,
            "patch": "@@ -1 +1 @@\n+one\n",
        }
        claude_comment = {
            "user": {"login": "claude[bot]"},
            "updated_at": "2026-11-14T09:00:00Z",
            "body": '<!-- ai-review-receipt:v1 {"review":{"provider":"claude","commit_sha":"'
            + self.HEAD
            + '","status":"completed","unresolved_findings":0,"coverage":"complete"}} -->',
        }
        clean_tree = {"truncated": False, "tree": [{"path": "app.py", "mode": "100644", "type": "blob"}]}

        def run_eval(policy, file_entry, tree_payload=clean_tree):
            def fake_request(m, p, **k):
                if p == "/repos/o/r/pulls/7":
                    return pull
                if p == "/repos/o/r":
                    return {"default_branch": "main"}
                if p == "/repos/o/r/branches/main":
                    return {"commit": {"sha": self.BASE}}
                if p == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                    return {"merge_base_commit": {"sha": self.BASE}, "files": [file_entry]}
                if p == f"/repos/o/r/git/trees/{self.HEAD}":
                    return tree_payload
                return None

            with mock.patch.object(gate, "request", side_effect=fake_request), \
                 mock.patch.object(gate, "load_policy", return_value=policy), \
                 mock.patch.object(gate, "verify_script", return_value=None), \
                 mock.patch.object(gate, "shared_head", return_value=False), \
                 mock.patch.object(gate, "base_action_files", return_value=set()), \
                 mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: (
                     [claude_comment] if p.endswith("/comments") else []
                 )), \
                 mock.patch.object(gate, "check_results", return_value=([], [], [], [])):
                return gate.evaluate("o/r", 7)

        strict_policy = {
            "codex_required": True,
            "ai_review_providers": ["claude"],
            "required_checks": ["test"],
            "_source": "main",
            "_sha256": "p1",
        }
        complete_file = {**truncated, "additions": 1, "changes": 1}
        strict_verdict, _ = run_eval(strict_policy, complete_file)
        self.assertEqual(strict_verdict["verdict"], "fail")
        self.assertEqual(strict_verdict["review_providers"], ["codex"])

        multi_policy = {
            "codex_required": False,
            "ai_review_providers": ["codex", "claude"],
            "required_checks": ["test"],
            "_source": "main",
            "_sha256": "p2",
        }
        multi_verdict, _ = run_eval(multi_policy, complete_file)
        self.assertEqual(multi_verdict["verdict"], "pass")
        self.assertEqual(multi_verdict["review_providers"], ["claude", "codex"])

        trunc_verdict, _ = run_eval(multi_policy, truncated)
        self.assertEqual(trunc_verdict["verdict"], "fail")
        self.assertEqual(trunc_verdict["unscanned"], ["app.py"])

        with mock.patch.object(gate, "request", return_value=pull), \
             mock.patch.object(gate, "load_policy", return_value=multi_policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "head_contains_base", return_value=(True, self.BASE)), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "paginate", return_value=[claude_comment]), \
             mock.patch.object(gate, "check_results", return_value=([], [], [], [])):
            reval = {
                "repo": "o/r",
                "pr": 7,
                "head_sha": self.HEAD,
                "base_ref": "main",
                "policy_ref": "main",
                "base_sha": self.BASE,
                "tier": "T1",
                "codex": "success",
                "review_providers": ["claude", "codex"],
                "required_checks": ["test"],
                "bootstrap": False,
                "body_sha256": gate.hashlib.sha256(b"").hexdigest(),
                "policy_sha256": "p2",
            }
            gate.revalidate("o/r", reval)

    def test_evaluate_rejects_symlinks_even_under_docs_and_handles_truncated_or_missing_trees(self):
        pull = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": self.HEAD, "ref": "feat/x", "repo": {"full_name": "o/r"}},
            "base": {"ref": "main"},
            "user": {"login": "contributor"},
            "changed_files": 1,
            "body": "## AI assistance\nCodex\n\n## What changed\nAdd link\n\n## How verified\nTested\n",
            "labels": [],
        }
        policy = {
            "codex_required": False,
            "require_checks": False,
            "owner_login": "owner-login",
            "_source": "main",
            "_sha256": "p3",
        }
        doc_link = {
            "filename": "docs/link.md",
            "status": "added",
            "sha": "blob123",
            "additions": 0,
            "deletions": 0,
            "changes": 0,
        }
        blob_calls = []

        def fake_request(m, p, params=None, **k):
            if p == "/repos/o/r/pulls/7":
                return pull
            if p == "/repos/o/r":
                return {"default_branch": "main"}
            if p == "/repos/o/r/branches/main":
                return {"commit": {"sha": self.BASE}}
            if p == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                return {"merge_base_commit": {"sha": self.BASE}, "files": [doc_link]}
            if p.startswith("/repos/o/r/git/blobs/"):
                blob_calls.append(p)
                return {"size": 0}
            if p == f"/repos/o/r/git/trees/{self.HEAD}" and params == {"recursive": "1"}:
                return {"truncated": False, "tree": [{"path": "docs/link.md", "mode": "120000", "type": "blob"}]}
            return None

        with mock.patch.object(gate, "request", side_effect=fake_request), \
             mock.patch.object(gate, "load_policy", return_value=policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: []):
            verdict, reasons = gate.evaluate("o/r", 7)
        self.assertEqual(verdict["verdict"], "fail")
        self.assertEqual(verdict["tier"], "T2")
        self.assertEqual(blob_calls, [])
        self.assertTrue(any("Symlink entries are not allowed" in r for r in reasons))

        # Truncated recursive tree walks down child subtree SHAs cleanly.
        def truncated_request(m, p, params=None, **k):
            if p == "/repos/o/r/pulls/7":
                return pull
            if p == "/repos/o/r":
                return {"default_branch": "main"}
            if p == f"/repos/o/r/git/trees/{self.HEAD}" and params == {"recursive": "1"}:
                return {"truncated": True, "tree": []}
            if p == f"/repos/o/r/git/trees/{self.HEAD}" and params is None:
                return {"truncated": False, "tree": [{"path": "docs", "mode": "040000", "type": "tree", "sha": "sub1"}]}
            if p == "/repos/o/r/git/trees/sub1":
                return {"truncated": False, "tree": [{"path": "link.md", "mode": "120000", "type": "blob"}]}
            return None

        with mock.patch.object(gate, "request", side_effect=truncated_request):
            flagged, ok = gate.symlink_entries("o/r", self.HEAD, [doc_link])
        self.assertTrue(ok)
        self.assertEqual(flagged, ["docs/link.md"])

        # Missing head tree fails closed and upgrades tier to T2.
        def missing_tree_request(m, p, params=None, **k):
            if p == "/repos/o/r/pulls/7":
                return pull
            if p == "/repos/o/r":
                return {"default_branch": "main"}
            if p == "/repos/o/r/branches/main":
                return {"commit": {"sha": self.BASE}}
            if p == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                return {"merge_base_commit": {"sha": self.BASE}, "files": [clean_doc]}
            if p == f"/repos/o/r/git/trees/{self.HEAD}":
                return None
            return None

        clean_doc = {
            "filename": "docs/guide.md",
            "status": "added",
            "additions": 1,
            "deletions": 0,
            "changes": 1,
            "patch": "@@ -0,0 +1 @@\n+hello\n",
        }
        with mock.patch.object(gate, "request", side_effect=missing_tree_request), \
             mock.patch.object(gate, "load_policy", return_value=policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: []):
            missing_verdict, missing_reasons = gate.evaluate("o/r", 7)
        self.assertEqual(missing_verdict["verdict"], "fail")
        self.assertEqual(missing_verdict["tier"], "T2")
        self.assertIn("Cannot verify Git tree modes for changed files", missing_reasons)

    def test_missing_default_policy_fails_closed_without_head_fallback_and_accepts_policy_file(self):
        pull = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": self.HEAD, "ref": "feat/x", "repo": {"full_name": "o/r"}},
            "base": {"ref": "main"},
            "user": {"login": "contributor"},
            "changed_files": 1,
            "body": "## AI assistance\nCodex\n\n## What changed\nBootstrap\n\n## How verified\nTested\n",
            "labels": [{"name": "owner-approved"}],
        }
        doc_file = {
            "filename": "governance/policy.json",
            "status": "added",
            "additions": 1,
            "deletions": 0,
            "changes": 1,
            "patch": '@@ -0,0 +1 @@\n+{"owner_login":"owner"}\n',
        }
        tree_payload = {
            "truncated": False,
            "tree": [{"path": "governance/policy.json", "mode": "100644", "type": "blob"}],
        }
        policy_refs_seen = []
        default_policy_payload = None

        def fake_request(method, path, params=None, **kwargs):
            if path == "/repos/o/r/pulls/7":
                return pull
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/branches/main":
                return {"commit": {"sha": self.BASE}}
            if path == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                return {"merge_base_commit": {"sha": self.BASE}, "files": [doc_file]}
            if path == "/repos/o/r/contents/governance/policy.json":
                ref = (params or {}).get("ref")
                policy_refs_seen.append(ref)
                if ref == self.HEAD:
                    raise AssertionError("Must never load bootstrap policy from PR head")
                return default_policy_payload
            if path == "/repos/o/r/contents/governance/merge_gate.py":
                return None
            if path == "/repos/o/r/contents/.github/scripts/dependabot-policy.json":
                return None
            if path == f"/repos/o/r/git/trees/{self.HEAD}":
                return tree_payload
            return None

        with mock.patch.object(gate, "request", side_effect=fake_request):
            with self.assertRaises(gate.Refusal) as ctx:
                gate.evaluate("o/r", 7)
        self.assertIn("--policy-file", str(ctx.exception))
        self.assertEqual(policy_refs_seen, ["main"])

        trusted_policy = {
            "owner_login": "owner",
            "codex_required": False,
            "require_checks": False,
        }
        raw_policy = json.dumps(trusted_policy).encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "bootstrap-policy.json"
            policy_path.write_bytes(raw_policy)
            with mock.patch.object(gate, "request", side_effect=fake_request), \
                 mock.patch.object(gate, "shared_head", return_value=False), \
                 mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: []), \
                 mock.patch.object(gate, "live_label", return_value="owner-approved"):
                verdict, reasons = gate.evaluate("o/r", 7, policy_file=str(policy_path))
                self.assertEqual(reasons, [])
                self.assertEqual(verdict["verdict"], "pass")
                self.assertTrue(verdict["bootstrap"])
                self.assertEqual(verdict["policy_sha256"], gate.hashlib.sha256(raw_policy).hexdigest())

                # Revalidation with trusted --policy-file succeeds, while omitting it fails closed.
                gate.revalidate("o/r", verdict, policy_file=str(policy_path))
                with self.assertRaises(gate.Refusal):
                    gate.revalidate("o/r", verdict)
                with self.assertRaises(gate.Refusal):
                    gate.revalidate("o/r", {**verdict, "bootstrap": False}, policy_file=str(policy_path))

                out = io.StringIO()
                with mock.patch.object(gate.sys, "argv", [
                    "merge_gate.py", "--repo", "o/r", "--pr", "7", "--dry-run", "--policy-file", str(policy_path)
                ]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    code = gate.main()
                self.assertEqual(code, 0)
                self.assertTrue(json.loads(out.getvalue())["bootstrap"])

                # Once default_branch has governance/policy.json (or non-404 response), refuse --policy-file.
                for payload in ({"type": "file", "content": ""}, [], {}):
                    default_policy_payload = payload
                    with self.assertRaises(gate.Refusal) as eval_refused:
                        gate.evaluate("o/r", 7, policy_file=str(policy_path))
                    self.assertIn("already exists", str(eval_refused.exception))
                    with self.assertRaises(gate.Refusal) as rev_refused:
                        gate.revalidate("o/r", verdict, policy_file=str(policy_path))
                    self.assertIn("already exists", str(rev_refused.exception))

        with mock.patch.object(gate.sys, "argv", [
            "merge_gate.py", "--repo", "o/r", "--pr", "7", "--policy-ref", "refs/tags/trusted"
        ]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as sys_exit:
                gate.main()
        self.assertEqual(sys_exit.exception.code, 2)

    def test_base_ref_changed_invalidates_both_label_and_receipt_on_unchanged_head_until_reapproved(self):
        pull = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": self.HEAD, "ref": "feat/x", "repo": {"full_name": "o/r"}},
            "base": {"ref": "main"},
            "user": {"login": "contributor"},
            "changed_files": 1,
            "body": "## AI assistance\nCodex\n\n## What changed\nConfig\n\n## How verified\nTested\n",
            "labels": [{"name": "owner-approved"}],
        }
        protected_file = {
            "filename": ".github/workflows/ci.yml",
            "status": "modified",
            "additions": 1,
            "deletions": 0,
            "changes": 1,
            "patch": "@@ -1 +1 @@\n+# tweak\n",
        }
        tree_payload = {
            "truncated": False,
            "tree": [{"path": ".github/workflows/ci.yml", "mode": "100644", "type": "blob"}],
        }
        policy = {
            "owner_login": "owner",
            "codex_required": False,
            "ai_review_providers": ["codex", "claude"],
            "require_checks": False,
            "_source": "main",
            "_sha256": "p3",
        }
        pre_receipt = {
            "user": {"login": "claude[bot]"},
            "updated_at": "2026-11-14T08:00:10Z",
            "body": '<!-- ai-review-receipt:v1 {"review":{"provider":"claude","commit_sha":"'
            + self.HEAD
            + '","status":"completed","unresolved_findings":0,"coverage":"complete"}} -->',
        }
        pre_status = {
            "context": "clearing-label",
            "state": "success",
            "creator": {"login": gate.ACTIONS_BOT},
            "description": "owner-approved for PR 7 at event 101 on this head",
            "updated_at": "2026-11-14T08:00:05Z",
        }
        base_timeline = [
            {
                "id": 101,
                "event": "labeled",
                "label": {"name": "owner-approved"},
                "actor": {"login": "owner"},
                "created_at": "2026-11-14T08:00:00Z",
            },
            {"event": "base_ref_changed", "created_at": "2026-11-14T08:05:00Z"},
        ]

        state = {
            "comments": [pre_receipt],
            "timeline": list(base_timeline),
            "statuses": [pre_status],
        }

        def fake_request(method, path, **kwargs):
            if path == "/repos/o/r/pulls/7":
                return pull
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/branches/main":
                return {"commit": {"sha": self.BASE}}
            if path == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                return {"merge_base_commit": {"sha": self.BASE}, "files": [protected_file]}
            if path == f"/repos/o/r/git/trees/{self.HEAD}":
                return tree_payload
            return None

        def fake_paginate(path, params=None):
            if path.endswith("/comments"):
                return state["comments"]
            if path.endswith("/timeline"):
                return state["timeline"]
            if path.endswith("/statuses"):
                return state["statuses"]
            return []

        with mock.patch.object(gate, "request", side_effect=fake_request), \
             mock.patch.object(gate, "load_policy", return_value=policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "branch_activities", return_value=[]), \
             mock.patch.object(gate, "paginate", side_effect=fake_paginate):
            verdict, reasons = gate.evaluate("o/r", 7)
            self.assertEqual(verdict["verdict"], "fail")
            self.assertTrue(any("base change" in r for r in reasons))
            self.assertTrue(any("owner-approved" in r for r in reasons))

            # Untimed base_ref_changed also fails closed.
            state["timeline"] = [base_timeline[0], {"event": "base_ref_changed"}]
            untimed_verdict, untimed_reasons = gate.evaluate("o/r", 7)
            self.assertEqual(untimed_verdict["verdict"], "fail")
            self.assertTrue(any("base change" in r for r in untimed_reasons))
            self.assertTrue(any("owner-approved" in r for r in untimed_reasons))

            # Fresh post-retarget label, clearing-label status, and receipt pass evaluate + revalidate.
            state["timeline"] = list(base_timeline) + [
                {
                    "id": 102,
                    "event": "labeled",
                    "label": {"name": "owner-approved"},
                    "actor": {"login": "owner"},
                    "created_at": "2026-11-14T08:10:00Z",
                }
            ]
            state["statuses"].append(
                {
                    "context": "clearing-label",
                    "state": "success",
                    "creator": {"login": gate.ACTIONS_BOT},
                    "description": "owner-approved for PR 7 at event 102 on this head",
                    "updated_at": "2026-11-14T08:10:05Z",
                }
            )
            state["comments"].append(
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "updated_at": "2026-11-14T08:10:10Z",
                    "body": '<!-- codex-review-state:v1 {"code_review":{"commit_sha":"'
                    + self.HEAD
                    + '","status":"completed","has_unresolved_findings":false}} -->',
                }
            )
            ok_verdict, ok_reasons = gate.evaluate("o/r", 7)
            self.assertEqual(ok_reasons, [])
            self.assertEqual(ok_verdict["verdict"], "pass")
            gate.revalidate("o/r", ok_verdict)

            # A base toggle between evaluate and revalidate also causes revalidate to refuse.
            state["timeline"].append({"event": "base_ref_changed", "created_at": "2026-11-14T08:15:00Z"})
            with self.assertRaises(gate.Refusal):
                gate.revalidate("o/r", ok_verdict)

    def test_evaluate_binds_files_and_dependabot_commits_to_captured_head_against_swapped_pr_ref(self):
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
        workflow_file = {
            "filename": ".github/workflows/ci.yml",
            "status": "modified",
            "additions": 1,
            "deletions": 1,
            "changes": 2,
            "patch": "@@ -1 +1 @@\n-      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n+      uses: actions/checkout@4f1c2a8d0e9b7c6a5f4e3d2c1b0a9f8e7d6c5b4a\n",
        }
        policy = {
            "owner_login": "owner",
            "codex_required": False,
            "require_checks": False,
            "_source": "main",
            "_sha256": "p-bind",
        }
        tree_payload = {
            "truncated": False,
            "tree": [{"path": ".github/workflows/ci.yml", "mode": "100644", "type": "blob"}],
        }
        seen_paths = []

        def fake_request(method, path, params=None, **kwargs):
            seen_paths.append(path)
            if path == "/repos/o/r/pulls/7":
                return pull
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/branches/main":
                return {"commit": {"sha": self.BASE}}
            if path == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                return {"merge_base_commit": {"sha": self.BASE}, "files": [workflow_file]}
            if path == f"/repos/o/r/git/trees/{self.HEAD}":
                return tree_payload
            return None

        def guard_paginate(path, params=None):
            if path.endswith("/files"):
                raise AssertionError("evaluate() must never inspect mutable /pulls/{n}/files")
            return []

        with mock.patch.object(gate, "request", side_effect=fake_request), \
             mock.patch.object(gate, "load_policy", return_value=policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "paginate", side_effect=guard_paginate):
            verdict, reasons = gate.evaluate("o/r", 7)
        self.assertEqual(verdict["verdict"], "fail")
        self.assertEqual(verdict["tier"], "T2")
        self.assertIn(f"/repos/o/r/compare/{self.BASE}...{self.HEAD}", seen_paths)
        self.assertTrue(any("owner-approved" in r for r in reasons))

        # dependabot_head refuses commits whose tip does not match captured head.
        swapped_dependabot_commit = {
            "sha": "b" * 40,
            "author": {"login": "dependabot[bot]"},
            "committer": {"login": "web-flow"},
            "commit": {"verification": {"verified": True}},
        }
        matching_dependabot_commit = {**swapped_dependabot_commit, "sha": self.HEAD}
        with mock.patch.object(gate, "paginate", return_value=[swapped_dependabot_commit]):
            self.assertFalse(gate.dependabot_head("o/r", 7, head=self.HEAD))
        with mock.patch.object(gate, "paginate", return_value=[matching_dependabot_commit]):
            self.assertTrue(gate.dependabot_head("o/r", 7, head=self.HEAD))

        # In evaluate(), swapped commits on /pulls/{n}/commits cannot unlock dependabot fast-path,
        # while an immutable compare commits list bound to HEAD succeeds without touching /pulls/{n}/commits.
        dep_pull = {**pull, "user": {"login": "dependabot[bot]"}, "body": "bump checkout"}
        compare_with_commits = {"value": None}

        def dep_request(method, path, params=None, **kwargs):
            if path == "/repos/o/r/pulls/7":
                return dep_pull
            if path == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                payload = {
                    "merge_base_commit": {"sha": self.BASE},
                    "files": [workflow_file],
                }
                if compare_with_commits["value"] is not None:
                    payload.update(compare_with_commits["value"])
                return payload
            return fake_request(method, path, params=params, **kwargs)

        def dep_paginate(path, params=None):
            if path == "/repos/o/r/pulls/7/commits":
                if compare_with_commits["value"] is not None:
                    raise AssertionError("should not query mutable /pulls/{n}/commits when compare includes commits")
                return [swapped_dependabot_commit]
            return guard_paginate(path, params)

        with mock.patch.object(gate, "request", side_effect=dep_request), \
             mock.patch.object(gate, "load_policy", return_value=policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value={".github/workflows/ci.yml"}), \
             mock.patch.object(gate, "paginate", side_effect=dep_paginate):
            dep_verdict, dep_reasons = gate.evaluate("o/r", 7)
            self.assertEqual(dep_verdict["verdict"], "fail")
            self.assertEqual(dep_verdict["tier"], "T2")
            self.assertTrue(any("owner-approved" in r for r in dep_reasons))

            compare_with_commits["value"] = {
                "commits": [matching_dependabot_commit],
                "total_commits": 1,
            }
            fast_verdict, fast_reasons = gate.evaluate("o/r", 7)
            self.assertEqual(fast_reasons, [])
            self.assertEqual(fast_verdict["verdict"], "pass")
            self.assertEqual(fast_verdict["tier"], "T1")

    def test_evaluate_fails_closed_on_missing_or_partial_compare_files(self):
        policy = {
            "owner_login": "owner",
            "codex_required": False,
            "require_checks": False,
            "_source": "main",
            "_sha256": "p-cap",
        }
        doc_file = {
            "filename": "docs/a.md",
            "status": "added",
            "additions": 1,
            "deletions": 0,
            "changes": 1,
            "patch": "@@ -0,0 +1 @@\n+hi\n",
        }
        three_hundred_files = [
            {**doc_file, "filename": f"docs/f{i}.md"} for i in range(300)
        ]
        cases = (
            ("missing_files", 1, {"merge_base_commit": {"sha": self.BASE}}),
            ("non_list_files", 1, {"merge_base_commit": {"sha": self.BASE}, "files": {}}),
            ("count_mismatch", 2, {"merge_base_commit": {"sha": self.BASE}, "files": [doc_file]}),
            ("compare_300_cap", 300, {"merge_base_commit": {"sha": self.BASE}, "files": three_hundred_files}),
        )
        for label, changed_count, compare_payload in cases:
            with self.subTest(case=label):
                pull = {
                    "number": 7,
                    "state": "open",
                    "draft": False,
                    "head": {"sha": self.HEAD, "ref": "feat/x", "repo": {"full_name": "o/r"}},
                    "base": {"ref": "main"},
                    "user": {"login": "contributor"},
                    "changed_files": changed_count,
                    "body": "",
                    "labels": [],
                }
                tree_payload = {
                    "truncated": False,
                    "tree": [
                        {"path": item["filename"], "mode": "100644", "type": "blob"}
                        for item in (compare_payload.get("files") if isinstance(compare_payload.get("files"), list) else [])
                    ],
                }

                def fake_request(method, path, params=None, **kwargs):
                    if path == "/repos/o/r/pulls/7":
                        return pull
                    if path == "/repos/o/r":
                        return {"default_branch": "main"}
                    if path == "/repos/o/r/branches/main":
                        return {"commit": {"sha": self.BASE}}
                    if path == f"/repos/o/r/compare/{self.BASE}...{self.HEAD}":
                        return compare_payload
                    if path == f"/repos/o/r/git/trees/{self.HEAD}":
                        return tree_payload
                    return None

                with mock.patch.object(gate, "request", side_effect=fake_request), \
                     mock.patch.object(gate, "load_policy", return_value=policy), \
                     mock.patch.object(gate, "verify_script", return_value=None), \
                     mock.patch.object(gate, "shared_head", return_value=False), \
                     mock.patch.object(gate, "base_action_files", return_value=set()), \
                     mock.patch.object(gate, "paginate", return_value=[]):
                    verdict, reasons = gate.evaluate("o/r", 7)
                self.assertEqual(verdict["verdict"], "fail")
                self.assertIn("Changed-file list is incomplete; refuse to judge a partial diff", reasons)


class DefaultRepoTests(unittest.TestCase):
    def test_default_repo_handles_dotted_names(self):
        cases = (
            ("git@github.com:synthetic-owner/service.api.git\n", "synthetic-owner/service.api"),
            ("git@github.com:synthetic-owner/service.api\n", "synthetic-owner/service.api"),
            ("https://github.com/synthetic-owner/service.api.git\n", "synthetic-owner/service.api"),
            ("https://github.com/synthetic-owner/repo-name.git\n", "synthetic-owner/repo-name"),
            ("https://gitlab.example.com/owner/repo.git\n", None),
        )
        for remote_url, expected in cases:
            with self.subTest(remote_url=remote_url.strip()):
                fake_proc = mock.Mock(stdout=remote_url)
                with mock.patch.object(gate.subprocess, "run", return_value=fake_proc):
                    self.assertEqual(gate.default_repo(), expected)


class TypedValidatorTests(unittest.TestCase):
    def test_expect_helpers_preserve_falsy_values_and_reject_bool_as_int(self):
        self.assertEqual(gate._expect_dict({}), {})
        self.assertIsNone(gate._expect_dict([]))
        self.assertEqual(gate._expect_list([]), [])
        self.assertIsNone(gate._expect_list({}))

        self.assertEqual(gate._expect_str(""), "")
        self.assertIsNone(gate._expect_str("", non_empty=True))
        self.assertIsNone(gate._expect_str("   ", non_empty=True, strip=True))
        self.assertEqual(gate._expect_str("  abc  ", non_empty=True, strip=True), "abc")

        self.assertIs(gate._expect_bool(False), False)
        self.assertIsNone(gate._expect_bool(0))
        self.assertIsNone(gate._expect_bool(1))

        self.assertEqual(gate._expect_int(0), 0)
        self.assertEqual(gate._expect_int(-3), -3)
        self.assertIsNone(gate._expect_int(True))
        self.assertIsNone(gate._expect_int(False))

        self.assertEqual(gate._expect_nonneg_int(0), 0)
        self.assertIsNone(gate._expect_nonneg_int(-1))
        self.assertIsNone(gate._expect_nonneg_int(True))
        self.assertIsNone(gate._expect_nonneg_int(False))

        self.assertEqual(gate._expect_sha40("A" * 40), "a" * 40)
        self.assertIsNone(gate._expect_sha40(" " + "a" * 40))
        self.assertEqual(gate._expect_sha40(" " + "A" * 40 + "\n", strip=True), "a" * 40)
        self.assertIsNone(gate._expect_sha40("a" * 39))
        self.assertIsNone(gate._expect_sha40("g" * 40))

        self.assertEqual(gate._dict_at({"a": {"b": 1}}, "a"), {"b": 1})
        self.assertEqual(gate._dict_at({"a": "not-a-dict"}, "a", "b"), {})
        self.assertEqual(gate._dict_at(None, "a"), {})


class PolicyFileDiagnosticsTests(unittest.TestCase):
    def test_load_policy_file_uses_fixed_diagnostics_without_raw_exception_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_path = str(Path(tmp) / "missing.json")
            with mock.patch.object(gate.Path, "read_bytes", side_effect=OSError("raw-os-secret-detail")):
                with self.assertRaises(gate.Refusal) as os_ctx:
                    gate._load_policy_file(missing_path)
            self.assertEqual(str(os_ctx.exception), f"Cannot read policy file {missing_path}")
            self.assertNotIn("raw-os-secret-detail", str(os_ctx.exception))

            bad_json_path = Path(tmp) / "bad.json"
            bad_json_path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(gate.Refusal) as json_ctx:
                gate._load_policy_file(str(bad_json_path))
            self.assertEqual(str(json_ctx.exception), f"Invalid JSON in policy file {bad_json_path}")
            self.assertNotIn("Expecting", str(json_ctx.exception))
            self.assertNotIn("line 1", str(json_ctx.exception))

            non_utf8_path = Path(tmp) / "binary.json"
            non_utf8_path.write_bytes(b"\xff\xfe")
            with self.assertRaises(gate.Refusal) as bin_ctx:
                gate._load_policy_file(str(non_utf8_path))
            self.assertEqual(str(bin_ctx.exception), f"Invalid JSON in policy file {non_utf8_path}")
            self.assertNotIn("codec", str(bin_ctx.exception))


if __name__ == "__main__":
    unittest.main()
