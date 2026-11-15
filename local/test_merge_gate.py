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

    def test_added_tests_are_t0(self):
        files = [changed("tests/test_reader.py", status="added")]
        self.assertEqual(gate.classify(files, False, set(), ()), ("T0", False))

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
             mock.patch.object(gate, "load_policy", lambda *a, **k: policy), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None):
            self.assertEqual(gate.audit("o/r", 1, False), 2)

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

        def wrap_scan(repo, default, since, merge_shas, acknowledged, strict, direct_limit):
            seen_limit["since"] = since
            seen_limit["acknowledged"] = acknowledged
            seen_limit["strict"] = strict
            seen_limit["direct_limit"] = direct_limit
            return orig_scan(repo, default, since, merge_shas, acknowledged, strict, direct_limit)

        captured = io.StringIO()
        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [self.verdict()]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: untrusted_policy), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None), \
             mock.patch.object(gate, "scan_direct_pushes", wrap_scan), \
             contextlib.redirect_stdout(captured):
            code = gate.audit("o/r", 20, True)
        self.assertEqual(code, 2)
        self.assertEqual(seen_limit, {"since": "", "acknowledged": {}, "strict": True, "direct_limit": 40})
        self.assertIn(f"violation: {direct[:7]} on main is not associated", captured.getvalue())

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

    def run_audit(self, chain, policy=None, strict_direct=False, details=None, attributed=(), related_pulls=None):
        base = {"owner_login": "synthetic-owner", "audit_since": "", "audit_ignore_prs": []}
        base.update(policy or {})
        pull = {
            "number": 7,
            "merged_at": self.DATE,
            "head": {"sha": "h" * 40},
            "merge_commit_sha": self.TIP,
        }
        details = details or {}
        attributed = set(attributed)
        related_pulls = related_pulls or {}

        def fake_request(method, path, body=None, params=None, allow=()):
            if path == "/repos/o/r":
                return {"default_branch": "main"}
            if path == "/repos/o/r/pulls":
                return [pull] if params and params.get("page") == 1 else []
            if path == "/repos/o/r/commits":
                return chain
            if path.startswith("/repos/o/r/commits/") and path.endswith("/pulls"):
                sha = path.rsplit("/", 2)[-2]
                if sha in related_pulls:
                    return related_pulls[sha]
                # Only the shas named here have a merged pull request attached;
                # everything else asks the entry and gets nothing back.
                return [{"merged_at": self.DATE, "base": {"ref": "main"}}] if sha in attributed else []
            if path.startswith("/repos/o/r/commits/"):
                return details.get(path.rsplit("/", 1)[-1])
            return []

        with mock.patch.object(gate, "request", fake_request), \
             mock.patch.object(gate, "paginate", lambda path, params=None: [self.verdict_comment()]), \
             mock.patch.object(gate, "load_policy", lambda *a, **k: base), \
             mock.patch.object(gate, "verify_script", lambda *a, **k: None):
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = gate.audit("o/r", 20, strict_direct)
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
        related = {self.PREV: [{"merged_at": self.DATE, "base": {"ref": "release"}}]}
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
        code, output = self.run_audit(chain, policy)
        self.assertEqual(code, 0)
        self.assertIn(f"note: acknowledged direct push {self.DIRECT[:7]}: owner decision", output)

    def test_policy_can_relax_the_direct_push_audit(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.DIRECT, (), "governance: loosen a check")]
        code, output = self.run_audit(chain, {"audit_strict_direct": False})
        self.assertEqual(code, 0)
        self.assertIn(f"warning: {self.DIRECT[:7]} on main is not associated", output)

    def test_direct_push_scan_skips_commits_outside_the_audit_window(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request"),
                 self.commit(self.DIRECT, (), "governance: loosen a check")]
        code, _ = self.run_audit(chain, {"audit_since": "2026-01-06T00:00:00Z"})
        self.assertEqual(code, 0)

    def test_backdated_tip_does_not_hide_an_in_window_direct_push(self):
        chain = [self.commit(self.TIP, (self.DIRECT,), "feat: via pull request",
                             date="2026-01-01T00:00:00Z"),
                 self.commit(self.DIRECT, (), "governance: loosen a check",
                             date="2026-01-05T00:00:00Z")]
        code, output = self.run_audit(chain, {"audit_since": "2026-01-02T00:00:00Z"})
        self.assertEqual(code, 2)
        self.assertIn(f"violation: {self.DIRECT[:7]} on main is not associated", output)

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

    def test_cursor_receipt_with_omitted_status_and_valid_coverages_passes(self):
        for coverage in ("complete", "completed", "full", "reported_complete", "all", " Full "):
            with self.subTest(coverage=coverage):
                comment = self.comment(
                    "cursor[bot]",
                    "ai-review-receipt:v1",
                    {
                        "review": {
                            "provider": "cursor",
                            "commit_sha": self.HEAD,
                            "unresolved_findings": False,
                            "coverage": coverage,
                        }
                    },
                )
                state, note = self.verdict([comment])
                self.assertEqual(state, "success")
                self.assertIn("cursor", note)

    def test_codex_receipt_v1_with_omitted_status_passes(self):
        comment = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-receipt:v1",
            {
                "review": {
                    "provider": "codex",
                    "commit_sha": self.HEAD,
                    "unresolved_findings": 0,
                    "coverage": "complete",
                }
            },
        )
        self.assertEqual(self.verdict([comment])[0], "success")

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

    def test_codex_state_v1_requires_explicit_completed_status(self):
        comment = self.comment(
            "chatgpt-codex-connector[bot]",
            "codex-review-state:v1",
            {
                "code_review": {
                    "commit_sha": self.HEAD,
                    "has_unresolved_findings": False,
                }
            },
        )
        self.assertEqual(self.verdict([comment])[0], "pending")

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
                if p == f"/repos/o/r/git/trees/{self.HEAD}":
                    return tree_payload
                return None

            with mock.patch.object(gate, "request", side_effect=fake_request), \
                 mock.patch.object(gate, "load_policy", return_value=policy), \
                 mock.patch.object(gate, "verify_script", return_value=None), \
                 mock.patch.object(gate, "head_contains_base", return_value=(True, self.BASE)), \
                 mock.patch.object(gate, "shared_head", return_value=False), \
                 mock.patch.object(gate, "base_action_files", return_value=set()), \
                 mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: (
                     [file_entry] if p.endswith("/files") else [claude_comment] if p.endswith("/comments") else []
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
            if p.startswith("/repos/o/r/git/blobs/"):
                blob_calls.append(p)
                return {"size": 0}
            if p == f"/repos/o/r/git/trees/{self.HEAD}" and params == {"recursive": "1"}:
                return {"truncated": False, "tree": [{"path": "docs/link.md", "mode": "120000", "type": "blob"}]}
            return None

        with mock.patch.object(gate, "request", side_effect=fake_request), \
             mock.patch.object(gate, "load_policy", return_value=policy), \
             mock.patch.object(gate, "verify_script", return_value=None), \
             mock.patch.object(gate, "head_contains_base", return_value=(True, self.BASE)), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: [doc_link] if p.endswith("/files") else []):
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
             mock.patch.object(gate, "head_contains_base", return_value=(True, self.BASE)), \
             mock.patch.object(gate, "shared_head", return_value=False), \
             mock.patch.object(gate, "base_action_files", return_value=set()), \
             mock.patch.object(gate, "paginate", side_effect=lambda p, params=None: [clean_doc] if p.endswith("/files") else []):
            missing_verdict, missing_reasons = gate.evaluate("o/r", 7)
        self.assertEqual(missing_verdict["verdict"], "fail")
        self.assertEqual(missing_verdict["tier"], "T2")
        self.assertIn("Cannot verify Git tree modes for changed files", missing_reasons)


if __name__ == "__main__":
    unittest.main()
