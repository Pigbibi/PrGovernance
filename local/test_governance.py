#!/usr/bin/env python3
"""Tests for the local governance hook runner."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import governance  # noqa: E402

GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
SLACK_TOKEN = "xoxb-1234567890-abcdefghij"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"


def run(*args, cwd=None, input_text=None):
    return subprocess.run(args, cwd=cwd, input=input_text, capture_output=True,
                          text=True, check=False)


class SecretScanTests(unittest.TestCase):
    def test_each_rule_is_detected(self):
        cases = {
            "private-key": PRIVATE_KEY,
            "github-token": f'token = "{GITHUB_TOKEN}"',
            "aws-access-key": f'aws_access_key_id = "{AWS_KEY}"',
            "slack-token": f'SLACK = "{SLACK_TOKEN}"',
            "credential-assignment": 'password = "hunter2hunter2hunter2"',
        }
        for rule, line in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(governance.scan_text(line), [(1, rule)])

    def test_placeholders_and_environment_references_pass(self):
        lines = [
            'api_key = "your_key_here"',
            'token = "<token>"',
            'password = "changeme"',
            'secret = os.environ["APP_SECRET"]',
            "token: process.env.GITHUB_TOKEN",
            "api_key = getenv('API_KEY')",
            'client_secret = "synthetic"',
            'PASSWORD="${DB_PASSWORD:-}"',
            'TIKHUB_API_KEY="${TIKHUB_API_KEY:-${FALLBACK_KEY:-}}"',
            'API_KEY="$API_KEY"',
            'TARGET_SECRET = "CONTACT_PHONE_LIST_JSON"',
            'DEV_SESSION_SECRET = "dev-session-secret-change-me"',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)), [])

    def test_an_exemption_on_the_line_does_not_exempt_the_value(self):
        lines = [
            'token = os.getenv("TOKEN", "' + GITHUB_TOKEN + '")',
            'token = "' + GITHUB_TOKEN + '"  # example account',
            'password = "hunter2hunter2hunter2"  # see sample config',
        ]
        findings = governance.scan_text("\n".join(lines))
        self.assertEqual([rule for _number, rule in findings],
                         ["github-token", "github-token", "credential-assignment"])

    def test_placeholders_do_not_mask_a_later_match(self):
        line = '{"token":"your_token_123456789012345","password":"hunter2hunter2hunter2"}'
        self.assertEqual(governance.scan_text(line), [(1, "credential-assignment")])

    def test_quoted_values_may_contain_punctuation(self):
        lines = [
            'password = "S0mething!LongEnough123"',
            'token = "c2VjcmV0S2V5MTIzNDU2Nzg5MA=="',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)),
                         [(1, "credential-assignment"), (2, "credential-assignment")])

    def test_prefixed_credential_names_are_detected(self):
        lines = [
            'client_secret = "hunter2hunter2hunter2"',
            'DATABASE_PASSWORD = "hunter2hunter2hunter2"',
            'OPENAI_API_KEY = "hunter2hunter2hunter2"',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)),
                         [(1, "credential-assignment"), (2, "credential-assignment"),
                          (3, "credential-assignment")])

    def test_quoted_keys_are_recognized(self):
        self.assertEqual(
            governance.scan_text('{"token": "hunter2hunter2hunter2"}'),
            [(1, "credential-assignment")])

    def test_short_or_low_entropy_values_are_not_credentials(self):
        lines = [
            '{"token": "changeme"}',
            '{"password": "hunter2"}',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)), [])

    def test_temporary_aws_key_is_detected(self):
        token = "ASIA" + "ABCDEFGHIJKLMNOP"
        self.assertEqual(governance.scan_text(f"AWS_ACCESS_KEY_ID={token}"),
                         [(1, "aws-access-key")])

    def test_encrypted_private_key_is_detected(self):
        self.assertEqual(governance.scan_text("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
                         [(1, "private-key")])

    def test_fine_grained_token_is_detected(self):
        token = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnop"
        self.assertEqual(governance.scan_text(f"Authorization: Bearer {token}"),
                         [(1, "github-token")])

    def test_finding_reports_the_line_number(self):
        text = "clean line\nanother\n" + PRIVATE_KEY
        self.assertEqual(governance.scan_text(text), [(3, "private-key")])

    def test_fixture_words_are_not_credentials(self):
        lines = [
            'token = "test-access-token"',
            'token = "fake-session-value"',
            'secret = "mca_gemini_test_key_NOT_FOR_LOG"',
            'main.PASSWORD = "test-password-value"',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)), [])

    def test_long_alphabetic_passphrases_are_credentials(self):
        lines = [
            'password = "correcthorsebatterystaple"',
            'password = "correct-horse-battery-staple"',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)),
                         [(1, "credential-assignment"), (2, "credential-assignment")])

    def test_function_results_are_not_credentials(self):
        lines = [
            "token = _h5_token_from_client(client)",
            "api_key = _repo_gemini_api_key_fallback()",
            "options.password = decodeURIComponent(parsed.password)",
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)), [])


class SensitivePathTests(unittest.TestCase):
    def test_sensitive_files(self):
        flagged = [".env", ".env.local", "config/credentials.json", "deploy/id_rsa",
                   "certs/server.pem", "keys/signing.key", "keys/release.jks",
                   "keys/release.bks"]
        for path in flagged:
            with self.subTest(path=path):
                self.assertIsNotNone(governance.SENSITIVE_FILE.search(path))
                self.assertIsNone(governance.SENSITIVE_EXEMPT.search(path))

    def test_templates_are_exempt(self):
        for path in [".env.example", ".env.sample", ".env.template",
                     "credentials.example.json"]:
            with self.subTest(path=path):
                self.assertIsNotNone(governance.SENSITIVE_EXEMPT.search(path))


class CommitHeaderTests(unittest.TestCase):
    settings = governance.DEFAULT_CONFIG

    def test_conventional_headers_pass(self):
        for header in ["feat: add retry", "fix(parser): handle empty input",
                       "chore(deps)!: drop python 3.8", 'Revert "feat: add retry"',
                       "Merge branch 'main' into feature"]:
            with self.subTest(header=header):
                self.assertIsNone(governance.check_header(header, self.settings))

    def test_unknown_type_fails(self):
        self.assertIn("conventional type",
                      governance.check_header("update stuff", self.settings))

    def test_long_header_fails(self):
        error = governance.check_header("feat: " + "x" * 80, self.settings)
        self.assertIn("characters", error)

    def test_configured_types_are_honoured(self):
        settings = dict(self.settings, commit_types=["feat"])
        self.assertIn("conventional type",
                      governance.check_header("fix: nope", settings))


class ProtectedPushTests(unittest.TestCase):
    settings = governance.DEFAULT_CONFIG

    @staticmethod
    def ancestor(old, new):
        return old != "f" * 40 and new != "0" * 40 and old != "e" * 40

    def test_direct_push_to_protected_branch_fails(self):
        line = f"refs/heads/main {'a' * 40} refs/heads/main {'b' * 40}"
        self.assertIn("protected branch main",
                      governance.protected_push([line], self.settings, self.ancestor)[0])

    def test_feature_branch_fast_forward_passes(self):
        line = f"refs/heads/feat/x {'a' * 40} refs/heads/feat/x {'b' * 40}"
        self.assertEqual(governance.protected_push([line], self.settings, self.ancestor), [])

    def test_force_push_fails(self):
        line = f"refs/heads/feat/x {'a' * 40} refs/heads/feat/x {'e' * 40}"
        self.assertIn("non-fast-forward",
                      governance.protected_push([line], self.settings, self.ancestor)[0])

    def test_deleting_a_feature_branch_passes(self):
        line = f"(delete) {'0' * 40} refs/heads/feat/x {'b' * 40}"
        self.assertEqual(governance.protected_push([line], self.settings, self.ancestor), [])

    def test_sha256_null_object_ids_are_recognized(self):
        line = f"(delete) {'0' * 64} refs/heads/feat/x {'b' * 64}"
        self.assertEqual(governance.protected_push([line], self.settings, self.ancestor), [])

    def test_deleting_a_protected_branch_fails(self):
        line = f"(delete) {'0' * 40} refs/heads/main {'b' * 40}"
        self.assertIn("protected branch main",
                      governance.protected_push([line], self.settings, self.ancestor)[0])


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = self.directory.name
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")

    def tearDown(self):
        self.directory.cleanup()

    def git(self, *args, cwd=None):
        result = run("git", "-C", cwd or self.root, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def write(self, name, text):
        path = Path(self.root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def cli(self, *args, input_text=None):
        return run(sys.executable, str(Path(__file__).parent / "governance.py"),
                   *args, "--root", self.root, input_text=input_text)

    def test_staged_secret_is_reported(self):
        self.write("settings.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "settings.py")
        findings = governance.audit(self.root, True, governance.config(self.root))
        self.assertEqual(findings, ["settings.py:1: github-token"])

    def test_clean_index_passes(self):
        self.write("settings.py", 'TOKEN = os.environ["TOKEN"]\n')
        self.git("add", "settings.py")
        self.assertEqual(governance.audit(self.root, True, governance.config(self.root)), [])

    def test_tracked_sensitive_file_is_reported(self):
        self.write(".env", "PORT=8080\n")
        self.git("add", ".env")
        findings = governance.audit(self.root, True, governance.config(self.root))
        self.assertEqual(findings, [".env: sensitive file is tracked"])

    def test_env_template_is_allowed(self):
        self.write(".env.example", "PORT=8080\nTOKEN=your_token_here\n")
        self.git("add", ".env.example")
        self.assertEqual(governance.audit(self.root, True, governance.config(self.root)), [])

    def test_history_audit_reads_committed_content(self):
        self.write("notes.txt", "nothing to see\n")
        self.git("add", "notes.txt")
        self.git("commit", "-q", "-m", "docs: add notes")
        self.assertEqual(governance.audit(self.root, False, governance.config(self.root)), [])
        self.write("notes.txt", f"key {AWS_KEY}\n")
        self.git("add", "notes.txt")
        self.git("commit", "-q", "-m", "docs: add key")
        self.assertEqual(governance.audit(self.root, False, governance.config(self.root)),
                         ["notes.txt:1: aws-access-key"])

    def test_history_audit_ignores_staged_deletion(self):
        self.write("settings.txt", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "settings.txt")
        self.git("commit", "-q", "-m", "feat: add settings")
        self.git("rm", "-q", "settings.txt")
        findings = governance.audit(self.root, False, governance.config(self.root))
        self.assertEqual(findings, ["settings.txt:1: github-token"])

    def test_newline_in_filename_does_not_hide_other_files(self):
        self.write("a\nb.txt", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.write("z.txt", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "-A")
        findings = governance.audit(self.root, True, governance.config(self.root))
        self.assertEqual(sum("github-token" in finding for finding in findings), 2)

    def test_audit_fails_outside_a_repository(self):
        with tempfile.TemporaryDirectory() as plain:
            with self.assertRaises(SystemExit):
                governance.audit(plain, False, governance.config(plain))

    def test_type_change_is_scanned(self):
        self.write("real.txt", "x\n")
        (Path(self.root) / "settings.py").symlink_to("real.txt")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "feat: add link")
        (Path(self.root) / "settings.py").unlink()
        self.write("settings.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "settings.py")
        findings = governance.audit(self.root, True, governance.config(self.root))
        self.assertEqual(findings, ["settings.py:1: github-token"])

    def test_missing_blob_fails_closed(self):
        self.write("settings.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "settings.py")
        sha = run("git", "-C", self.root, "ls-files", "-s", "settings.py").stdout.split()[1]
        object_path = Path(self.root) / ".git" / "objects" / sha[:2] / sha[2:]
        object_path.unlink()
        with self.assertRaises(SystemExit):
            governance.audit(self.root, True, governance.config(self.root))

    def test_install_uses_the_common_git_directory(self):
        self.write("a.txt", "x\n")
        self.git("add", "a.txt")
        self.git("commit", "-q", "-m", "feat: add a")
        with tempfile.TemporaryDirectory() as parent:
            worktree = Path(parent) / "wt"
            self.git("worktree", "add", "-q", "-b", "wt-branch", str(worktree))
            hooks = worktree / ".githooks"
            hooks.mkdir()
            for name in ["governance.py", "pre-commit", "commit-msg", "pre-push"]:
                (hooks / name).write_bytes(
                    (Path(__file__).parent / name).read_bytes())
            result = run(sys.executable, str(hooks / "governance.py"), "install",
                         "--root", str(worktree))
            self.assertEqual(result.returncode, 0, result.stderr)
            configured = run("git", "-C", self.root, "config", "core.hooksPath").stdout.strip()
            self.assertEqual(Path(configured).resolve(),
                             (Path(self.root) / ".git" / "governance").resolve())
            self.git("worktree", "remove", "--force", str(worktree))
            self.assertTrue((Path(configured) / "governance.py").is_file())

    def test_staged_audit_scans_the_whole_index(self):
        self.write("settings.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "settings.py")
        self.git("commit", "-q", "-m", "feat: add settings")
        self.assertEqual(governance.audit(self.root, True, governance.config(self.root)),
                         ["settings.py:1: github-token"])
        self.assertEqual(governance.hook_pre_commit(self.root), [])

    def test_staged_submodule_is_skipped(self):
        self.write("a.txt", "x\n")
        self.git("add", "a.txt")
        self.git("commit", "-q", "-m", "feat: add a")
        sha = run("git", "-C", self.root, "rev-parse", "HEAD").stdout.strip()
        self.git("update-index", "--add", "--cacheinfo", f"160000,{sha},vendor/sub")
        self.assertEqual(governance.audit(self.root, True, governance.config(self.root)), [])

    def test_audit_from_subdirectory_covers_the_whole_tree(self):
        self.write("secret.txt", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", "secret.txt")
        self.git("commit", "-q", "-m", "feat: add secret")
        self.write("src/clean.py", "print(1)\n")
        self.git("add", "src/clean.py")
        self.git("commit", "-q", "-m", "feat: add clean")
        result = run(sys.executable, str(Path(__file__).parent / "governance.py"),
                     "audit", cwd=Path(self.root) / "src")
        self.assertEqual(result.returncode, 1)
        self.assertIn("secret.txt", result.stderr)

    def test_repository_config_overrides_defaults(self):
        self.write(".git/governance/governance.json",
                   json.dumps({"protected_branches": ["trunk"], "max_header": 10}))
        settings = governance.config(self.root)
        self.assertEqual(settings["protected_branches"], ["trunk"])
        self.assertEqual(settings["max_header"], 10)
        self.assertEqual(settings["commit_types"], governance.DEFAULT_CONFIG["commit_types"])

    def test_branch_config_is_not_read_before_install(self):
        self.write(".githooks/governance.json",
                   json.dumps({"ignore_paths": ["secret.txt"], "protected_branches": []}))
        settings = governance.config(self.root)
        self.assertEqual(settings["ignore_paths"], [])
        self.assertEqual(settings["protected_branches"], ["main", "master"])

    def test_config_cannot_disable_the_audit(self):
        for payload in [{"ignore_paths": [""]}, {"ignore_paths": "tests/"},
                        {"max_header": 0}, {"commit_types": [""]}]:
            with self.subTest(payload=payload):
                self.write(".git/governance/governance.json", json.dumps(payload))
                with self.assertRaises(SystemExit):
                    governance.config(self.root)

    def test_pre_commit_command_fails_closed(self):
        self.write("app.js", "const token = '" + SLACK_TOKEN + "';\n")
        self.git("add", "app.js")
        result = self.cli("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("slack-token", result.stderr)

    def test_commit_msg_command_reads_the_file(self):
        message = self.write("msg.txt", "update things\n")
        result = self.cli("commit-msg", str(message))
        self.assertEqual(result.returncode, 1)
        self.assertIn("conventional type", result.stderr)

    def test_pre_push_command_reads_stdin(self):
        line = f"refs/heads/main {'a' * 40} refs/heads/main {'b' * 40}\n"
        result = self.cli("pre-push", input_text=line)
        self.assertEqual(result.returncode, 1)
        self.assertIn("protected branch main", result.stderr)

    def test_install_wires_the_hooks_path(self):
        names = ["governance.py", "pre-commit", "commit-msg", "pre-push"]
        for name in names:
            self.write(f".githooks/{name}", "#!/bin/sh\n")
        result = self.cli("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        git_dir = run("git", "-C", self.root, "rev-parse", "--absolute-git-dir").stdout.strip()
        target = Path(git_dir) / "governance"
        configured = run("git", "-C", self.root, "config", "core.hooksPath").stdout.strip()
        self.assertEqual(configured, str(target))
        for name in names:
            self.assertTrue((target / name).is_file())
            self.assertTrue(os.access(target / name, os.X_OK))
        self.assertFalse(os.access(Path(self.root) / ".githooks" / "pre-commit", os.X_OK))

    def test_installed_config_wins_over_the_branch(self):
        names = ["governance.py", "pre-commit", "commit-msg", "pre-push"]
        for name in names:
            self.write(f".githooks/{name}", "#!/bin/sh\n")
        self.write(".githooks/governance.json",
                   json.dumps({"ignore_paths": [".githooks/"]}))
        self.assertEqual(self.cli("install").returncode, 0)
        self.write(".githooks/governance.json",
                   json.dumps({"ignore_paths": ["secret.txt"], "protected_branches": []}))
        self.assertEqual(governance.config(self.root)["ignore_paths"], [".githooks/"])
        self.assertEqual(governance.config(self.root)["protected_branches"], ["main", "master"])

    def test_install_from_a_trusted_source(self):
        with tempfile.TemporaryDirectory() as trusted:
            for name in ["governance.py", "pre-commit", "commit-msg", "pre-push"]:
                (Path(trusted) / name).write_text("#!/bin/sh\n")
            result = governance.install(self.root, trusted)
            self.assertEqual(result, [])
            configured = run("git", "-C", self.root, "config", "core.hooksPath").stdout.strip()
            self.assertTrue((Path(configured) / "governance.py").is_file())

    def test_utf16_text_is_scanned(self):
        (Path(self.root) / "deploy.ps1").write_bytes(
            f'TOKEN = "{GITHUB_TOKEN}"\n'.encode("utf-16"))
        self.git("add", "deploy.ps1")
        findings = governance.audit(self.root, True, governance.config(self.root))
        self.assertEqual(findings, ["deploy.ps1:1: github-token"])

    def test_binary_files_are_skipped(self):
        (Path(self.root) / "image.bin").write_bytes(b"\x00\x01\x02" * 100)
        self.git("add", "image.bin")
        self.assertEqual(governance.audit(self.root, True, governance.config(self.root)), [])

    def test_credentials_beside_the_hooks_are_scanned(self):
        self.write(".githooks/release.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", ".githooks/release.py")
        self.assertEqual(governance.audit(self.root, True, governance.config(self.root)),
                         [".githooks/release.py:1: github-token"])

    def test_ignored_file_does_not_hide_a_sibling(self):
        self.write(".githooks/governance.json", "{}\n")
        self.write(".githooks/governance.json.bak", f'TOKEN = "{GITHUB_TOKEN}"\n')
        self.git("add", ".githooks")
        settings = dict(governance.DEFAULT_CONFIG, ignore_paths=[".githooks/governance.json"])
        self.assertEqual(governance.audit(self.root, True, settings),
                         [".githooks/governance.json.bak:1: github-token"])

    def test_install_refuses_a_partial_checkout(self):
        self.write(".githooks/pre-commit", "#!/bin/sh\n")
        result = self.cli("install")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing file commit-msg", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
