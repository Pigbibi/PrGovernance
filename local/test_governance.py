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
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)), [])

    def test_finding_reports_the_line_number(self):
        text = "clean line\nanother\n" + PRIVATE_KEY
        self.assertEqual(governance.scan_text(text), [(3, "private-key")])

    def test_fixture_words_are_not_credentials(self):
        lines = [
            'token = "test-access-token"',
            'token = "must-not-land-in-session"',
            'secret = "mca_gemini_test_key_NOT_FOR_LOG"',
            'main.PASSWORD = "test-password-value"',
        ]
        self.assertEqual(governance.scan_text("\n".join(lines)), [])

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
                   "certs/server.pem", "keys/signing.key"]
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
        line = f"(delete) {governance.ZERO_SHA} refs/heads/feat/x {'b' * 40}"
        self.assertEqual(governance.protected_push([line], self.settings, self.ancestor), [])

    def test_deleting_a_protected_branch_fails(self):
        line = f"(delete) {governance.ZERO_SHA} refs/heads/main {'b' * 40}"
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

    def test_repository_config_overrides_defaults(self):
        self.write(".githooks/governance.json",
                   json.dumps({"protected_branches": ["trunk"], "max_header": 10}))
        settings = governance.config(self.root)
        self.assertEqual(settings["protected_branches"], ["trunk"])
        self.assertEqual(settings["max_header"], 10)
        self.assertEqual(settings["commit_types"], governance.DEFAULT_CONFIG["commit_types"])

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
        for name in ["pre-commit", "commit-msg", "pre-push"]:
            self.write(f".githooks/{name}", "#!/bin/sh\n")
        result = self.cli("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        configured = run("git", "-C", self.root, "config", "core.hooksPath").stdout.strip()
        self.assertEqual(configured, ".githooks")
        for name in ["pre-commit", "commit-msg", "pre-push"]:
            self.assertTrue(os.access(Path(self.root) / ".githooks" / name, os.X_OK))

    def test_install_refuses_a_partial_checkout(self):
        self.write(".githooks/pre-commit", "#!/bin/sh\n")
        result = self.cli("install")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing hook commit-msg", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
