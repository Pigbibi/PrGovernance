#!/usr/bin/env python3
"""Tests for repository documentation and naming hygiene checks."""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent / "check_hygiene.py"
SPEC = importlib.util.spec_from_file_location("check_hygiene", SCRIPT_PATH)
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class CheckHygieneAncestorSkipDirTests(unittest.TestCase):
    def _init_minimal_repo(self, repo: Path) -> None:
        repo.mkdir(parents=True, exist_ok=True)
        agents = "\n".join(
            ["<!-- content-boundary:begin -->"] + [f"## {s}\nOK" for s in hygiene.AGENTS_SECTIONS]
        )
        (repo / "AGENTS.md").write_text(agents + "\n", encoding="utf-8")
        (repo / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
        (repo / "SECURITY.md").write_text("# Security\n\nReport issues privately.\n", encoding="utf-8")
        (repo / ".gitignore").write_text("docs/audits/\n", encoding="utf-8")
        (repo / "docs").mkdir(exist_ok=True)
        (repo / "docs" / "guide.md").write_text("# Guide\n\nSetup steps.\n", encoding="utf-8")
        (repo / "build" / "plans").mkdir(parents=True, exist_ok=True)
        (repo / "build" / "2026-01-01-audit.md").write_text("# Build artifact\n", encoding="utf-8")

        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
        subprocess.run(["git", "add", "AGENTS.md", "CLAUDE.md", "SECURITY.md", ".gitignore"], cwd=repo, check=True)

    def test_repo_under_build_ancestor_scans_repo_and_skips_repo_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "build" / "repo"
            self._init_minimal_repo(repo)

            found_rels = {p.relative_to(repo).as_posix() for p in hygiene.iter_files(repo)}
            self.assertIn("docs/guide.md", found_rels)
            self.assertNotIn("build/2026-01-01-audit.md", found_rels)

            clean = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--root", str(repo)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clean.returncode, 0, msg=clean.stdout + clean.stderr)

            (repo / "plans").mkdir()
            (repo / "docs" / "postmortem.md").write_text("# Notes\n", encoding="utf-8")

            dirty = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--root", str(repo)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(dirty.returncode, 1, msg=dirty.stdout + dirty.stderr)
            self.assertIn("plans/: do not split directories by phase", dirty.stdout)
            self.assertIn("docs/postmortem.md:", dirty.stdout)


if __name__ == "__main__":
    unittest.main()
