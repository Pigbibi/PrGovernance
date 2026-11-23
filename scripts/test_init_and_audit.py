import json
import tempfile
import unittest
from pathlib import Path

from scripts.init_repo import scaffold_repo
from scripts.org_audit import evaluate_repo_snapshot


class InitRepoAndAuditTests(unittest.TestCase):
    def test_scaffold_public_python_creates_required_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            created = scaffold_repo(
                target,
                repo_slug="QuantStrategyLab/SampleService",
                visibility="public",
                stack="python",
                governance_root=Path(__file__).resolve().parents[1],
                pr_governance_sha="a" * 40,
            )
            self.assertIn("AGENTS.md", created)
            self.assertIn("CLAUDE.md", created)
            self.assertIn(".ruff.toml", created)
            self.assertIn(".importlinter", created)
            self.assertIn("pyrightconfig.json", created)
            self.assertEqual((target / "CLAUDE.md").read_text(encoding="utf-8"), "@AGENTS.md\n")
            wf = (target / ".github/workflows/risk-gate.yml").read_text(encoding="utf-8")
            self.assertIn("Pigbibi/PrGovernance/pr-governance@" + "a" * 40, wf)
            pyright = json.loads((target / "pyrightconfig.json").read_text(encoding="utf-8"))
            self.assertEqual(pyright["include"], ["src/sampleservice"])

    def test_scaffold_private_ts_adds_githooks_and_biome(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            created = scaffold_repo(
                target,
                repo_slug="Pigbibi/PrivateWeb",
                visibility="private",
                stack="ts",
                governance_root=Path(__file__).resolve().parents[1],
            )
            self.assertIn(".githooks/pre-commit", created)
            self.assertIn("governance/policy.json", created)
            self.assertIn("biome.json", created)
            self.assertFalse((target / ".github/workflows/risk-gate.yml").exists())

    def test_audit_distinguishes_missing_vs_unverified_bp_and_private_hooks(self):
        sha = "b" * 40
        finding = evaluate_repo_snapshot(
            repo="QuantStrategyLab/Example",
            archived=False,
            visibility="public",
            has_agents_md=False,
            has_claude_md=True,
            has_branch_protection=False,
            pinned_shas=["c" * 40],
            canonical_sha=sha,
            oversized_files=[("src/big.py", 51200)],
        )
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertIn("missing AGENTS.md", finding.issues)
        self.assertIn("missing branch protection", finding.issues)
        self.assertTrue(any("stale PrGovernance SHA" in i for i in finding.issues))
        self.assertTrue(any("monolith files >=40KB" in i for i in finding.issues))

        unverified = evaluate_repo_snapshot(
            repo="QuantStrategyLab/Other",
            archived=False,
            visibility="public",
            has_agents_md=True,
            has_claude_md=True,
            has_branch_protection=None,
            pinned_shas=[sha],
            canonical_sha=sha,
            oversized_files=[],
        )
        self.assertIsNotNone(unverified)
        assert unverified is not None
        self.assertIn("branch protection unverified (token lacks admin:read)", unverified.issues)

        priv = evaluate_repo_snapshot(
            repo="Pigbibi/Private",
            archived=False,
            visibility="private",
            has_agents_md=True,
            has_claude_md=True,
            has_branch_protection=None,
            pinned_shas=[],
            canonical_sha="",
            oversized_files=[],
            has_githooks=False,
            has_precommit=False,
        )
        self.assertIsNotNone(priv)
        assert priv is not None
        self.assertIn("missing .githooks", priv.issues)
        self.assertIn("missing .pre-commit-config.yaml", priv.issues)


if __name__ == "__main__":
    unittest.main()
