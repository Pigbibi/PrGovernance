#!/usr/bin/env python3
"""Scaffold a new or existing repository to comply with org governance rules."""

from __future__ import annotations

import argparse
import json
import shutil
import stat
import subprocess
from pathlib import Path

PR_GOVERNANCE_SHA_DEFAULT = "3d44e3d057681d5ae2730ad76af2f53b72d26767"

PRECOMMIT_GITLEAKS = """repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: 83d9cd684c87d95d656c1458ef04895a7f1cbd8e # v8.30.1
    hooks:
      - id: gitleaks
        args: [--redact]
"""

PR_TEMPLATE = """## AI assistance
- Model / agent:

## What changed
-

## How verified
-

## Why
-

## Risk
-
"""

BIOME_JSON = """{
  "formatter": {
    "enabled": false
  },
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "complexity": {
        "noExcessiveCognitiveComplexity": {
          "level": "warn",
          "options": {
            "maxAllowedComplexity": 20
          }
        }
      }
    }
  },
  "files": {
    "includes": ["src/**"]
  }
}
"""

RUFF_TOML = """target-version = "py311"

[lint]
extend-select = ["B", "C901"]

[lint.mccabe]
max-complexity = 15

[lint.per-file-ignores]
"tests/**/*.py" = ["E402", "B", "C901"]
"""


def _write_if_missing(path: Path, content: str, executable: bool = False) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


def _agents_md(repo_name: str, stack: str, visibility: str) -> str:
    return (
        f"# {repo_name}\n\n"
        f"Stack: `{stack}` · Visibility: `{visibility}`\n\n"
        "## Rules\n"
        "- Never commit secrets, tokens, or real account identifiers.\n"
        "- Keep functions modular and under Ruff `C901 <= 15` (or Biome complexity <= 20).\n"
        "- Use Conventional Commits (<= 72 chars) and fill `.github/PULL_REQUEST_TEMPLATE.md`.\n"
    )


def _pyright_json(pkg_name: str) -> str:
    return json.dumps(
        {
            "include": [f"src/{pkg_name}"],
            "extraPaths": ["src"],
            "pythonVersion": "3.11",
            "typeCheckingMode": "basic",
        },
        indent=2,
    ) + "\n"


def _importlinter_ini(pkg_name: str) -> str:
    return (
        "[importlinter]\n"
        f"root_package = {pkg_name}\n\n"
        "[importlinter:contract:application_no_entrypoints]\n"
        "name = Application must not import entrypoints or routes\n"
        "type = forbidden\n"
        "source_modules =\n"
        f"    {pkg_name}.application\n"
        "forbidden_modules =\n"
        f"    {pkg_name}.entrypoints\n"
    )


def _pinned_workflow(template_text: str, sha: str) -> str:
    return (
        template_text
        .replace("__GOVERNANCE_REPO__", "Pigbibi/PrGovernance")
        .replace("__GOVERNANCE_SHA__", sha)
        .replace("Pigbibi/PrGovernance/pr-governance@v1", f"Pigbibi/PrGovernance/pr-governance@{sha}")
    )


def scaffold_repo(
    target_dir: Path,
    *,
    repo_slug: str,
    visibility: str = "public",
    stack: str = "python",
    governance_root: Path | None = None,
    pr_governance_sha: str = PR_GOVERNANCE_SHA_DEFAULT,
) -> list[str]:
    """Create missing governance and Tier-1 baseline files without overwriting existing ones."""
    created: list[str] = []
    repo_name = repo_slug.split("/")[-1]
    pkg_name = repo_name.lower().replace("-", "_")
    gov_root = governance_root or Path(__file__).resolve().parents[1]

    if _write_if_missing(target_dir / "AGENTS.md", _agents_md(repo_name, stack, visibility)):
        created.append("AGENTS.md")
    if _write_if_missing(target_dir / "CLAUDE.md", "@AGENTS.md\n"):
        created.append("CLAUDE.md")
    if _write_if_missing(target_dir / ".github/PULL_REQUEST_TEMPLATE.md", PR_TEMPLATE):
        created.append(".github/PULL_REQUEST_TEMPLATE.md")
    if _write_if_missing(target_dir / ".pre-commit-config.yaml", PRECOMMIT_GITLEAKS):
        created.append(".pre-commit-config.yaml")

    if visibility == "public":
        tpl_dir = gov_root / "pr-governance/templates"
        for tpl_name in ("gitleaks.yml", "risk-gate.yml", "pr-review-signal.yml", "codex-nudge.yml"):
            src = tpl_dir / tpl_name
            if src.exists():
                dst = target_dir / ".github/workflows" / tpl_name
                if _write_if_missing(dst, _pinned_workflow(src.read_text(encoding="utf-8"), pr_governance_sha)):
                    created.append(f".github/workflows/{tpl_name}")
    else:
        local_dir = gov_root / "local"
        for hook in ("commit-msg", "pre-commit", "pre-push", "governance.py"):
            src = local_dir / hook
            dst = target_dir / ".githooks" / hook
            if src.exists() and not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                created.append(f".githooks/{hook}")
        pol_src = gov_root / "pr-governance/policy.default.json"
        if pol_src.exists() and _write_if_missing(target_dir / "governance/policy.json", pol_src.read_text(encoding="utf-8")):
            created.append("governance/policy.json")
        gate_src = local_dir / "merge_gate.py"
        if gate_src.exists():
            gate_dst = target_dir / "governance/merge_gate.py"
            if not gate_dst.exists():
                gate_dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(gate_src, gate_dst)
                gate_dst.chmod(gate_dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                created.append("governance/merge_gate.py")

    if stack == "python":
        if _write_if_missing(target_dir / ".ruff.toml", RUFF_TOML):
            created.append(".ruff.toml")
        if _write_if_missing(target_dir / "pyrightconfig.json", _pyright_json(pkg_name)):
            created.append("pyrightconfig.json")
        if _write_if_missing(target_dir / ".importlinter", _importlinter_ini(pkg_name)):
            created.append(".importlinter")
    elif stack == "ts":
        if _write_if_missing(target_dir / "biome.json", BIOME_JSON):
            created.append("biome.json")

    return created


def apply_branch_protection(repo_slug: str, branch: str = "main") -> None:
    """Apply standard required checks on a public GitHub repository."""
    payload = {
        "required_status_checks": {
            "strict": True,
            "contexts": ["Gitleaks", "pr-template", "ai-review", "risk-gate"],
        },
        "enforce_admins": True,
        "required_pull_request_reviews": None,
        "restrictions": None,
    }
    subprocess.run(
        ["gh", "api", "-X", "PUT", f"repos/{repo_slug}/branches/{branch}/protection", "--input", "-"],
        input=json.dumps(payload),
        text=True,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialize repository governance and Tier-1 gates.")
    parser.add_argument("--repo", required=True, help="Repository slug, e.g. QuantStrategyLab/NewRepo")
    parser.add_argument("--target", default=".", help="Local repository path")
    parser.add_argument("--visibility", choices=("public", "private"), default="public")
    parser.add_argument("--stack", choices=("python", "ts", "java"), default="python")
    parser.add_argument("--sha", default=PR_GOVERNANCE_SHA_DEFAULT, help="Pinned PrGovernance SHA")
    parser.add_argument("--apply-bp", action="store_true", help="Apply GitHub branch protection (public only)")
    parser.add_argument("--branch", default="main", help="Default branch name for branch protection")
    args = parser.parse_args(argv)

    created = scaffold_repo(
        Path(args.target),
        repo_slug=args.repo,
        visibility=args.visibility,
        stack=args.stack,
        pr_governance_sha=args.sha,
    )
    print(json.dumps({"repo": args.repo, "created": created}, ensure_ascii=False))
    if args.apply_bp and args.visibility == "public":
        apply_branch_protection(args.repo, branch=args.branch)
        print(f"Applied branch protection to {args.repo}:{args.branch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
