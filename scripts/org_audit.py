#!/usr/bin/env python3
"""Centralized drift and monolith audit for GitHub namespaces and local private repos."""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

PIN_RE = re.compile(r"Pigbibi/PrGovernance/pr-governance@([0-9a-f]{40})")


@dataclass(frozen=True)
class RepoFinding:
    repo: str
    issues: tuple[str, ...]


def evaluate_repo_snapshot(
    *,
    repo: str,
    archived: bool,
    visibility: str,
    has_agents_md: bool,
    has_claude_md: bool,
    has_branch_protection: bool | None,
    pinned_shas: list[str],
    canonical_sha: str,
    oversized_files: list[tuple[str, int]],
    max_file_bytes: int = 40960,
    has_githooks: bool | None = None,
    has_precommit: bool | None = None,
) -> RepoFinding | None:
    """Evaluate a repository snapshot and return drift/monolith findings if any."""
    if archived:
        return None
    issues: list[str] = []
    if not has_agents_md:
        issues.append("missing AGENTS.md")
    if not has_claude_md:
        issues.append("missing CLAUDE.md")
    if visibility.lower() == "public":
        if has_branch_protection is False:
            issues.append("missing branch protection")
        elif has_branch_protection is None:
            issues.append("branch protection unverified (token lacks admin:read)")
        if not pinned_shas:
            issues.append("missing PrGovernance workflow pin")
        elif any(sha != canonical_sha for sha in pinned_shas):
            stale = sorted({sha[:8] for sha in pinned_shas if sha != canonical_sha})
            issues.append(f"stale PrGovernance SHA ({', '.join(stale)} != {canonical_sha[:8]})")
    else:
        if has_githooks is False:
            issues.append("missing .githooks")
        if has_precommit is False:
            issues.append("missing .pre-commit-config.yaml")
    big = [f"{p} ({sz // 1024}KB)" for p, sz in oversized_files if sz >= max_file_bytes]
    if big:
        issues.append(f"monolith files >=40KB: {', '.join(big[:5])}")
    return RepoFinding(repo=repo, issues=tuple(issues)) if issues else None


def _gh_json_status(args: list[str], runner: Callable[..., subprocess.CompletedProcess]) -> tuple[int, object]:
    res = runner(["gh", *args], capture_output=True, text=True, check=False)
    if res.returncode != 0 or not res.stdout.strip():
        return res.returncode, res.stderr or res.stdout
    try:
        return 0, json.loads(res.stdout)
    except json.JSONDecodeError:
        return res.returncode, None


def audit_namespace(
    owner: str,
    canonical_sha: str,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> list[RepoFinding]:
    """Audit active public repositories in an owner/org namespace via gh CLI."""
    rc, repos = _gh_json_status(
        ["repo", "list", owner, "--limit", "100", "--json", "name,isArchived,visibility,defaultBranchRef"],
        runner,
    )
    if rc != 0 or not isinstance(repos, list):
        return []
    findings: list[RepoFinding] = []
    for item in repos:
        if item.get("isArchived") or str(item.get("visibility", "")).lower() != "public":
            continue
        name = item["name"]
        slug = f"{owner}/{name}"
        branch = (item.get("defaultBranchRef") or {}).get("name") or "main"
        _, tree = _gh_json_status(["api", f"repos/{slug}/git/trees/{branch}?recursive=1"], runner)
        entries = tree.get("tree", []) if isinstance(tree, dict) else []
        paths = {e["path"]: int(e.get("size") or 0) for e in entries if e.get("type") == "blob"}

        bp_rc, bp = _gh_json_status(["api", f"repos/{slug}/branches/{branch}/protection"], runner)
        if bp_rc == 0 and isinstance(bp, dict) and "required_status_checks" in bp:
            has_bp: bool | None = True
        elif isinstance(bp, str) and "404" in bp:
            has_bp = False
        else:
            has_bp = None

        pinned_shas: list[str] = []
        for wf_path in (".github/workflows/risk-gate.yml", ".github/workflows/gitleaks.yml", ".github/workflows/engineering-governance.yml"):
            if wf_path in paths:
                raw = runner(["gh", "api", f"repos/{slug}/contents/{wf_path}", "--jq", ".content"], capture_output=True, text=True, check=False)
                if raw.returncode == 0 and raw.stdout.strip():
                    text = base64.b64decode(raw.stdout.strip()).decode("utf-8", errors="ignore")
                    pinned_shas.extend(PIN_RE.findall(text))

        oversized = [(p, sz) for p, sz in paths.items() if p.endswith((".py", ".ts", ".js", ".vue", ".java")) and sz >= 40960]
        finding = evaluate_repo_snapshot(
            repo=slug,
            archived=False,
            visibility="public",
            has_agents_md="AGENTS.md" in paths,
            has_claude_md="CLAUDE.md" in paths,
            has_branch_protection=has_bp,
            pinned_shas=pinned_shas,
            canonical_sha=canonical_sha,
            oversized_files=oversized,
        )
        if finding:
            findings.append(finding)
    return findings


def audit_private_dir(root: Path) -> list[RepoFinding]:
    """Audit local private repository checkouts for hooks, configs, and monoliths."""
    findings: list[RepoFinding] = []
    if not root.is_dir():
        return findings
    for child in sorted(root.iterdir()):
        if not child.is_dir() or not (child / ".git").exists():
            continue
        oversized = []
        for ext in ("*.py", "*.ts", "*.js", "*.vue", "*.java"):
            for p in child.rglob(ext):
                if any(part in {".git", "node_modules", ".venv", "dist", "external"} for part in p.parts):
                    continue
                sz = p.stat().st_size
                if sz >= 40960:
                    oversized.append((str(p.relative_to(child)), sz))
        finding = evaluate_repo_snapshot(
            repo=child.name,
            archived=False,
            visibility="private",
            has_agents_md=(child / "AGENTS.md").is_file(),
            has_claude_md=(child / "CLAUDE.md").is_file(),
            has_branch_protection=None,
            pinned_shas=[],
            canonical_sha="",
            oversized_files=oversized,
            has_githooks=(child / ".githooks/pre-commit").is_file(),
            has_precommit=(child / ".pre-commit-config.yaml").is_file(),
        )
        if finding:
            findings.append(finding)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Weekly centralized governance drift audit.")
    parser.add_argument("--owners", nargs="+", default=["Pigbibi", "GdeiAssistant", "QuantStrategyLab"])
    parser.add_argument("--canonical-sha", required=True)
    parser.add_argument("--private-dir", type=Path, default=None, help="Optional directory of local private repo checkouts")
    args = parser.parse_args(argv)

    all_findings: list[RepoFinding] = []
    for owner in args.owners:
        all_findings.extend(audit_namespace(owner, args.canonical_sha))
    if args.private_dir is not None:
        all_findings.extend(audit_private_dir(args.private_dir))

    for f in all_findings:
        print(f"- {f.repo}: {'; '.join(f.issues)}")
    print(f"Total repos with findings: {len(all_findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
